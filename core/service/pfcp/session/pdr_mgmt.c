/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "session_instance.h"
#include "session_orphan.h"
#include "session_teid.h"
#include "far_mgmt.h"
#include "session_report.h"
#include "pfd_mgmt.h"
#include "sp_dns_cache.h"
#include "session_ethernet.h"

#include "local_parse.h"
#include "pdr_mgmt.h"
#include "predefine_rule_mgmt.h"

struct pdr_table_head pdr_tbl_head;
struct sdf_filter_table sdf_filter_head;
struct eth_filter_table eth_filter_head;

void sdf_filter_show(struct sdf_filter_entry *filter_entry)
{
    LOG(SESSION, RUNNING, "SDF filter index: %u", filter_entry->index);
    LOG(SESSION, RUNNING, "SDF filter flag: %d", filter_entry->sdf_cfg.sdf_flag.value);
    if (filter_entry->sdf_cfg.sdf_flag.d.fd) {
        LOG(SESSION, RUNNING, "SDF filter match ip type: %d",
            filter_entry->sdf_cfg.desc.ip_type);
        if (SESSION_IP_V4 & filter_entry->sdf_cfg.desc.ip_type) {
            LOG(SESSION, RUNNING, "SDF filter sip: 0x%x",
                filter_entry->sdf_cfg.desc.sip.sipv4);
            LOG(SESSION, RUNNING, "SDF filter sip mask: 0x%x",
                filter_entry->sdf_cfg.desc.smask.sipv4_mask);
            LOG(SESSION, RUNNING, "SDF filter dip: 0x%x",
                filter_entry->sdf_cfg.desc.dip.dipv4);
            LOG(SESSION, RUNNING, "SDF filter dip mask: 0x%x",
                filter_entry->sdf_cfg.desc.dmask.dipv4_mask);
            LOG(SESSION, RUNNING, "SDF filter sport min: %d",
                filter_entry->sdf_cfg.desc.sp_min);
            LOG(SESSION, RUNNING, "SDF filter sport max: %d",
                filter_entry->sdf_cfg.desc.sp_max);
            LOG(SESSION, RUNNING, "SDF filter dport min: %d",
                filter_entry->sdf_cfg.desc.dp_min);
            LOG(SESSION, RUNNING, "SDF filter dport max: %d",
                filter_entry->sdf_cfg.desc.dp_max);
            LOG(SESSION, RUNNING, "SDF filter protcol : %d",
                filter_entry->sdf_cfg.desc.protocol);
            LOG(SESSION, RUNNING, "SDF filter IP type : %d",
                filter_entry->sdf_cfg.desc.ip_type);
            LOG(SESSION, RUNNING, "SDF filter no-sp : %d, no-dp : %d",
                filter_entry->sdf_cfg.desc.no_sp, filter_entry->sdf_cfg.desc.no_dp);
        } else if (SESSION_IP_V6 & filter_entry->sdf_cfg.desc.ip_type) {
            // show ipv6
        }
    }
    if (filter_entry->sdf_cfg.sdf_flag.d.ttc) {
        LOG(SESSION, RUNNING, "SDF filter tos: %d",
            filter_entry->sdf_cfg.tos_traffic_class.d.tos);
        LOG(SESSION, RUNNING, "SDF filter tos mask: %d",
            filter_entry->sdf_cfg.tos_traffic_class.d.tos_mask);
    }
    if (filter_entry->sdf_cfg.sdf_flag.d.spi) {
        LOG(SESSION, RUNNING, "SDF filter ipsec spi: %u",
            filter_entry->sdf_cfg.ipsec_spi);
    }
    if (filter_entry->sdf_cfg.sdf_flag.d.fl) {
        LOG(SESSION, RUNNING, "SDF filter flowlabel: %d",
            filter_entry->sdf_cfg.label.value);
    }
    if (filter_entry->sdf_cfg.sdf_flag.d.bid) {
        LOG(SESSION, RUNNING, "SDF filter id: %u",
            filter_entry->sdf_cfg.sdf_id);
    }
    LOG(SESSION, RUNNING," ");
}

void pdr_table_show(struct pdr_table *pdr_tbl)
{
    uint32_t cnt = 0;
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    struct dl_list *list_head = NULL;

    LOG(SESSION, RUNNING, "--------------pdr--------------");
    LOG(SESSION, RUNNING, "index(instance id):  %u", pdr_tbl->index);
    LOG(SESSION, RUNNING, "pdr id:              %u", pdr_tbl->pdr.pdr_id);
    LOG(SESSION, RUNNING, "precedence:          %u", pdr_tbl->pdr.precedence);
    LOG(SESSION, RUNNING, "nocp flag:           %d", ros_atomic16_read(&pdr_tbl->nocp_flag));
    LOG(SESSION, RUNNING, "outer header removal present: %d",
        pdr_tbl->pdr.outer_header_removal.ohr_flag);
    LOG(SESSION, RUNNING, "outer header removal type: %d",
        pdr_tbl->pdr.outer_header_removal.type);
    LOG(SESSION, RUNNING, "outer header removal flag: %d",
        pdr_tbl->pdr.outer_header_removal.flag);


    LOG(SESSION, RUNNING, "far id: %u", pdr_tbl->pdr.far_id);
    LOG(SESSION, RUNNING, "urr list number: %u",
        pdr_tbl->pdr.urr_list_number);
    for (cnt = 0; cnt < pdr_tbl->pdr.urr_list_number; ++cnt) {
        LOG(SESSION, RUNNING, "urr id: %u",
            pdr_tbl->pdr.urr_id_array[cnt]);
    }
    LOG(SESSION, RUNNING, "qer list number: %u",
        pdr_tbl->pdr.qer_list_number);
    for (cnt = 0; cnt < pdr_tbl->pdr.qer_list_number; ++cnt) {
        LOG(SESSION, RUNNING, "qer id: %u",
            pdr_tbl->pdr.qer_id_array[cnt]);
    }
    LOG(SESSION, RUNNING, "source interface: %d",
        pdr_tbl->pdr.pdi_content.si);
    for (cnt = 0; cnt < pdr_tbl->pdr.pdi_content.local_fteid_num; ++cnt) {
        session_f_teid *loc_fteid = &pdr_tbl->pdr.pdi_content.local_fteid[cnt].local_fteid;

        LOG(SESSION, RUNNING, "f-teid type: %d", loc_fteid->f_teid_flag.value);
        if (loc_fteid->f_teid_flag.d.chid) {
            LOG(SESSION, RUNNING, "choose id of local fteid: %d",
                loc_fteid->choose_id);
        }
        if (loc_fteid->f_teid_flag.d.v4) {
            LOG(SESSION, RUNNING, "f-teid ipv4 address: 0x%08x",
                loc_fteid->ipv4_addr);
        }
        if (loc_fteid->f_teid_flag.d.v6) {
            LOG(SESSION, RUNNING, "f-teid ipv6 address: 0x%02x%02x%02x%02x "
                "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                loc_fteid->ipv6_addr[0],
                loc_fteid->ipv6_addr[1],
                loc_fteid->ipv6_addr[2],
                loc_fteid->ipv6_addr[3],
                loc_fteid->ipv6_addr[4],
                loc_fteid->ipv6_addr[5],
                loc_fteid->ipv6_addr[6],
                loc_fteid->ipv6_addr[7],
                loc_fteid->ipv6_addr[8],
                loc_fteid->ipv6_addr[9],
                loc_fteid->ipv6_addr[10],
                loc_fteid->ipv6_addr[11],
                loc_fteid->ipv6_addr[12],
                loc_fteid->ipv6_addr[13],
                loc_fteid->ipv6_addr[14],
                loc_fteid->ipv6_addr[15]);
        }
        LOG(SESSION, RUNNING, "teid: %u", loc_fteid->teid);
    }

    LOG(SESSION, RUNNING, "ueip number: %d", pdr_tbl->pdr.pdi_content.ue_ipaddr_num);
    for (cnt = 0; cnt < pdr_tbl->pdr.pdi_content.ue_ipaddr_num; ++cnt) {
        struct pdr_ue_ipaddress *ue_ip = &pdr_tbl->pdr.pdi_content.ue_ipaddr[cnt];

        if (ue_ip->ueip.ueip_flag.d.v4) {
            LOG(SESSION, RUNNING, "ueip ipv4 address: 0x%08x",
                ue_ip->ueip.ipv4_addr);
        }
        if (ue_ip->ueip.ueip_flag.d.v6) {
            LOG(SESSION, RUNNING, "ueip ipv6 address: 0x%02x%02x%02x%02x "
                "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                ue_ip->ueip.ipv6_addr[0],
                ue_ip->ueip.ipv6_addr[1],
                ue_ip->ueip.ipv6_addr[2],
                ue_ip->ueip.ipv6_addr[3],
                ue_ip->ueip.ipv6_addr[4],
                ue_ip->ueip.ipv6_addr[5],
                ue_ip->ueip.ipv6_addr[6],
                ue_ip->ueip.ipv6_addr[7],
                ue_ip->ueip.ipv6_addr[8],
                ue_ip->ueip.ipv6_addr[9],
                ue_ip->ueip.ipv6_addr[10],
                ue_ip->ueip.ipv6_addr[11],
                ue_ip->ueip.ipv6_addr[12],
                ue_ip->ueip.ipv6_addr[13],
                ue_ip->ueip.ipv6_addr[14],
                ue_ip->ueip.ipv6_addr[15]);
        }
    }

    for (cnt = 0; cnt < pdr_tbl->pdr.pdi_content.traffic_endpoint_num; ++cnt) {
        LOG(SESSION, RUNNING, "traffic endpoint id: %d",
            pdr_tbl->pdr.pdi_content.traffic_endpoint_id[cnt]);
    }
    LOG(SESSION, RUNNING, "filter type: %d",
        pdr_tbl->pdr.pdi_content.filter_type);
    list_head = &pdr_tbl->pdr.pdi_content.filter_list;

    if (FILTER_SDF == pdr_tbl->pdr.pdi_content.filter_type) {
        /* SDF filter */
        struct sdf_filter_entry *filter_entry = NULL;

        dl_list_for_each_safe(pos, next, list_head) {
            filter_entry = (struct sdf_filter_entry *)container_of(pos,
                    struct sdf_filter_entry, sdf_filter_node);
            sdf_filter_show(filter_entry);
        }
    } else if (FILTER_ETH == pdr_tbl->pdr.pdi_content.filter_type) {
        /* SDF filter */
        struct dl_list *sdf_pos = NULL;
        struct dl_list *sdf_next = NULL;
        struct dl_list *sdf_list_head = NULL;
        struct eth_filter_entry *filter_entry = NULL;
        struct sdf_filter_entry *sdf_entry = NULL;
        uint8_t cnt = 0;

        dl_list_for_each_safe(pos, next, list_head) {
            filter_entry = (struct eth_filter_entry *)container_of(pos,
                    struct eth_filter_entry, eth_filter_node);
            LOG(SESSION, RUNNING, "ETH filter id: %u",
                    filter_entry->eth_cfg.eth_filter_id);
            LOG(SESSION, RUNNING, "ETH filter prop: %d",
                    filter_entry->eth_cfg.eth_filter_prop.value);
            for (cnt = 0; cnt < filter_entry->eth_cfg.mac_addr_num; ++cnt) {
                if (filter_entry->eth_cfg.mac_addr[cnt].mac_flag.d.sour) {
                    LOG(SESSION, RUNNING,
                        "ETH filter src mac: 0x%02x%02x%02x%02x%02x%02x",
                            filter_entry->eth_cfg.mac_addr[cnt].src[0],
                            filter_entry->eth_cfg.mac_addr[cnt].src[1],
                            filter_entry->eth_cfg.mac_addr[cnt].src[2],
                            filter_entry->eth_cfg.mac_addr[cnt].src[3],
                            filter_entry->eth_cfg.mac_addr[cnt].src[4],
                            filter_entry->eth_cfg.mac_addr[cnt].src[5]);
                }
                if (filter_entry->eth_cfg.mac_addr[cnt].mac_flag.d.dest) {
                    LOG(SESSION, RUNNING,
                        "ETH filter dest mac: 0x%02x%02x%02x%02x%02x%02x",
                            filter_entry->eth_cfg.mac_addr[cnt].dst[0],
                            filter_entry->eth_cfg.mac_addr[cnt].dst[1],
                            filter_entry->eth_cfg.mac_addr[cnt].dst[2],
                            filter_entry->eth_cfg.mac_addr[cnt].dst[3],
                            filter_entry->eth_cfg.mac_addr[cnt].dst[4],
                            filter_entry->eth_cfg.mac_addr[cnt].dst[5]);
                }
                if (filter_entry->eth_cfg.mac_addr[cnt].mac_flag.d.usou) {
                    LOG(SESSION, RUNNING,
                        "ETH filter upper src mac: 0x%02x%02x%02x%02x%02x%02x",
                            filter_entry->eth_cfg.mac_addr[cnt].upper_src[0],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_src[1],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_src[2],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_src[3],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_src[4],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_src[5]);
                }
                if (filter_entry->eth_cfg.mac_addr[cnt].mac_flag.d.udes) {
                    LOG(SESSION, RUNNING,
                        "ETH filter upper dest mac: 0x%02x%02x%02x%02x%02x%02x",
                            filter_entry->eth_cfg.mac_addr[cnt].upper_dst[0],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_dst[1],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_dst[2],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_dst[3],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_dst[4],
                            filter_entry->eth_cfg.mac_addr[cnt].upper_dst[5]);
                }
            }
            LOG(SESSION, RUNNING, "ETH filter eth type: %d",
                    filter_entry->eth_cfg.eth_type);
            LOG(SESSION, RUNNING, "ETH filter ctag flags: 0x%x, value: 0x%x",
                    filter_entry->eth_cfg.c_tag.flags.value,
                    filter_entry->eth_cfg.c_tag.value.value);
            LOG(SESSION, RUNNING, "ETH filter stag flags: 0x%x, value: 0x%x",
                    filter_entry->eth_cfg.s_tag.flags.value,
                    filter_entry->eth_cfg.s_tag.value.value);

            sdf_list_head = &filter_entry->eth_cfg.sdf_list;
            /* sdf filter */
            dl_list_for_each_safe(sdf_pos, sdf_next, sdf_list_head) {
                sdf_entry = (struct sdf_filter_entry *)container_of(sdf_pos,
                        struct sdf_filter_entry, sdf_filter_node);
                sdf_filter_show(sdf_entry);
            }
            LOG(SESSION, RUNNING, "---------ETH filter--------");
        }
    }

    LOG(SESSION, RUNNING, "qfi number: %u",
        pdr_tbl->pdr.pdi_content.qfi_number);
    for (cnt = 0; cnt < pdr_tbl->pdr.pdi_content.qfi_number; ++cnt) {
        LOG(SESSION, RUNNING, "qfi value: %d",
            pdr_tbl->pdr.pdi_content.qfi_array[cnt]);
    }

    LOG(SESSION, RUNNING, "eth pdu ses info: %d",
        pdr_tbl->pdr.pdi_content.eth_pdu_ses_info.value);

    LOG(SESSION, RUNNING, "activation time: %u",
        pdr_tbl->pdr.activation_time);
    LOG(SESSION, RUNNING, "deactivation time: %u",
        pdr_tbl->pdr.deactivation_time);

    LOG(SESSION, RUNNING, "mar present: %d", pdr_tbl->pdr.mar_present);
    LOG(SESSION, RUNNING, "mar id: %d", pdr_tbl->pdr.mar_id);

    LOG(SESSION, RUNNING, "framed routing: %u",
        pdr_tbl->pdr.pdi_content.framed_routing);

    LOG(SESSION, RUNNING, "framed ipv4 route number: %d",
        pdr_tbl->pdr.pdi_content.framed_ipv4_route_num);
    for (cnt = 0; cnt < pdr_tbl->pdr.pdi_content.framed_ipv4_route_num; ++cnt) {
#ifdef LOG_MODE_DEBUG
        struct pdr_framed_route *fr_v4 =
            &pdr_tbl->pdr.pdi_content.framed_ipv4_route[cnt];
#endif

        LOG(SESSION, RUNNING, "---------framed route(%d)---------",
            cnt + 1);
        LOG(SESSION, RUNNING, "FR linked pdr(%p)", fr_v4->pdr_tbl);
        LOG(SESSION, RUNNING, "FR dest ip: 0x%08x",
            fr_v4->route.dest_ip);
        LOG(SESSION, RUNNING, "FR ip mask: 0x%08x",
            fr_v4->route.ip_mask);
        LOG(SESSION, RUNNING, "FR gateway: 0x%08x",
            fr_v4->route.gateway);
        LOG(SESSION, RUNNING, "FR metrics: %u",
            fr_v4->route.metrics);
    }

    LOG(SESSION, RUNNING, "framed ipv6 route number: %d",
        pdr_tbl->pdr.pdi_content.framed_ipv6_route_num);
    for (cnt = 0; cnt < pdr_tbl->pdr.pdi_content.framed_ipv6_route_num; ++cnt) {
#ifdef LOG_MODE_DEBUG
        struct pdr_framed_route_ipv6 *fr_v6 =
            &pdr_tbl->pdr.pdi_content.framed_ipv6_route[cnt];
#endif

        LOG(SESSION, RUNNING, "------framed route ipv6 (%d)------",
            cnt + 1);
        LOG(SESSION, RUNNING, "FR linked pdr(%p)", fr_v6->pdr_tbl);
        LOG(SESSION, RUNNING, "FR dest ip: 0x%016lx %016lx",
            ntohll(*(uint64_t *)fr_v6->route.dest_ip),
            ntohll(*(uint64_t *)(fr_v6->route.dest_ip + 8)));
        LOG(SESSION, RUNNING, "FR ip mask: 0x%016lx %016lx",
            ntohll(*(uint64_t *)fr_v6->route.ip_mask),
            ntohll(*(uint64_t *)(fr_v6->route.ip_mask + 8)));
        LOG(SESSION, RUNNING, "FR gateway: 0x%016lx %016lx",
            ntohll(*(uint64_t *)fr_v6->route.gateway),
            ntohll(*(uint64_t *)(fr_v6->route.gateway + 8)));
        LOG(SESSION, RUNNING, "FR metrics: %u",
            fr_v6->route.metrics);
    }

}

inline struct pdr_table_head *pdr_get_head(void)
{
    return &pdr_tbl_head;
}

inline struct pdr_table *pdr_get_table(uint32_t index)
{
    return &pdr_tbl_head.pdr_table[index];
}

struct pdr_table *pdr_get_table_public(uint32_t index)
{
    if (index >= pdr_tbl_head.max_num) {
        LOG(SESSION, ERR, "parameter invalid, index: %u.", index);
        return NULL;
    }

    return &pdr_tbl_head.pdr_table[index];
}

inline uint32_t pdr_get_max_num(void)
{
    return pdr_tbl_head.max_num;
}

static inline uint32_t pdr_get_use_num(void)
{
    return ros_atomic32_read(&pdr_tbl_head.use_num);
}

inline uint16_t pdr_get_pool_id(void)
{
    return pdr_tbl_head.pool_id;
}

static inline void pdr_use_num_add(int number)
{
    ros_atomic32_add(&pdr_tbl_head.use_num, number);
}

static inline void pdr_use_num_sub(int number)
{
    ros_atomic32_sub(&pdr_tbl_head.use_num, number);
}

inline struct sdf_filter_table *sdf_filter_get_head(void)
{
    return &sdf_filter_head;
}

inline struct sdf_filter_entry *sdf_filter_get_table(uint32_t index)
{
    return &sdf_filter_head.sdf_filter_entry[index];
}

inline struct eth_filter_table *eth_filter_get_head(void)
{
    return &eth_filter_head;
}

inline struct eth_filter_entry *eth_filter_get_table(uint32_t index)
{
    return &eth_filter_head.eth_filter_entry[index];
}

static int pdr_id_compare(struct rb_node *node, void *key)
{
    struct pdr_table *pdr_node = (struct pdr_table *)node;
    uint16_t pdr_id = *(uint16_t *)key;

    if (pdr_id < pdr_node->pdr.pdr_id) {
        return -1;
    } else if (pdr_id > pdr_node->pdr.pdr_id) {
        return 1;
    }

    return 0;
}

static int pdr_fteid_v4_compare(struct rb_node *node, void *key)
{
    struct pdr_local_fteid *node_fteid =
        (struct pdr_local_fteid *)container_of(node, struct pdr_local_fteid, v4_node);
    struct pdr_key *key_cfg = (struct pdr_key *)key;

    if (node_fteid->local_fteid.ipv4_addr < key_cfg->ip_addr.ipv4) {
        return -1;
    } else if (node_fteid->local_fteid.ipv4_addr > key_cfg->ip_addr.ipv4) {
        return 1;
    }

    if (node_fteid->local_fteid.teid < key_cfg->teid) {
        return -1;
    } else if (node_fteid->local_fteid.teid > key_cfg->teid) {
        return 1;
    }

    return 0;
}

static int pdr_fteid_v6_compare(struct rb_node *node, void *key)
{
    struct pdr_local_fteid *node_fteid =
        (struct pdr_local_fteid *)container_of(node, struct pdr_local_fteid, v6_node);
    struct pdr_key *key_cfg = (struct pdr_key *)key;

    if (*(uint64_t *)(node_fteid->local_fteid.ipv6_addr) < key_cfg->ip_addr.ipv6.d.key1) {
        return -1;
    } else if (*(uint64_t *)(node_fteid->local_fteid.ipv6_addr) >
        key_cfg->ip_addr.ipv6.d.key1) {
        return 1;
    }

    if (*(uint64_t *)(node_fteid->local_fteid.ipv6_addr + 8) <
        key_cfg->ip_addr.ipv6.d.key2) {
        return -1;
    } else if (*(uint64_t *)(node_fteid->local_fteid.ipv6_addr + 8) >
        key_cfg->ip_addr.ipv6.d.key2) {
        return 1;
    }

    if (node_fteid->local_fteid.teid < key_cfg->teid) {
        return -1;
    } else if (node_fteid->local_fteid.teid > key_cfg->teid) {
        return 1;
    }

    return 0;
}

static int pdr_ueip_v4_compare(struct rb_node *node, void *key)
{
    struct pdr_ue_ipaddress *node_ueip =
        (struct pdr_ue_ipaddress *)container_of(node, struct pdr_ue_ipaddress, v4_node);
    struct pdr_key *key_cfg = (struct pdr_key *)key;

    if (node_ueip->ueip.ipv4_addr < key_cfg->ip_addr.ipv4) {
        return -1;
    } else if (node_ueip->ueip.ipv4_addr > key_cfg->ip_addr.ipv4) {
        return 1;
    }

    return 0;
}

static int pdr_ueip_v6_compare(struct rb_node *node, void *key)
{
    struct pdr_ue_ipaddress *node_ueip =
        (struct pdr_ue_ipaddress *)container_of(node, struct pdr_ue_ipaddress, v6_node);
    struct pdr_key *key_cfg = (struct pdr_key *)key;

    if (*(uint64_t *)(node_ueip->ueip.ipv6_addr) < key_cfg->ip_addr.ipv6.d.key1) {
        return -1;
    } else if (*(uint64_t *)(node_ueip->ueip.ipv6_addr) >
        key_cfg->ip_addr.ipv6.d.key1) {
        return 1;
    }

    if (*(uint64_t *)(node_ueip->ueip.ipv6_addr + 8) <
        key_cfg->ip_addr.ipv6.d.key2) {
        return -1;
    } else if (*(uint64_t *)(node_ueip->ueip.ipv6_addr + 8) >
        key_cfg->ip_addr.ipv6.d.key2) {
        return 1;
    }

    return 0;
}

static int pdr_fr_v4_compare(struct rb_node *node, void *key)
{
    struct pdr_framed_route *node_fr = (struct pdr_framed_route *)node;
    uint32_t node_ip = node_fr->route.dest_ip & node_fr->route.ip_mask;
    uint32_t key_ip = *(uint32_t *)key;

    if (node_ip < key_ip) {
        return -1;
    } else if (node_ip > key_ip) {
        return 1;
    }

    return 0;
}

#if 0
static int pdr_fr_v6_compare(struct rb_node *node, void *key)
{
    struct pdr_framed_route_ipv6 *node_fr =
        (struct pdr_framed_route_ipv6 *)node;
    uint8_t *node_ip = node_fr->route.dest_ip;
    uint8_t valid_byte = node_fr->route.ip_mask >> 3;
    uint8_t valid_bit = node_fr->route.ip_mask & 0x7;
    uint8_t *key_ip = (uint8_t *)key, cnt = 0;
    uint8_t node_cmp_ip[IPV6_ALEN] = {0}, key_cmp_ip[IPV6_ALEN] = {0};

    for (cnt = 0; cnt < valid_byte; ++cnt) {
        node_cmp_ip[cnt] = node_ip[cnt];
    }
    node_cmp_ip[cnt] = ((uint16_t)node_ip[cnt]) >> (8 - valid_bit);

    for (cnt = 0; cnt < valid_byte; ++cnt) {
        key_cmp_ip[cnt] = key_ip[cnt];
    }
    key_cmp_ip[cnt] = ((uint16_t)key_ip[cnt]) >> (8 - valid_bit);


    if (*(uint64_t *)node_cmp_ip < *(uint64_t *)key_cmp_ip) {
        return -1;

    } else if (*(uint64_t *)node_cmp_ip > *(uint64_t *)key_cmp_ip) {
        return 1;

    }

    if (*(uint64_t *)(node_cmp_ip + 8) < *(uint64_t *)(key_cmp_ip + 8)) {
        return -1;

    } else if (*(uint64_t *)(node_cmp_ip + 8) > *(uint64_t *)(key_cmp_ip + 8)) {
        return 1;
    }

    return 0;
}
#else
static int pdr_fr_v6_compare(struct rb_node *node, void *key)
{
    struct pdr_framed_route_ipv6 *node_fr =
        (struct pdr_framed_route_ipv6 *)node;
    union pdr_ipv6_key *node_ip = (union pdr_ipv6_key *)node_fr->route.dest_ip;
    union pdr_ipv6_key *node_mask = (union pdr_ipv6_key *)node_fr->route.ip_mask;
    session_framed_route_ipv6 *key_fr = (session_framed_route_ipv6 *)key;
    union pdr_ipv6_key *key_ip = (union pdr_ipv6_key *)key_fr->dest_ip;
    union pdr_ipv6_key *key_mask = (union pdr_ipv6_key *)key_fr->ip_mask;

    if ((node_ip->d.key1 & node_mask->d.key1) < (key_ip->d.key1 & key_mask->d.key1)) {
        return -1;

    } else if ((node_ip->d.key1 & node_mask->d.key1) > (key_ip->d.key1 & key_mask->d.key1)) {
        return 1;

    }

    if ((node_ip->d.key2 & node_mask->d.key2) < (key_ip->d.key2 & key_mask->d.key2)) {
        return -1;

    } else if ((node_ip->d.key2 & node_mask->d.key2) > (key_ip->d.key2 & key_mask->d.key2)) {
        return 1;
    }

    return 0;
}
#endif

int pdr_arp_match_ueip(struct pdr_key *rb_key, uint8_t is_v4)
{
    struct pdr_table_head *pdr_head = pdr_get_head();
    struct rb_node *queue_node = NULL;

    LOG(SESSION, PERIOD, "ARP match key: 0x%08x %08x %08x %08x",
        *(uint32_t *)&rb_key->ip_addr.ipv6.value[0],
        *(uint32_t *)&rb_key->ip_addr.ipv6.value[4],
        *(uint32_t *)&rb_key->ip_addr.ipv6.value[8],
        *(uint32_t *)&rb_key->ip_addr.ipv6.value[12]);
    ros_rwlock_read_lock(&pdr_head->ueip_v4_lock);/* lock */
    if (is_v4) {
        queue_node = rbtree_search(&pdr_head->ueip_dv4_root,
            rb_key, pdr_ueip_v4_compare);
    } else {
        queue_node = rbtree_search(&pdr_head->ueip_dv6_root,
            rb_key, pdr_ueip_v6_compare);
    }
    ros_rwlock_read_unlock(&pdr_head->ueip_v4_lock);/* unlock */

    return queue_node ? 0 : -1;
}

static int64_t filter_table_init(uint32_t pdr_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct sdf_filter_entry *sdf_entry = NULL;
    struct eth_filter_entry *eth_entry = NULL;
    uint32_t max_num = 0;
    int64_t size = 0, total_memory = 0;

    if (0 == pdr_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, pdr_num: %u.", pdr_num);
        return -1;
    }

    max_num = pdr_num * MAX_SDF_FILTER_NUM;
    size = sizeof(struct sdf_filter_entry) * max_num;
    sdf_entry = ros_malloc(size);
    if (NULL == sdf_entry) {
        LOG(SESSION, ERR,
            "init pdr failed, no enough memory, max number: %u ="
            " pdr_num: %u * %d.", max_num,
            pdr_num, MAX_SDF_FILTER_NUM);
        return -1;
    }
    ros_memset(sdf_entry, 0, sizeof(struct sdf_filter_entry) * max_num);

    for (index = 0; index < max_num; ++index) {
        sdf_entry[index].index = index;
        dl_list_init(&sdf_entry->sdf_filter_node);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR,"create pool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR,"add section %u failed.", max_num);
        return -1;
    }

    sdf_filter_head.pool_id = pool_id;
    sdf_filter_head.sdf_filter_entry = sdf_entry;
    sdf_filter_head.max_num = max_num;
    ros_rwlock_init(&sdf_filter_head.lock);
    ros_atomic32_set(&sdf_filter_head.use_num, 0);
    total_memory += size;

    /* init eth filter */
    max_num = pdr_num * MAX_ETH_FILTER_NUM;
    size = sizeof(struct eth_filter_entry) * max_num;
    eth_entry = ros_malloc(size);
    if (NULL == eth_entry) {
        LOG(SESSION, ERR,
            "init pdr failed, no enough memory, max number: %u ="
            " pdr_num: %u * %d.", max_num,
            pdr_num, MAX_ETH_FILTER_NUM);
        return -1;
    }
    ros_memset(eth_entry, 0, sizeof(struct eth_filter_entry) * max_num);

    for (index = 0; index < max_num; ++index) {
        eth_entry[index].index = index;
        dl_list_init(&eth_entry->eth_filter_node);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR,"create pool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR,"add section %u failed.", max_num);
        return -1;
    }

    eth_filter_head.pool_id = pool_id;
    eth_filter_head.eth_filter_entry = eth_entry;
    eth_filter_head.max_num = max_num;
    ros_rwlock_init(&eth_filter_head.lock);
    ros_atomic32_set(&eth_filter_head.use_num, 0);
    total_memory += size;

    LOG(SESSION, RUNNING, "session mgmt init success.");

    return total_memory;
}

static inline void sdf_filter_clear(struct dl_list *list_head)
{
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    struct sdf_filter_entry *filter_entry = NULL;
    struct sdf_filter_table *sdf_head = sdf_filter_get_head();

    ros_rwlock_write_lock(&sdf_head->lock);/* lock */
    if (dl_list_empty(list_head)) {
        ros_rwlock_write_unlock(&sdf_head->lock);/* unlock */
        return;
    }
    dl_list_for_each_safe(pos, next, list_head) {
        filter_entry = (struct sdf_filter_entry *)container_of(pos,
                struct sdf_filter_entry, sdf_filter_node);
        if (!filter_entry->sdf_cfg.sdf_flag.d.bid) {
            dl_list_del(pos);
            Res_Free(sdf_head->pool_id, 0, filter_entry->index);
        }
    }
    ros_rwlock_write_unlock(&sdf_head->lock);/* unlock */
}

static inline void eth_filter_clear(struct dl_list *list_head)
{
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    struct eth_filter_entry *filter_entry = NULL;
    struct eth_filter_table *eth_head = eth_filter_get_head();

    ros_rwlock_write_lock(&eth_head->lock);/* lock */
    if (dl_list_empty(list_head)) {
        ros_rwlock_write_unlock(&eth_head->lock);/* unlock */
        return;
    }
    dl_list_for_each_safe(pos, next, list_head) {
        filter_entry = (struct eth_filter_entry *)container_of(pos,
                struct eth_filter_entry, eth_filter_node);
        dl_list_del(pos);
        sdf_filter_clear(&filter_entry->eth_cfg.sdf_list);

        Res_Free(eth_head->pool_id, 0, filter_entry->index);
    }
    ros_rwlock_write_unlock(&eth_head->lock);/* unlock */
}

struct pdr_table *pdr_table_create(struct session_t *sess, uint16_t id)
{
    struct pdr_table *pdr_tbl = NULL;
    uint32_t key = 0, index = 0;
    uint16_t pdr_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    if (G_FAILURE == Res_Alloc(pdr_get_pool_id(), &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            pdr_get_pool_id());
        return NULL;
    }

    pdr_tbl = pdr_get_table(index);

    ros_memset(&pdr_tbl->pdr, 0, sizeof(struct pkt_detection_rule));

    pdr_tbl->pdr.pdr_id = pdr_id;
    dl_list_init(&pdr_tbl->pdr.pdi_content.filter_list);
    dl_list_init(&pdr_tbl->eth_dl_node);
    /*dl_list_init(&pdr_tbl->pdr.act_pre_rule_list);*/
    ros_atomic16_set(&pdr_tbl->nocp_flag, 1);
    pdr_tbl->session_link = sess;
    pdr_tbl->is_active = 0;

    ros_rwlock_write_lock(&sess->lock);/* lock */
    /* insert node to session tree root*/
    if (rbtree_insert(&sess->session.pdr_root, &pdr_tbl->pdr_node,
        &pdr_id, pdr_id_compare) < 0) {
        ros_rwlock_write_unlock(&sess->lock);/* unlock */
        Res_Free(pdr_get_pool_id(), key, index);
        LOG(SESSION, ERR,
            "rb tree insert failed, pdr_id: %u.", pdr_id);
        return NULL;
    }
    ros_rwlock_write_unlock(&sess->lock);/* unlock */

    pdr_use_num_add(1);

    return pdr_tbl;
}

struct pdr_table *pdr_table_create_local(uint16_t id)
{
    struct pdr_table *pdr_tbl = NULL;
    uint32_t key = 0, index = 0;
    uint16_t pdr_id = id;

    if (G_FAILURE == Res_Alloc(pdr_get_pool_id(), &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            pdr_get_pool_id());
        return NULL;
    }

    pdr_tbl = pdr_get_table(index);

    memset(&pdr_tbl->pdr, 0, sizeof(struct pkt_detection_rule));

    pdr_tbl->pdr.pdr_id = pdr_id;
    dl_list_init(&pdr_tbl->pdr.pdi_content.filter_list);
    dl_list_init(&pdr_tbl->eth_dl_node);
    /*dl_list_init(&pdr_tbl->pdr.act_pre_rule_list);*/
    ros_atomic16_set(&pdr_tbl->nocp_flag, 1);
    pdr_tbl->session_link = NULL;
    pdr_tbl->is_active = 0;

    pdr_use_num_add(1);

    return pdr_tbl;
}

struct pdr_table *pdr_table_search(struct session_t *sess, uint16_t id)
{
    struct pdr_table *pdr_tbl = NULL;
    uint16_t pdr_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "search failed, sess is null.");
        return NULL;
    }

    /* search pdr table,if exist, free node, otherwise, failed */
    ros_rwlock_write_lock(&sess->lock);/* lock */
    pdr_tbl = (struct pdr_table *)rbtree_search(&sess->session.pdr_root,
        &pdr_id, pdr_id_compare);
    ros_rwlock_write_unlock(&sess->lock);/* unlock */
    if (NULL == pdr_tbl) {
        LOG(SESSION, ERR, "pdr_id %u search failed.", pdr_id);
        return NULL;
    }

    return pdr_tbl;
}

int sdf_filter_create(struct dl_list *sdf_list_head,
    session_sdf_filter *sdf_cfg)
{
    uint32_t res_key = 0, res_index = 0;
    struct sdf_filter_entry *local_filter_entry = NULL;
    struct sdf_filter_table *sdf_head = sdf_filter_get_head();

    if (NULL == sdf_list_head || NULL == sdf_cfg) {
        LOG(SESSION, ERR,
            "abnormal parameter, sdf_list_head(%p), sdf_cfg(%p).",
            sdf_list_head, sdf_cfg);
        return -1;
    }

    ros_rwlock_write_lock(&sdf_head->lock);/* lock */
    if (G_FAILURE == Res_Alloc(sdf_head->pool_id,
        &res_key, &res_index, EN_RES_ALLOC_MODE_OC)) {
        ros_rwlock_write_unlock(&sdf_head->lock);/* unlock */
        LOG(SESSION, ERR, "sdf filter alloc res failed.");
        return -1;
    }

    local_filter_entry = sdf_filter_get_table(res_index);
    ros_memcpy(&local_filter_entry->sdf_cfg, sdf_cfg,
        sizeof(session_sdf_filter));

    dl_list_add_tail(sdf_list_head, &local_filter_entry->sdf_filter_node);
    ros_atomic32_add(&sdf_head->use_num, 1);

    ros_rwlock_write_unlock(&sdf_head->lock);/* unlock */

    return 0;
}

struct eth_filter_entry *eth_filter_create(struct dl_list *eth_list_head,
    void *eth_cfg)
{
    uint32_t res_key = 0, res_index = 0;
    struct eth_filter_entry *local_filter_entry = NULL;
    struct eth_filter_table *eth_head = eth_filter_get_head();

    if (NULL == eth_list_head || NULL == eth_cfg) {
        LOG(SESSION, ERR,
            "abnormal parameter, eth_list_head(%p), eth_cfg(%p).",
            eth_list_head, eth_cfg);
        return NULL;
    }

    ros_rwlock_write_lock(&eth_head->lock);/* lock */
    if (G_FAILURE == Res_Alloc(eth_head->pool_id,
        &res_key, &res_index, EN_RES_ALLOC_MODE_OC)) {
        ros_rwlock_write_unlock(&eth_head->lock);/* unlock */
        LOG(SESSION, ERR, "eth filter alloc res failed.");
        return NULL;
    }
    ros_atomic32_add(&eth_head->use_num, 1);
    local_filter_entry = eth_filter_get_table(res_index);

    pdr_eth_filter_content_copy(&local_filter_entry->eth_cfg, eth_cfg);
    dl_list_init(&local_filter_entry->eth_cfg.sdf_list);

    dl_list_add_tail(eth_list_head, &local_filter_entry->eth_filter_node);
    ros_rwlock_write_unlock(&eth_head->lock);/* unlock */

    return local_filter_entry;
}

static int sdf_filter_process(struct filter_key *key, uint8_t *field_offset,
    session_sdf_filter *sdf_filter)
{
    struct pro_udp_hdr  *udp_hdr;
    struct pro_tcp_hdr  *tcp_hdr;
    uint16_t src_port, dst_port;

    /* match with sdf */
    if (likely(FLOW_MASK_FIELD_ISSET(field_offset, FLOW_FIELD_L1_IPV4))) {
        struct pro_ipv4_hdr *ip_hdr = FlowGetIpv4Header(key, field_offset);
        if (unlikely(!ip_hdr)) {
            return -1;
        }

        if (sdf_filter->sdf_flag.d.fd) {
            session_flow_desc *fd = &sdf_filter->desc;
            uint32_t remote_ip, ue_ip;

            if (!(fd->ip_type & SESSION_IP_V4)) {
                LOG(SESSION, RUNNING, "sdf filter ip type not match.");
                return -1;
            }

            switch(ip_hdr->protocol)
            {
                case IP_PRO_UDP:
                    udp_hdr = FlowGetUdpHeader(key, field_offset);
                    if (unlikely(!udp_hdr)) {
                        return -1;
                    }
                    src_port = htons(udp_hdr->source);
                    dst_port = htons(udp_hdr->dest);
                    break;

                case IP_PRO_TCP:
                    tcp_hdr = FlowGetTcpHeader(key, field_offset);
                    if (unlikely(!tcp_hdr)) {
                        return -1;
                    }
                    src_port = htons(tcp_hdr->source);
                    dst_port = htons(tcp_hdr->dest);
                    break;

                default:
                    src_port = 0;
                    dst_port = 0;
                    break;
            }

            if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_GTP_T_PDU)) {
                uint16_t tmp_port;

                ue_ip = htonl(ip_hdr->source);
                remote_ip = htonl(ip_hdr->dest);
                tmp_port = src_port;
                src_port = dst_port;
                dst_port = tmp_port;
            } else {
                remote_ip = htonl(ip_hdr->source);
                ue_ip = htonl(ip_hdr->dest);
            }

            LOG(SESSION, RUNNING, "sdf filter with ipv4 packet.");
            LOG(SESSION, RUNNING,
                "packet info::sip:0x%08x, dip:0x%08x, sp:%u, dp:%u, proto:%u.",
                remote_ip, ue_ip, src_port, dst_port, ip_hdr->protocol);

            LOG(SESSION, RUNNING,
                "key info::sip:0x%08x/0x%08x, dip:0x%08x/0x%08x, "
                "sp:%u-%u, dp:%u-%u, proto:%u, no_sport: %d, no_dport: %d.",
                fd->sip.sipv4, fd->smask.sipv4_mask, fd->dip.dipv4,
                fd->dmask.dipv4_mask,fd->sp_min, fd->sp_max, fd->dp_min,
                fd->dp_max, fd->protocol, fd->no_sp, fd->no_dp);

            if (fd->protocol && ip_hdr->protocol != fd->protocol) {
                return -1;
            } else if (fd->sip.sipv4 &&
                ((remote_ip & fd->smask.sipv4_mask) != (fd->sip.sipv4&fd->smask.sipv4_mask))) {
                return -1;
            } else if (fd->dip.dipv4 &&
                ((ue_ip & fd->dmask.dipv4_mask) != (fd->dip.dipv4&fd->dmask.dipv4_mask))) {
                return -1;
            } else if (0 == fd->no_sp && ((src_port < fd->sp_min) || (src_port > fd->sp_max))) {
                return -1;
            } else if (0 == fd->no_dp && ((dst_port < fd->dp_min) || (dst_port > fd->dp_max))) {
                return -1;
            }
        }

        if (sdf_filter->sdf_flag.d.ttc) {
            session_tos_tc *tos = &sdf_filter->tos_traffic_class;

            if ((tos->d.tos & tos->d.tos_mask) != ip_hdr->tos) {
                return -1;
            }
        }

        LOG(SESSION, RUNNING, "sdf filter match success.");
        return 0;
    }
    else if (FLOW_MASK_FIELD_ISSET(field_offset, FLOW_FIELD_L1_IPV6)) {
        LOG(SESSION, RUNNING, "sdf filter with ipv6 packet.");

        struct pro_ipv6_hdr *ip_hdr = FlowGetIpv6Header(key,field_offset);
        uint64_t *ipsaddr,*fdsaddr,*samask;
        uint64_t *ipdaddr,*fddaddr,*damask;
        if (unlikely(!ip_hdr)) {
          LOG(SESSION, RUNNING, "sdf filter with ipv6 head get fail.");
          return -1;
        }

        if (sdf_filter->sdf_flag.d.fd) {
            session_flow_desc *fd = &sdf_filter->desc;
            uint8_t remote_ip[IPV6_ALEN], ue_ip[IPV6_ALEN];

            if (!(fd->ip_type & SESSION_IP_V6)) {
              LOG(SESSION, RUNNING, "sdf filter ip type not match.");
              return -1;
            }

            switch(ip_hdr->nexthdr)
            {
              case IP_PRO_UDP:
                udp_hdr = FlowGetUdpHeader(key, field_offset);
                if (unlikely(!udp_hdr)) {
                  return -1;
                }
                src_port = htons(udp_hdr->source);
                dst_port = htons(udp_hdr->dest);
                break;

              case IP_PRO_TCP:
                tcp_hdr = FlowGetTcpHeader(key, field_offset);
                if (unlikely(!tcp_hdr)) {
                  return -1;
                }
                src_port = htons(tcp_hdr->source);
                dst_port = htons(tcp_hdr->dest);
                break;

              default:
                src_port = 0;
                dst_port = 0;
                break;
            }

            if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_GTP_T_PDU)) {
                uint16_t tmp_port;

                ros_memcpy(ue_ip, ip_hdr->saddr, IPV6_ALEN);
                ros_memcpy(remote_ip, ip_hdr->daddr, IPV6_ALEN);
                tmp_port = src_port;
                src_port = dst_port;
                dst_port = tmp_port;
            } else {
                ros_memcpy(remote_ip, ip_hdr->saddr, IPV6_ALEN);
                ros_memcpy(ue_ip, ip_hdr->daddr, IPV6_ALEN);
            }

            LOG(SESSION, RUNNING,
                "packet info::(dip:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)"
                "(sip:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)"
                " sp:%u, dp:%u, proto:%u.",
                ue_ip[0],ue_ip[1],ue_ip[2],ue_ip[3],
                ue_ip[4],ue_ip[5],ue_ip[6],ue_ip[7],
                ue_ip[8],ue_ip[9],ue_ip[10],ue_ip[11],
                ue_ip[12],ue_ip[13],ue_ip[14],ue_ip[15],
                remote_ip[0],remote_ip[1],remote_ip[2],remote_ip[3],
                remote_ip[4],remote_ip[5],remote_ip[6],remote_ip[7],
                remote_ip[8],remote_ip[9],remote_ip[10],remote_ip[11],
                remote_ip[12],remote_ip[13],remote_ip[14],remote_ip[15],
              src_port,dst_port, ip_hdr->nexthdr);

            LOG(SESSION, RUNNING,
              " key  info::(keydip:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)"
               "(dmask:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)"
              "(keysip:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x) "
              "(smask:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)"
              "sp:%u-%u, dp:%u-%u, proto:%u, no_sport: %d, no_dport: %d.",
              fd->dip.dipv6[0],fd->dip.dipv6[1],fd->dip.dipv6[2],fd->dip.dipv6[3],
              fd->dip.dipv6[4],fd->dip.dipv6[5],fd->dip.dipv6[6],fd->dip.dipv6[7],
              fd->dip.dipv6[8],fd->dip.dipv6[9],fd->dip.dipv6[10],fd->dip.dipv6[11],
              fd->dip.dipv6[12],fd->dip.dipv6[13],fd->dip.dipv6[14],fd->dip.dipv6[15],
              fd->dmask.dipv6_mask[0],fd->dmask.dipv6_mask[1],fd->dmask.dipv6_mask[2],fd->dmask.dipv6_mask[3],
              fd->dmask.dipv6_mask[4],fd->dmask.dipv6_mask[5],fd->dmask.dipv6_mask[6],fd->dmask.dipv6_mask[7],
              fd->dmask.dipv6_mask[8],fd->dmask.dipv6_mask[9],fd->dmask.dipv6_mask[10],fd->dmask.dipv6_mask[11],
              fd->dmask.dipv6_mask[12],fd->dmask.dipv6_mask[13],fd->dmask.dipv6_mask[14],fd->dmask.dipv6_mask[15],

              fd->sip.sipv6[0],fd->sip.sipv6[1],fd->sip.sipv6[2],fd->sip.sipv6[3],
              fd->sip.sipv6[4],fd->sip.sipv6[5],fd->sip.sipv6[6],fd->sip.sipv6[7],
              fd->sip.sipv6[8],fd->sip.sipv6[9],fd->sip.sipv6[10],fd->sip.sipv6[11],
              fd->sip.sipv6[12],fd->sip.sipv6[13],fd->sip.sipv6[14],fd->sip.sipv6[15],
              fd->smask.sipv6_mask[0],fd->smask.sipv6_mask[1],fd->smask.sipv6_mask[2],fd->smask.sipv6_mask[3],
              fd->smask.sipv6_mask[4],fd->smask.sipv6_mask[5],fd->smask.sipv6_mask[6],fd->smask.sipv6_mask[7],
              fd->smask.sipv6_mask[8],fd->smask.sipv6_mask[9],fd->smask.sipv6_mask[10],fd->smask.sipv6_mask[11],
              fd->smask.sipv6_mask[12],fd->smask.sipv6_mask[13],fd->smask.sipv6_mask[14],fd->smask.sipv6_mask[15],
              fd->sp_min, fd->sp_max, fd->dp_min,fd->dp_max, fd->protocol, fd->no_sp, fd->no_dp);

            ipsaddr = (uint64_t *)remote_ip;
            fdsaddr = (uint64_t *)fd->sip.sipv6;
            samask = (uint64_t *)fd->smask.sipv6_mask;
            ipdaddr = (uint64_t *)ue_ip;
            fddaddr = (uint64_t *)fd->dip.dipv6;
            damask = (uint64_t *)fd->dmask.dipv6_mask;


            if (fd->protocol && ip_hdr->nexthdr!= fd->protocol) {
                LOG(SESSION, RUNNING, "sdf filter protocol mismatch,ipprotocol:%d,sdfprotocol:%d",ip_hdr->nexthdr,fd->protocol);
                return -1;
            }
            else if (((ipsaddr[0] & samask[0]) != (fdsaddr[0] & samask[0])) || ((ipsaddr[1] & samask[1]) != (fdsaddr[1] & samask[1]))) {

                LOG(SESSION, RUNNING, "sdf filter ip saddr mismatch,ip:%16lx:%16lx, keysip:%16lx:%16lx",
                    (ipsaddr[0] & samask[0]), (ipsaddr[1] & samask[1]),
                    (fdsaddr[0] & samask[0]), (fdsaddr[1] & samask[1]));

                return -1;
            }
            else if(((ipdaddr[0] & damask[0]) != (fddaddr[0] & damask[0])) || ((ipdaddr[1] & damask[1]) != (fddaddr[1] & damask[1]))) {

                LOG(SESSION, RUNNING, "sdf filter ip daddr mismatch,ip:%16lx:%16lx, keysip:%16lx:%16lx",
                    (ipdaddr[0] & damask[0]), (ipdaddr[1] & damask[1]),
                    (fddaddr[0] & damask[0]), (fddaddr[1] & damask[1]));

                return -1;
            }
            else if (0 == fd->no_sp && ((src_port < fd->sp_min) || (src_port > fd->sp_max))) {
                LOG(SESSION, RUNNING, "sdf filter ip sport mismatch");
                return -1;
            }
            else if (0 == fd->no_dp && ((dst_port < fd->dp_min) || (dst_port > fd->dp_max))) {
                LOG(SESSION, RUNNING, "sdf filter ip dport mismatch");
                return -1;
            }
        }
        return 0;
    }
    else {
        LOG(SESSION, RUNNING, "Not ipv4 and ipv6 packet.");
        return 0;
    }
}

/* incoming packet match process, with pdi content,
   if matched, return 1, else return 0 */
static inline int ethernet_filter_process(struct filter_key *key, uint8_t *field_offset,
                                      struct eth_filter *ethFilter)
{
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    struct sdf_filter_entry *sdfFilter = NULL;
    //struct pro_eth_hdr *eth_hdr = FlowGetMACHeader(key, field_offset);
    uint8_t cnt;

    /* match ethernet filter at first */
    for (cnt = 0; cnt < ethFilter->mac_addr_num; ++cnt) {

    }

    if (FLOW_MASK_FIELD_ISSET(field_offset, FLOW_FIELD_L1_CVLAN)) {
        LOG(SESSION, RUNNING, "sdf filter with ipv4 packet.");
    }

    if (FLOW_MASK_FIELD_ISSET(field_offset, FLOW_FIELD_L1_SVLAN)) {
        LOG(SESSION, RUNNING, "sdf filter with ipv4 packet.");
    }

    if (FLOW_MASK_FIELD_ISSET(field_offset, FLOW_FIELD_L1_ETH)) {
        LOG(SESSION, RUNNING, "sdf filter with ipv4 packet.");
    }

    if (dl_list_empty(&ethFilter->sdf_list)) {
        return 0;
    }

    /* if sdf exist, match sdf */
    dl_list_for_each_safe(pos, next, &ethFilter->sdf_list) {
        sdfFilter = (struct sdf_filter_entry *)container_of(pos,
            struct sdf_filter_entry, sdf_filter_node);
        if (0 == sdf_filter_process(key, field_offset, &sdfFilter->sdf_cfg)) {
            return 0;
        }
    }

    return -1;
}

static inline int pdr_match_qfi(struct filter_key *key, uint8_t *qfi_array, uint8_t qfi_number)
{
    uint8_t *gtpExt;
    uint8_t index;
    uint8_t pkt_qfi;

    if (NULL == key || NULL == qfi_array) {
        LOG(SESSION, ERR, "Abnormal parameters, key(%p), qfi_array(%p).",
            key, qfi_array);
        return -1;
    }

    gtpExt = FlowGetGtpuExt(key);
    if (NULL == gtpExt) {
        LOG(SESSION, ERR, "get gtp ext head failed.");
        return -1;
    }

    /*
    * See clause 5.2.1 of 3GPP TS 29.281
    * For a GTP-PDU with several Extension Headers,
    * the PDU Session Container should be the first Extension Header.
    */
    if (0x85 == gtpExt[0]) {
        pkt_qfi = gtpExt[2] & 0x3F;

        LOG(SESSION, DEBUG, "Uplink packet matching QFI %d.", pkt_qfi);
        for (index = 0; index < qfi_number; index++) {
            if (pkt_qfi == qfi_array[index]) {
                LOG(SESSION, DEBUG, "QFI %d match success.", pkt_qfi);
                return 0;
            }
        }
    }

    return -1;
}

static int white_list_filter_process(struct pdr_table *pdr_tbl, struct pro_ipv4_hdr *ip_hdr)
{
    struct white_list_table *white_list = NULL;
    struct pro_tcp_hdr       *tcp_hdr = NULL;
    struct pkt_detection_info *pdi_content = NULL;
    struct session_t        *session_link = NULL;
    uint32_t                dst_ip,sni_ip;
    extensions_key          e_key[11] = {{0}};
    char                    sni[256]={0};
    char                    http_url[1024]={0};
    char                    host[256]={0};
    char                    buf_str[32]={0};
    uint16_t                sni_len = 0;
    int                     result = 0;
    uint8_t                 exist_17516 = 0;
    uint64_t                local_info_64 = 0,user_info_64 = 0;

    if (pdr_tbl == NULL || NULL == ip_hdr) {
        LOG(SESSION, ERR, "The condition is not satisfied, pdr_tbl(%p), ip_hdr(%p)", pdr_tbl, ip_hdr);
        return result;
    }

    session_link = pdr_tbl->session_link;
    pdi_content = &(pdr_tbl->pdr.pdi_content);
    dst_ip = ntohl(ip_hdr->dest);
    if (unlikely(ip_hdr->protocol == IP_PRO_TCP))
    {
        tcp_hdr = (struct pro_tcp_hdr *)((char *)ip_hdr + (ip_hdr->ihl << 2));
        if(unlikely(tcp_hdr->psh))
        {
            if((ntohs(tcp_hdr->dest) == 80) || (ntohs(tcp_hdr->dest) == 8080))//http的协议判断host
            {
                if(!layer7_url_extract(tcp_hdr, ntohs(ip_hdr->tot_len), http_url, host, sizeof(http_url)))
                {
                    if((white_list=white_list_entry_search(host,0,1)))
                    {
                        pdi_content->head_enrich_flag = 0;
                        result = 0;
                        LOG(SESSION, RUNNING,
                            "white list filter process host[%s] flag[%x]\n",host, pdi_content->head_enrich_flag);
                        return result;
                    }
                }
            }
            else if (ntohs(tcp_hdr->dest) == 443)
            {
                if (pkt_parse_https(tcp_hdr, e_key, 1, &exist_17516) == 0)//https的协议判断SNI(Server Name Indication)
                {
                    //先进行防欺诈处理
                    if (exist_17516)
                    {
                        if (session_link == NULL)
                        {
                            LOG(SESSION, ERR,"ERROR: PDR linked session is NULL");
                            pdi_content->head_enrich_flag = 0;
                            return 1;
                        }
                        if (e_key[1].is_vaild)
                        {
                            //比对手机号码一不一致，前7字节固定为"msisdn-"。
                            if (strncmp((char *)(e_key[1].value_ptr),"msisdn-",7))
                            {
                                ros_memcpy(buf_str,(e_key[1].value_ptr),7);
                                result = -1;
                                LOG(SESSION, ERR,"ERROR: msisdn diff: phone_num[%s] isn't \"msisdn-\"\n",buf_str);
                                pdi_content->head_enrich_flag = 0;
                                return result;
                            }
                            local_info_64 = ntohll(*((uint64_t *)(e_key[1].value_ptr+7)));
                            user_info_64 = bcd_to_int64(session_link->session.user_id.msisdn,8,1);
                            if (local_info_64 != user_info_64)
                            {
                                result = -1;
                                LOG(SESSION, ERR,"ERROR: phone_num[%ld] != local_num[%ld]\n",
                                    local_info_64,user_info_64);
                                pdi_content->head_enrich_flag = 0;
                                return result;
                            }
                        }
                        if (e_key[3].is_vaild)
                        {
                            //比对imsi一不一致，前5字节固定为"imsi-"。
                            if (strncmp((char *)(e_key[3].value_ptr),"imsi-",5))
                            {
                                ros_memcpy(buf_str,(e_key[3].value_ptr),5);
                                result = -1;
                                LOG(SESSION, ERR,"ERROR: imsi[%s] isn't \"imsi-\"\n",buf_str);
                                pdi_content->head_enrich_flag = 0;
                                return result;
                            }
                            local_info_64 = ntohll(*((uint64_t *)(e_key[3].value_ptr+5)));
                            user_info_64 = bcd_to_int64(session_link->session.user_id.imsi,8,1);
                            if (local_info_64 != user_info_64)
                            {
                                result = -1;
                                LOG(SESSION, ERR,"ERROR: imsi[%ld] != local_imsi[%ld]\n",
                                    local_info_64,user_info_64);
                                pdi_content->head_enrich_flag = 0;
                                return result;
                            }
                        }
                        if (e_key[4].is_vaild)
                        {
                            //比对imei一不一致，前5字节固定为"imei-"。
                            if (strncmp((char *)(e_key[4].value_ptr),"imei-",5))
                            {
                                ros_memcpy(buf_str,(e_key[4].value_ptr),5);
                                result = -1;
                                LOG(SESSION, ERR,"ERROR: imei[%s] isn't \"imei-\"\n",buf_str);
                                pdi_content->head_enrich_flag = 0;
                                return result;
                            }
                            local_info_64 = ntohll(*((uint64_t *)(e_key[4].value_ptr+5)));
                            user_info_64 = bcd_to_int64(session_link->session.user_id.imei,8,1);
                            if (local_info_64 != user_info_64)
                            {
                                result = -1;
                                LOG(SESSION, ERR,"ERROR: imei[%ld] != local_imei[%ld] flag[%x]\n",
                                    local_info_64,user_info_64,pdi_content->head_enrich_flag);
                                pdi_content->head_enrich_flag = 0;
                                return result;
                            }
                        }
                    }

                    if (e_key[0].is_vaild)
                    {
                        sni_len = ntohs(*((uint16_t *)(e_key[0].value_ptr+3)));
                        ros_memcpy(sni,(e_key[0].value_ptr+5),sni_len);
                        sni_ip=htonl(inet_addr(sni));
                        if ((sni_ip != 0xffffffff) && (sni_ip != dst_ip))
                        {
                            result = -1;
                            LOG(SESSION, ERR,"ERROR: sni_ip[%x] != dst_ip[%x]\n",sni_ip, dst_ip);
                            pdi_content->head_enrich_flag = 0;
                            return result;
                        }

                        if ((white_list=white_list_entry_search(sni,0,1)))
                        {
                            pdi_content->head_enrich_flag = white_list->head_enrich_flag;
                            result = 0;
                            return result;
                        }
                    }
                }
            }
        }
    }

    if(unlikely((white_list=white_list_entry_search(NULL, dst_ip, 0))))
    {
        pdi_content->head_enrich_flag = white_list->head_enrich_flag;
        result = 0;
        return result;
    }

    pdi_content->head_enrich_flag = 0;
    return result;
}

static int filter_process(struct filter_key *key, uint8_t *field_offset,
    struct pkt_detection_info *pdi_content, int *url_depth)
{
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    struct sdf_filter_entry *sdfFilter = NULL;
    struct eth_filter_entry *ethFilter = NULL;
    *url_depth = -1; /* 没有URL匹配的情况设置为-1 */

    LOG(SESSION, RUNNING, "filter_type:%d.", pdi_content->filter_type);

    /* 上行流才匹配qfi */
    if (likely(FLOW_MASK_FIELD_ISSET(field_offset, FLOW_FIELD_GTP_T_PDU))) {
        if (0 < pdi_content->qfi_number) {
            if (0 != pdr_match_qfi(key, pdi_content->qfi_array, pdi_content->qfi_number)) {
                LOG(SESSION, RUNNING, "Uplink packet match QFI failed.");
                return -1;
            }
        }
    }

    if (pdi_content->application_id_present) {
        if (EN_PFD_MATCH_FAIL == pfd_match_process(key, field_offset, pdi_content->application_id, url_depth)) {
            LOG(SESSION, RUNNING, "Match PFD failed.");
            return -1;
        }
    }

    if (pdi_content->filter_type == FILTER_ETH) {
        dl_list_for_each_safe(pos, next, &pdi_content->filter_list) {
            ethFilter = (struct eth_filter_entry *)container_of(pos,
                     struct eth_filter_entry, eth_filter_node);
            /* match with eth */
            if (0 != ethernet_filter_process(key, field_offset, &ethFilter->eth_cfg)) {
                LOG(SESSION, RUNNING, "Match Ethernet filter failed.");
                return -1;
            }
        }
    } else if (pdi_content->filter_type == FILTER_SDF) {
        dl_list_for_each_safe(pos, next, &pdi_content->filter_list) {
            sdfFilter = (struct sdf_filter_entry *)container_of(pos,
                                 struct sdf_filter_entry, sdf_filter_node);
            if (0 != sdf_filter_process(key, field_offset, &sdfFilter->sdf_cfg)) {
                LOG(SESSION, RUNNING, "Match SDF filter failed.");
                return -1;
            }
        }
    }

    return 0;
}

static void pdr_map_v4_key_fill(struct pkt_detection_info *pdi_content,
    struct pdr_key *fill_key, uint8_t fill_fteid, uint8_t index)
{
    if (fill_fteid) {
        fill_key->teid = pdi_content->local_fteid[index].local_fteid.teid;
        fill_key->ip_addr.ipv4 = pdi_content->local_fteid[index].local_fteid.ipv4_addr;
    } else {
        fill_key->ip_addr.ipv4 = pdi_content->ue_ipaddr[index].ueip.ipv4_addr;
    }
}

static void pdr_map_v6_key_fill(struct pkt_detection_info *pdi_content,
    struct pdr_key *fill_key, uint8_t fill_fteid, uint8_t index)
{
    if (fill_fteid) {
        fill_key->teid = pdi_content->local_fteid[index].local_fteid.teid;
        ros_memcpy(&fill_key->ip_addr.ipv6, pdi_content->local_fteid[index].local_fteid.ipv6_addr,
            IPV6_ALEN);
    } else {
        ros_memcpy(&fill_key->ip_addr.ipv6, pdi_content->ue_ipaddr[index].ueip.ipv6_addr,
            IPV6_ALEN);
    }
}

static int pdr_map_insert(struct pdr_table *pdr_tbl)
{
    struct pdr_table_head *pdr_head = pdr_get_head();
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    int ret = 0, flag = 0;
    uint32_t precedence = pdr_tbl->pdr.precedence;
    struct pkt_detection_info *pdi = &pdr_tbl->pdr.pdi_content;

    if (COMM_SRC_IF_DN == pdi->si) {
        struct pdr_key key = {.teid = 0};
        uint8_t cnt;
        struct pdr_ue_ipaddress *new_ueip = NULL, *ueip_queue = NULL;
        struct rb_root *ueip_root = NULL;

        /* UEIP */
        for (cnt = 0; cnt < pdi->ue_ipaddr_num; ++cnt) {
            new_ueip = &pdi->ue_ipaddr[cnt];

            /* ipv4 */
            if (new_ueip->ueip.ueip_flag.d.v4) {
                pdr_map_v4_key_fill(pdi, &key, 0, cnt);

                if (new_ueip->ueip.ueip_flag.d.s_d == 0) {
                    ueip_root = &pdr_head->ueip_sv4_root;
                } else {
                    ueip_root = &pdr_head->ueip_dv4_root;
                }

                ros_rwlock_write_lock(&pdr_head->ueip_v4_lock); /* lock */
                struct rb_node *queue_node = rbtree_search(ueip_root,
                    &key, pdr_ueip_v4_compare);
                if (NULL == queue_node) {
                    /* 没有查询到重复项 */
                    dl_list_init(&new_ueip->v4_pq_node);
                    ret = rbtree_insert(ueip_root, &new_ueip->v4_node,
                        &key, pdr_ueip_v4_compare);
                    ros_rwlock_write_unlock(&pdr_head->ueip_v4_lock); /* unlock */
                    if (-1 == ret) {
                        LOG(SESSION, ERR,
                            "insert pdr failed, pdr id %u.", pdr_tbl->pdr.pdr_id);
                        return -1;
                    }
                } else {
                    /* 存在该节点,往该节点队列上加 */
                    ueip_queue = (struct pdr_ue_ipaddress *)container_of(queue_node,
                        struct pdr_ue_ipaddress, v4_node);
                    if (precedence < ueip_queue->pdr_tbl->pdr.precedence) {
                        /* 新节点的优先级为队列上最高的(数值最小)放最前面,替换二叉树上的节点 */
                        dl_list_add_tail(&ueip_queue->v4_pq_node, &new_ueip->v4_pq_node);
                        rbtree_replace_node(&ueip_queue->v4_node, &new_ueip->v4_node, ueip_root);
                    } else {
                        /* 新节点的优先级比第一个根节点要小,往后找一个合适的位置插入 */
                        dl_list_for_each_safe(pos, next, &ueip_queue->v4_pq_node) {
                            struct pdr_ue_ipaddress *cur = (struct pdr_ue_ipaddress *)container_of(pos,
                                struct pdr_ue_ipaddress, v4_pq_node);
                            if (precedence < cur->pdr_tbl->pdr.precedence) {
                                dl_list_add_tail(&cur->v4_pq_node, &new_ueip->v4_pq_node);
                                flag = 1;
                                break;
                            }
                        }
                        if (!flag) {
                            /* 队列上左右的节点都比新节点的优先级要大,往最后插入 */
                            dl_list_add_tail(&ueip_queue->v4_pq_node, &new_ueip->v4_pq_node);
                        }
                    }
                    ros_rwlock_write_unlock(&pdr_head->ueip_v4_lock);/* unlock */
                }
                LOG(SESSION, RUNNING, "Add pdr map success, ipaddr: 0x%08x.", key.ip_addr.ipv4);
            }

            /* ipv6 */
            if (new_ueip->ueip.ueip_flag.d.v6) {
                pdr_map_v6_key_fill(pdi, &key, 0, cnt);

                if (new_ueip->ueip.ueip_flag.d.s_d == 0) {
                    ueip_root = &pdr_head->ueip_sv6_root;
                } else {
                    ueip_root = &pdr_head->ueip_dv6_root;
                }

                ros_rwlock_write_lock(&pdr_head->ueip_v6_lock); /* lock */
                struct rb_node *queue_node = rbtree_search(ueip_root, &key, pdr_ueip_v6_compare);
                if (NULL == queue_node) {
                    /* 没有查询到重复项 */
                    dl_list_init(&new_ueip->v6_pq_node);
                    ret = rbtree_insert(ueip_root, &new_ueip->v6_node,
                        &key, pdr_ueip_v6_compare);
                    ros_rwlock_write_unlock(&pdr_head->ueip_v6_lock);/* unlock */
                    if (-1 == ret) {
                        LOG(SESSION, ERR, "insert pdr failed, pdr id %u.", pdr_tbl->pdr.pdr_id);
                        return -1;
                    }
                } else {
                    /* 存在该节点,往该节点队列上加 */
                    ueip_queue = (struct pdr_ue_ipaddress *)container_of(queue_node,
                        struct pdr_ue_ipaddress, v6_node);
                    if (precedence < ueip_queue->pdr_tbl->pdr.precedence) {
                        /* 新节点的优先级为队列上最高的(数值最小)放最前面,替换二叉树上的节点 */
                        dl_list_add_tail(&ueip_queue->v6_pq_node, &new_ueip->v6_pq_node);
                        rbtree_replace_node(&ueip_queue->v6_node, &new_ueip->v6_node, ueip_root);
                    } else {
                        /* 新节点的优先级比第一个根节点要小,往后找一个合适的位置插入 */
                        dl_list_for_each_safe(pos, next, &ueip_queue->v6_pq_node) {
                            struct pdr_ue_ipaddress *cur = (struct pdr_ue_ipaddress *)container_of(pos,
                                struct pdr_ue_ipaddress, v6_pq_node);
                            if (precedence < cur->pdr_tbl->pdr.precedence) {
                                dl_list_add_tail(&cur->v6_pq_node, &new_ueip->v6_pq_node);
                                flag = 1;
                                break;
                            }
                        }
                        if (!flag) {
                            /* 队列上左右的节点都比新节点的优先级要大,往最后插入 */
                            dl_list_add_tail(&ueip_queue->v6_pq_node, &new_ueip->v6_pq_node);
                        }
                    }
                    ros_rwlock_write_unlock(&pdr_head->ueip_v6_lock);/* unlock */
                }
                LOG(SESSION, RUNNING,
                    "add pdr map success, ipaddr6: 0x%08x %08x %08x %08x.",
                    ntohl(*(uint32_t *)(key.ip_addr.ipv6.value)),
                    ntohl(*(uint32_t *)(key.ip_addr.ipv6.value + 4)),
                    ntohl(*(uint32_t *)(key.ip_addr.ipv6.value + 8)),
                    ntohl(*(uint32_t *)(key.ip_addr.ipv6.value + 12)));
            }
        }

        if (pdi->framed_ipv4_route_num > 0) {
            uint8_t cnt = 0;
            uint8_t fr_num = pdi->framed_ipv4_route_num;
            uint32_t v4_key = 0;
            struct pdr_framed_route *fr_v4 = NULL, *fr_v4_queue = NULL;

            ros_rwlock_write_lock(&pdr_head->fr_v4_lock);/* lock */
            for (cnt = 0; cnt < fr_num; ++cnt) {
                fr_v4 = &pdi->framed_ipv4_route[cnt];
                v4_key = fr_v4->route.dest_ip & fr_v4->route.ip_mask;

                fr_v4_queue = (struct pdr_framed_route *)rbtree_search(&pdr_head->fr_v4_root,
                    &v4_key, pdr_fr_v4_compare);
                if (NULL == fr_v4_queue) {
                    /* 没有查询到重复项 */
                    dl_list_init(&fr_v4->pq_node);
                    ret = rbtree_insert(&pdr_head->fr_v4_root, &fr_v4->route_node,
                        &v4_key, pdr_fr_v4_compare);
                    if (-1 == ret) {
                        ros_rwlock_write_unlock(&pdr_head->fr_v4_lock);/* unlock */
                        LOG(SESSION, ERR,
                            "insert framed route failed, pdr id %u.", pdr_tbl->pdr.pdr_id);
                        return -1;
                    }
                } else {
                    /* 存在该节点,往该节点队列上加 */
                    if (fr_v4->route.metrics < fr_v4_queue->route.metrics) {
                        /* 新节点的优先级为队列上最高的(数值最小)放最前面,替换二叉树上的节点 */
                        dl_list_add_tail(&fr_v4_queue->pq_node, &fr_v4->pq_node);
                        rbtree_replace_node(&fr_v4_queue->route_node, &fr_v4->route_node,
                            &pdr_head->fr_v4_root);
                    } else {
                        /* 新节点的优先级比第一个根节点要小,往后找一个合适的位置插入 */
                        dl_list_for_each_safe(pos, next, &fr_v4_queue->pq_node) {
                            struct pdr_framed_route *cur = (struct pdr_framed_route *)container_of(pos,
                                struct pdr_framed_route, pq_node);
                            if (fr_v4->route.metrics < cur->route.metrics) {
                                dl_list_add_tail(&cur->pq_node, &fr_v4->pq_node);
                                flag = 1;
                                break;
                            }
                        }
                        if (!flag) {
                            /* 队列上左右的节点都比新节点的优先级要大,往最后插入 */
                            dl_list_add_tail(&fr_v4_queue->pq_node, &fr_v4->pq_node);
                        }
                    }
                }
            }
            ros_rwlock_write_unlock(&pdr_head->fr_v4_lock);/* unlock */
        }

        if (pdi->framed_ipv6_route_num > 0) {
            uint8_t cnt = 0;
            uint8_t fr_num = pdi->framed_ipv6_route_num;
            session_framed_route_ipv6 *v6_key = NULL;
            struct pdr_framed_route_ipv6 *fr_v6 = NULL, *fr_v6_queue = NULL;

            ros_rwlock_write_lock(&pdr_head->fr_v6_lock);/* lock */
            for (cnt = 0; cnt < fr_num; ++cnt) {
                fr_v6 = &pdi->framed_ipv6_route[cnt];
                v6_key = &fr_v6->route;

                fr_v6_queue = (struct pdr_framed_route_ipv6 *)rbtree_search(&pdr_head->fr_v6_root,
                    &v6_key, pdr_fr_v6_compare);
                if (NULL == fr_v6_queue) {
                    /* 没有查询到重复项 */
                    dl_list_init(&fr_v6->pq_node);
                    ret = rbtree_insert(&pdr_head->fr_v6_root, &fr_v6->route_node,
                        &v6_key, pdr_fr_v6_compare);
                    if (-1 == ret) {
                        ros_rwlock_write_unlock(&pdr_head->fr_v6_lock);/* unlock */
                        LOG(SESSION, ERR, "insert framed route ipv6 failed, pdr id %u.",
                            pdr_tbl->pdr.pdr_id);
                        return -1;
                    }
                } else {
                    /* 存在该节点,往该节点队列上加 */
                    if (fr_v6->route.metrics < fr_v6_queue->route.metrics) {
                        /* 新节点的优先级为队列上最高的(数值最小)放最前面,替换二叉树上的节点 */
                        dl_list_add_tail(&fr_v6_queue->pq_node, &fr_v6->pq_node);
                        rbtree_replace_node(&fr_v6_queue->route_node, &fr_v6->route_node,
                            &pdr_head->fr_v6_root);
                    } else {
                        /* 新节点的优先级比第一个根节点要小,往后找一个合适的位置插入 */
                        dl_list_for_each_safe(pos, next, &fr_v6_queue->pq_node) {
                            struct pdr_framed_route_ipv6 *cur = (struct pdr_framed_route_ipv6 *)container_of(pos,
                                struct pdr_framed_route_ipv6, pq_node);
                            if (fr_v6->route.metrics < cur->route.metrics) {
                                dl_list_add_tail(&cur->pq_node, &fr_v6->pq_node);
                                flag = 1;
                                break;
                            }
                        }
                        if (!flag) {
                            /* 队列上左右的节点都比新节点的优先级要大,往最后插入 */
                            dl_list_add_tail(&fr_v6_queue->pq_node, &fr_v6->pq_node);
                        }
                    }
                }
            }
            ros_rwlock_write_unlock(&pdr_head->fr_v6_lock);/* unlock */
        }

        if (pdr_tbl->session_link && PDN_TYPE_ETHERNET == pdr_tbl->session_link->session.pdn_type) {
            struct session_t *sess = pdr_tbl->session_link;

            if (dl_list_empty(&sess->eth_dl_head)) {
                dl_list_add_tail(&sess->eth_dl_head, &pdr_tbl->eth_dl_node);
            } else {

                /* 存在该节点,往该节点队列上加 */
                /* 新节点的优先级比第一个根节点要小,往后找一个合适的位置插入 */
                dl_list_for_each_safe(pos, next, &sess->eth_dl_head) {
                    struct pdr_table *cur = (struct pdr_table *)container_of(pos,
                        struct pdr_table, eth_dl_node);
                    if (precedence < cur->pdr.precedence) {
                        dl_list_add_tail(&cur->eth_dl_node, &pdr_tbl->eth_dl_node);
                        break;
                    }
                }
            }
        }

        return 0;
    } else {
        struct pdr_key key = {.teid = 0};
        uint8_t cnt;
        struct pdr_local_fteid *new_fteid = NULL, *fteid_queue = NULL;
        struct rb_node *queue_node;

        for (cnt = 0; cnt < pdi->local_fteid_num; ++cnt) {
            new_fteid = &pdi->local_fteid[cnt];

            /* ipv4 */
            if (new_fteid->local_fteid.f_teid_flag.d.v4) {
                pdr_map_v4_key_fill(pdi, &key, 1, cnt);

                ros_rwlock_write_lock(&pdr_head->teid_v4_lock); /* lock */
                queue_node = rbtree_search(&pdr_head->fteid_v4_root,
                    &key, pdr_fteid_v4_compare);
                if (NULL == queue_node) {
                    dl_list_init(&new_fteid->v4_pq_node);
                    ret = rbtree_insert(&pdr_head->fteid_v4_root, &new_fteid->v4_node,
                        &key, pdr_fteid_v4_compare);
                    ros_rwlock_write_unlock(&pdr_head->teid_v4_lock);/* unlock */
                    if (-1 == ret) {
                        LOG(SESSION, ERR,
                            "insert pdr failed, pdr id %u.", pdr_tbl->pdr.pdr_id);
                        return -1;
                    }

                } else {
                    fteid_queue = (struct pdr_local_fteid *)container_of(queue_node,
                        struct pdr_local_fteid, v4_node);
                    if (precedence < fteid_queue->pdr_tbl->pdr.precedence) {
                        dl_list_add_tail(&fteid_queue->v4_pq_node, &new_fteid->v4_pq_node);
                        rbtree_replace_node(&fteid_queue->v4_node, &new_fteid->v4_node,
                            &pdr_head->fteid_v4_root);
                    } else {
                        dl_list_for_each_safe(pos, next, &fteid_queue->v4_pq_node) {
                            struct pdr_local_fteid *cur = (struct pdr_local_fteid *)container_of(pos,
                                struct pdr_local_fteid, v4_pq_node);
                            if (precedence < cur->pdr_tbl->pdr.precedence) {
                                dl_list_add_tail(&cur->v4_pq_node, &new_fteid->v4_pq_node);
                                flag = 1;
                                break;
                            }
                        }
                        if (!flag) {
                            dl_list_add_tail(&fteid_queue->v4_pq_node, &new_fteid->v4_pq_node);
                        }
                    }
                    ros_rwlock_write_unlock(&pdr_head->teid_v4_lock);/* unlock */
                }
                LOG(SESSION, RUNNING, "add pdr map success, teid: %u, ipaddr: 0x%08x.",
                    key.teid, key.ip_addr.ipv4);
            }

            /* ipv6 */
            if (new_fteid->local_fteid.f_teid_flag.d.v6) {
                pdr_map_v6_key_fill(pdi, &key, 1, cnt);

                ros_rwlock_write_lock(&pdr_head->teid_v6_lock); /* lock */
                struct rb_node *queue_node = rbtree_search(&pdr_head->fteid_v6_root,
                    &key, pdr_fteid_v6_compare);
                if (NULL == queue_node) {
                    dl_list_init(&new_fteid->v6_pq_node);
                    ret = rbtree_insert(&pdr_head->fteid_v6_root, &new_fteid->v6_node,
                        &key, pdr_fteid_v6_compare);
                    ros_rwlock_write_unlock(&pdr_head->teid_v6_lock);/* unlock */
                    if (-1 == ret) {
                        LOG(SESSION, ERR, "insert pdr failed, pdr id %u.", pdr_tbl->pdr.pdr_id);
                        return -1;
                    }

                } else {
                    fteid_queue = (struct pdr_local_fteid *)container_of(queue_node,
                        struct pdr_local_fteid, v6_node);
                    if (precedence < fteid_queue->pdr_tbl->pdr.precedence) {
                        dl_list_add_tail(&fteid_queue->v6_pq_node, &new_fteid->v6_pq_node);
                        rbtree_replace_node(&fteid_queue->v6_node, &new_fteid->v6_node,
                            &pdr_head->fteid_v6_root);
                    } else {
                        dl_list_for_each_safe(pos, next, &fteid_queue->v6_pq_node) {
                            struct pdr_local_fteid *cur = (struct pdr_local_fteid *)container_of(pos,
                                struct pdr_local_fteid, v6_pq_node);
                            if (precedence < cur->pdr_tbl->pdr.precedence) {
                                dl_list_add_tail(&cur->v6_pq_node, &new_fteid->v6_pq_node);
                                flag = 1;
                                break;
                            }
                        }
                        if (!flag) {
                            dl_list_add_tail(&fteid_queue->v6_pq_node, &new_fteid->v6_pq_node);
                        }
                    }
                    ros_rwlock_write_unlock(&pdr_head->teid_v6_lock);/* unlock */
                }
                LOG(SESSION, RUNNING,
                    "add pdr map success, teid: %u, ipaddr6: 0x%08x %08x %08x %08x.",
                    key.teid, ntohl(*(uint32_t *)(key.ip_addr.ipv6.value)),
                    ntohl(*(uint32_t *)(key.ip_addr.ipv6.value + 4)),
                    ntohl(*(uint32_t *)(key.ip_addr.ipv6.value + 8)),
                    ntohl(*(uint32_t *)(key.ip_addr.ipv6.value + 12)));
            }
        }

        return 0;
    }
}

static int pdr_map_remove(struct pdr_table *pdr_tbl)
{
    struct pdr_table_head *pdr_head = pdr_get_head();
    struct pkt_detection_info *pdi = &pdr_tbl->pdr.pdi_content;

    if (COMM_SRC_IF_DN == pdr_tbl->pdr.pdi_content.si) {
        struct pdr_key key = {.teid = 0};
        uint8_t cnt;
        struct pdr_ue_ipaddress *cur_ueip = NULL, *ueip_queue = NULL;
        struct rb_root *ueip_root;

        for (cnt = 0; cnt < pdi->ue_ipaddr_num; ++cnt) {
            cur_ueip = &pdi->ue_ipaddr[cnt];

            /* ipv4 */
            if (cur_ueip->ueip.ueip_flag.d.v4) {
                pdr_map_v4_key_fill(pdi, &key, 0, cnt);

                if (cur_ueip->ueip.ueip_flag.d.s_d == 0) {
                    ueip_root = &pdr_head->ueip_sv4_root;
                } else {
                    ueip_root = &pdr_head->ueip_dv4_root;
                }

                ros_rwlock_write_lock(&pdr_head->ueip_v4_lock);/* lock */
                struct rb_node *queue_node = rbtree_search(ueip_root, &key, pdr_ueip_v4_compare);
                if (NULL == queue_node) {
                    /* 没有匹配的节点 */
                    ros_rwlock_write_unlock(&pdr_head->ueip_v4_lock); /* unlock */
                    LOG(SESSION, ERR, "search pdr failed, pdr id %u.", pdr_tbl->pdr.pdr_id);
                    continue;
                } else {
                    /* 找到匹配节点 */
                    ueip_queue = (struct pdr_ue_ipaddress *)container_of(queue_node,
                        struct pdr_ue_ipaddress, v4_node);
                    if (cur_ueip == ueip_queue) {
                        /* 要删除的节点是该队列的首节点 */
                        if (dl_list_empty(&ueip_queue->v4_pq_node)) {
                            /* 队列上没有其他节点,直接将二叉树上的节点删除 */
                            if (NULL == rbtree_delete(ueip_root, &key, pdr_ueip_v4_compare)) {
                                ros_rwlock_write_unlock(&pdr_head->ueip_v4_lock);/* unlock*/
                                LOG(SESSION, ERR, "delete pdr map failed, pdr id %u.",
                                    pdr_tbl->pdr.pdr_id);
                                continue;
                            }
                        } else {
                            /* 队列上存在其他节点,需要替换后再删除 */
                            struct pdr_ue_ipaddress *tmp_ueip = (struct pdr_ue_ipaddress *)
                                dl_list_entry_next(ueip_queue, v4_pq_node);
                            rbtree_replace_node(&ueip_queue->v4_node, &tmp_ueip->v4_node, ueip_root);
                            dl_list_del(&ueip_queue->v4_pq_node);
                        }
                    } else {
                        /* 要删除的节点不是队列上的首个节点,直接从队列上删除即可 */
                        dl_list_del(&cur_ueip->v4_pq_node);
                    }
                    ros_rwlock_write_unlock(&pdr_head->ueip_v4_lock);/* unlock */
                }
            }

            /* ipv6 */
            if (cur_ueip->ueip.ueip_flag.d.v6) {
                pdr_map_v6_key_fill(pdi, &key, 0, cnt);

                if (cur_ueip->ueip.ueip_flag.d.s_d == 0) {
                    ueip_root = &pdr_head->ueip_sv6_root;
                } else {
                    ueip_root = &pdr_head->ueip_dv6_root;
                }

                ros_rwlock_write_lock(&pdr_head->ueip_v6_lock);/* lock */
                struct rb_node *queue_node = rbtree_search(ueip_root, &key, pdr_ueip_v6_compare);
                if (NULL == queue_node) {
                    ros_rwlock_write_unlock(&pdr_head->ueip_v6_lock);/* unlock */
                    LOG(SESSION, ERR,
                        "search pdr failed, pdr id %u.", pdr_tbl->pdr.pdr_id);
                    continue;
                } else {
                    ueip_queue = (struct pdr_ue_ipaddress *)container_of(queue_node,
                        struct pdr_ue_ipaddress, v6_node);
                    if (cur_ueip == ueip_queue) {
                        if (dl_list_empty(&ueip_queue->v6_pq_node)) {
                            if (NULL == rbtree_delete(ueip_root, &key, pdr_ueip_v6_compare)) {
                                ros_rwlock_write_unlock(
                                    &pdr_head->ueip_v6_lock);/* unlock*/
                                LOG(SESSION, ERR, "delete pdr map failed, pdr id %u.",
                                    pdr_tbl->pdr.pdr_id);
                                continue;
                            }
                        } else {
                            struct pdr_ue_ipaddress *tmp_ueip = (struct pdr_ue_ipaddress *)
                                dl_list_entry_next(ueip_queue, v6_pq_node);
                            rbtree_replace_node(&ueip_queue->v6_node, &tmp_ueip->v6_node, ueip_root);
                            dl_list_del(&ueip_queue->v6_pq_node);
                        }
                    } else {
                        dl_list_del(&cur_ueip->v6_pq_node);
                    }
                    ros_rwlock_write_unlock(&pdr_head->ueip_v6_lock);/* unlock */
                }
            }
        }

        if (pdi->framed_ipv4_route_num > 0) {
            uint8_t cnt = 0;
            uint8_t fr_num = pdi->framed_ipv4_route_num;
            uint32_t v4_key = 0;
            struct pdr_framed_route *fr_v4 = NULL, *fr_v4_queue = NULL;

            ros_rwlock_write_lock(&pdr_head->fr_v4_lock);/* lock */
            for (cnt = 0; cnt < fr_num; ++cnt) {
                fr_v4 = &pdi->framed_ipv4_route[cnt];
                v4_key = fr_v4->route.dest_ip & fr_v4->route.ip_mask;

                fr_v4_queue = (struct pdr_framed_route *)rbtree_search(&pdr_head->fr_v4_root,
                    &v4_key, pdr_fr_v4_compare);
                if (NULL == fr_v4_queue) {
                    /* 没有匹配的节点, 不应该出现 */
                    LOG(SESSION, ERR, "search framed route map failed, pdr id %u.",
                        pdr_tbl->pdr.pdr_id);
                    continue;
                } else {
                    /* 找到匹配节点 */
                    if (fr_v4 == fr_v4_queue) {
                        /* 要删除的节点是该队列的首节点 */
                        if (dl_list_empty(&fr_v4_queue->pq_node)) {
                            /* 队列上没有其他节点,直接将二叉树上的节点删除 */
                            if (NULL == rbtree_delete(&pdr_head->fr_v4_root,
                                &v4_key, pdr_fr_v4_compare)) {
                                LOG(SESSION, ERR, "delete framed route map failed, pdr id %u.",
                                    pdr_tbl->pdr.pdr_id);
                                continue;
                            }
                        } else {
                            /* 队列上存在其他节点,需要替换后再删除 */
                            struct pdr_framed_route *tmp_fr_v4 = (struct pdr_framed_route *)
                                dl_list_entry_next(fr_v4_queue, pq_node);
                            rbtree_replace_node(&fr_v4_queue->route_node, &tmp_fr_v4->route_node,
                                &pdr_head->fr_v4_root);
                            dl_list_del(&fr_v4_queue->pq_node);
                        }
                    } else {
                        /* 要删除的节点不是队列上的首个节点,直接从队列上删除即可 */
                        dl_list_del(&fr_v4->pq_node);
                    }
                }
            }
            ros_rwlock_write_unlock(&pdr_head->fr_v4_lock);/* unlock */
        }

        if (pdi->framed_ipv6_route_num > 0) {
            uint8_t cnt = 0;
            uint8_t fr_num = pdi->framed_ipv6_route_num;
            session_framed_route_ipv6 *v6_key = NULL;
            struct pdr_framed_route_ipv6 *fr_v6 = NULL, *fr_v6_queue = NULL;

            ros_rwlock_write_lock(&pdr_head->fr_v6_lock);/* lock */
            for (cnt = 0; cnt < fr_num; ++cnt) {
                fr_v6 = &pdi->framed_ipv6_route[cnt];
                v6_key = &fr_v6->route;

                fr_v6_queue = (struct pdr_framed_route_ipv6 *)rbtree_search(&pdr_head->fr_v6_root,
                    &v6_key, pdr_fr_v6_compare);
                if (NULL == fr_v6_queue) {
                    /* 没有匹配的节点, 不应该出现 */
                    LOG(SESSION, ERR, "search framed route map failed, pdr id %u.",
                        pdr_tbl->pdr.pdr_id);
                    continue;
                } else {
                    /* 找到匹配节点 */
                    if (fr_v6 == fr_v6_queue) {
                        /* 要删除的节点是该队列的首节点 */
                        if (dl_list_empty(&fr_v6_queue->pq_node)) {
                            /* 队列上没有其他节点,直接将二叉树上的节点删除 */
                            if (NULL == rbtree_delete(&pdr_head->fr_v6_root,
                                &v6_key, pdr_fr_v6_compare)) {
                                LOG(SESSION, ERR, "delete framed route map failed, pdr id %u.",
                                    pdr_tbl->pdr.pdr_id);
                                continue;
                            }
                        } else {
                            /* 队列上存在其他节点,需要替换后再删除 */
                            struct pdr_framed_route_ipv6 *tmp_fr_v6 = (struct pdr_framed_route_ipv6 *)
                                dl_list_entry_next(fr_v6_queue, pq_node);
                            rbtree_replace_node(&fr_v6_queue->route_node, &tmp_fr_v6->route_node,
                                &pdr_head->fr_v6_root);
                            dl_list_del(&fr_v6_queue->pq_node);
                        }
                    } else {
                        /* 要删除的节点不是队列上的首个节点,直接从队列上删除即可 */
                        dl_list_del(&fr_v6->pq_node);
                    }
                }
            }
            ros_rwlock_write_unlock(&pdr_head->fr_v6_lock);/* unlock */
        }

        /* Ethernet PDN type */
        if (pdr_tbl->session_link && PDN_TYPE_ETHERNET == pdr_tbl->session_link->session.pdn_type) {
            dl_list_del(&pdr_tbl->eth_dl_node);
        }

        return 0;
    } else {
        struct pdr_key key = {.teid = 0};
        uint8_t cnt;
        struct pdr_local_fteid *cur_fteid = NULL, *fteid_queue = NULL;

        for (cnt = 0; cnt < pdi->local_fteid_num; ++cnt) {
            cur_fteid = &pdi->local_fteid[cnt];
            /* ipv4 */
            if (cur_fteid->local_fteid.f_teid_flag.d.v4) {
                pdr_map_v4_key_fill(pdi, &key, 1, cnt);

                ros_rwlock_write_lock(&pdr_head->teid_v4_lock);/* lock */
                struct rb_node *queue_node = rbtree_search(&pdr_head->fteid_v4_root,
                    &key, pdr_fteid_v4_compare);
                if (NULL == queue_node) {
                    ros_rwlock_write_unlock(&pdr_head->teid_v4_lock);/* unlock */
                    LOG(SESSION, ERR,
                        "search pdr failed, pdr id %u.", pdr_tbl->pdr.pdr_id);
                    continue;
                } else {
                    fteid_queue = (struct pdr_local_fteid *)container_of(queue_node,
                        struct pdr_local_fteid, v4_node);
                    if (cur_fteid == fteid_queue) {
                        if (dl_list_empty(&fteid_queue->v4_pq_node)) {
                            if (NULL == rbtree_delete(&pdr_head->fteid_v4_root,
                                &key, pdr_fteid_v4_compare)) {
                                ros_rwlock_write_unlock(&pdr_head->teid_v4_lock);/* unlock*/
                                LOG(SESSION, ERR, "delete pdr map failed, pdr id %u.",
                                    pdr_tbl->pdr.pdr_id);
                                continue;
                            }
                        } else {
                            struct pdr_local_fteid *tmp_fteid = (struct pdr_local_fteid *)
                                dl_list_entry_next(fteid_queue, v4_pq_node);
                            rbtree_replace_node(&fteid_queue->v4_node,
                                &tmp_fteid->v4_node, &pdr_head->fteid_v4_root);
                            dl_list_del(&fteid_queue->v4_pq_node);
                        }
                    } else {
                        /* Direct deletion */
                        dl_list_del(&cur_fteid->v4_pq_node);
                    }
                    ros_rwlock_write_unlock(&pdr_head->teid_v4_lock);/* unlock */
                }
            }

            /* ipv6 */
            if (cur_fteid->local_fteid.f_teid_flag.d.v6) {
                pdr_map_v6_key_fill(pdi, &key, 1, cnt);

                ros_rwlock_write_lock(&pdr_head->teid_v6_lock);/* lock */
                struct rb_node *queue_node = rbtree_search(&pdr_head->fteid_v6_root,
                    &key, pdr_fteid_v6_compare);
                if (NULL == queue_node) {
                    ros_rwlock_write_unlock(&pdr_head->teid_v6_lock);/* unlock */
                    LOG(SESSION, ERR,
                        "search pdr failed, pdr id %u.", pdr_tbl->pdr.pdr_id);
                    continue;
                } else {
                    fteid_queue = (struct pdr_local_fteid *)container_of(queue_node,
                        struct pdr_local_fteid, v6_node);
                    if (cur_fteid == fteid_queue) {
                        if (dl_list_empty(&fteid_queue->v6_pq_node)) {
                            if (NULL == rbtree_delete(&pdr_head->fteid_v6_root,
                                &key, pdr_fteid_v6_compare)) {
                                ros_rwlock_write_unlock(&pdr_head->teid_v6_lock);/* unlock*/
                                LOG(SESSION, ERR, "delete pdr map failed, pdr id %u.",
                                    pdr_tbl->pdr.pdr_id);
                                continue;
                            }
                        } else {
                            struct pdr_local_fteid *tmp_fteid = (struct pdr_local_fteid *)
                                dl_list_entry_next(fteid_queue, v6_pq_node);
                            rbtree_replace_node(&fteid_queue->v6_node,
                                &tmp_fteid->v6_node, &pdr_head->fteid_v6_root);
                            dl_list_del(&fteid_queue->v6_pq_node);
                        }
                    } else {
                        /* Direct deletion */
                        dl_list_del(&cur_fteid->v6_pq_node);
                    }
                    ros_rwlock_write_unlock(&pdr_head->teid_v6_lock);/* unlock */
                }
            }
        }

        return 0;
    }
}

static struct pdr_table *pdr_match_frv6(uint8_t *dip, struct filter_key *key)
{
    struct pdr_table_head *pdr_head = pdr_get_head();
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    struct rb_node *queue_node = NULL;
    int cur_url_depth, get_url_depth;
    struct pdr_table *ret_pdr = NULL;
    struct pdr_framed_route_ipv6 *fr_v6 = NULL;
    session_framed_route_ipv6 v6_key;
    int prefix_cnt;
    struct pdr_framed_route_ipv6 *cur;

    LOG(SESSION, RUNNING, "Matching framed route v6.");
    ros_rwlock_read_lock(&pdr_head->fr_v6_lock);/* lock */
    memcpy(v6_key.dest_ip, dip, IPV6_ALEN);
    for (prefix_cnt = 128; prefix_cnt >= 0; --prefix_cnt) {
        ipv6_prefix_to_mask(v6_key.ip_mask, prefix_cnt);

        queue_node = rbtree_search(&pdr_head->fr_v6_root,
            &v6_key, pdr_fr_v6_compare);
        if (queue_node) {
            break;
        }
    }
    ros_rwlock_read_unlock(&pdr_head->fr_v6_lock);/* unlock */

    if (NULL == queue_node) {
        LOG(SESSION, RUNNING,
            "search pdr failed, dest ipv6 0x%08x %08x %08x %08x.",
        htonl(*(uint32_t *)(dip)),
        htonl(*(uint32_t *)(dip + 4)),
        htonl(*(uint32_t *)(dip + 8)),
        htonl(*(uint32_t *)(dip + 12)));
        return NULL;
    }

    fr_v6 = (struct pdr_framed_route_ipv6 *)container_of(queue_node,
        struct pdr_framed_route_ipv6, route_node);
    /* fill filter */
    ros_rwlock_read_lock(&pdr_head->fr_v6_lock);/* lock */
    if (0 == filter_process(key, key->field_offset, &fr_v6->pdr_tbl->pdr.pdi_content,
        &cur_url_depth)) {
        ret_pdr = fr_v6->pdr_tbl;

        /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */
        dl_list_for_each_safe(pos, next, &fr_v6->pq_node) {
            cur = (struct pdr_framed_route_ipv6 *)container_of(
                pos, struct pdr_framed_route_ipv6, pq_node);
            if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                break;
            } else {
                if (0 == filter_process(key, key->field_offset,
                    &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                    LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                        cur->pdr_tbl->pdr.pdr_id);
                    if (cur_url_depth < get_url_depth) {
                        cur_url_depth = get_url_depth;
                        ret_pdr = cur->pdr_tbl;
                    }
                }
            }
        }
        LOG(SESSION, RUNNING,
            "pdr map lookup success, pdr_id %u.", fr_v6->pdr_tbl->pdr.pdr_id);
    } else {
        dl_list_for_each_safe(pos, next, &fr_v6->pq_node) {
            struct pdr_framed_route_ipv6 *cur = (struct pdr_framed_route_ipv6 *)container_of(
                pos, struct pdr_framed_route_ipv6, pq_node);
            if (0 == filter_process(key, key->field_offset,
                &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */

                LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                    cur->pdr_tbl->pdr.pdr_id);

                if (NULL == ret_pdr) {
                    cur_url_depth = get_url_depth;
                    ret_pdr = cur->pdr_tbl;

                    continue;
                }

                if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                    break;
                } else {
                    if (cur_url_depth < get_url_depth) {
                        cur_url_depth = get_url_depth;
                        ret_pdr = cur->pdr_tbl;
                    }
                }
            }
        }
    }
    ros_rwlock_read_unlock(&pdr_head->fr_v6_lock); /* unlock */

    /* 查找ip和host白名单 */
    if (ret_pdr && -1 == white_list_filter_process(ret_pdr, FlowGetL1Ipv4Header(key))) {
        LOG(SESSION, DEBUG,
            "Match pdr (%p), pdr_id: %u, pdr_match_frv6 failed!",
            ret_pdr, ret_pdr ? ret_pdr->pdr.pdr_id : 0);
        return NULL;
    }
    LOG(SESSION, DEBUG,
        "Finally, Match pdr (%p), pdr_id: %u(0 is invalid).", ret_pdr, ret_pdr ? ret_pdr->pdr.pdr_id : 0);

    return ret_pdr;
}

static struct pdr_table *pdr_match_frv4(uint32_t dip, struct filter_key *key)
{
    struct pdr_table_head *pdr_head = pdr_get_head();
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    struct rb_node *queue_node = NULL;
    int cur_url_depth, get_url_depth;
    struct pdr_table *ret_pdr = NULL;
    struct pdr_framed_route *fr = NULL;
    uint32_t v4_key = dip;
    int prefix_cnt;
    struct pdr_framed_route *cur;

    LOG(SESSION, RUNNING, "Matching framed route v4.");
    ros_rwlock_read_lock(&pdr_head->fr_v4_lock);/* lock */
    for (prefix_cnt = 32; prefix_cnt >= 0; --prefix_cnt) {
        v4_key &= num_to_mask(prefix_cnt);

        queue_node = rbtree_search(&pdr_head->fr_v4_root,
            &v4_key, pdr_fr_v4_compare);
        if (queue_node) {
            break;
        }
    }
    ros_rwlock_read_unlock(&pdr_head->fr_v4_lock);/* unlock */

    if (NULL == queue_node) {
        LOG(SESSION, RUNNING, "search pdr failed, dest ipv4 0x%08x.", dip);
        return NULL;
    }
    fr = (struct pdr_framed_route *)container_of(queue_node,
        struct pdr_framed_route, route_node);
    /* fill filter */
    ros_rwlock_read_lock(&pdr_head->fr_v4_lock);/* lock */
    if (0 == filter_process(key, key->field_offset, &fr->pdr_tbl->pdr.pdi_content,
            &cur_url_depth)) {
        ret_pdr = fr->pdr_tbl;

        /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */
        dl_list_for_each_safe(pos, next, &fr->pq_node) {
            cur = (struct pdr_framed_route *)container_of(
                pos, struct pdr_framed_route, pq_node);
            if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                break;
            } else {
                if (0 == filter_process(key, key->field_offset,
                    &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                    LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                        cur->pdr_tbl->pdr.pdr_id);
                    if (cur_url_depth < get_url_depth) {
                        cur_url_depth = get_url_depth;
                        ret_pdr = cur->pdr_tbl;
                    }
                }
            }
        }
        LOG(SESSION, DEBUG,
            "pdr map lookup success, pdr_id %u.", fr->pdr_tbl->pdr.pdr_id);
    } else {
        dl_list_for_each_safe(pos, next, &fr->pq_node) {
            cur = (struct pdr_framed_route *)container_of(
                pos, struct pdr_framed_route, pq_node);
            if (0 == filter_process(key, key->field_offset,
                &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */

                LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                    cur->pdr_tbl->pdr.pdr_id);

                if (NULL == ret_pdr) {
                    cur_url_depth = get_url_depth;
                    ret_pdr = cur->pdr_tbl;

                    continue;
                }

                if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                    break;
                } else {
                    if (cur_url_depth < get_url_depth) {
                        cur_url_depth = get_url_depth;
                        ret_pdr = cur->pdr_tbl;
                    }
                }
            }
        }
    }
    ros_rwlock_read_unlock(&pdr_head->fr_v4_lock); /* unlock */

    /* 查找ip和host白名单 */
    if (ret_pdr && -1 == white_list_filter_process(ret_pdr, FlowGetL1Ipv4Header(key))) {
        LOG(SESSION, DEBUG,
            "Match pdr (%p), pdr_id: %u, pdr_match_frv6 failed!",
            ret_pdr, ret_pdr ? ret_pdr->pdr.pdr_id : 0);
        return NULL;
    }
    LOG(SESSION, DEBUG,
        "Match pdr (%p), pdr_id: %u(0 is invalid).", ret_pdr, ret_pdr ? ret_pdr->pdr.pdr_id : 0);

    return ret_pdr;
}

static struct pdr_table *pdr_match_ueip(struct pdr_ue_ipaddress *ueip_queue, struct filter_key *key)
{
    struct pdr_table_head *pdr_head = pdr_get_head();
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    int cur_url_depth, get_url_depth;
    struct pdr_table *ret_pdr = NULL;
    struct pdr_ue_ipaddress *cur;

    ros_rwlock_read_lock(&pdr_head->ueip_v6_lock);/* lock */
    if (0 == filter_process(key, key->field_offset, &ueip_queue->pdr_tbl->pdr.pdi_content,
            &cur_url_depth)) {
        ret_pdr = ueip_queue->pdr_tbl;

        /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */
        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV4)) {
            dl_list_for_each_safe(pos, next, &ueip_queue->v4_pq_node) {
                cur = (struct pdr_ue_ipaddress *)container_of(
                    pos, struct pdr_ue_ipaddress, v4_pq_node);
                if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                    break;
                } else {
                    if (0 == filter_process(key, key->field_offset,
                        &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                        LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                            cur->pdr_tbl->pdr.pdr_id);
                        if (cur_url_depth < get_url_depth) {
                            cur_url_depth = get_url_depth;
                            ret_pdr = cur->pdr_tbl;
                        }
                    }
                }
            }
        } else if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV6)) {
            dl_list_for_each_safe(pos, next, &ueip_queue->v6_pq_node) {
                cur = (struct pdr_ue_ipaddress *)container_of(
                    pos, struct pdr_ue_ipaddress, v6_pq_node);
                if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                    break;
                } else {
                    if (0 == filter_process(key, key->field_offset,
                        &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                        LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                            cur->pdr_tbl->pdr.pdr_id);
                        if (cur_url_depth < get_url_depth) {
                            cur_url_depth = get_url_depth;
                            ret_pdr = cur->pdr_tbl;
                        }
                    }
                }
            }
        }
    } else {
        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV4)) {
            dl_list_for_each_safe(pos, next, &ueip_queue->v4_pq_node) {
                cur = (struct pdr_ue_ipaddress *)container_of(
                    pos, struct pdr_ue_ipaddress, v4_pq_node);
                if (0 == filter_process(key, key->field_offset,
                    &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                    /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */

                    LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                        cur->pdr_tbl->pdr.pdr_id);

                    if (NULL == ret_pdr) {
                        cur_url_depth = get_url_depth;
                        ret_pdr = cur->pdr_tbl;

                        continue;
                    }

                    if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                        break;
                    } else {
                        if (cur_url_depth < get_url_depth) {
                            cur_url_depth = get_url_depth;
                            ret_pdr = cur->pdr_tbl;
                        }
                    }
                }
            }
        } else if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV6)) {
            dl_list_for_each_safe(pos, next, &ueip_queue->v6_pq_node) {
                cur = (struct pdr_ue_ipaddress *)container_of(
                    pos, struct pdr_ue_ipaddress, v6_pq_node);
                if (0 == filter_process(key, key->field_offset,
                    &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                    /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */

                    LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                        cur->pdr_tbl->pdr.pdr_id);

                    if (NULL == ret_pdr) {
                        cur_url_depth = get_url_depth;
                        ret_pdr = cur->pdr_tbl;

                        continue;
                    }

                    if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                        break;
                    } else {
                        if (cur_url_depth < get_url_depth) {
                            cur_url_depth = get_url_depth;
                            ret_pdr = cur->pdr_tbl;
                        }
                    }
                }
            }
        }
    }
    ros_rwlock_read_unlock(&pdr_head->ueip_v6_lock); /* unlock */

    /* 查找ip和host白名单 */
    if (ret_pdr && -1 == white_list_filter_process(ret_pdr, FlowGetL1Ipv4Header(key))) {
        LOG(SESSION, DEBUG,
            "Match pdr (%p), pdr_id: %u, pdr_match_frv6 failed!",
            ret_pdr, ret_pdr ? ret_pdr->pdr.pdr_id : 0);
        return NULL;
    }
    LOG(SESSION, DEBUG,
        "Finally, Match pdr (%p), pdr_id: %u(0 is invalid).", ret_pdr, ret_pdr ? ret_pdr->pdr.pdr_id : 0);

    return ret_pdr;
}

static struct pdr_table *pdr_match_fteid(struct pdr_local_fteid *fteid_queue, struct filter_key *key)
{
    struct pdr_table_head *pdr_head = pdr_get_head();
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    int cur_url_depth, get_url_depth;
    struct pdr_table *ret_pdr = NULL;
    struct pdr_local_fteid *cur;

    ros_rwlock_read_lock(&pdr_head->teid_v6_lock);/* lock */
    if (0 == filter_process(key, &(key->field_offset[FLOW_FIELD_L2_ETH]),
            &fteid_queue->pdr_tbl->pdr.pdi_content, &cur_url_depth)) {
        ret_pdr = fteid_queue->pdr_tbl;

        LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
            fteid_queue->pdr_tbl->pdr.pdr_id);

        /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */
        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV4)) {
            dl_list_for_each_safe(pos, next, &fteid_queue->v4_pq_node) {
                cur = (struct pdr_local_fteid *)container_of(
                    pos, struct pdr_local_fteid, v4_pq_node);
                if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                    break;
                } else {
                    if (0 == filter_process(key, &(key->field_offset[FLOW_FIELD_L2_ETH]),
                        &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                        LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                            cur->pdr_tbl->pdr.pdr_id);
                        if (cur_url_depth < get_url_depth) {
                            cur_url_depth = get_url_depth;
                            ret_pdr = cur->pdr_tbl;
                        }
                    }
                }
            }
        } else if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV6)) {
            dl_list_for_each_safe(pos, next, &fteid_queue->v6_pq_node) {
                cur = (struct pdr_local_fteid *)container_of(
                    pos, struct pdr_local_fteid, v6_pq_node);
                if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                    break;
                } else {
                    if (0 == filter_process(key, &(key->field_offset[FLOW_FIELD_L2_ETH]),
                        &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                        LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                            cur->pdr_tbl->pdr.pdr_id);
                        if (cur_url_depth < get_url_depth) {
                            cur_url_depth = get_url_depth;
                            ret_pdr = cur->pdr_tbl;
                        }
                    }
                }
            }
        }
    } else {
        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV4)) {
            dl_list_for_each_safe(pos, next, &fteid_queue->v4_pq_node) {
                cur = (struct pdr_local_fteid *)container_of(
                    pos, struct pdr_local_fteid, v4_pq_node);
                if (0 == filter_process(key, &(key->field_offset[FLOW_FIELD_L2_ETH]),
                        &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                    /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */

                    LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                        cur->pdr_tbl->pdr.pdr_id);

                    if (NULL == ret_pdr) {
                        cur_url_depth = get_url_depth;
                        ret_pdr = cur->pdr_tbl;

                        continue;
                    }

                    if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                        break;
                    } else {
                        if (cur_url_depth < get_url_depth) {
                            cur_url_depth = get_url_depth;
                            ret_pdr = cur->pdr_tbl;
                        }
                    }
                }
            }
        } else if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV6)) {
            dl_list_for_each_safe(pos, next, &fteid_queue->v6_pq_node) {
                cur = (struct pdr_local_fteid *)container_of(
                    pos, struct pdr_local_fteid, v6_pq_node);
                if (0 == filter_process(key, &(key->field_offset[FLOW_FIELD_L2_ETH]),
                        &cur->pdr_tbl->pdr.pdi_content, &get_url_depth)) {
                    /* 查询到可匹配PDR后再检查同一优先级但深度不同的URL匹配 */

                    LOG(SESSION, DEBUG, "pdr map lookup success, pdr_id %u.",
                        cur->pdr_tbl->pdr.pdr_id);

                    if (NULL == ret_pdr) {
                        cur_url_depth = get_url_depth;
                        ret_pdr = cur->pdr_tbl;

                        continue;
                    }

                    if (cur->pdr_tbl->pdr.precedence != ret_pdr->pdr.precedence) {
                        break;
                    } else {
                        if (cur_url_depth < get_url_depth) {
                            cur_url_depth = get_url_depth;
                            ret_pdr = cur->pdr_tbl;
                        }
                    }
                }
            }
        }
    }
    ros_rwlock_read_unlock(&pdr_head->teid_v6_lock); /* unlock */

    /* 查找ip和host白名单 */
    if (ret_pdr && -1 == white_list_filter_process(ret_pdr, FlowGetL2Ipv4Header(key))) {
        LOG(SESSION, DEBUG,
            "Match pdr (%p), pdr_id: %u, pdr_match_frv6 failed!",
            ret_pdr, ret_pdr ? ret_pdr->pdr.pdr_id : 0);
        return NULL;
    }

    /* Save UE MAC address */
    if (ret_pdr && ret_pdr->session_link && PDN_TYPE_ETHERNET == ret_pdr->session_link->session.pdn_type) {
        struct pro_eth_hdr *eth_hdr = FlowGetL2MACHeader(key);

        if (eth_hdr && 0 > se_entry_insert(ret_pdr->session_link, eth_hdr->source)) {
            LOG(SESSION, ERR, "Insert UE MAC failed.");
        }
    }

    LOG(SESSION, DEBUG,
        "Finally, Match pdr (%p), pdr_id: %u(0 is invalid).", ret_pdr, ret_pdr ? ret_pdr->pdr.pdr_id : 0);

    return ret_pdr;
}

static struct pdr_table *pdr_match_dl_ethernet(struct filter_key *key)
{
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    int url_depth;
    struct pdr_table *ret_pdr = NULL;
    struct pdr_table *cur_pdr;
    struct session_ethernet_entry *eth_entry;
    struct session_t *sess_tbl;
    struct pro_eth_hdr *eth_hdr = FlowGetL1MACHeader(key);
    if (unlikely(NULL == eth_hdr)) {
        LOG(SESSION, ERR, "eth_hdr is NULL.");
        return NULL;
    }
    LOG(SESSION, RUNNING, "Matching downlink Ethernet packet.");

    eth_entry = se_entry_search(eth_hdr->dest);
    if (NULL == eth_entry || NULL == eth_entry->session) {
        LOG(SESSION, RUNNING, "Match UE MAC failed, eth_entry(%p), session(%p).",
            eth_entry, eth_entry ? eth_entry->session : NULL);
        return NULL;
    }
    sess_tbl = eth_entry->session;

    ros_rwlock_read_lock(&sess_tbl->lock);/* lock */
    dl_list_for_each_safe(pos, next, &sess_tbl->eth_dl_head) {
        cur_pdr = (struct pdr_table *)container_of(
            pos, struct pdr_table, eth_dl_node);
        if (0 == filter_process(key, key->field_offset,
            &cur_pdr->pdr.pdi_content, &url_depth)) {
            ret_pdr = cur_pdr;
            break;
        }
    }
    ros_rwlock_read_unlock(&sess_tbl->lock);/* unlock */

    LOG(SESSION, DEBUG,
        "Finally, Match pdr (%p), pdr_id: %u(0 is invalid).", ret_pdr, ret_pdr ? ret_pdr->pdr.pdr_id : 0);

    return ret_pdr;
}

struct pdr_table *pdr_map_lookup(struct filter_key *key)
{
    struct pdr_table_head *pdr_head = pdr_get_head();
    struct rb_node *queue_node = NULL;

    if (unlikely(NULL == key)) {
        LOG(SESSION, ERR, "Abnormal prarameter, key(%p).", key);
        return NULL;
    }
    LOG(SESSION, DEBUG, "PDR matching");

    if (!FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_GTP_T_PDU)) {
        /* 下行报文 */
        struct pdr_key rb_key = {.teid = 0};
        struct pdr_ue_ipaddress *ueip_queue = NULL;

        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV4)) {
            struct pro_ipv4_hdr *ip_hdr = FlowGetL1Ipv4Header(key);
            if (unlikely(!ip_hdr)) {
                LOG(SESSION, ERR, "ip_hdr is NULL.");
                return NULL;
            }
            LOG(SESSION, RUNNING, "Matching UEIP v4.");

            ros_rwlock_read_lock(&pdr_head->ueip_v4_lock);/* lock */
            /* 先用目的ip去查询ueip */
            rb_key.ip_addr.ipv4 = htonl(ip_hdr->dest);
            queue_node = rbtree_search(&pdr_head->ueip_dv4_root,
                &rb_key, pdr_ueip_v4_compare);
            if (NULL == queue_node) {
                rb_key.ip_addr.ipv4 = htonl(ip_hdr->source);
                queue_node = rbtree_search(&pdr_head->ueip_sv4_root,
                    &rb_key, pdr_ueip_v4_compare);
            }
            ros_rwlock_read_unlock(&pdr_head->ueip_v4_lock);/* unlock */
            if (NULL == queue_node) {
                return pdr_match_frv4(htonl(ip_hdr->dest), key);
            } else {
                ueip_queue = (struct pdr_ue_ipaddress *)container_of(queue_node,
                    struct pdr_ue_ipaddress, v4_node);
            }
        }
        else if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV6)) {
            struct pro_ipv6_hdr *ip_hdr = FlowGetL1Ipv6Header(key);
            if (unlikely(!ip_hdr)) {
                LOG(SESSION, ERR, "ip_hdr is NULL.");
                return NULL;
            }
            LOG(SESSION, RUNNING, "Matching UEIP v6.");

            ros_rwlock_read_lock(&pdr_head->ueip_v6_lock);/* lock */
            ros_memcpy(&rb_key.ip_addr.ipv6, ip_hdr->daddr, IPV6_ALEN);
            queue_node = rbtree_search(&pdr_head->ueip_dv6_root,
                &rb_key, pdr_ueip_v6_compare);
            if (NULL == queue_node) {
                ros_memcpy(&rb_key.ip_addr.ipv6, ip_hdr->saddr, IPV6_ALEN);
                queue_node = rbtree_search(&pdr_head->ueip_sv6_root,
                    &rb_key, pdr_ueip_v6_compare);
            }
            ros_rwlock_read_unlock(&pdr_head->ueip_v6_lock);/* unlock */
            if (NULL == queue_node) {
                return pdr_match_frv6(ip_hdr->daddr, key);
            } else {
                ueip_queue = (struct pdr_ue_ipaddress *)container_of(queue_node,
                    struct pdr_ue_ipaddress, v6_node);
            }
        }
        else if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_ETHERNET_DL)) {

            return pdr_match_dl_ethernet(key);
        }
        else {
            LOG(SESSION, DEBUG, "Unknown packet type.\n");
            return NULL;
        }

        if (unlikely(NULL == ueip_queue)) {
            LOG(SESSION, ERR, "Match PDR failed.");
            return NULL;
        }

        /* Match ueip */
        return pdr_match_ueip(ueip_queue, key);
    } else {
        struct pdr_key rb_key = {.teid = 0};
        struct pro_gtp_hdr *gtp_hdr;
        struct pdr_local_fteid *fteid_queue = NULL;

        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV4)) {
            struct pro_ipv4_hdr *ip_hdr = FlowGetL1Ipv4Header(key);
            if (unlikely(!ip_hdr)) {
                LOG(SESSION, ERR, "ip_hdr is NULL.");
                return NULL;
            }

            LOG(SESSION, RUNNING, "Matching F-TEID v4.");
            gtp_hdr = FlowGetGtpuHeader(key);
            if (unlikely(!gtp_hdr)) {
                LOG(SESSION, ERR, "gtpu packet, but gtp_hdr is NULL.");
                return NULL;
            }

            rb_key.ip_addr.ipv4 = htonl(ip_hdr->dest);
            rb_key.teid         = htonl(gtp_hdr->teid);

            ros_rwlock_read_lock(&pdr_head->teid_v4_lock);/* lock */
            queue_node = rbtree_search(&pdr_head->fteid_v4_root,
                &rb_key, pdr_fteid_v4_compare);
            ros_rwlock_read_unlock(&pdr_head->teid_v4_lock);/* unlock */
            if (NULL == queue_node) {
                LOG(SESSION, ERR,
                    "search pdr failed, teid 0x%x, ipv4: 0x%08x.",
                    rb_key.teid, rb_key.ip_addr.ipv4);
                return NULL;
            }
            fteid_queue = (struct pdr_local_fteid *)container_of(queue_node,
                struct pdr_local_fteid, v4_node);
        }
        else if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L1_IPV6)) {
            struct pro_ipv6_hdr *ip_hdr = FlowGetL1Ipv6Header(key);
            if (unlikely(!ip_hdr)) {
                LOG(SESSION, ERR, "ip_hdr is NULL.");
                return NULL;
            }

            LOG(SESSION, RUNNING, "Matching F-TEID v6.");
            gtp_hdr = FlowGetGtpuHeader(key);
            if (unlikely(!gtp_hdr)) {
                LOG(SESSION, ERR, "gtpu packet, but gtp_hdr is NULL.");
                return NULL;
            }

            ros_memcpy(&rb_key.ip_addr.ipv6, ip_hdr->daddr, IPV6_ALEN);
            rb_key.teid      = htonl(gtp_hdr->teid);

            ros_rwlock_read_lock(&pdr_head->teid_v6_lock);/* lock */
            queue_node = rbtree_search(&pdr_head->fteid_v6_root,
                &rb_key, pdr_fteid_v6_compare);
            ros_rwlock_read_unlock(&pdr_head->teid_v6_lock);/* unlock */
            if (NULL == queue_node) {
                LOG(SESSION, ERR,
                    "search pdr failed, teid 0x%x, ipv6 0x%08x %08x %08x %08x.",
                    rb_key.teid,
                    htonl(*(uint32_t *)(rb_key.ip_addr.ipv6.value)),
                    htonl(*(uint32_t *)(rb_key.ip_addr.ipv6.value + 4)),
                    htonl(*(uint32_t *)(rb_key.ip_addr.ipv6.value + 8)),
                    htonl(*(uint32_t *)(rb_key.ip_addr.ipv6.value + 12)));
                return NULL;
            }
            fteid_queue = (struct pdr_local_fteid *)container_of(queue_node,
                struct pdr_local_fteid, v6_node);
        } else {
            LOG(SESSION, DEBUG, "Unknown packet type.\n");
            return NULL;
        }

        /* fill filter */
        return pdr_match_fteid(fteid_queue, key);
    }

    return NULL;
}

int pdr_fraud_identify(struct filter_key *key, struct pdr_table *pdr_tbl)
{
    struct far_table *far_tbl;
    struct pro_tcp_hdr *tcp_hdr;
    struct phr_request_info req_info;
    size_t payload_len;
    char *payload;
    uint32_t ip_tlen;
    //void *dst_ip;
    //uint8_t ip_ver;

    if (pdr_tbl->pdr.pdi_content.si == EN_COMM_SRC_IF_ACCESS) {
        /* 只检查上行报文 */
        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L2_IPV4)) {
            struct pro_ipv4_hdr *ip_hdr = FlowGetL2Ipv4Header(key);
            if (unlikely(NULL == ip_hdr)) {
                LOG(SESSION, ERR, "get inner ipv4 header fail.");
                return -1;
            }
            ip_tlen = ntohs(ip_hdr->tot_len);
            //dst_ip = (void *)&ip_hdr->dest;
            //ip_ver = EN_DNS_IPV4;
        } else if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_L2_IPV6)) {
            struct pro_ipv6_hdr *ip6_hdr = FlowGetL2Ipv6Header(key);
            if (unlikely(NULL == ip6_hdr)) {
                LOG(SESSION, ERR, "get inner ipv4 header fail.");
                return -1;
            }
            ip_tlen = ntohs(ip6_hdr->payload_len);
            //dst_ip = (void *)ip6_hdr->daddr;
            //ip_ver = EN_DNS_IPV6;
        } else {
            LOG(SESSION, DEBUG, "Unsupport packet.");
            return 0;
        }
        tcp_hdr = FlowGetL2TcpHeader(key);
        if (NULL == tcp_hdr) {
            /* 不是TCP报文不做检查 */
            return 0;
        }

        if (tcp_hdr->psh) {
            uint32_t cnt;
            payload_len = ip_tlen - (tcp_hdr->doff << 2);
            payload = ((char *)tcp_hdr) + (tcp_hdr->doff << 2);

            if (0 > phr_parse_request(payload, payload_len, &req_info, 0)) {
                LOG(SESSION, DEBUG, "Maybe not HTTP packet.");
                return 0;
            }

            /* 检查http的host是否和DNS的映射IP匹配 */
            /*for (cnt = 0; cnt < req_info.num_headers; ++cnt) {
                if (0 == strncmp(req_info.headers[cnt].name, "host", 4)) {
                    char dn[COMM_MSG_DNS_NAME_LENG];

                    if (req_info.headers[cnt].value_len >= COMM_MSG_DNS_NAME_LENG) {
                        LOG(SESSION, MUST, "The COMM_MSG_DNS_NAME_LENG: %u too short, current need %lu.",
                            COMM_MSG_DNS_NAME_LENG, req_info.headers[cnt].value_len);
                        return -1;
                    }
                    ros_memcpy(dn, req_info.headers[cnt].value, req_info.headers[cnt].value_len);
                    dn[req_info.headers[cnt].value_len] = '\0';
                    if (0 > sdc_check_dns(dn, (void *)dst_ip, ip_ver)) {
                        return -1;
                    } else {
                        return 0;
                    }
                }
            }*/

            /* 检查头增强防欺诈 */
            far_tbl = far_get_table(pdr_tbl->pdr_pri.far_index);
            if (far_tbl->far_cfg.choose.d.flag_header_enrich) {
                comm_msg_header_enrichment_t *far_he = &far_tbl->far_cfg.forw_enrich;

                /* 携带头部增强才去识别欺诈的HTTP头部 */
                for (cnt = 0; cnt < req_info.num_headers; ++cnt) {
                    if (0 == strncmp(far_he->name, req_info.headers[cnt].name,
                        far_he->name_length > req_info.headers[cnt].name_len ? far_he->name_length : req_info.headers[cnt].name_len)) {
                        if (0 != strncmp(far_he->value, req_info.headers[cnt].value,
                            far_he->value_length > req_info.headers[cnt].value_len ? far_he->value_length : req_info.headers[cnt].value_len)) {
                            return -1;
                        }
                    }
                }
            }
        }

        return 0;
    }

    return 0;
}

uint8_t pdr_table_delete_local(uint32_t *arr, uint8_t num)
{
  struct pdr_table    *pdr_tbl = NULL;
    uint32_t index_cnt = 0;

  if (NULL == arr) {
        LOG(SESSION, ERR, "pdr remove failed, arr(%p)",arr);
        return -1;
    }

  for (index_cnt = 0; index_cnt < num; ++index_cnt)
  {
    if(NULL == (pdr_tbl = pdr_get_table(arr[index_cnt])))
    {
          LOG(SESSION, ERR, "pdr_get_table[%d] failed",arr[index_cnt]);
          return -1;
      }

    /* stop timer */
      ros_timer_stop(pdr_tbl->timer_id);
      ros_timer_stop(pdr_tbl->nocp_report_timer);

      /* if sdf filter, delete filter list,
         otherwise, need delete each sdf filter in ethernet filter */
      if (FILTER_SDF == pdr_tbl->pdr.pdi_content.filter_type) {
          sdf_filter_clear(&pdr_tbl->pdr.pdi_content.filter_list);
      } else if (FILTER_ETH == pdr_tbl->pdr.pdi_content.filter_type) {
          eth_filter_clear(&pdr_tbl->pdr.pdi_content.filter_list);
      }

      /* resource free */
      Res_Free(pdr_get_pool_id(), 0, pdr_tbl->index);
      pdr_use_num_sub(1);
  }

  return 0;
}

void pdr_set_deactive_timer_cb(void *timer, uint64_t para)
{
    struct pdr_table *pdr_tbl = NULL;
    struct session_t *sess = NULL;

    if (0 == para) {
        LOG(SESSION, ERR, "abnormal parameter, arg(0x%016lx).\n", para);
        return;
    }

    pdr_tbl = (struct pdr_table *)para;
    sess = pdr_tbl->session_link;
    if (unlikely(NULL == sess)) {
        LOG(SESSION, ERR,
            "set active failed, pdr linked session is NULL, pdr id: %d.\n",
            pdr_tbl->pdr.pdr_id);
        return;
    }
    LOG(SESSION, RUNNING, "ready set pdr deactive.");

    ros_rwlock_write_lock(&pdr_tbl->lock);/* lock */
    if (0 == pdr_tbl->is_active) {
        ros_rwlock_write_unlock(&pdr_tbl->lock);/* unlock */
        /* This situation is usually normal */
        LOG(SESSION, RUNNING,
            "pdr set deactive failed, active flag: %d.\n", pdr_tbl->is_active);
        return;
    }
    ros_timer_stop(pdr_tbl->timer_id);
    ros_timer_stop(pdr_tbl->nocp_report_timer);
    pdr_tbl->is_active = 0;
    ros_rwlock_write_unlock(&pdr_tbl->lock);/* unlock */

    if (0 > pdr_map_remove(pdr_tbl)) {
        LOG(SESSION, ERR, "delete pdr map failed.");
        /* don't be return, Continue to execute */
    }

    if (-1 == session_instance_del(pdr_tbl->index, 1)) {
        LOG(SESSION, ERR, "delete instance: %u failed.", pdr_tbl->index);
        /* don't be return, Continue to execute */
    }

    LOG(SESSION, RUNNING, "done.\n");
}

static void pdr_set_active_timer_cb(void *timer, uint64_t para)
{
    struct pdr_table *pdr_tbl = NULL;
    struct session_t *sess = NULL;
    comm_msg_inst_config inst_cfg = {0};
    struct session_inst_control inst_ctrl = {0};
    uint8_t is_update = 0, fp_sync = timer ? TRUE : FALSE;

    if (0 == para) {
        LOG(SESSION, ERR, "abnormal parameter, para(0x%016lx).\n", para);
        return;
    }

    pdr_tbl = (struct pdr_table *)para;
    sess = pdr_tbl->session_link;
    if (unlikely(NULL == sess)) {
        LOG(SESSION, ERR,
            "set active failed, pdr linked session is NULL, pdr id: %d.\n",
            pdr_tbl->pdr.pdr_id);
        return;
    }
    LOG(SESSION, RUNNING, "ready set pdr active.");

    /* fill instance */
    switch (sess->session.pdn_type) {
        case PDN_TYPE_ETHERNET:
            inst_cfg.choose.d.flag_bearer_net = 1;
            break;

        case PDN_TYPE_NON_IP:
            inst_cfg.choose.d.flag_bearer_net = 2;
            break;

        default:
            inst_cfg.choose.d.flag_bearer_net = 0;
            break;
    }

    if (pdr_tbl->pdr.outer_header_removal.ohr_flag) {
        inst_cfg.rm_outh.type = pdr_tbl->pdr.outer_header_removal.type;
        inst_cfg.rm_outh.flag = pdr_tbl->pdr.outer_header_removal.flag;
        inst_cfg.choose.d.flag_rm_header = 1;
    }
    if (pdr_tbl->pdr.pdi_content.ue_ipaddr_num) {
        if (pdr_tbl->pdr.pdi_content.ue_ipaddr[0].ueip.ueip_flag.d.v4) {
            inst_cfg.ueip.ipv4 = pdr_tbl->pdr.pdi_content.ue_ipaddr[0].ueip.ipv4_addr;
            inst_cfg.choose.d.flag_ueip_type = 0;
        } else if (pdr_tbl->pdr.pdi_content.ue_ipaddr[0].ueip.ueip_flag.d.v6) {
            memcpy(inst_cfg.ueip.ipv6, pdr_tbl->pdr.pdi_content.ue_ipaddr[0].ueip.ipv6_addr, IPV6_ALEN);
            inst_cfg.choose.d.flag_ueip_type = 1;
        }
    }

    if (-1 == session_instance_fill_far(sess, pdr_tbl, &inst_cfg)) {
        LOG(SESSION, ERR, "instance table fill far failed.");
    }

    if (-1 == session_instance_fill_urr(sess,
        pdr_tbl->pdr.urr_list_number, pdr_tbl->pdr.urr_id_array,
        &inst_cfg, &inst_ctrl)) {
        LOG(SESSION, ERR, "instance table fill urr failed.");
    }

    if (-1 == session_instance_fill_qer(sess,
        pdr_tbl->pdr.qer_list_number,
        pdr_tbl->pdr.qer_id_array, &inst_cfg)) {
        LOG(SESSION, ERR, "instance table fill qer failed.");
    }

    if (-1 == session_instance_fill_user_info(sess, pdr_tbl, &inst_cfg)) {
        LOG(SESSION, ERR, "instance table fill user info failed.");
    }

    ros_rwlock_write_lock(&pdr_tbl->lock);/* lock */
    if (pdr_tbl->is_active) {
        LOG(SESSION, RUNNING, "update pdr.");

        ros_rwlock_write_unlock(&pdr_tbl->lock);/* unlock */
        /* This situation happened at modify pdr */
        is_update = 1;

        if (-1 == session_instance_modify(pdr_tbl->index, &inst_cfg, fp_sync, &inst_ctrl)) {
            LOG(SESSION, ERR, "modify instance failed.");
            /* don't be return, Continue to execute */
        }

    } else {
        LOG(SESSION, RUNNING, "insert pdr.");

        pdr_tbl->is_active = 1;
        ros_rwlock_write_unlock(&pdr_tbl->lock);/* unlock */

        if (-1 == session_instance_add(pdr_tbl->index, &inst_cfg, fp_sync, &inst_ctrl)) {
            LOG(SESSION, ERR, "add instance failed.");
            /* don't be return, Continue to execute */
        }
    }

    if (fp_sync) {
        if (-1 == session_orphan_modify(&pdr_tbl->index, 1)) {
            LOG(SESSION, ERR, "remove fast entry for orphan tree failed.");
            /* don't be return, Continue to execute */
        }
    }

    if (0 == is_update) {
        LOG(SESSION, RUNNING, "ready insert pdr map.");
        if (0 > pdr_map_insert(pdr_tbl)) {
            LOG(SESSION, ERR, "insert pdr map failed.\n");
            return;
        }
    }

    if (pdr_tbl->pdr.activation_time < pdr_tbl->pdr.deactivation_time) {
        uint32_t cur_time = ros_getime();
        uint32_t time_diff = pdr_tbl->pdr.deactivation_time - cur_time;

        if (pdr_tbl->pdr.deactivation_time > cur_time) {
            /* set deactive timer */
            ros_timer_reset(pdr_tbl->timer_id, time_diff * _1_SECONDS_TIME,
                ROS_TIMER_MODE_ONCE, (uint64_t)pdr_tbl, pdr_set_deactive_timer_cb);
        } else {
            /* set deactive */
            pdr_set_deactive_timer_cb(NULL, (uint64_t)pdr_tbl);
        }
    }
    LOG(SESSION, RUNNING, "done.\n");
}

int pdr_set_active(struct pdr_table *pdr_tbl)
{
    uint32_t cur_time = 0;
    uint32_t timer_time = 0;
    int ret = 0;

    if (pdr_tbl->pdr.activation_time == pdr_tbl->pdr.deactivation_time) {
        /* activation_time == deactivation_time */
        if (0 == pdr_tbl->pdr.activation_time) {
            LOG(SESSION, RUNNING,
                "active and deactive not set. set pdr active");
            pdr_set_active_timer_cb(NULL, (uint64_t)pdr_tbl);
        }
    } else if (pdr_tbl->pdr.activation_time < pdr_tbl->pdr.deactivation_time) {
        cur_time = ros_getime();

        if (cur_time < pdr_tbl->pdr.activation_time) {
            /* Deactivate an activated PDR */
            ros_rwlock_read_lock(&pdr_tbl->lock);/* lock */
            if (1 == pdr_tbl->is_active) {
                ros_rwlock_read_unlock(&pdr_tbl->lock);/* unlock */
                pdr_set_deactive_timer_cb(NULL, (uint64_t)pdr_tbl);
            } else {
                ros_rwlock_read_unlock(&pdr_tbl->lock);/* unlock */
            }

            /* set active timer and deactive timer */
            timer_time = pdr_tbl->pdr.activation_time - cur_time;

            ros_timer_reset(pdr_tbl->timer_id, timer_time * _1_SECONDS_TIME, ROS_TIMER_MODE_ONCE,
                (uint64_t)pdr_tbl, pdr_set_active_timer_cb);

            LOG(SESSION, RUNNING,
                "set active timer(%u s) and deactive timer.", timer_time);

        } else if (cur_time < pdr_tbl->pdr.deactivation_time) {
            /* set active, set deactive timer */
            pdr_set_active_timer_cb(NULL, (uint64_t)pdr_tbl);
            LOG(SESSION, RUNNING, "set active and set deactive timer.");
        } else {
            ros_rwlock_read_lock(&pdr_tbl->lock);/* lock */
            if (1 == pdr_tbl->is_active) {
                ros_rwlock_read_unlock(&pdr_tbl->lock);/* unlock */
                pdr_set_deactive_timer_cb(NULL, (uint64_t)pdr_tbl);
                LOG(SESSION, RUNNING, "set deactive.");
            } else {
                ros_rwlock_read_unlock(&pdr_tbl->lock);/* unlock */
            }
        }
    } else {
        if (cur_time < pdr_tbl->pdr.activation_time) {
            /* Deactivate an activated PDR */
            ros_rwlock_read_lock(&pdr_tbl->lock);/* lock */
            if (1 == pdr_tbl->is_active) {
                ros_rwlock_read_unlock(&pdr_tbl->lock);/* unlock */
                pdr_set_deactive_timer_cb(NULL, (uint64_t)pdr_tbl);
            } else {
                ros_rwlock_read_unlock(&pdr_tbl->lock);/* unlock */
            }

            /* set active timer */
            cur_time = ros_getime();
            timer_time = pdr_tbl->pdr.activation_time - cur_time;

            ros_timer_reset(pdr_tbl->timer_id, timer_time * _1_SECONDS_TIME, ROS_TIMER_MODE_ONCE,
                (uint64_t)pdr_tbl, pdr_set_active_timer_cb);

            LOG(SESSION, RUNNING, "set active timer(%u s).", timer_time);
        } else {
            /* set active */
            pdr_set_active_timer_cb(NULL, (uint64_t)pdr_tbl);
            LOG(SESSION, RUNNING, "set active.");
        }
    }

    return ret;
}


int pdr_insert(struct session_t *sess, void *parse_pdr_arr,
    uint32_t pdr_num, uint32_t *fail_id)
{
    struct pdr_table    *pdr_tbl = NULL;
    uint32_t            index_cnt = 0;

    if (NULL == sess || (NULL == parse_pdr_arr && pdr_num)) {
        LOG(SESSION, ERR, "insert failed, sess(%p), parse_pdr_arr(%p),"
            " pdr_num: %u.", sess, parse_pdr_arr, pdr_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < pdr_num; ++index_cnt) {

        pdr_tbl = pdr_add(sess, parse_pdr_arr, index_cnt, fail_id);
        if (NULL == pdr_tbl) {
            LOG(SESSION, ERR, "pdr add failed.");
            return -1;
        }

        if (-1 == pdr_set_active(pdr_tbl)) {
            LOG(SESSION, ERR, "pdr set active failed, pdr id: %d.",
                pdr_tbl->pdr.pdr_id);
        }
    }

    return 0;
}

int pdr_remove(struct session_t *sess, uint16_t *id_arr, uint8_t id_num,
    uint32_t *rm_pdr_index_arr, uint32_t *rm_pdr_num)
{
    struct pdr_table    *pdr_tbl = NULL;
    uint32_t index_arr[MAX_URR_NUM], index_cnt = 0;
    uint32_t success_cnt = 0, rm_pdr_cnt = 0;

    if (NULL == sess || (NULL == id_arr && id_num)) {
        LOG(SESSION, ERR, "remove failed, sess(%p), id_arr(%p),"
            " id_num: %d.", sess, id_arr, id_num);
        return -1;
    }
    if (rm_pdr_num)
        rm_pdr_cnt = *rm_pdr_num;

    for (index_cnt = 0; index_cnt < id_num; ++index_cnt) {
        ros_rwlock_write_lock(&sess->lock);/* lock */
        /* search pdr table,if exist, free node, otherwise, failed */
        pdr_tbl = (struct pdr_table *)rbtree_delete(&sess->session.pdr_root,
            &id_arr[index_cnt], pdr_id_compare);
        if (NULL == pdr_tbl) {
            ros_rwlock_write_unlock(&sess->lock);/* unlock */
            LOG(SESSION, ERR, "No such pdr table, pdr_id %u.",
                id_arr[index_cnt]);
            return -1;
        }
        ros_rwlock_write_unlock(&sess->lock);/* unlock */

        /* stop timer */
        ros_timer_stop(pdr_tbl->timer_id);
        ros_timer_stop(pdr_tbl->nocp_report_timer);

        /* if sdf filter, delete filter list,
           otherwise, need delete each sdf filter in ethernet filter */
        /*目前pdr如果带了激活预定义规则，则默认去取本地filter,
           所以不要删除。只有不带，才去删除*/
        if(pdr_tbl->pdr.act_pre_number == 0)
        {
            if (FILTER_SDF == pdr_tbl->pdr.pdi_content.filter_type) {
                sdf_filter_clear(&pdr_tbl->pdr.pdi_content.filter_list);
            } else if (FILTER_ETH == pdr_tbl->pdr.pdi_content.filter_type) {
                eth_filter_clear(&pdr_tbl->pdr.pdi_content.filter_list);
            }
        }

        ros_rwlock_write_lock(&pdr_tbl->lock);/* lock */
        /* is active, need delete map, instance, gtpu entry */

        if (pdr_tbl->is_active) {
            pdr_tbl->is_active = 0;
            ros_rwlock_write_unlock(&pdr_tbl->lock);/* unlock */

            if (0 > pdr_map_remove(pdr_tbl)) {
                LOG(SESSION, ERR, "delete pdr map failed.");
            }

            if (0 > session_instance_del(pdr_tbl->index, 0)) {
                LOG(SESSION, ERR, "delete instance:%u failed.",
                    pdr_tbl->index);
            } else {
                if (rm_pdr_index_arr) {
                    rm_pdr_index_arr[rm_pdr_cnt++] = pdr_tbl->index;
                }
                index_arr[success_cnt] = pdr_tbl->index;
                ++success_cnt;
            }
        } else {
            ros_rwlock_write_unlock(&pdr_tbl->lock);/* unlock */
        }

        /* resource free */
        Res_Free(pdr_get_pool_id(), 0, pdr_tbl->index);
        pdr_use_num_sub(1);
    }

    if (rm_pdr_num) {
        *rm_pdr_num = rm_pdr_cnt;
    }

    if (NULL == rm_pdr_num && success_cnt) {
        if (-1 == rules_fp_del(index_arr, success_cnt, EN_COMM_MSG_UPU_INST_DEL, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "fp del failed.");
        }
    }

    return 0;
}

int pdr_modify(struct session_t *sess, void *parse_pdr_arr,
    uint32_t pdr_num, uint32_t *fail_id)
{
    struct pdr_table    *pdr_tbl = NULL;
    uint32_t            index_cnt = 0;

    if (NULL == sess || (NULL == parse_pdr_arr && pdr_num)) {
        LOG(SESSION, ERR, "modify failed, sess(%p), parse_pdr_arr(%p),"
            " pdr_num: %u.", sess, parse_pdr_arr, pdr_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < pdr_num; ++index_cnt) {
        pdr_tbl = pdr_update(sess, parse_pdr_arr, index_cnt, fail_id);
        if (NULL == pdr_tbl) {
            LOG(SESSION, ERR, "pdr update failed.");
            return -1;
        }
    }

    return 0;
}

/* clear all pdr rules releated the current pfcp session */
int pdr_clear(struct session_t *sess,
    uint8_t fp_sync, struct session_rules_index * rules)
{
    struct pdr_table *pdr_tbl = NULL;
    uint16_t id = 0;
    uint32_t index_arr[MAX_PDR_NUM], index_cnt = 0;

    if (NULL == sess || (0 == fp_sync && NULL == rules)) {
        LOG(SESSION, ERR, "clear failed, cb is null.");
        return -1;
    }

    ros_rwlock_write_lock(&sess->lock);/* lock */
    pdr_tbl = (struct pdr_table *)rbtree_first(&sess->session.pdr_root);
    while (NULL != pdr_tbl) {
        id = pdr_tbl->pdr.pdr_id;
        pdr_tbl = (struct pdr_table *)rbtree_delete(&sess->session.pdr_root,
            &id, pdr_id_compare);
        if (NULL == pdr_tbl) {
            LOG(SESSION, ERR, "clear failed, id: %u.", id);
            pdr_tbl = (struct pdr_table *)rbtree_next(&pdr_tbl->pdr_node);
            continue;
        }

        /* stop timer */
        ros_timer_stop(pdr_tbl->timer_id);
        ros_timer_stop(pdr_tbl->nocp_report_timer);

        /* if sdf filter, delete filter list,
           otherwise, need delete each sdf filter in ethernet filter */
        if (FILTER_SDF == pdr_tbl->pdr.pdi_content.filter_type) {
            sdf_filter_clear(&pdr_tbl->pdr.pdi_content.filter_list);
        } else if (FILTER_ETH == pdr_tbl->pdr.pdi_content.filter_type) {
            eth_filter_clear(&pdr_tbl->pdr.pdi_content.filter_list);
        }

        Res_Free(pdr_get_pool_id(), 0, pdr_tbl->index);

        ros_rwlock_write_lock(&pdr_tbl->lock);/* lock */
        /* is active, need delete map, instance, gtpu entry */

        if (pdr_tbl->is_active) {
            pdr_tbl->is_active = 0;
            ros_rwlock_write_unlock(&pdr_tbl->lock);/* unlock */

            if (0 > session_instance_del(pdr_tbl->index, 0)) {
                LOG(SESSION, ERR, "instance entry del failed, id: %u.",
                    pdr_tbl->index);
            } else {
                if (fp_sync) {
                    index_arr[index_cnt] = pdr_tbl->index;
                    ++index_cnt;
                } else {
                    rules->index_arr[EN_RULE_INST][rules->index_num[
                        EN_RULE_INST]] = pdr_tbl->index;
                    ++rules->index_num[EN_RULE_INST];

                    if (rules->index_num[EN_RULE_INST] >=
                        SESSION_RULE_INDEX_LIMIT) {
                        rules->overflow.d.rule_inst = 1;
                    }
                }
            }

            if (0 > pdr_map_remove(pdr_tbl)) {
                LOG(SESSION, ERR, "delete pdr map failed.");
            }
        } else {
            ros_rwlock_write_unlock(&pdr_tbl->lock);/* unlock */
        }

        pdr_use_num_sub(1);

        pdr_tbl = (struct pdr_table *)rbtree_next(&pdr_tbl->pdr_node);
    }
    ros_rwlock_write_unlock(&sess->lock);// unlock

    if (fp_sync && index_cnt) {
        if (-1 == rules_fp_del(index_arr, index_cnt, EN_COMM_MSG_UPU_INST_DEL, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "fp del failed.");
            return -1;
        }
    }

    return 0;
}

int pdr_sum(void)
{
    struct pdr_table_head    *pdr_head = pdr_get_head();

    return ros_atomic32_read(&pdr_head->use_num);
}

int64_t pdr_table_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct pdr_table *pdr_tbl = NULL;
    uint32_t max_num = 0;
    int64_t size = 0, total_memory = 0;

    if (0 == session_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, session_num: %u.", session_num);
        return -1;
    }

    max_num = session_num * MAX_PDR_NUM;
    size = sizeof(struct pdr_table) * max_num;
    pdr_tbl = ros_malloc(size);
    if (NULL == pdr_tbl) {
        LOG(SESSION, ERR,
            "init pdr failed, no enough memory, max number: %u ="
            " session_num: %u * %d.", max_num,
            session_num, MAX_PDR_NUM);
        return -1;
    }
    ros_memset(pdr_tbl, 0, sizeof(struct pdr_table) * max_num);

    for (index = 0; index < max_num; ++index) {
        pdr_tbl[index].index = index;
        dl_list_init(&pdr_tbl[index].pdr.pdi_content.filter_list);
        /*dl_list_init(&pdr_tbl[index].pdr.act_pre_rule_list);*/
        ros_atomic16_set(&pdr_tbl[index].nocp_flag, 1);
        pdr_tbl[index].timer_id = ros_timer_create(ROS_TIMER_MODE_ONCE,
            _1_SECONDS_TIME, (uint64_t)&pdr_tbl[index], pdr_set_deactive_timer_cb);
        if (NULL == pdr_tbl[index].timer_id) {
            LOG(SESSION, ERR, "Create timer failed.\r\n");
            return -1;
        }
        pdr_tbl[index].nocp_report_timer = ros_timer_create(ROS_TIMER_MODE_ONCE,
            _1_SECONDS_TIME, (uint64_t)&pdr_tbl[index], session_report_nocp);
        if (NULL == pdr_tbl[index].timer_id) {
            LOG(SESSION, ERR, "Create timer failed.\r\n");
            return -1;
        }
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR,"create pool failed.");
        return -1;
    }

    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR,"add section %u failed.", max_num);
        return -1;
    }

    /* Here the first number is set to 1 in order to match the INST table. */
    if (G_FAILURE == Res_AllocTarget(pool_id, 0, COMM_MSG_ORPHAN_NUMBER)) {
        LOG(SESSION, ERR, "add orphan instance entry failed.");
        return -1;
    }

    pdr_tbl_head.pool_id = pool_id;
    pdr_tbl_head.pdr_table = pdr_tbl;
    pdr_tbl_head.max_num = max_num;
    pdr_tbl_head.fteid_v4_root = RB_ROOT_INIT_VALUE;
    pdr_tbl_head.fteid_v6_root = RB_ROOT_INIT_VALUE;
    pdr_tbl_head.ueip_dv4_root = RB_ROOT_INIT_VALUE;
    pdr_tbl_head.ueip_dv6_root = RB_ROOT_INIT_VALUE;
    pdr_tbl_head.ueip_sv4_root = RB_ROOT_INIT_VALUE;
    pdr_tbl_head.ueip_sv6_root = RB_ROOT_INIT_VALUE;
    pdr_tbl_head.fr_v4_root = RB_ROOT_INIT_VALUE;
    pdr_tbl_head.fr_v6_root = RB_ROOT_INIT_VALUE;
    ros_rwlock_init(&pdr_tbl_head.teid_v4_lock);
    ros_rwlock_init(&pdr_tbl_head.teid_v6_lock);
    ros_rwlock_init(&pdr_tbl_head.ueip_v4_lock);
    ros_rwlock_init(&pdr_tbl_head.ueip_v6_lock);
    ros_rwlock_init(&pdr_tbl_head.fr_v4_lock);
    ros_rwlock_init(&pdr_tbl_head.fr_v6_lock);
    ros_atomic32_set(&pdr_tbl_head.use_num, 1);/* 这里设置为1是因为需要空出index 0给orphan用 */
    total_memory += size;

    /* init filter */
    size = filter_table_init(max_num);
    if (size < 0) {
        LOG(SESSION, ERR, "filter init failed.");
        return -1;
    }
    total_memory += size;

    LOG(SESSION, MUST, "session mgmt init success.");

    return total_memory;
}

int pdr_show_activate_table(struct cli_def *cli, int argc, char **argv)
{
  int i,sum=0;
  char *access="access";
  char *core="core";
  struct pdr_table *pdr_tbl = NULL;
  struct pdr_table_head *pdr_head = pdr_get_head();

  for (i = 0; i < pdr_head->max_num; i++) {
    pdr_tbl = &pdr_tbl_head.pdr_table[i];
    if (pdr_tbl->is_active) {
      cli_print(cli, "i:%d index:%d interface:%s pdr_id:%d far_present:%d far[index:%d id:%d] teid[%d] teid_ip[%x] ueip[%x]\r\n",i,pdr_tbl->index,
        (pdr_tbl->pdr.pdi_content.si)?core:access,
        pdr_tbl->pdr.pdr_id,pdr_tbl->pdr.far_present,pdr_tbl->pdr_pri.far_index,pdr_tbl->pdr.far_id,
        pdr_tbl->pdr.pdi_content.local_fteid[0].local_fteid.teid,
        pdr_tbl->pdr.pdi_content.local_fteid[0].local_fteid.ipv4_addr,
        pdr_tbl->pdr.pdi_content.ue_ipaddr[0].ueip.ipv4_addr);

      sum++;
    }
  }
  cli_print(cli, "all pdr:%d\r\nactivate num:%d\r\n", pdr_head->max_num, sum);

  return 0;
}

struct pdr_table *pdr_ueip_match(struct pdr_key *rb_key, uint8_t is_v4)
{
    struct pdr_table_head *pdr_head = pdr_get_head();
    struct rb_node *queue_node = NULL;
    struct pdr_ue_ipaddress *ueip_queue = NULL;
    struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
    struct pdr_ue_ipaddress *cur;

    LOG(SESSION, RUNNING, "match key: %08x",rb_key->ip_addr.ipv4);

    ros_rwlock_read_lock(&pdr_head->ueip_v4_lock);/* lock */
    if (is_v4) {
        queue_node = rbtree_search(&pdr_head->ueip_dv4_root,
            rb_key, pdr_ueip_v4_compare);
    } else {
        queue_node = rbtree_search(&pdr_head->ueip_dv6_root,
            rb_key, pdr_ueip_v6_compare);
    }
    ros_rwlock_read_unlock(&pdr_head->ueip_v4_lock);/* unlock */

    if (queue_node == NULL) {
        LOG(SESSION, ERR, "Can not find queue_node");
        return NULL;
    }
    ueip_queue = (struct pdr_ue_ipaddress *)container_of(queue_node,
        struct pdr_ue_ipaddress, v4_node);

    if(ueip_queue == NULL)
    {
        LOG(SESSION, ERR, "Can not find ueip_queue");
        return NULL;
    }

    session_table_show(&(ueip_queue->pdr_tbl->session_link->session));
    dl_list_for_each_safe(pos, next, &ueip_queue->v4_pq_node)
    {
        cur = (struct pdr_ue_ipaddress *)container_of(
            pos, struct pdr_ue_ipaddress, v4_pq_node);
        session_table_show(&(cur->pdr_tbl->session_link->session));
    }


    return ueip_queue->pdr_tbl;
}




