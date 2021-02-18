/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "upc_prerule.h"


#define SECTION_IP_PAIR_NAME        "ip_pair"
#define SECTION_ESTABLISH_NAME      "establish"
#define SECTION_MODIFICATION_NAME   "modification"
#define SECTION_DELETION_NAME       "deletion"
#define SECTION_CREATE_PDR          "create_pdr"
#define SECTION_CREATE_FAR          "create_far"
#define SECTION_CREATE_URR          "create_urr"
#define SECTION_CREATE_QER          "create_qer"
#define SECTION_CREATE_BAR          "create_bar"
#define SECTION_CREATE_TC_ENDPOINT  "create_tc"
#define SECTION_CREATE_MAR          "create_mar"

#define SECTION_UPDATE_PDR          "update_pdr"
#define SECTION_UPDATE_FAR          "update_far"
#define SECTION_UPDATE_URR          "update_urr"
#define SECTION_UPDATE_QER          "update_qer"
#define SECTION_UPDATE_BAR          "update_bar"
#define SECTION_UPDATE_TC_ENDPOINT  "update_tc"
#define SECTION_UPDATE_MAR          "update_mar"

#define SECTION_REMOVE_PDR          "remove_pdr"
#define SECTION_REMOVE_FAR          "remove_far"
#define SECTION_REMOVE_URR          "remove_urr"
#define SECTION_REMOVE_QER          "remove_qer"
#define SECTION_REMOVE_BAR          "remove_bar"
#define SECTION_REMOVE_TC_ENDPOINT  "remove_tc"
#define SECTION_REMOVE_MAR          "remove_mar"

#define SECTION_QUERY_URR           "query_urr"


#define FRAMED_ROUTE_STR_LEN    (256)

#define IPV4_PKT_UDP_HEADER_POS     (ETH_HLEN + sizeof(struct pro_ipv4_hdr))


/* check parse KV pair parameters */
#define MAX_PARSE_TRAFFIC_ENDPOINT_ID_NUM   (2)
#define MAX_PARSE_SDF_FILTER_NUM            (1)
#define MAX_PARSE_ETH_FILTER_NUM            (1)
#define MAX_PARSE_SDF_OF_ETH_FILTER_NUM     (1)
#define MAX_PARSE_ETH_FILTER_MAC_ADDR_NUM   (1)
#define MAX_PARSE_QFI_NUM                   (4)
#define MAX_PARSE_PDR_FR_NUM                (4)
#define MAX_PARSE_PDR_FR_IPV6_NUM           (4)
#define MAX_PARSE_PDR_URR_ID_NUM            (6)
#define MAX_PARSE_PDR_QER_ID_NUM            (6)
#define MAX_PARSE_LINKED_URR_NUM            (5)
#define MAX_PARSE_ADDED_MINITOR_TIME_NUM    (1)
#define MAX_PARSE_TE_FR_NUM                 (4)
#define MAX_PARSE_TE_FR_IPV6_NUM            (4)
#define MAX_PARSE_AFAI_LINKED_URR_NUM       (5)
#define MAX_PARSE_UEIP_NUM                  (2)


int upc_parse_local_cfg_fteid(session_f_teid *fteid,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* flag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fteid->f_teid_flag.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* teid */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fteid->teid = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ipv4 */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET, cfg_key_pair[index].val,
            &fteid->ipv4_addr)) {
            LOG(STUB, ERR, "parse ipv4 address failed.");
            return -1;
        }
        fteid->ipv4_addr = ntohl(fteid->ipv4_addr);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ipv6 */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET6, cfg_key_pair[index].val,
            fteid->ipv6_addr)) {
            LOG(STUB, ERR, "parse ipv6 address failed.");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* choose id */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fteid->choose_id = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_ueip(session_ue_ip *ueip,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* flag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        ueip->ueip_flag.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ipv4 */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET, cfg_key_pair[index].val,
            &ueip->ipv4_addr)) {
            LOG(STUB, ERR, "parse ipv4 address failed.");
            return -1;
        }
        ueip->ipv4_addr = ntohl(ueip->ipv4_addr);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ipv6 */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET6, cfg_key_pair[index].val,
            ueip->ipv6_addr)) {
            LOG(STUB, ERR, "parse ipv6 address failed.");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ipv6 prefix */
    if (strlen(cfg_key_pair[index].val) > 0) {
        ueip->ipv6_prefix = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }
    ueip->ipv6_prefix_len = ueip->ipv6_prefix;

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_fd(session_flow_desc *desc,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* ip type */
    if (strlen(cfg_key_pair[index].val) > 0) {
        desc->ip_type = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strchr(cfg_key_pair[index].val, ':')) {
        /* sipv6 */
        if (strlen(cfg_key_pair[index].val) > 0) {
            if (1 != inet_pton(AF_INET6, cfg_key_pair[index].val,
                desc->sip.sipv6)) {
                LOG(STUB, ERR, "parse ipv6 address failed.");
                return -1;
            }
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }
        /* sipv6 mask */
        if (strlen(cfg_key_pair[index].val) > 0) {
            desc->smask.sipv6_mask[0] =
                strtol(cfg_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }
        /* dipv6 */
        if (strlen(cfg_key_pair[index].val) > 0) {
            if (1 != inet_pton(AF_INET6, cfg_key_pair[index].val,
                desc->dip.dipv6)) {
                LOG(STUB, ERR, "parse ipv6 address failed.");
                return -1;
            }
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }
        /* dipv6 mask */
        if (strlen(cfg_key_pair[index].val) > 0) {
            desc->dmask.dipv6_mask[0] =
                strtol(cfg_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }
    } else {
        /* sipv4 */
        if (strlen(cfg_key_pair[index].val) > 0) {
            if (1 != inet_pton(AF_INET, cfg_key_pair[index].val,
                &desc->sip.sipv4)) {
                LOG(STUB, ERR, "parse ipv4 address failed.");
                return -1;
            }
            desc->sip.sipv4 = ntohl(desc->sip.sipv4);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }
        /* sipv4 mask */
        if (strlen(cfg_key_pair[index].val) > 0) {
            desc->smask.sipv4_mask = strtol(cfg_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }

        /* dipv4 */
        if (strlen(cfg_key_pair[index].val) > 0) {
            if (1 != inet_pton(AF_INET, cfg_key_pair[index].val,
                &desc->dip.dipv4)) {
                LOG(STUB, ERR, "parse ipv4 address failed.");
                return -1;
            }
            desc->dip.dipv4 = ntohl(desc->dip.dipv4);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }
        /* dipv4 mask */
        if (strlen(cfg_key_pair[index].val) > 0) {
            desc->dmask.dipv4_mask = strtol(cfg_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }
    }

    /* sp min */
    if (strlen(cfg_key_pair[index].val) > 0) {
        desc->sp_min = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            cfg_key_pair[index].key, cfg_key_pair[index].val);
        return -1;
    }

    /* sp max */
    if (strlen(cfg_key_pair[index].val) > 0) {
        desc->sp_max = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            cfg_key_pair[index].key, cfg_key_pair[index].val);
        return -1;
    }

    /* dp min */
    if (strlen(cfg_key_pair[index].val) > 0) {
        desc->dp_min = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* dp max */
    if (strlen(cfg_key_pair[index].val) > 0) {
        desc->dp_max = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* protocol */
    if (strlen(cfg_key_pair[index].val) > 0) {
        desc->protocol = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

int upc_parse_local_cfg_mac(uint8_t *mac, char *str)
{
    int cnt_mac = 0;
    char mac_str[6][PCF_STR_LEN] = {{0,},};
    int ret = -1;

    if (NULL == mac || NULL == str) {
        LOG(STUB, ERR, "Abnormal parameters, mac(%p), str(%p).",
            mac, str);
        return -1;
    }

    ret = pcf_str_split(str, ':', mac_str, ETH_ALEN);
    if (ret < ETH_ALEN) {
        LOG(STUB, ERR, "split string: %s failed, ret: %d.", str, ret);
        return -1;
    }
    for (cnt_mac = 0; cnt_mac < ETH_ALEN; ++cnt_mac) {
        mac[cnt_mac] = strtol(mac_str[cnt_mac], NULL, 16);
    }

    return 0;
}

static int upc_parse_local_cfg_mac_addr(session_mac_addr *mac,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* flag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mac->mac_flag.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Source MAC */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (0 > upc_parse_local_cfg_mac(mac->src, cfg_key_pair[index].val)) {
            LOG(STUB, ERR, "parse mac failed: %s:%s.\n", cfg_key_pair[index].key,
                cfg_key_pair[index].val);
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Destination MAC */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (0 > upc_parse_local_cfg_mac(mac->dst, cfg_key_pair[index].val)) {
            LOG(STUB, ERR, "parse mac failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Upper Source MAC */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (0 > upc_parse_local_cfg_mac(mac->upper_src, cfg_key_pair[index].val)) {
            LOG(STUB, ERR, "parse mac failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Upper Destination MAC */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (0 > upc_parse_local_cfg_mac(mac->upper_dst, cfg_key_pair[index].val)) {
            LOG(STUB, ERR, "parse mac failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_sdf_filter(session_sdf_filter *sdf,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* flag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        sdf->sdf_flag.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Flow Description */
    if (0 > upc_parse_local_cfg_fd(&sdf->desc, cfg_key_pair, &index)) {
        LOG(STUB, ERR, "parse Flow Description failed.");
        return -1;
    }

    /* ToS Traffic Class */
    if (strlen(cfg_key_pair[index].val) > 0) {
        sdf->tos_traffic_class.d.tos = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        sdf->tos_traffic_class.d.tos_mask =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Security Parameter Index */
    if (strlen(cfg_key_pair[index].val) > 0) {
        sdf->sdf_id = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Flow Label */
    if (strlen(cfg_key_pair[index].val) > 0) {
        sdf->label.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* SDF Filter ID */
    if (strlen(cfg_key_pair[index].val) > 0) {
        sdf->sdf_id = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_eth_filter(session_eth_filter *eth,
    struct kv_pair *cfg_key_pair, int *offset)
{
    uint8_t cnt = 0;
    int index = *offset;

    /* Ethernet Filter ID */
    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->member_flag.d.eth_filter_id_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->eth_filter_id = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Ethernet Filter Properties */
    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->member_flag.d.eth_filter_prop_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->eth_filter_prop.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* MAC address */
    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->mac_addr_num = strtol(cfg_key_pair[index].val, NULL, 10);
        if (eth->mac_addr_num > MAX_PARSE_ETH_FILTER_MAC_ADDR_NUM) {
            LOG(STUB, ERR, "Parse eth filter mac addr num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < MAX_PARSE_ETH_FILTER_MAC_ADDR_NUM; ++cnt) {
        if (0 > upc_parse_local_cfg_mac_addr(&eth->mac_addr[cnt],
            cfg_key_pair, &index)) {
            LOG(STUB, ERR, "Parse mac address failed.\n");
            return -1;
        }
    }

    /* Ethertype */
    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->member_flag.d.eth_type_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->eth_type = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* C-TAG */
    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->member_flag.d.c_tag_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->c_tag.value.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* S-TAG */
    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->member_flag.d.s_tag_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->s_tag.value.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* SDF Filter */
    if (strlen(cfg_key_pair[index].val) > 0) {
        eth->sdf_arr_num = strtol(cfg_key_pair[index].val, NULL, 10);
        if (eth->sdf_arr_num > MAX_PARSE_SDF_OF_ETH_FILTER_NUM) {
            LOG(STUB, ERR, "Parse erh filter mac addr num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < MAX_PARSE_SDF_OF_ETH_FILTER_NUM; ++cnt) {
        if (0 > upc_parse_local_cfg_sdf_filter(&eth->sdf_arr[cnt],
            cfg_key_pair, &index)) {
            LOG(STUB, ERR, "Parse sdf filter failed.\n");
            return -1;
        }
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_framed_route(session_framed_route *fr,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* dest ip */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET, cfg_key_pair[index].val,
            &fr->dest_ip)) {
            LOG(STUB, ERR, "parse ipv4 address failed.");
            return -1;
        }
        fr->dest_ip = ntohl(fr->dest_ip);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* dest ip mask */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fr->ip_mask = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* gateway */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET, cfg_key_pair[index].val,
            &fr->gateway)) {
            LOG(STUB, ERR, "parse ipv4 address failed.");
            return -1;
        }
        fr->gateway = ntohl(fr->gateway);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* metrics */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fr->metrics = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_framed_route_v6(session_framed_route_ipv6 *fr,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* dest ip */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET6, cfg_key_pair[index].val,
            fr->dest_ip)) {
            LOG(STUB, ERR, "parse ipv6 address failed.");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* dest ip mask */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fr->ip_mask[0] = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* gateway */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET6, cfg_key_pair[index].val,
            fr->gateway)) {
            LOG(STUB, ERR, "parse ipv6 address failed.");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* metrics */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fr->metrics = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_redir_server(uint8_t addr_type, session_redirect_server *ri_serv,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    switch (addr_type) {
        case 0:
            if (1 != inet_pton(AF_INET, cfg_key_pair[index].val,
                &ri_serv->ipv4_addr)) {
                LOG(STUB, ERR, "parse ipv4 address failed.");
                return -1;
            }
            ri_serv->ipv4_addr = ntohl(ri_serv->ipv4_addr);
            ++index;
            break;

        case 1:
            if (1 != inet_pton(AF_INET6, cfg_key_pair[index].val,
                ri_serv->ipv6_addr)) {
                LOG(STUB, ERR, "parse ipv6 address failed.");
                return -1;
            }
            ++index;
            break;

        case 2:
            if (strlen(cfg_key_pair[index].val) < REDIRECT_SERVER_ADDR_LEN) {
                strcpy(ri_serv->url, cfg_key_pair[index].val);
                ++index;
            } else {
                LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
                    cfg_key_pair[index].val);
                return -1;
            }
            break;

        case 3:
            if (strlen(cfg_key_pair[index].val) < REDIRECT_SERVER_ADDR_LEN) {
                strcpy(ri_serv->sip_url, cfg_key_pair[index].val);
                ++index;
            } else {
                LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
                    cfg_key_pair[index].val);
                return -1;
            }
            break;

        case 4:
            {
                char str[2][128] = {{0}};

                sscanf(cfg_key_pair[index].val, "%[^|]|%s", str[0], str[1]);

                if (1 != inet_pton(AF_INET, str[0],
                    &ri_serv->v4_v6.ipv4)) {
                    LOG(STUB, ERR, "parse ipv4 address failed.");
                    return -1;
                }
                ri_serv->v4_v6.ipv4 = ntohl(ri_serv->v4_v6.ipv4);

                if (1 != inet_pton(AF_INET6, str[1], ri_serv->v4_v6.ipv6)) {
                    LOG(STUB, ERR, "parse ipv6 address failed.");
                    return -1;
                }
                ++index;
            }
            break;

        default:
            LOG(STUB, ERR, "parse failed, unkonw address type.");
            return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_redir_info(session_redirect_info *ri,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* address type */
    if (strlen(cfg_key_pair[index].val) > 0) {
        ri->addr_type = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* address and other address */
    if (0 > upc_parse_local_cfg_redir_server(ri->addr_type, &ri->address, cfg_key_pair, &index)) {
        LOG(STUB, ERR, "parse redirect address failed.\n");
        return -1;
    }

    if (0 > upc_parse_local_cfg_redir_server(ri->addr_type, &ri->other_address, cfg_key_pair, &index)) {
        LOG(STUB, ERR, "parse redirect other address failed.\n");
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_ohc(session_outer_header_create *ohc,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* type */
    if (strlen(cfg_key_pair[index].val) > 0) {
        ohc->type.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* port */
    if (strlen(cfg_key_pair[index].val) > 0) {
        ohc->port = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* teid */
    if (strlen(cfg_key_pair[index].val) > 0) {
        ohc->teid = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ipv4 */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET, cfg_key_pair[index].val,
            &ohc->ipv4)) {
            LOG(STUB, ERR, "parse ipv4 address failed.");
            return -1;
        }
        ohc->ipv4 = ntohl(ohc->ipv4);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* ipv6 */
    if (strlen(cfg_key_pair[index].val) > 0) {
        if (1 != inet_pton(AF_INET6, cfg_key_pair[index].val, ohc->ipv6)) {
            LOG(STUB, ERR, "parse ipv6 address failed.");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* c-tag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        ohc->ctag.value.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* s-tag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        ohc->stag.value.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_fwd_para(session_forward_params *fp,
    struct pcf_file *conf, char *fp_sec_name)
{
    int index = 0;
    /* the key pair and value get must be in order */
    struct kv_pair cfg_key_pair[] = {
        { "far_fp_dif_present", NULL },
        { "far_fp_dif", NULL },
        { "far_fp_ni_present", NULL },
        { "far_fp_ni", NULL },
        { "far_fp_ri_present", NULL },
        { "far_fp_ri_addr_type", NULL },
        { "far_fp_ri_addr", NULL },
        { "far_fp_ri_other_addr", NULL },
        { "far_fp_ohc_present", NULL },
        { "far_fp_ohc_type", NULL },
        { "far_fp_ohc_port", NULL },
        { "far_fp_ohc_teid", NULL },
        { "far_fp_ohc_ipv4", NULL },
        { "far_fp_ohc_ipv6", NULL },
        { "far_fp_ohc_ctag", NULL },
        { "far_fp_ohc_stag", NULL },
        { "far_fp_trans_present", NULL },
        { "far_fp_trans_tos", NULL },
        { "far_fp_trans_tos_mask", NULL },
        { "far_fp_fwd_policy_present", NULL },
        { "far_fp_he_present", NULL },
        { "far_fp_he_name", NULL },
        { "far_fp_he_value", NULL },
        { "far_fp_link_te_presnet", NULL },
        { "far_fp_link_te_id", NULL },
        { "far_fp_proxy_presnet", NULL },
        { "far_fp_proxy", NULL },
        { "far_fp_dif_type_present", NULL },
        { "far_fp_dif_type", NULL },
        { NULL, NULL, }
    };

    while (cfg_key_pair[index].key != NULL) {
        cfg_key_pair[index].val = pcf_get_key_value(conf,
                     fp_sec_name, cfg_key_pair[index].key);
        if (!cfg_key_pair[index].val) {
            LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                cfg_key_pair[index].key, fp_sec_name);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* Destination Interface */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.dest_if_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->dest_if = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Network Instance */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.network_instance_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        if (strlen(cfg_key_pair[index].val) > NETWORK_INSTANCE_LEN) {
            LOG(STUB, ERR, "%s:%s Too long.\n", cfg_key_pair[index].key,
                cfg_key_pair[index].val);
            return -1;
        }
        strcpy(fp->network_instance, cfg_key_pair[index].val);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Redirect Information */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.redirect_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_redir_info(&fp->redirect_addr, cfg_key_pair, &index)) {
        LOG(STUB, ERR, "parse redirect info failed.\n");
        return -1;
    }

    /* Outer Header Creation */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.ohc_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_ohc(&fp->outer_header_creation, cfg_key_pair, &index)) {
        LOG(STUB, ERR, "parse outer header creation failed.\n");
        return -1;
    }

    /* Transport Level Marking */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.trans_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->trans.d.tos = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->trans.d.tos_mask = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Forwarding Policy */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.forwarding_policy_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Header Enrichment */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.header_enrichment_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        uint8_t len = strlen(cfg_key_pair[index].val);

        if (len >= SESSION_MAX_HEADER_FIELD_LEN) {
            LOG(STUB, ERR, "parse header enrichment length failed.\n");
            return -1;
        }
        strncpy(fp->header_enrichment.name, cfg_key_pair[index].val, len);
        fp->header_enrichment.name_length = len;
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        uint8_t len = strlen(cfg_key_pair[index].val);

        if (len >= SESSION_MAX_HEADER_FIELD_LEN) {
            LOG(STUB, ERR, "parse header enrichment length failed.\n");
            return -1;
        }
        strncpy(fp->header_enrichment.value, cfg_key_pair[index].val, len);
        fp->header_enrichment.value_length = len;
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Linked Traffic Endpoint ID */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.traffic_endpoint_id_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->traffic_endpoint_id = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Proxying */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.proxying_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->proxying.value= strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Destination Interface Type */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->member_flag.d.dest_if_type_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        fp->dest_if_type.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    return 0;
}

static int upc_parse_local_cfg_volume(session_urr_volume *vol,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* flag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        vol->flag.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* total */
    if (strlen(cfg_key_pair[index].val) > 0) {
        vol->total = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* uplink */
    if (strlen(cfg_key_pair[index].val) > 0) {
        vol->uplink = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* downlink */
    if (strlen(cfg_key_pair[index].val) > 0) {
        vol->downlink = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_drop_thres(session_urr_drop_thres *dt,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* flag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        dt->flag.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* packets */
    if (strlen(cfg_key_pair[index].val) > 0) {
        dt->packets = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* bytes */
    if (strlen(cfg_key_pair[index].val) > 0) {
        dt->bytes = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_added_moni_time(session_urr_add_mon_time *mt,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* Monitoring Time */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->member_flag.d.mon_time_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->mon_time = strtol(cfg_key_pair[index].val, NULL, 10) + ros_getime();
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Subsequent Volume Threshold */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->member_flag.d.sub_vol_thres_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_volume(&mt->sub_vol_thres, cfg_key_pair, &index)) {
        LOG(STUB, ERR, "parse volume failed.\n");
        return -1;
    }

    /* Subsequent Time Threshold */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->member_flag.d.sub_tim_thres_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->sub_tim_thres = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Subsequent Volume Quota */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->member_flag.d.sub_vol_quota_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_volume(&mt->sub_vol_quota, cfg_key_pair, &index)) {
        LOG(STUB, ERR, "parse volume failed.\n");
        return -1;
    }

    /* Subsequent Time Quota */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->member_flag.d.sub_tim_quota_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->sub_tim_quota = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Subsequent Event Threshold */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->member_flag.d.sub_eve_thres_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->sub_eve_thres = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Subsequent Event Quota */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->member_flag.d.sub_eve_quota_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        mt->sub_eve_quota = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_mbr(session_mbr *mbr,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* ul MBR */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mbr->ul_mbr = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* dl MBR */
    if (strlen(cfg_key_pair[index].val) > 0) {
        mbr->dl_mbr = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_gbr(session_gbr *gbr,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* ul MBR */
    if (strlen(cfg_key_pair[index].val) > 0) {
        gbr->ul_gbr = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* dl MBR */
    if (strlen(cfg_key_pair[index].val) > 0) {
        gbr->dl_gbr = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

int upc_parse_local_cfg_fl_marking(session_dl_fl_marking *fl,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* flag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fl->flag.value = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* tos traffic class */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fl->tos_traffic_class.d.tos = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        fl->tos_traffic_class.d.tos_mask =
            strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* service class indicator */
    if (strlen(cfg_key_pair[index].val) > 0) {
        fl->service_class_indicator =
            strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_packet_rate_status(session_packet_rate_status *prs,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* flag */
    if (strlen(cfg_key_pair[index].val) > 0) {
        prs->flag.value = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Number of Remaining Uplink Packets Allowed */
    if (strlen(cfg_key_pair[index].val) > 0) {
        prs->remain_ul_packets = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Number of Remaining Additional Uplink Packets Allowed */
    if (strlen(cfg_key_pair[index].val) > 0) {
        prs->addit_remain_ul_packets = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Number of Remaining Downlink Packets Allowed */
    if (strlen(cfg_key_pair[index].val) > 0) {
        prs->remain_dl_packets = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Number of Remaining Additional Downlink Packets Allowed */
    if (strlen(cfg_key_pair[index].val) > 0) {
        prs->addit_remain_dl_packets = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Rate Control Status Validity Time */
    if (strlen(cfg_key_pair[index].val) > 0) {
        prs->rate_ctrl_status_time = strtoul(cfg_key_pair[index].val, NULL, 10);
        if (prs->rate_ctrl_status_time > 0) {
            prs->rate_ctrl_status_time =
                (uint64_t)(prs->rate_ctrl_status_time + ros_getime()) << 32;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_afai_body(session_access_forwarding_action *afai,
    struct kv_pair *cfg_key_pair, int *offset)
{
    uint8_t cnt = 0;
    int index = *offset;

    /* Weight */
    if (strlen(cfg_key_pair[index].val) > 0) {
        afai->member_flag.d.weight_present =
            strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        afai->weight = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Priority */
    if (strlen(cfg_key_pair[index].val) > 0) {
        afai->member_flag.d.priority_present =
            strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        afai->priority = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* URR ID */
    if (strlen(cfg_key_pair[index].val) > 0) {
        afai->urr_num = strtoul(cfg_key_pair[index].val, NULL, 10);
        if (afai->urr_num > MAX_PARSE_AFAI_LINKED_URR_NUM) {
            LOG(STUB, ERR, "parse urr number failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < afai->urr_num; ++cnt) {
        if (strlen(cfg_key_pair[index].val) > 0) {
            afai->urr_id_arr[cnt] = strtoul(cfg_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }
    }

    *offset = index;

    return 0;
}

static int upc_parse_local_cfg_afai(session_access_forwarding_action *afai,
    struct kv_pair *cfg_key_pair, int *offset)
{
    int index = *offset;

    /* FAR ID */
    if (strlen(cfg_key_pair[index].val) > 0) {
        afai->member_flag.d.far_id_present =
            strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        afai->far_id = strtoul(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* afai body */
    if (0 > upc_parse_local_cfg_afai_body(afai, cfg_key_pair, &index)) {
        LOG(STUB, ERR, "parse body failed.");
        return -1;
    }

    *offset = index;

    return 0;
}

/* Create and update the structure shared by urr */
static int upc_parse_local_cfg_urr_body(session_usage_report_rule *urr,
    struct pcf_file *conf, char *urr_sec_name)
{
    int index = 0;
    uint8_t cnt_l2 = 0;
    /* the key pair and value get must be in order */
    struct kv_pair urr_key_pair[] = {
        { "urr_period_present", NULL },
        { "urr_period", NULL },
        { "urr_vol_thres_present", NULL },
        { "urr_vol_thres_flag", NULL },
        { "urr_vol_thres_total", NULL },
        { "urr_vol_thres_ul", NULL },
        { "urr_vol_thres_dl", NULL },
        { "urr_vol_quota_present", NULL },
        { "urr_vol_quota_flag", NULL },
        { "urr_vol_quota_total", NULL },
        { "urr_vol_quota_ul", NULL },
        { "urr_vol_quota_dl", NULL },
        { "urr_eve_thres_present", NULL },
        { "urr_eve_thres", NULL },
        { "urr_eve_quota_present", NULL },
        { "urr_eve_quota", NULL },
        { "urr_time_thres_present", NULL },
        { "urr_time_thres", NULL },
        { "urr_time_quota_present", NULL },
        { "urr_time_quota", NULL },
        { "urr_quota_hold_present", NULL },
        { "urr_quota_hold", NULL },
        { "urr_drop_thres_present", NULL },
        { "urr_drop_thres_flag", NULL },
        { "urr_drop_thres_pkts", NULL },
        { "urr_drop_thres_bytes", NULL },
        { "urr_moni_time_present", NULL },
        { "urr_moni_time", NULL },
        { "urr_sub_vol_thres_present", NULL },
        { "urr_sub_vol_thres_flag", NULL },
        { "urr_sub_vol_thres_total", NULL },
        { "urr_sub_vol_thres_ul", NULL },
        { "urr_sub_vol_thres_dl", NULL },
        { "urr_sub_time_thres_present", NULL },
        { "urr_sub_time_thres", NULL },
        { "urr_sub_vol_quota_present", NULL },
        { "urr_sub_vol_quota_flag", NULL },
        { "urr_sub_vol_quota_total", NULL },
        { "urr_sub_vol_quota_ul", NULL },
        { "urr_sub_vol_quota_dl", NULL },
        { "urr_sub_time_quota_present", NULL },
        { "urr_sub_time_quota", NULL },
        { "urr_sub_eve_thres_present", NULL },
        { "urr_sub_eve_thres", NULL },
        { "urr_sub_eve_quota_present", NULL },
        { "urr_sub_eve_quota", NULL },
        { "urr_inact_detec_present", NULL },
        { "urr_inact_detec", NULL },
        { "urr_link_urr_num", NULL },
        { "urr_link_urr_id_1", NULL },
        { "urr_link_urr_id_2", NULL },
        { "urr_link_urr_id_3", NULL },
        { "urr_link_urr_id_4", NULL },
        { "urr_link_urr_id_5", NULL },
        { "urr_measu_info_present", NULL },
        { "urr_measu_info", NULL },
        { "urr_quota_far_present", NULL },
        { "urr_quota_far_id", NULL },
        { "urr_eth_inact_timer_present", NULL },
        { "urr_eth_inact_timer", NULL },
        { "urr_added_moni_time_num", NULL },
        { "urr_added_moni_time_present", NULL },
        { "urr_added_moni_time", NULL },
        { "urr_added_sub_vol_thres_present", NULL },
        { "urr_added_sub_vol_thres_flag", NULL },
        { "urr_added_sub_vol_thres_total", NULL },
        { "urr_added_sub_vol_thres_ul", NULL },
        { "urr_added_sub_vol_thres_dl", NULL },
        { "urr_added_sub_time_thres_present", NULL },
        { "urr_added_sub_time_thres", NULL },
        { "urr_added_sub_vol_quota_present", NULL },
        { "urr_added_sub_vol_quota_flag", NULL },
        { "urr_added_sub_vol_quota_total", NULL },
        { "urr_added_sub_vol_quota_ul", NULL },
        { "urr_added_sub_vol_quota_dl", NULL },
        { "urr_added_sub_time_quota_present", NULL },
        { "urr_added_sub_time_quota", NULL },
        { "urr_added_sub_eve_thres_present", NULL },
        { "urr_added_sub_eve_thres", NULL },
        { "urr_added_sub_eve_quota_present", NULL },
        { "urr_added_sub_eve_quota", NULL },
        { NULL, NULL, }
    };


    while (urr_key_pair[index].key != NULL) {
        urr_key_pair[index].val = pcf_get_key_value(conf,
                     urr_sec_name, urr_key_pair[index].key);
        if (!urr_key_pair[index].val) {
            LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                urr_key_pair[index].key, urr_sec_name);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* Measurement Period */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.period_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->period = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Volume Threshold */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.vol_thres_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_volume(&urr->vol_thres, urr_key_pair, &index)) {
        LOG(STUB, ERR, "parse volume failed.\n");
        return -1;
    }

    /* Volume Quota */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.vol_quota_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_volume(&urr->vol_quota, urr_key_pair, &index)) {
        LOG(STUB, ERR, "parse volume failed.\n");
        return -1;
    }

    /* Event Threshold */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.eve_thres_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->eve_thres = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Event Quota */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.eve_quota_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->eve_quota = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Time Threshold */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.tim_thres_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->tim_thres = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Time Quota */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.tim_quota_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->tim_quota = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Quota Holding Time */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.quota_hold_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->quota_hold = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Dropped DL Traffic Threshold */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.drop_thres_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_drop_thres(&urr->drop_thres, urr_key_pair, &index)) {
        LOG(STUB, ERR, "parse Dropped DL Traffic Threshold failed.\n");
        return -1;
    }

    /* Monitoring Time */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.mon_time_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->mon_time = strtol(urr_key_pair[index].val, NULL, 10) + ros_getime();
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Subsequent Volume Threshold */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.sub_vol_thres_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_volume(&urr->sub_vol_thres, urr_key_pair, &index)) {
        LOG(STUB, ERR, "parse volume failed.\n");
        return -1;
    }

    /* Subsequent Time Threshold */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.sub_tim_thres_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->sub_tim_thres = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Subsequent Volume Quota */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.sub_vol_quota_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_volume(&urr->sub_vol_quota, urr_key_pair, &index)) {
        LOG(STUB, ERR, "parse volume failed.\n");
        return -1;
    }

    /* Subsequent Time Quota */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.sub_tim_quota_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->sub_tim_quota = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Subsequent Event Threshold */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.sub_eve_thres_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->sub_eve_thres = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Subsequent Event Quota */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.sub_eve_quota_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->sub_eve_quota = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Inactivity Detection Time */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.inact_detect_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->inact_detect = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Linked URR ID */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->linked_urr_number = strtol(urr_key_pair[index].val, NULL, 10);
        if (urr->linked_urr_number > MAX_PARSE_LINKED_URR_NUM) {
            LOG(STUB, ERR,
                "parse added monitor time number failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    for (cnt_l2 = 0; cnt_l2 < MAX_PARSE_LINKED_URR_NUM; ++cnt_l2) {
        if (strlen(urr_key_pair[index].val) > 0) {
            urr->linked_urr[cnt_l2] =
                strtol(urr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                urr_key_pair[index].key, urr_key_pair[index].val);
            return -1;
        }
    }

    /* Measurement Information */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.measu_info_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->measu_info.value = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* FAR ID for Quota Action */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.quota_far_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->quota_far = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Ethernet Inactivity Timer */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->member_flag.d.eth_inact_time_present =
            strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    if (strlen(urr_key_pair[index].val) > 0) {
        urr->eth_inact_time = strtol(urr_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    /* Additional Monitoring Time */
    if (strlen(urr_key_pair[index].val) > 0) {
        urr->add_mon_time_number =
            strtol(urr_key_pair[index].val, NULL, 10);
        if (urr->add_mon_time_number > MAX_PARSE_ADDED_MINITOR_TIME_NUM) {
            LOG(STUB, ERR,
                "parse added monitor time number failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            urr_key_pair[index].key, urr_key_pair[index].val);
        return -1;
    }

    for (cnt_l2 = 0; cnt_l2 < MAX_PARSE_ADDED_MINITOR_TIME_NUM; ++cnt_l2) {
        if (0 > upc_parse_local_cfg_added_moni_time(&urr->add_mon_time[cnt_l2],
            urr_key_pair, &index)) {
            LOG(STUB, ERR, "parse added monitor time failed.\n");
            return -1;
        }
    }

    return 0;
}

static int upc_parse_local_cfg_pdi(session_packet_detection_info *pdi,
    struct pcf_file *conf, char *pdi_sec_name)
{
    uint8_t cnt = 0;
    int index = 0;
    struct kv_pair cfg_key_pair[] = {
        { "pdi_si_present", NULL },
        { "pdi_si", NULL },
        { "pdi_fteid_present", NULL },
        { "pdi_fteid_flag", NULL },
        { "pdi_fteid_teid", NULL },
        { "pdi_fteid_ipv4", NULL },
        { "pdi_fteid_ipv6", NULL },
        { "pdi_ch_id", NULL },
        { "network_inst_present", NULL },
        { "network_inst", NULL },
        { "pdi_ueip_num", NULL },
        { "pdi_ueip1_flag", NULL },
        { "pdi_ueip1_ipv4", NULL },
        { "pdi_ueip1_ipv6", NULL },
        { "pdi_ueip1_prefix", NULL },
        { "pdi_ueip2_flag", NULL },
        { "pdi_ueip2_ipv4", NULL },
        { "pdi_ueip2_ipv6", NULL },
        { "pdi_ueip2_prefix", NULL },
        { "pdi_tc_num", NULL },
        { "pdi_tc_id1", NULL },
        { "pdi_tc_id2", NULL },
        { "pdi_sdf_num", NULL },
        { "pdi_sdf_flag", NULL },
        { "pdi_sdf_fd_iptype", NULL },
        { "pdi_sdf_fd_sip", NULL },
        { "pdi_sdf_fd_smask", NULL },
        { "pdi_sdf_fd_dip", NULL },
        { "pdi_sdf_fd_dmask", NULL },
        { "pdi_sdf_fd_spmin", NULL },
        { "pdi_sdf_fd_spmax", NULL },
        { "pdi_sdf_fd_dpmin", NULL },
        { "pdi_sdf_fd_dpmax", NULL },
        { "pdi_sdf_fd_pro", NULL },
        { "pdi_sdf_tc", NULL },
        { "pdi_sdf_tc_mask", NULL },
        { "pdi_sdf_spi", NULL },
        { "pdi_sdf_label", NULL },
        { "pdi_sdf_id", NULL },
        { "pdi_app_id_present", NULL },
        { "pdi_app_id", NULL },
        { "pdi_eth_pdu_ses_present", NULL },
        { "pdi_eth_pdu_ses", NULL },
        { "pdi_eth_filter_num", NULL },
        { "pdi_eth_filter_id_present", NULL },
        { "pdi_eth_filter_id", NULL },
        { "pdi_eth_filter_prop_present", NULL },
        { "pdi_eth_filter_prop", NULL },
        { "pdi_eth_filter_mac_num", NULL },
        { "pdi_eth_filter_mac_flag", NULL },
        { "pdi_eth_filter_mac_src", NULL },
        { "pdi_eth_filter_mac_dst", NULL },
        { "pdi_eth_filter_mac_upper_src", NULL },
        { "pdi_eth_filter_mac_upper_dst", NULL },
        { "pdi_eth_filter_eth_type_present", NULL },
        { "pdi_eth_filter_eth_type", NULL },
        { "pdi_eth_filter_c_tag_present", NULL },
        { "pdi_eth_filter_c_tag", NULL },
        { "pdi_eth_filter_s_tag_present", NULL },
        { "pdi_eth_filter_s_tag", NULL },
        { "pdi_eth_filter_sdf_num", NULL },
        { "pdi_eth_filter_sdf_flag", NULL },
        { "pdi_eth_filter_sdf_fd_iptype", NULL },
        { "pdi_eth_filter_sdf_fd_sip", NULL },
        { "pdi_eth_filter_sdf_fd_smask", NULL },
        { "pdi_eth_filter_sdf_fd_dip", NULL },
        { "pdi_eth_filter_sdf_fd_dmask", NULL },
        { "pdi_eth_filter_sdf_fd_spmin", NULL },
        { "pdi_eth_filter_sdf_fd_spmax", NULL },
        { "pdi_eth_filter_sdf_fd_dpmin", NULL },
        { "pdi_eth_filter_sdf_fd_dpmax", NULL },
        { "pdi_eth_filter_sdf_fd_pro", NULL },
        { "pdi_eth_filter_sdf_tc", NULL },
        { "pdi_eth_filter_sdf_tc_mask", NULL },
        { "pdi_eth_filter_sdf_spi", NULL },
        { "pdi_eth_filter_sdf_label", NULL },
        { "pdi_eth_filter_sdf_id", NULL },
        { "pdi_qfi_num", NULL },
        { "pdi_qfi_1", NULL },
        { "pdi_qfi_2", NULL },
        { "pdi_qfi_3", NULL },
        { "pdi_qfi_4", NULL },
        { "pdi_fr_num", NULL },
        { "pdi_fr_1_dip", NULL },
        { "pdi_fr_1_mask", NULL },
        { "pdi_fr_1_gateway", NULL },
        { "pdi_fr_1_metrics", NULL },
        { "pdi_fr_2_dip", NULL },
        { "pdi_fr_2_mask", NULL },
        { "pdi_fr_2_gateway", NULL },
        { "pdi_fr_2_metrics", NULL },
        { "pdi_fr_3_dip", NULL },
        { "pdi_fr_3_mask", NULL },
        { "pdi_fr_3_gateway", NULL },
        { "pdi_fr_3_metrics", NULL },
        { "pdi_fr_4_dip", NULL },
        { "pdi_fr_4_mask", NULL },
        { "pdi_fr_4_gateway", NULL },
        { "pdi_fr_4_metrics", NULL },
        { "pdi_fr_routing_present", NULL },
        { "pdi_fr_routing", NULL },
        { "pdi_fr_v6_num", NULL },
        { "pdi_fr_v6_1_dip", NULL },
        { "pdi_fr_v6_1_mask", NULL },
        { "pdi_fr_v6_1_gateway", NULL },
        { "pdi_fr_v6_1_metrics", NULL },
        { "pdi_fr_v6_2_dip", NULL },
        { "pdi_fr_v6_2_mask", NULL },
        { "pdi_fr_v6_2_gateway", NULL },
        { "pdi_fr_v6_2_metrics", NULL },
        { "pdi_fr_v6_3_dip", NULL },
        { "pdi_fr_v6_3_mask", NULL },
        { "pdi_fr_v6_3_gateway", NULL },
        { "pdi_fr_v6_3_metrics", NULL },
        { "pdi_fr_v6_4_dip", NULL },
        { "pdi_fr_v6_4_mask", NULL },
        { "pdi_fr_v6_4_gateway", NULL },
        { "pdi_fr_v6_4_metrics", NULL },
        { "pdi_src_if_type_present", NULL },
        { "pdi_src_if_type", NULL },
        { NULL, NULL, }
    };


    while (cfg_key_pair[index].key != NULL) {
        cfg_key_pair[index].val = pcf_get_key_value(conf,
                     pdi_sec_name, cfg_key_pair[index].key);
        if (!cfg_key_pair[index].val) {
            LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                cfg_key_pair[index].key, pdi_sec_name);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* Source Interface */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->member_flag.d.si_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->si = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Local F-TEID */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->member_flag.d.local_fteid_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_fteid(&pdi->local_fteid, cfg_key_pair, &index)) {
        LOG(STUB, ERR, "Parse f-teid failed.\n");
        return -1;
    }

    /* Network Instance */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->member_flag.d.network_instance_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        if (strlen(cfg_key_pair[index].val) > NETWORK_INSTANCE_LEN) {
            LOG(STUB, ERR, "%s:%s too long.\n", cfg_key_pair[index].key,
                cfg_key_pair[index].val);
            return -1;
        }
        strcpy(pdi->network_instance, cfg_key_pair[index].val);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* UE IP address */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->ue_ipaddr_num = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < MAX_PARSE_UEIP_NUM; ++cnt) {
        if (0 > upc_parse_local_cfg_ueip(&pdi->ue_ipaddr[cnt], cfg_key_pair, &index)) {
            LOG(STUB, ERR, "Parse ueip failed.\n");
            return -1;
        }
    }

    /* Traffic Endpoint ID */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->traffic_endpoint_num =
            strtol(cfg_key_pair[index].val, NULL, 10);
        if (pdi->traffic_endpoint_num > MAX_PARSE_TRAFFIC_ENDPOINT_ID_NUM) {
            LOG(STUB, ERR, "Parse traffic endpoint id num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < MAX_PARSE_TRAFFIC_ENDPOINT_ID_NUM; ++cnt) {
        if (strlen(cfg_key_pair[index].val) > 0) {
            pdi->traffic_endpoint_id[cnt] = strtol(cfg_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
                cfg_key_pair[index].val);
            return -1;
        }
    }

    /* SDF Filter */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->sdf_filter_num = strtol(cfg_key_pair[index].val, NULL, 10);
        if (pdi->sdf_filter_num > MAX_PARSE_SDF_FILTER_NUM) {
            LOG(STUB, ERR, "Parse sdf filter num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < MAX_PARSE_SDF_FILTER_NUM; ++cnt) {
        if (0 > upc_parse_local_cfg_sdf_filter(&pdi->sdf_filter[cnt],
            cfg_key_pair, &index)) {
            LOG(STUB, ERR, "Parse sdf filter failed.\n");
            return -1;
        }
    }

    /* Application ID */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->member_flag.d.application_id_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }
    if (strlen(cfg_key_pair[index].val) > 0 && strlen(cfg_key_pair[index].val) < MAX_APP_ID_LEN) {
        strcpy(pdi->application_id, cfg_key_pair[index].val);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Ethernet PDU Session Information */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->member_flag.d.eth_pdu_ses_info_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->eth_pdu_ses_info.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Ethernet Packet Filter */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->eth_filter_num = strtol(cfg_key_pair[index].val, NULL, 10);
        if (pdi->eth_filter_num > MAX_PARSE_ETH_FILTER_NUM) {
            LOG(STUB, ERR, "Parse eth filter num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < MAX_PARSE_ETH_FILTER_NUM; ++cnt) {
        if (0 > upc_parse_local_cfg_eth_filter(&pdi->eth_filter[cnt],
            cfg_key_pair, &index)) {
            LOG(STUB, ERR, "Parse eth filter failed.\n");
            return -1;
        }
    }

    /* QFI */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->qfi_number = strtol(cfg_key_pair[index].val, NULL, 10);
        if (pdi->qfi_number > MAX_PARSE_QFI_NUM) {
            LOG(STUB, ERR, "Parse QFI num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < MAX_PARSE_QFI_NUM; ++cnt) {
        if (strlen(cfg_key_pair[index].val) > 0) {
            pdi->qfi_array[cnt] = strtol(cfg_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                cfg_key_pair[index].key, cfg_key_pair[index].val);
            return -1;
        }
    }

    /* Framed-Route */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->framed_route_num = strtol(cfg_key_pair[index].val, NULL, 10);
        if (pdi->framed_route_num > MAX_PARSE_PDR_FR_NUM) {
            LOG(STUB, ERR, "Parse framed route num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < MAX_PARSE_PDR_FR_NUM; ++cnt) {
        if (0 > upc_parse_local_cfg_framed_route(&pdi->framed_route[cnt],
            cfg_key_pair, &index)) {
            LOG(STUB, ERR, "Parse framed route failed.\n");
            return -1;
        }
    }

    /* Framed-Routing */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->member_flag.d.framed_routing_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->framed_routing = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    /* Framed-IPv6-Route */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->framed_ipv6_route_num = strtol(cfg_key_pair[index].val, NULL, 10);
        if (pdi->framed_ipv6_route_num > MAX_PARSE_PDR_FR_IPV6_NUM) {
            LOG(STUB, ERR, "Parse framed ipv6 route num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    for (cnt = 0; cnt < MAX_PARSE_PDR_FR_IPV6_NUM; ++cnt) {
        if (0 > upc_parse_local_cfg_framed_route_v6(&pdi->framed_ipv6_route[cnt],
            cfg_key_pair, &index)) {
            LOG(STUB, ERR, "Parse framed ipv6 route failed.\n");
            return -1;
        }
    }

    /* Source Interface Type */
    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->member_flag.d.src_if_type_present =
            strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    if (strlen(cfg_key_pair[index].val) > 0) {
        pdi->src_if_type.value = strtol(cfg_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", cfg_key_pair[index].key,
            cfg_key_pair[index].val);
        return -1;
    }

    return 0;
}

static int upc_parse_local_cfg_qer_body(session_qos_enforcement_rule *qer,
    struct pcf_file *conf, char *qer_sec_name)
{
    int index = 0;
    /* the key pair and value get must be in order */
    struct kv_pair qer_key_pair[] = {
        { "qer_mbr_present", NULL },
        { "qer_mbr_ul", NULL },
        { "qer_mbr_dl", NULL },
        { "qer_gbr_present", NULL },
        { "qer_gbr_ul", NULL },
        { "qer_gbr_dl", NULL },
        { "qer_pkt_rate_status_present", NULL },
        { "qer_pkt_rate_status_flag", NULL },
        { "qer_remain_ul_packets", NULL },
        { "qer_addit_remain_ul_packets", NULL },
        { "qer_remain_dl_packets", NULL },
        { "qer_addit_remain_dl_packets", NULL },
        { "qer_rate_ctrl_status_time", NULL },
        { "qer_qfi_present", NULL },
        { "qer_qfi", NULL },
        { "qer_rqi_present", NULL },
        { "qer_rqi", NULL },
        { "qer_ppi_present", NULL },
        { "qer_ppi", NULL },
        { "qer_aw_present", NULL },
        { "qer_aw", NULL },
        { "qer_qer_ctrl_indic", NULL },
        { NULL, NULL, }
    };

    while (qer_key_pair[index].key != NULL) {
        qer_key_pair[index].val = pcf_get_key_value(conf,
                     qer_sec_name, qer_key_pair[index].key);
        if (!qer_key_pair[index].val) {
            LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                qer_key_pair[index].key, qer_sec_name);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* Maximum Bitrate */
    if (strlen(qer_key_pair[index].val) > 0) {
        qer->member_flag.d.mbr_value_present =
            strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_mbr(&qer->mbr_value, qer_key_pair, &index)) {
        LOG(STUB, ERR, "parse MBR failed.\n");
        return -1;
    }

    /* Guaranteed Bitrate */
    if (strlen(qer_key_pair[index].val) > 0) {
        qer->member_flag.d.gbr_value_present =
            strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_gbr(&qer->gbr_value, qer_key_pair, &index)) {
        LOG(STUB, ERR, "parse GBR failed.\n");
        return -1;
    }

    /* Packet Rate Status */
    if (strlen(qer_key_pair[index].val) > 0) {
        qer->member_flag.d.packet_rate_status_present =
            strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    if (0 > upc_parse_local_cfg_packet_rate_status(&qer->pkt_rate_status, qer_key_pair, &index)) {
        LOG(STUB, ERR, "parse Packet Rate Status failed.\n");
        return -1;
    }

    /* QoS flow identifier */
    if (strlen(qer_key_pair[index].val) > 0) {
        qer->member_flag.d.qfi_present =
            strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    if (strlen(qer_key_pair[index].val) > 0) {
        qer->qfi = strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    /* Reflective QoS */
    if (strlen(qer_key_pair[index].val) > 0) {
        qer->member_flag.d.ref_qos_present =
            strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    if (strlen(qer_key_pair[index].val) > 0) {
        qer->ref_qos = strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    /* Paging Policy Indicator */
    if (strlen(qer_key_pair[index].val) > 0) {
        qer->member_flag.d.ppi_present =
            strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    if (strlen(qer_key_pair[index].val) > 0) {
        qer->paging_policy_indic = strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    /* Averaging Window */
    if (strlen(qer_key_pair[index].val) > 0) {
        qer->member_flag.d.averaging_window_present =
            strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    if (strlen(qer_key_pair[index].val) > 0) {
        qer->averaging_window = strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    /* QER Control Indications */
    if (strlen(qer_key_pair[index].val) > 0) {
        qer->qer_ctrl_indic.value = strtol(qer_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n", qer_key_pair[index].key,
            qer_key_pair[index].val);
        return -1;
    }

    return 0;
}

static int upc_parse_local_cfg_cm_tc_endpoint_body(session_tc_endpoint *tc,
    struct pcf_file *conf, char *tc_sec_name)
{
    int index = 0;
    uint8_t cnt_l2 = 0;
    /* the key pair and value get must be in order */
    struct kv_pair tc_key_pair[] = {
        { "pdi_fr_num", NULL },
        { "pdi_fr_1_dip", NULL },
        { "pdi_fr_1_mask", NULL },
        { "pdi_fr_1_gateway", NULL },
        { "pdi_fr_1_metrics", NULL },
        { "pdi_fr_2_dip", NULL },
        { "pdi_fr_2_mask", NULL },
        { "pdi_fr_2_gateway", NULL },
        { "pdi_fr_2_metrics", NULL },
        { "pdi_fr_3_dip", NULL },
        { "pdi_fr_3_mask", NULL },
        { "pdi_fr_3_gateway", NULL },
        { "pdi_fr_3_metrics", NULL },
        { "pdi_fr_4_dip", NULL },
        { "pdi_fr_4_mask", NULL },
        { "pdi_fr_4_gateway", NULL },
        { "pdi_fr_4_metrics", NULL },
        { "pdi_fr_routing_present", NULL },
        { "pdi_fr_routing", NULL },
        { "pdi_fr_v6_num", NULL },
        { "pdi_fr_v6_1_dip", NULL },
        { "pdi_fr_v6_1_mask", NULL },
        { "pdi_fr_v6_1_gateway", NULL },
        { "pdi_fr_v6_1_metrics", NULL },
        { "pdi_fr_v6_2_dip", NULL },
        { "pdi_fr_v6_2_mask", NULL },
        { "pdi_fr_v6_2_gateway", NULL },
        { "pdi_fr_v6_2_metrics", NULL },
        { "pdi_fr_v6_3_dip", NULL },
        { "pdi_fr_v6_3_mask", NULL },
        { "pdi_fr_v6_3_gateway", NULL },
        { "pdi_fr_v6_3_metrics", NULL },
        { "pdi_fr_v6_4_dip", NULL },
        { "pdi_fr_v6_4_mask", NULL },
        { "pdi_fr_v6_4_gateway", NULL },
        { "pdi_fr_v6_4_metrics", NULL },
        { NULL, NULL, }
    };

    while (tc_key_pair[index].key != NULL) {
        tc_key_pair[index].val = pcf_get_key_value(conf,
                     tc_sec_name, tc_key_pair[index].key);
        if (!tc_key_pair[index].val) {
            LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                tc_key_pair[index].key, tc_sec_name);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* Framed-Route */
    if (strlen(tc_key_pair[index].val) > 0) {
        tc->framed_route_num = strtol(tc_key_pair[index].val, NULL, 10);
        if (tc->framed_route_num > MAX_PARSE_TE_FR_NUM) {
            LOG(STUB, ERR, "Parse framed route num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            tc_key_pair[index].key, tc_key_pair[index].val);
        return -1;
    }

    for (cnt_l2 = 0; cnt_l2 < MAX_PARSE_TE_FR_NUM; ++cnt_l2) {
        if (0 > upc_parse_local_cfg_framed_route(&tc->framed_route[cnt_l2],
            tc_key_pair, &index)) {
            LOG(STUB, ERR, "Parse framed route failed.\n");
            return -1;
        }
    }

    /* Framed-Routing */
    if (strlen(tc_key_pair[index].val) > 0) {
        tc->member_flag.d.framed_routing_present =
            strtol(tc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            tc_key_pair[index].key, tc_key_pair[index].val);
        return -1;
    }

    if (strlen(tc_key_pair[index].val) > 0) {
        tc->framed_routing = strtol(tc_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            tc_key_pair[index].key, tc_key_pair[index].val);
        return -1;
    }

    /* Framed-IPv6-Route */
    if (strlen(tc_key_pair[index].val) > 0) {
        tc->framed_ipv6_route_num =
            strtol(tc_key_pair[index].val, NULL, 10);
        if (tc->framed_ipv6_route_num > MAX_PARSE_TE_FR_IPV6_NUM) {
            LOG(STUB, ERR, "Parse framed ipv6 route num failed.\n");
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            tc_key_pair[index].key, tc_key_pair[index].val);
        return -1;
    }

    for (cnt_l2 = 0; cnt_l2 < MAX_PARSE_TE_FR_IPV6_NUM; ++cnt_l2) {
        if (0 > upc_parse_local_cfg_framed_route_v6(&tc->framed_ipv6_route[cnt_l2],
            tc_key_pair, &index)) {
            LOG(STUB, ERR, "Parse framed ipv6 route failed.\n");
            return -1;
        }
    }

    return 0;
}

static int upc_parse_local_cfg_create_pdr(session_pdr_create *pdr_arr, uint8_t pdr_num,
    struct pcf_file *conf)
{
    int index = 0;
    uint8_t cnt = 0, cnt_l2 = 0;
    session_pdr_create *pdr = NULL;
    char create_pdr_name[128] = {0};
    /* the key pair and value get must be in order */
    struct kv_pair pdr_key_pair[] = {
        { "pdr_id_present", NULL },
        { "pdr_id", NULL },
        { "precedence_present", NULL },
        { "precedence", NULL },
        { "pdi_present", NULL },
        { "pdr_ohr_present", NULL },
        { "pdr_ohr_type", NULL },
        { "pdr_ohr_exten", NULL },
        { "pdr_far_id_present", NULL },
        { "pdr_far_id", NULL },
        { "pdr_urr_id_num", NULL },
        { "pdr_urr_id_1", NULL },
        { "pdr_urr_id_2", NULL },
        { "pdr_urr_id_3", NULL },
        { "pdr_urr_id_4", NULL },
        { "pdr_urr_id_5", NULL },
        { "pdr_urr_id_6", NULL },
        { "pdr_qer_id_num", NULL },
        { "pdr_qer_id_1", NULL },
        { "pdr_qer_id_2", NULL },
        { "pdr_qer_id_3", NULL },
        { "pdr_qer_id_4", NULL },
        { "pdr_qer_id_5", NULL },
        { "pdr_qer_id_6", NULL },
        { "pdr_act_pre_num", NULL },
        { "pdr_active_time_present", NULL },
        { "pdr_active_time", NULL },
        { "pdr_deactive_time_present", NULL },
        { "pdr_deactive_time", NULL },
        { "pdr_mar_id_present", NULL },
        { "pdr_mar_id", NULL },
        { "pdr_ueip_pool_id_present", NULL },
        { "pdr_ueip_pool_id", NULL },
        { NULL, NULL, }
    };

    for (cnt = 0; cnt < pdr_num; ++cnt) {
        sprintf(create_pdr_name, "%s_%d", SECTION_CREATE_PDR, cnt + 1);
        pdr = &pdr_arr[cnt];
        index = 0;

        while (pdr_key_pair[index].key != NULL) {
            pdr_key_pair[index].val = pcf_get_key_value(conf,
                         create_pdr_name, pdr_key_pair[index].key);
            if (!pdr_key_pair[index].val) {
                LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                    pdr_key_pair[index].key, create_pdr_name);
                return -1;
            }
            ++index;
        }
        index = 0;


        /* PDR ID */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->member_flag.d.pdr_id_present =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->pdr_id = strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        /* Precedence */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->member_flag.d.precedence_present =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->precedence = strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        /* PDI */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->member_flag.d.pdi_content_present =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        if (0 > upc_parse_local_cfg_pdi(&pdr->pdi_content,
            conf, create_pdr_name)) {
            LOG(STUB, ERR, "Parse PDI failed.\n");
            return -1;
        }

        /* Outer Header Removal */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->member_flag.d.OHR_present =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->outer_header_removal.type =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->outer_header_removal.gtp_u_exten =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        /* FAR ID */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->member_flag.d.far_id_present =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->far_id = strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        /* URR ID */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->urr_id_number = strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        for (cnt_l2 = 0; cnt_l2 < MAX_PARSE_PDR_URR_ID_NUM; ++cnt_l2) {
            if (strlen(pdr_key_pair[index].val) > 0) {
                pdr->urr_id_array[cnt_l2] =
                    strtol(pdr_key_pair[index].val, NULL, 10);
                ++index;
            } else {
                LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
                return -1;
            }
        }

        /* QER ID */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->qer_id_number = strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        for (cnt_l2 = 0; cnt_l2 < MAX_PARSE_PDR_QER_ID_NUM; ++cnt_l2) {
            if (strlen(pdr_key_pair[index].val) > 0) {
                pdr->qer_id_array[cnt_l2] =
                    strtol(pdr_key_pair[index].val, NULL, 10);
                ++index;
            } else {
                LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
                return -1;
            }
        }

        /* Activate Predefined Rules */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->act_pre_number = strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        /* Activation Time */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->member_flag.d.act_time_present =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->activation_time = ros_getime() + strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        /* Deactivation Time */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->member_flag.d.deact_time_present =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->deactivation_time = ros_getime() + strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        /* MAR ID */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->member_flag.d.mar_id_present =
                strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->mar_id = strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                pdr_key_pair[index].key, pdr_key_pair[index].val);
            return -1;
        }

        /* UEIP pool id */
        if (strlen(pdr_key_pair[index].val) > 0) {
            pdr->ueip_addr_pool_identity_num = strtol(pdr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n", pdr_key_pair[index].key,
                pdr_key_pair[index].val);
            return -1;
        }

        if (strlen(pdr_key_pair[index].val) > 0) {
            if (strlen(pdr_key_pair[index].val) > UE_IP_ADDRESS_POOL_LEN) {
                LOG(STUB, ERR, "%s:%s too long.\n", pdr_key_pair[index].key,
                    pdr_key_pair[index].val);
                return -1;
            }
            strcpy(pdr->ueip_addr_pool_identity[0].pool_identity, pdr_key_pair[index].val);
            pdr->ueip_addr_pool_identity[0].pool_id_len =
                strlen(pdr->ueip_addr_pool_identity[0].pool_identity);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n", pdr_key_pair[index].key,
                pdr_key_pair[index].val);
            return -1;
        }
    }

    return 0;
}

static int upc_parse_local_cfg_create_far(session_far_create *far_arr, uint8_t far_num,
    struct pcf_file *conf)
{
    int index = 0;
    uint8_t cnt = 0;
    session_far_create *c_far = NULL;
    char create_far_name[128] = {0};
    /* the key pair and value get must be in order */
    struct kv_pair far_key_pair[] = {
        { "far_id_present", NULL },
        { "far_id", NULL },
        { "far_action_present", NULL },
        { "far_action", NULL },
        { "far_fp_present", NULL },
        { "far_bar_id_present", NULL },
        { "far_bar_id", NULL },
        { NULL, NULL, }
    };

    for (cnt = 0; cnt < far_num; ++cnt) {
        sprintf(create_far_name, "%s_%d", SECTION_CREATE_FAR, cnt + 1);
        c_far = &far_arr[cnt];
        index = 0;

        while (far_key_pair[index].key != NULL) {
            far_key_pair[index].val = pcf_get_key_value(conf,
                         create_far_name, far_key_pair[index].key);
            if (!far_key_pair[index].val) {
                LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                    far_key_pair[index].key, create_far_name);
                return -1;
            }
            ++index;
        }
        index = 0;

        /* FAR ID */
        if (strlen(far_key_pair[index].val) > 0) {
            c_far->member_flag.d.far_id_present =
                strtol(far_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                far_key_pair[index].key, far_key_pair[index].val);
            return -1;
        }

        if (strlen(far_key_pair[index].val) > 0) {
            c_far->far_id = strtol(far_key_pair[index].val, NULL, 10);
            ++index;
            LOG(STUB, RUNNING, "far id: %u, far section: %s.\n",
                c_far->far_id, create_far_name);
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                far_key_pair[index].key, far_key_pair[index].val);
            return -1;
        }

        /* Apply Action */
        if (strlen(far_key_pair[index].val) > 0) {
            c_far->member_flag.d.action_present =
                strtol(far_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                far_key_pair[index].key, far_key_pair[index].val);
            return -1;
        }

        if (strlen(far_key_pair[index].val) > 0) {
            c_far->action.value = strtol(far_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                far_key_pair[index].key, far_key_pair[index].val);
            return -1;
        }

        /* Forwarding Parameters */
        if (strlen(far_key_pair[index].val) > 0) {
            c_far->member_flag.d.forw_param_present =
                strtol(far_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                far_key_pair[index].key, far_key_pair[index].val);
            return -1;
        }

        if (0 > upc_parse_local_cfg_fwd_para(&c_far->forw_param,
            conf, create_far_name)) {
            LOG(STUB, ERR, "parse forwarding parameters failed.\n");
            return -1;
        }

        /* Duplicating Parameters */

        /* BAR ID */
        if (strlen(far_key_pair[index].val) > 0) {
            c_far->member_flag.d.bar_id_present =
                strtol(far_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                far_key_pair[index].key, far_key_pair[index].val);
            return -1;
        }

        if (strlen(far_key_pair[index].val) > 0) {
            c_far->bar_id = strtol(far_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                far_key_pair[index].key, far_key_pair[index].val);
            return -1;
        }
    }

    return 0;
}

static int upc_parse_local_cfg_create_urr(session_usage_report_rule *urr_arr,
    uint8_t urr_num, struct pcf_file *conf)
{
    int index = 0;
    uint8_t cnt = 0;
    session_usage_report_rule *urr = NULL;
    char create_urr_name[128] = {0};
    /* the key pair and value get must be in order */
    struct kv_pair urr_key_pair[] = {
        { "urr_id_present", NULL },
        { "urr_id", NULL },
        { "urr_method_present", NULL },
        { "urr_method", NULL },
        { "urr_triggers_present", NULL },
        { "urr_triggers", NULL },
        { NULL, NULL, }
    };

    for (cnt = 0; cnt < urr_num; ++cnt) {
        sprintf(create_urr_name, "%s_%d", SECTION_CREATE_URR, cnt + 1);
        urr = &urr_arr[cnt];
        index = 0;

        while (urr_key_pair[index].key != NULL) {
            urr_key_pair[index].val = pcf_get_key_value(conf,
                         create_urr_name, urr_key_pair[index].key);
            if (!urr_key_pair[index].val) {
                LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                    urr_key_pair[index].key, create_urr_name);
                return -1;
            }
            ++index;
        }
        index = 0;

        /* URR ID */
        if (strlen(urr_key_pair[index].val) > 0) {
            urr->member_flag.d.urr_id_present =
                strtol(urr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                urr_key_pair[index].key, urr_key_pair[index].val);
            return -1;
        }

        if (strlen(urr_key_pair[index].val) > 0) {
            urr->urr_id = strtol(urr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                urr_key_pair[index].key, urr_key_pair[index].val);
            return -1;
        }

        /* Measurement Method */
        if (strlen(urr_key_pair[index].val) > 0) {
            urr->member_flag.d.method_present =
                strtol(urr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                urr_key_pair[index].key, urr_key_pair[index].val);
            return -1;
        }

        if (strlen(urr_key_pair[index].val) > 0) {
            urr->method.value = strtol(urr_key_pair[index].val, NULL, 10);

            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                urr_key_pair[index].key, urr_key_pair[index].val);
            return -1;
        }

        /* Reporting Triggers */
        if (strlen(urr_key_pair[index].val) > 0) {
            urr->member_flag.d.trigger_present =
                strtol(urr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                urr_key_pair[index].key, urr_key_pair[index].val);
            return -1;
        }

        if (strlen(urr_key_pair[index].val) > 0) {
            urr->trigger.value = strtol(urr_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                urr_key_pair[index].key, urr_key_pair[index].val);
            return -1;
        }

        /* urr body */
        if (0 > upc_parse_local_cfg_urr_body(urr, conf, create_urr_name)) {
            LOG(STUB, ERR, "parse URR body failed.");
            return -1;
        }
        LOG(STUB, ERR, "URR member flag: %u.\n", urr->member_flag.value);
    }

    return 0;
}

static int upc_parse_local_cfg_create_qer(session_qos_enforcement_rule *qer_arr,
    uint8_t qer_num, struct pcf_file *conf)
{
    int index = 0;
    uint8_t cnt = 0;
    session_qos_enforcement_rule *qer = NULL;
    char create_qer_name[128] = {0};
    /* the key pair and value get must be in order */
    struct kv_pair qer_key_pair[] = {
        { "qer_id_present", NULL },
        { "qer_id", NULL },
        { "qer_cor_id_present", NULL },
        { "qer_cor_id", NULL },
        { "qer_gate_status_present", NULL },
        { "qer_gate_status", NULL },
        { NULL, NULL, }
    };

    for (cnt = 0; cnt < qer_num; ++cnt) {
        sprintf(create_qer_name, "%s_%d", SECTION_CREATE_QER, cnt + 1);
        qer = &qer_arr[cnt];
        index = 0;

        while (qer_key_pair[index].key != NULL) {
            qer_key_pair[index].val = pcf_get_key_value(conf,
                         create_qer_name, qer_key_pair[index].key);
            if (!qer_key_pair[index].val) {
                LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                    qer_key_pair[index].key, create_qer_name);
                return -1;
            }
            ++index;
        }
        index = 0;

        /* QER ID */
        if (strlen(qer_key_pair[index].val) > 0) {
            qer->member_flag.d.qer_id_present =
                strtol(qer_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                qer_key_pair[index].key, qer_key_pair[index].val);
            return -1;
        }

        if (strlen(qer_key_pair[index].val) > 0) {
            qer->qer_id = strtol(qer_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                qer_key_pair[index].key, qer_key_pair[index].val);
            return -1;
        }

        /* QER Correlation ID */
        if (strlen(qer_key_pair[index].val) > 0) {
            qer->member_flag.d.qer_corr_id_present =
                strtol(qer_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                qer_key_pair[index].key, qer_key_pair[index].val);
            return -1;
        }

        if (strlen(qer_key_pair[index].val) > 0) {
            qer->qer_corr_id = strtol(qer_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                qer_key_pair[index].key, qer_key_pair[index].val);
            return -1;
        }

        /* Gate Status */
        if (strlen(qer_key_pair[index].val) > 0) {
            qer->member_flag.d.gate_status_present =
                strtol(qer_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                qer_key_pair[index].key, qer_key_pair[index].val);
            return -1;
        }

        if (strlen(qer_key_pair[index].val) > 0) {
            qer->gate_status.value = strtol(qer_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                qer_key_pair[index].key, qer_key_pair[index].val);
            return -1;
        }

        /* qer body */
        if (0 > upc_parse_local_cfg_qer_body(qer, conf, create_qer_name)) {
            LOG(STUB, ERR, "parse qer body failed.");
            return -1;
        }
    }

    return 0;
}

static int upc_parse_local_cfg_create_bar(session_buffer_action_rule *bar,
    struct pcf_file *conf)
{
    int index = 0;
    /* the key pair and value get must be in order */
    struct kv_pair bar_key_pair[] = {
        { "bar_id_present", NULL },
        { "bar_id", NULL },
        { "bar_ddnd_present", NULL },
        { "bar_ddnd", NULL },
        { "bar_sbpc_present", NULL },
        { "bar_sbpc", NULL },
        { NULL, NULL, }
    };

    while (bar_key_pair[index].key != NULL) {
        bar_key_pair[index].val = pcf_get_key_value(conf,
                     SECTION_CREATE_BAR, bar_key_pair[index].key);
        if (!bar_key_pair[index].val) {
            LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                bar_key_pair[index].key, SECTION_CREATE_BAR);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* BAR ID */
    if (strlen(bar_key_pair[index].val) > 0) {
        bar->member_flag.d.bar_id_present =
            strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    if (strlen(bar_key_pair[index].val) > 0) {
        bar->bar_id = strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    /* Downlink Data Notification Delay */
    if (strlen(bar_key_pair[index].val) > 0) {
        bar->member_flag.d.notify_delay_present =
            strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    if (strlen(bar_key_pair[index].val) > 0) {
        bar->notify_delay = strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    /* Suggested Buffering Packets Count */
    if (strlen(bar_key_pair[index].val) > 0) {
        bar->member_flag.d.buffer_pkts_cnt_present =
            strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    if (strlen(bar_key_pair[index].val) > 0) {
        bar->buffer_pkts_cnt = strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    return 0;
}

int upc_parse_local_cfg_report_update_bar(session_bar_response_update *bar,
    struct pcf_file *conf)
{
    int index = 0;
    /* the key pair and value get must be in order */
    struct kv_pair bar_key_pair[] = {
        { "bar_id", NULL },
        { "bar_ddnd_present", NULL },
        { "bar_ddnd", NULL },
        { "bar_sbpc_present", NULL },
        { "bar_sbpc", NULL },
        { "bar_dbd_present", NULL },
        { "bar_dbd", NULL },
        { "bar_dbspc_present", NULL },
        { "bar_dbspc", NULL },
        { NULL, NULL, }
    };

    while (bar_key_pair[index].key != NULL) {
        bar_key_pair[index].val = pcf_get_key_value(conf,
                     SECTION_UPDATE_BAR, bar_key_pair[index].key);
        if (!bar_key_pair[index].val) {
            LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                bar_key_pair[index].key, SECTION_UPDATE_BAR);
            return -1;
        }
        ++index;
    }
    index = 0;

	/* BAR ID */
	if (strlen(bar_key_pair[index].val) > 0) {
		bar->bar_id = strtol(bar_key_pair[index].val, NULL, 10);
		++index;
	} else {
		LOG(STUB, ERR, "Invalid %s:%s config.\n",
			bar_key_pair[index].key, bar_key_pair[index].val);
		return -1;
	}

    /* Downlink Data Notification Delay */
    if (strlen(bar_key_pair[index].val) > 0) {
        bar->member_flag.d.notify_delay_present =
            strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    if (strlen(bar_key_pair[index].val) > 0) {
        bar->notify_delay = strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    /* Suggested Buffering Packets Count */
    if (strlen(bar_key_pair[index].val) > 0) {
        bar->member_flag.d.buffer_pkts_cnt_present =
            strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    if (strlen(bar_key_pair[index].val) > 0) {
        bar->buffer_pkts_cnt = strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }
    /* dl_buff_duration */
    if (strlen(bar_key_pair[index].val) > 0) {
        bar->member_flag.d.dl_buff_duration_present =
            strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    if (strlen(bar_key_pair[index].val) > 0) {
        bar->dl_buff_duration.value= strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }
	    /* dl_buff_pkts_cnt */
    if (strlen(bar_key_pair[index].val) > 0) {
        bar->member_flag.d.dl_buff_pkts_cnt_present =
            strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    if (strlen(bar_key_pair[index].val) > 0) {
        bar->dl_buff_pkts_cnt = strtol(bar_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            bar_key_pair[index].key, bar_key_pair[index].val);
        return -1;
    }

    return 0;
}

static int upc_parse_local_cfg_create_mar(session_mar_create *mar_arr,
    uint8_t mar_num, struct pcf_file *conf)
{
    int index = 0;
    uint8_t cnt = 0;
    session_mar_create *mar = NULL;
    char create_mar_name[128] = {0};
    /* the key pair and value get must be in order */
    struct kv_pair mar_key_pair[] = {
        { "mar_id_present", NULL },
        { "mar_id", NULL },
        { "mar_steer_func_present", NULL },
        { "mar_steer_func", NULL },
        { "mar_steer_mode_present", NULL },
        { "mar_steer_mode", NULL },
        { "mar_afai_1_present", NULL },
        { "mar_afai_1_far_id_present", NULL },
        { "mar_afai_1_far_id", NULL },
        { "mar_afai_1_weight_present", NULL },
        { "mar_afai_1_weight", NULL },
        { "mar_afai_1_priority_present", NULL },
        { "mar_afai_1_priority", NULL },
        { "mar_afai_1_urr_num", NULL },
        { "mar_afai_1_urr_id_1", NULL },
        { "mar_afai_1_urr_id_2", NULL },
        { "mar_afai_1_urr_id_3", NULL },
        { "mar_afai_1_urr_id_4", NULL },
        { "mar_afai_1_urr_id_5", NULL },
        { "mar_afai_2_present", NULL },
        { "mar_afai_2_far_id_present", NULL },
        { "mar_afai_2_far_id", NULL },
        { "mar_afai_2_weight_present", NULL },
        { "mar_afai_2_weight", NULL },
        { "mar_afai_2_priority_present", NULL },
        { "mar_afai_2_priority", NULL },
        { "mar_afai_2_urr_num", NULL },
        { "mar_afai_2_urr_id_1", NULL },
        { "mar_afai_2_urr_id_2", NULL },
        { "mar_afai_2_urr_id_3", NULL },
        { "mar_afai_2_urr_id_4", NULL },
        { "mar_afai_2_urr_id_5", NULL },
        { NULL, NULL, }
    };

    for (cnt = 0; cnt < mar_num; ++cnt) {
        sprintf(create_mar_name, "%s_%d", SECTION_CREATE_MAR, cnt + 1);
        mar = &mar_arr[cnt];
        index = 0;

        while (mar_key_pair[index].key != NULL) {
            mar_key_pair[index].val = pcf_get_key_value(conf,
                         create_mar_name, mar_key_pair[index].key);
            if (!mar_key_pair[index].val) {
                LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                    mar_key_pair[index].key, create_mar_name);
                return -1;
            }
            ++index;
        }
        index = 0;

        /* MAR ID */
        if (strlen(mar_key_pair[index].val) > 0) {
            mar->member_flag.d.mar_id_present =
                strtol(mar_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                mar_key_pair[index].key, mar_key_pair[index].val);
            return -1;
        }

        if (strlen(mar_key_pair[index].val) > 0) {
            mar->mar_id = strtol(mar_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                mar_key_pair[index].key, mar_key_pair[index].val);
            return -1;
        }

        /* Steering Functionality */
        if (strlen(mar_key_pair[index].val) > 0) {
            mar->member_flag.d.steer_func_present =
                strtol(mar_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                mar_key_pair[index].key, mar_key_pair[index].val);
            return -1;
        }

        if (strlen(mar_key_pair[index].val) > 0) {
            mar->steer_func = strtol(mar_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                mar_key_pair[index].key, mar_key_pair[index].val);
            return -1;
        }

        /* Steering Mode */
        if (strlen(mar_key_pair[index].val) > 0) {
            mar->member_flag.d.steer_mod_present =
                strtol(mar_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                mar_key_pair[index].key, mar_key_pair[index].val);
            return -1;
        }

        if (strlen(mar_key_pair[index].val) > 0) {
            mar->steer_mod = strtol(mar_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                mar_key_pair[index].key, mar_key_pair[index].val);
            return -1;
        }

        /* Access Forwarding Action Information 1 */
        if (strlen(mar_key_pair[index].val) > 0) {
            mar->member_flag.d.afai_1_present =
                strtol(mar_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                mar_key_pair[index].key, mar_key_pair[index].val);
            return -1;
        }

        if (0 > upc_parse_local_cfg_afai(&mar->afai_1, mar_key_pair, &index)) {
            LOG(STUB, ERR,
                "parse Access Forwarding Action Information failed.\n");
            return -1;
        }

        /* Access Forwarding Action Information 2 */
        if (strlen(mar_key_pair[index].val) > 0) {
            mar->member_flag.d.afai_2_present =
                strtol(mar_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                mar_key_pair[index].key, mar_key_pair[index].val);
            return -1;
        }

        if (0 > upc_parse_local_cfg_afai(&mar->afai_2, mar_key_pair, &index)) {
            LOG(STUB, ERR,
                "parse Access Forwarding Action Information failed.\n");
            return -1;
        }

    }

    return 0;
}

static int upc_parse_local_cfg_create_tc_endpoint(session_tc_endpoint *tc_arr,
    uint8_t tc_num, struct pcf_file *conf)
{
    int index = 0;
    uint8_t cnt = 0, cntl2;
    session_tc_endpoint *tc = NULL;
    char create_tc_name[128] = {0};
    /* the key pair and value get must be in order */
    struct kv_pair tc_key_pair[] = {
        { "tc_id_present", NULL },
        { "tc_id", NULL },
        { "tc_fteid_present", NULL },
        { "tc_fteid_flag", NULL },
        { "tc_fteid_teid", NULL },
        { "tc_fteid_ipv4", NULL },
        { "tc_fteid_ipv6", NULL },
        { "tc_fteid_chid", NULL },
        { "tc_ni_present", NULL },
        { "tc_ni", NULL },
        { "tc_ueip_num", NULL },
        { "tc_ueip1_flag", NULL },
        { "tc_ueip1_ipv4", NULL },
        { "tc_ueip1_ipv6", NULL },
        { "tc_ueip1_prefix", NULL },
        { "tc_ueip2_flag", NULL },
        { "tc_ueip2_ipv4", NULL },
        { "tc_ueip2_ipv6", NULL },
        { "tc_ueip2_prefix", NULL },
        { "tc_eth_pdu_ses_present", NULL },
        { "tc_eth_pdu_ses", NULL },
        { NULL, NULL, }
    };

    for (cnt = 0; cnt < tc_num; ++cnt) {
        sprintf(create_tc_name, "%s_%d", SECTION_CREATE_TC_ENDPOINT, cnt + 1);
        tc = &tc_arr[cnt];
        index = 0;

        while (tc_key_pair[index].key != NULL) {
            tc_key_pair[index].val = pcf_get_key_value(conf,
                         create_tc_name, tc_key_pair[index].key);
            if (!tc_key_pair[index].val) {
                LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                    tc_key_pair[index].key, create_tc_name);
                return -1;
            }
            ++index;
        }
        index = 0;

        /* Traffic Endpoint ID */
        if (strlen(tc_key_pair[index].val) > 0) {
            tc->member_flag.d.endpoint_id_present =
                strtol(tc_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                tc_key_pair[index].key, tc_key_pair[index].val);
            return -1;
        }

        if (strlen(tc_key_pair[index].val) > 0) {
            tc->endpoint_id = strtol(tc_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                tc_key_pair[index].key, tc_key_pair[index].val);
            return -1;
        }

        /* Local F-TEID */
        if (strlen(tc_key_pair[index].val) > 0) {
            tc->member_flag.d.local_fteid_present =
                strtol(tc_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                tc_key_pair[index].key, tc_key_pair[index].val);
            return -1;
        }

        if (0 > upc_parse_local_cfg_fteid(&tc->local_fteid, tc_key_pair, &index)) {
            LOG(STUB, ERR, "Parse f-teid failed.\n");
            return -1;
        }

        /* Network Instance */
        if (strlen(tc_key_pair[index].val) > 0) {
            tc->member_flag.d.network_instance_present =
                strtol(tc_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                tc_key_pair[index].key, tc_key_pair[index].val);
            return -1;
        }

        if (strlen(tc_key_pair[index].val) > 0) {
            if (strlen(tc_key_pair[index].val) > NETWORK_INSTANCE_LEN) {
                LOG(STUB, ERR, "%s:%s Too long.\n",
                    tc_key_pair[index].key, tc_key_pair[index].val);
                return -1;
            }
            strcpy(tc->network_instance, tc_key_pair[index].val);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                tc_key_pair[index].key, tc_key_pair[index].val);
            return -1;
        }

        /* UE IP address */
        if (strlen(tc_key_pair[index].val) > 0) {
            tc->ue_ipaddr_num = strtol(tc_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                tc_key_pair[index].key, tc_key_pair[index].val);
            return -1;
        }

        for (cntl2 = 0; cntl2 < MAX_PARSE_UEIP_NUM; ++cntl2) {
            if (0 > upc_parse_local_cfg_ueip(&tc->ue_ipaddr[cntl2], tc_key_pair, &index)) {
                LOG(STUB, ERR, "Parse ueip failed.\n");
                return -1;
            }
        }

        /* Ethernet PDU Session Information */
        if (strlen(tc_key_pair[index].val) > 0) {
            tc->member_flag.d.eth_pdu_ses_info_present =
                strtol(tc_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                tc_key_pair[index].key, tc_key_pair[index].val);
            return -1;
        }

        if (strlen(tc_key_pair[index].val) > 0) {
            tc->eth_pdu_ses_info.value =
                strtol(tc_key_pair[index].val, NULL, 10);
            ++index;
        } else {
            LOG(STUB, ERR, "Invalid %s:%s config.\n",
                tc_key_pair[index].key, tc_key_pair[index].val);
            return -1;
        }

        if (0 > upc_parse_local_cfg_cm_tc_endpoint_body(tc, conf, create_tc_name)) {
            LOG(STUB, ERR, "parse tc endpoint body faild.");
            return -1;
        }
    }

    return 0;
}

int upc_parse_session_content(session_content_create *sess, struct pcf_file *conf)
{
    int index = 0;
    /* the key pair and value get must be in order */
    struct kv_pair session_key_pair[] = {
        { "pdn_type", NULL },
        { "smf_seid", NULL },
        { "pdr_num", NULL },
        { "far_num", NULL },
        { "urr_num", NULL },
        { "qer_num", NULL },
        { "bar_present", NULL },
        { "tc_endpoint_num", NULL },
        { "inactive_timer_present", NULL },
        { "inactive_timer", NULL },
        { "user_id_present", NULL },
        { "trace_info_present", NULL },
        { "apn_dnn_present", NULL },
        { "mar_num", NULL },
        { NULL, NULL, }
    };

    ros_memset(sess, 0, sizeof(session_content_create));

    while (session_key_pair[index].key != NULL) {
        session_key_pair[index].val = pcf_get_key_value(conf,
                     SECTION_ESTABLISH_NAME, session_key_pair[index].key);
        if (!session_key_pair[index].val) {
            LOG(STUB, ERR, "Can't get key[%s] in section[%s].\n",
                session_key_pair[index].key, SECTION_ESTABLISH_NAME);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* pdn_type */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->pdn_type = strtol(session_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* smf_seid */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->cp_f_seid.seid = strtol(session_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* pdr_num */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->pdr_num = strtol(session_key_pair[index].val, NULL, 10);
        if (sess->pdr_num > MAX_PDR_NUM) {
            LOG(STUB, ERR, "abnormal parameter, pdr_num > %d.",
                MAX_PDR_NUM);
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* far_num */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->far_num = strtol(session_key_pair[index].val, NULL, 10);
        if (sess->far_num > MAX_FAR_NUM) {
            LOG(STUB, ERR, "abnormal parameter, far_num > %d.",
                MAX_FAR_NUM);
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* urr_num */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->urr_num = strtol(session_key_pair[index].val, NULL, 10);
        if (sess->urr_num > MAX_URR_NUM) {
            LOG(STUB, ERR, "abnormal parameter, urr_num > %d.",
                MAX_URR_NUM);
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* qer_num */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->qer_num = strtol(session_key_pair[index].val, NULL, 10);
        if (sess->qer_num > MAX_QER_NUM) {
            LOG(STUB, ERR, "abnormal parameter, qer_num > %d.",
                MAX_QER_NUM);
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* bar_present */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->member_flag.d.bar_present = strtol(session_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* tc_endpoint_num */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->tc_endpoint_num = strtol(session_key_pair[index].val, NULL, 10);
        if (sess->tc_endpoint_num > MAX_TC_ENDPOINT_NUM) {
            LOG(STUB, ERR, "abnormal parameter, tc_endpoint_num > %d.",
                MAX_TC_ENDPOINT_NUM);
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* inactive_timer_present */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->member_flag.d.inactivity_timer_present =
            strtol(session_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* inactive_timer */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->inactivity_timer = strtol(session_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* user_id_present */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->member_flag.d.user_id_present = strtol(session_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* trace_info_present */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->member_flag.d.trace_info_present =
            strtol(session_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* apn_dnn_present */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->member_flag.d.apn_dnn_present = strtol(session_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* mar_num */
    if (strlen(session_key_pair[index].val) > 0) {
        sess->mar_num = strtol(session_key_pair[index].val, NULL, 10);
        if (sess->mar_num > MAX_MAR_NUM) {
            LOG(STUB, ERR, "abnormal parameter, mar_num > %d.",
                MAX_MAR_NUM);
            return -1;
        }
        ++index;
    } else {
        LOG(STUB, ERR, "Invalid %s:%s config.\n",
            session_key_pair[index].key, session_key_pair[index].val);
        return -1;
    }

    /* parse sub rules */
    if (sess->pdr_num > 0) {
        if (0 > upc_parse_local_cfg_create_pdr(sess->pdr_arr, sess->pdr_num, conf)) {
            LOG(STUB, ERR, "parse PDR failed.\n");
            return -1;
        }
    }

    if (sess->far_num > 0) {
        if (0 > upc_parse_local_cfg_create_far(sess->far_arr, sess->far_num, conf)) {
            LOG(STUB, ERR, "parse FAR failed.\n");
            return -1;
        }
    }

    if (sess->urr_num > 0) {
        if (0 > upc_parse_local_cfg_create_urr(sess->urr_arr, sess->urr_num, conf)) {
            LOG(STUB, ERR, "parse URR failed.\n");
            return -1;
        }
    }

    if (sess->qer_num > 0) {
        if (0 > upc_parse_local_cfg_create_qer(sess->qer_arr, sess->qer_num, conf)) {
            LOG(STUB, ERR, "parse QER failed.\n");
            return -1;
        }
    }

    if (sess->member_flag.d.bar_present) {
        if (0 > upc_parse_local_cfg_create_bar(&sess->bar, conf)) {
            LOG(STUB, ERR, "parse BAR failed.\n");
            return -1;
        }
    }

    if (sess->tc_endpoint_num > 0) {
        if (0 > upc_parse_local_cfg_create_tc_endpoint(sess->tc_endpoint_arr,
            sess->tc_endpoint_num, conf)) {
            LOG(STUB, ERR, "parse Traffic Endpoint failed.\n");
            return -1;
        }
    }

    if (sess->mar_num > 0) {
        if (0 > upc_parse_local_cfg_create_mar(sess->mar_arr, sess->mar_num, conf)) {
            LOG(STUB, ERR, "parse MAR failed.\n");
            return -1;
        }
    }

    return 0;
}

