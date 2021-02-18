/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "pfcp_def.h"
#include "upc_node.h"
#include "upc_main.h"
#include "upc_seid.h"
#include "pfcp_heartbeat.h"
#include "pfcp_association.h"
#include "upc_session.h"

static uint32_t node_heartbeat_interval = UPC_NODE_DEFAULT_HB_TIME;
upc_node_header upc_node_mng;
session_globally_unique_id upf_guid;


upc_node_header *upc_node_mng_get(void)
{
    return &upc_node_mng;
}

static inline upc_node_cb *upc_node_cb_get(uint8_t index)
{
    return &upc_node_mng.node[index];
}

upc_node_cb *upc_node_cb_get_public(uint8_t index)
{
	return &upc_node_mng.node[index];
}

uint8_t *upc_upf_guid_get(void)
{
    return upf_guid.value;
}

int upc_node_features_validity_query(uint64_t feature)
{
    session_up_features up_features = {.value = upc_get_up_features()};

    if ((up_features.value & feature) != feature) {
        return G_FALSE;
    }

    return G_TRUE;
}

int64_t upc_node_init(uint8_t node_num)
{
    uint8_t  node_loop, bit_no;
    uint16_t buf_pos = 0;
    uint32_t res_no;
    int64_t  ret64;
    session_ip_addr *local_ip;

    if (num_to_power(node_num, &bit_no) != 0) {
        LOG(UPC, ERR, "node num should be power of 2!");
        return ERROR;
    }

    upc_node_mng.node = ros_malloc(sizeof(upc_node_cb) * node_num);
    if (!upc_node_mng.node) {
        LOG(UPC, ERR, "alloc node memory failed!");
        return ERROR;
    }

    ros_random_uuid(upf_guid.value);

    for (node_loop = 0; node_loop < node_num; node_loop++) {
        upc_node_mng.node[node_loop].hb_timer = ros_timer_create(
            ROS_TIMER_MODE_ONCE, node_heartbeat_interval,
            (uint64_t)&(upc_node_mng.node[node_loop]),
            upc_node_proc_timer_hb);
        if (NULL == upc_node_mng.node[node_loop].hb_timer) {
            ros_free(upc_node_mng.node);
            upc_node_mng.node = NULL;
            return -1;
        }
        upc_node_mng.node[node_loop].index  = node_loop;
        memcpy(upc_node_mng.node[node_loop].guid.value, upf_guid.value, 16);

        upc_node_clear_param(&upc_node_mng.node[node_loop]);
    }

    upc_node_mng.node_max = node_num;

    res_no = Res_CreatePool();
    if (res_no < 0) {
        return -1;
    }

    ret64 = Res_AddSection(res_no, 0, 0, node_num);
    if (ret64 == G_FAILURE) {
        return -1;
    }
    upc_node_mng.res_no = res_no;

    /* Set local node id */
    local_ip = upc_get_local_ip();
    if (local_ip->version & SESSION_IP_V4) {
        upc_node_mng.local_idv4.type.d.type = UPF_NODE_TYPE_IPV4;
        buf_pos = 0;
        tlv_encode_uint32_t(upc_node_mng.local_idv4.node_id, &buf_pos,
            local_ip->ipv4);
    }
    if (local_ip->version & SESSION_IP_V6) {
        upc_node_mng.local_idv6.type.d.type = UPF_NODE_TYPE_IPV6;
        buf_pos = 0;
        tlv_encode_binary(upc_node_mng.local_idv6.node_id, &buf_pos,
            IPV6_ALEN, local_ip->ipv6);
    }

    /* Set local time stamp, change 1970 to 1900 */
    upc_node_mng.local_stamp = ros_getime();

    return (sizeof(upc_node_cb) * node_num);
}

void upc_node_clear_param(upc_node_cb *node)
{
    node->status = UPC_NODE_STATUS_INIT;
    ros_atomic16_init(&node->hb_timeout_cnt);
    ros_atomic32_init(&node->local_seq);
    ros_atomic32_init(&node->session_num);

    node->peer_id.type.d.type = UPF_NODE_TYPE_BUTT;
    memset(node->peer_id.node_id, 0, PFCP_MAX_NODE_ID_LEN);
    dl_list_init(&node->seid_list);
}

void upc_node_merge_features(upc_node_cb *node)
{
    session_up_features up_feature;

    /* Get device supported features */
    up_feature.value = upc_get_up_features();

    if ((node->assoc_config.cp_features.d.sset)&&(up_feature.d.SSET)) {
        node->assoc_config.up_features.d.SSET = 1;
    }

    if ((node->assoc_config.cp_features.d.epfar)&&(up_feature.d.EPFAR)) {
        node->assoc_config.up_features.d.EPFAR = 1;
    }
}

upc_node_cb *upc_node_get(uint8_t node_type, uint8_t *nodeid)
{
    uint8_t node_loop;

    for (node_loop = 0; node_loop < upc_node_mng.node_max; node_loop++) {
        if (upc_node_mng.node[node_loop].status == UPC_NODE_STATUS_INIT) {
            continue;
        }

        if (node_type == UPF_NODE_TYPE_IPV4) {
            if ((node_type == upc_node_mng.node[node_loop].peer_id.type.d.type)
              &&(memcmp((char *)upc_node_mng.node[node_loop].peer_id.node_id,
                (char *)nodeid, 4) == 0))

            return (&(upc_node_mng.node[node_loop]));
        }
        else if (node_type == UPF_NODE_TYPE_IPV6) {
            if ((node_type == upc_node_mng.node[node_loop].peer_id.type.d.type)
              &&(memcmp((char *)upc_node_mng.node[node_loop].peer_id.node_id,
                (char *)nodeid, 16) == 0))

            return (&(upc_node_mng.node[node_loop]));
        }
        else if (node_type == UPF_NODE_TYPE_FQDN) {
            if ((node_type == upc_node_mng.node[node_loop].peer_id.type.d.type)
              &&(strncmp((char *)upc_node_mng.node[node_loop].peer_id.node_id,
                (char *)nodeid, PFCP_MAX_NODE_ID_LEN) == 0))

            return (&(upc_node_mng.node[node_loop]));
        }
        else
        {
            return NULL;
        }
    }
    return NULL;
}

upc_node_cb *upc_get_node_by_sa(void *arg)
{
    uint8_t node_loop;
    struct sockaddr *sa = (struct sockaddr *)arg;

    if (AF_INET == sa->sa_family) {
        struct sockaddr_in *sa_v4 = (struct sockaddr_in *)sa, *node_sa_v4;

        for (node_loop = 0; node_loop < upc_node_mng.node_max; node_loop++) {
            if (upc_node_mng.node[node_loop].status == UPC_NODE_STATUS_INIT) {
                continue;
            }

            node_sa_v4 = &upc_node_mng.node[node_loop].peer_sa_v4;

            if (AF_INET == node_sa_v4->sin_family) {
                if ((node_sa_v4->sin_port == sa_v4->sin_port) &&
                    (node_sa_v4->sin_addr.s_addr == sa_v4->sin_addr.s_addr)) {
                    return &upc_node_mng.node[node_loop];
                }
            } else {
                continue;
            }
        }
    } else if (AF_INET6 == sa->sa_family) {
        struct sockaddr_in6 *sa_v6 = (struct sockaddr_in6 *)sa, *node_sa_v6;

        for (node_loop = 0; node_loop < upc_node_mng.node_max; node_loop++) {
            if (upc_node_mng.node[node_loop].status == UPC_NODE_STATUS_INIT) {
                continue;
            }

            node_sa_v6 = &upc_node_mng.node[node_loop].peer_sa_v6;

            if (AF_INET6 == node_sa_v6->sin6_family) {
                if ((node_sa_v6->sin6_port == sa_v6->sin6_port) &&
                    (0 == memcmp(&node_sa_v6->sin6_addr, &sa_v6->sin6_addr, IPV6_ALEN))) {
                    return &upc_node_mng.node[node_loop];
                }
            } else {
                continue;
            }
        }
    }

    return NULL;
}

void upc_node_update_peer_sa(upc_node_cb *node_cb, struct sockaddr *sa)
{
    //node_cb->peer_sa.sa_family = sa->sa_family;
    switch (sa->sa_family) {
        case AF_INET:
            {
                //struct sockaddr_in *sa_v4 = (struct sockaddr_in *)sa;

                //node_cb->peer_sa_v4.sin_addr.s_addr = sa_v4->sin_addr.s_addr;
                //node_cb->peer_sa_v4.sin_port = sa_v4->sin_port;
                memcpy(&node_cb->peer_sa_v4, sa, sizeof(struct sockaddr_in));
            }
            break;

        case AF_INET6:
            {
                //struct sockaddr_in6 *sa_v6 = (struct sockaddr_in6 *)sa;

                //memcpy(&node_cb->peer_sa_v6.sin6_addr, &sa_v6->sin6_addr, IPV6_ALEN);
                //node_cb->peer_sa_v6.sin6_port = sa_v6->sin6_port;
                memcpy(&node_cb->peer_sa_v6, sa, sizeof(struct sockaddr_in6));
            }
            break;

        default:
            memcpy(&node_cb->peer_sa, sa, sizeof(struct sockaddr));
            LOG(UPC, ERR, "Abnormal sockaddr family: %d.", sa->sa_family);
            break;
    }
}

upc_node_cb *upc_node_add(uint8_t node_index, uint8_t node_type, uint8_t *nodeid, struct sockaddr *sa)
{
    upc_node_header *node_mgmt = upc_node_mng_get();
    upc_node_cb *node;
    uint32_t index, key = 0;

    /* If can't find matched node */
    node = upc_node_get(node_type, nodeid);
    if (NULL != node) {
        /* By the remark of association request on manual */
        /* If receive request from same smf, need release old one */
        /* regardless timestamp */
        if (0 > upc_node_del(node)) {
            LOG(UPC, ERR, "Delete node failed.");
        }
    }

    switch (node_index) {
        case UPC_NODE_INVALID_INDEX:
            if (G_FAILURE == Res_Alloc(node_mgmt->res_no, &key, &index, EN_RES_ALLOC_MODE_OC)) {
                LOG(UPC, ERR, "Node alloc target %d resource failed.", node_index);
                return NULL;
            }
            break;

        default:
            key = 0;
            index = node_index;
            if (G_FAILURE == Res_AllocTarget(node_mgmt->res_no, key, node_index)) {
                LOG(UPC, ERR, "Node alloc target %d resource failed.", node_index);
                return NULL;
            }
            break;
    }

    node = upc_node_cb_get(index);

    ros_rwlock_write_lock(&node->lock); /* lock */
    upc_node_clear_param(node);

    /* Save node info */
    node->peer_id.type.d.type = node_type;
    switch (node_type) {
        case UPF_NODE_TYPE_IPV4:
            memcpy((char *)node->peer_id.node_id, (char *)nodeid, 4);
            if (NULL == sa) {
                struct sockaddr_in sa_v4 = {.sin_family = AF_INET, .sin_addr.s_addr = *(uint32_t *)nodeid,
                    .sin_port = htons(UDP_PRO_PFCP)};
                upc_node_update_peer_sa(node, (struct sockaddr *)&sa_v4);
            }
            break;

        case UPF_NODE_TYPE_IPV6:
            memcpy((char *)node->peer_id.node_id, (char *)nodeid, IPV6_ALEN);
            if (NULL == sa) {
                struct sockaddr_in6 sa_v6 = {.sin6_family = AF_INET6, .sin6_port = htons(UDP_PRO_PFCP)};
                memcpy(&sa_v6.sin6_addr, nodeid, IPV6_ALEN);

                upc_node_update_peer_sa(node, (struct sockaddr *)&sa_v6);
            }
            break;

        case UPF_NODE_TYPE_FQDN:
            strncpy((char *)node->peer_id.node_id, (char *)nodeid, PFCP_MAX_NODE_ID_LEN);
            break;

        default:
            Res_Free(node_mgmt->res_no, key, index);
            return NULL;
    }
    if (sa) {
        upc_node_update_peer_sa(node, sa);
    }
    node->status = UPC_NODE_STATUS_RUN;
    ros_rwlock_write_unlock(&node->lock); /* unlock */

    if (HA_STATUS_ACTIVE == upc_get_work_status()) {
        ros_timer_start(node->hb_timer);
    }

    return node;
}

int upc_node_del(upc_node_cb *node)
{
    if (HA_STATUS_ACTIVE == upc_get_work_status()) {
        ros_timer_stop(node->hb_timer);
    }

    node->status = UPC_NODE_STATUS_INIT;
    Res_Free(upc_node_mng.res_no, 0, node->index);

    if (0 > upc_seid_release_from_node(node)) {
        LOG(UPC, ERR, "seid entry release failed.");
        return -1;
    }

    node->peer_id.type.d.type = UPF_NODE_TYPE_BUTT;
    memset(node->peer_id.node_id, 0, PFCP_MAX_NODE_ID_LEN);
    dl_list_init(&node->seid_list);

    return 0;
}

void upc_node_proc_timer_hb(void *timer, uint64_t para)
{
    upc_node_cb *node = (upc_node_cb *)para;

    ros_atomic16_inc(&node->hb_timeout_cnt);
    if (ros_atomic16_read(&node->hb_timeout_cnt) > 5) {
        session_association_release_request assoc_rels = {{0}};

        LOG(UPC, ERR,
            "too much times heartbeat fail, delete node %02x%02x%02x%02x",
            node->peer_id.node_id[0],
            node->peer_id.node_id[1],
            node->peer_id.node_id[2],
            node->peer_id.node_id[3]);

        assoc_rels.node_id_index = node->index;

        if (0 > upc_node_del(node)) {
            LOG(UPC, ERR, "Delete node failed.");
        }

        if (upc_hk_build_data_block) {
            if (0 > upc_hk_build_data_block(HA_SYNC_DATA_NODE, HA_REMOVE, HA_SYNC_FINAL_STATE,
                HA_SYNC_EVENT_SUCC, &assoc_rels)) {
                LOG(UPC, ERR, "Build session sync msg failed.");
            }
        }

        return;
    }

    pfcp_build_heartbeat_request(node);

    ros_timer_start(node->hb_timer);
}

pfcp_node_id *upc_node_get_local_node_id(uint8_t node_type)
{
    switch (node_type) {
        case UPF_NODE_TYPE_IPV4:
            return (&(upc_node_mng.local_idv4));

        case UPF_NODE_TYPE_IPV6:
            return (&(upc_node_mng.local_idv6));

        default:
            return (&(upc_node_mng.local_idv4));
    }
}

uint32_t upc_node_get_local_time_stamp(void)
{
    return upc_node_mng.local_stamp;
}

uint32_t upc_node_get_max_num(void)
{
    return upc_node_mng.node_max;
}

pfcp_node_id *upc_node_get_peer_node(upc_node_cb *node_cb)
{
    return &node_cb->peer_id;
}

uint32_t upc_node_get_peer_ipv4(upc_node_cb *node_cb)
{
    return node_cb->peer_sa_v4.sin_addr.s_addr;
}

upc_node_cb *upc_node_get_of_index(uint32_t index)
{
    if (index >= upc_node_mng.node_max) {
        LOG(UPC, ERR, "get node cb failed, index: %u error.", index);
        return NULL;
    }

    if (upc_node_mng.node[index].status == UPC_NODE_STATUS_RUN) {
        return &upc_node_mng.node[index];
    } else {
        return NULL;
    }
}

void upc_node_create_node(uint8_t ipver, uint32_t ipv4, uint8_t *ipv6,
    uint16_t peer_port)
{
    upc_node_cb     *node;
    struct sockaddr_in sa_v4 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(ipv4), .sin_port = peer_port};
    struct sockaddr_in6 sa_v6 = {.sin6_family = AF_INET6, .sin6_port = peer_port};;
    uint32_t net_ipv4 = htonl(ipv4);

    if (ipver == UPF_NODE_TYPE_IPV4) {
        node = upc_node_add(UPC_NODE_INVALID_INDEX, UPF_NODE_TYPE_IPV4,
            (uint8_t *)&net_ipv4, (struct sockaddr *)&sa_v4);
    }
    else if (ipver == UPF_NODE_TYPE_IPV6) {
        memcpy(&sa_v6.sin6_addr, ipv6, IPV6_ALEN);
        node = upc_node_add(UPC_NODE_INVALID_INDEX, UPF_NODE_TYPE_IPV6, ipv6, (struct sockaddr *)&sa_v6);
    } else {
        node = upc_node_add(UPC_NODE_INVALID_INDEX, UPF_NODE_TYPE_IPV4,
            (uint8_t *)&net_ipv4, (struct sockaddr *)&sa_v4);
    }

	node->assoc_config.up_features.value = upc_get_up_features();
    pfcp_build_association_setup_request(node);
}

void upc_node_update_node(uint8_t ipver, uint32_t ipv4, uint8_t *ipv6)
{
    session_ip_addr smf_ip;
    upc_node_cb     *node;

    if (ipver == SESSION_IP_V4) {
        smf_ip.version = SESSION_IP_V4;
        smf_ip.ipv4    = ipv4;
        node = upc_node_get(UPF_NODE_TYPE_IPV4, (uint8_t *)&ipv4);
    }
    else if (ipver == SESSION_IP_V6) {
        smf_ip.version = SESSION_IP_V6;
        memcpy(smf_ip.ipv6, ipv6, IPV6_ALEN);
        node = upc_node_get(UPF_NODE_TYPE_IPV6, ipv6);
    } else {
        smf_ip.version = SESSION_IP_V4;
        smf_ip.ipv4    = ipv4;
        node = upc_node_get(UPF_NODE_TYPE_IPV4, (uint8_t *)&ipv4);
    }

    pfcp_build_association_update_request(node, 0, 1, 0);
}

uint32_t upc_node_time_struct_to_second(uint8_t time_struct)
{
    session_timer *time = (session_timer *)&time_struct;
    uint32_t time_in_sec;

    /*
    Timer value
    Bits 5 to 1 represent the binary coded timer value
    Timer unit
    Bits 6 to 8 defines the timer value unit as follows:
    Bits
    8 7 6
    0 0 0  value is incremented in multiples of 2 seconds
    0 0 1  value is incremented in multiples of 1 minute
    0 1 0  value is incremented in multiples of 10 minutes
    0 1 1  value is incremented in multiples of 1 hour
    1 0 0  value is incremented in multiples of 10 hours
    1 1 1  value indicates that the timer is infinite
    */
    switch(time->d.unit) {
        case 0:
            time_in_sec = time->d.value * 2;
            break;
        case 1:
            time_in_sec = time->d.value * 60;
            break;
        case 2:
            time_in_sec = time->d.value * 600;
            break;
        case 3:
            time_in_sec = time->d.value * 3600;
            break;
        case 4:
            time_in_sec = time->d.value * 36000;
            break;
        case 7:
            time_in_sec = 0xFFFFFFFF;/*3268 year*/
            break;
        case 5:
        case 6:
        default:
            time_in_sec = 0xFFFFFFFF;
            break;
    }

    return time_in_sec;
}

uint8_t upc_node_second_to_time_struct(uint32_t time_in_sec)
{
    session_timer time_struct;

    /*
    Timer value
    Bits 5 to 1 represent the binary coded timer value
    Timer unit
    Bits 6 to 8 defines the timer value unit as follows:
    Bits
    8 7 6
    0 0 0  value is incremented in multiples of 2 seconds
    0 0 1  value is incremented in multiples of 1 minute
    0 1 0  value is incremented in multiples of 10 minutes
    0 1 1  value is incremented in multiples of 1 hour
    1 0 0  value is incremented in multiples of 10 hours
    1 1 1  value indicates that the timer is infinite
    */
    if (time_in_sec > 36000) {
        time_struct.d.unit  = 4;
        time_struct.d.value = time_in_sec/36000;
    }
    else if (time_in_sec > 3600) {
        time_struct.d.unit  = 3;
        time_struct.d.value = time_in_sec/3600;
    }
    else if (time_in_sec > 600) {
        time_struct.d.unit  = 2;
        time_struct.d.value = time_in_sec/600;
    }
    else if (time_in_sec > 60) {
        time_struct.d.unit  = 1;
        time_struct.d.value = time_in_sec/60;
    }
    else if (time_in_sec >= 2) {
        time_struct.d.unit  = 0;
        time_struct.d.value = time_in_sec/2;
    }

    return time_struct.value;
}

uint32_t upc_node_notify_session_report(upc_node_cb *node_cb)
{
    return 0;
}

int upc_node_hb_timer_start(void)
{
    upc_node_cb *node_cb = NULL;
    int32_t cur_index = -1;

    cur_index = Res_GetAvailableInBand(upc_node_mng.res_no, cur_index + 1, upc_node_mng.node_max);
    while (-1 != cur_index) {
        node_cb = upc_node_get_of_index(cur_index);
        if (NULL == node_cb) {
            LOG(UPC, ERR, "Get node cb by index: %u failed.", cur_index);
            cur_index = Res_GetAvailableInBand(upc_node_mng.res_no, cur_index + 1, upc_node_mng.node_max);
            continue;
        }

        ros_timer_start(node_cb->hb_timer);

        cur_index = Res_GetAvailableInBand(upc_node_mng.res_no, cur_index + 1, upc_node_mng.node_max);
    }

    return 0;
}

int upc_node_hb_timer_stop(void)
{
    upc_node_cb *node_cb = NULL;
    int32_t cur_index = -1;

    cur_index = Res_GetAvailableInBand(upc_node_mng.res_no, cur_index + 1, upc_node_mng.node_max);
    while (-1 != cur_index) {
        node_cb = upc_node_get_of_index(cur_index);
        if (NULL == node_cb) {
            LOG(UPC, ERR, "Get node cb by index: %u failed.", cur_index);
            cur_index = Res_GetAvailableInBand(upc_node_mng.res_no, cur_index + 1, upc_node_mng.node_max);
            continue;
        }

        ros_timer_stop(node_cb->hb_timer);

        cur_index = Res_GetAvailableInBand(upc_node_mng.res_no, cur_index + 1, upc_node_mng.node_max);
    }

    return 0;
}

int upc_node_show_up_cp(struct cli_def * cli,int index, int flag)
{
	uint8_t  cp_value = 0;
	uint32_t i = 0, bit = 0, offset = 0;
	uint32_t *up_low = NULL;
	uint32_t *up_height = NULL;
	uint64_t up_value = 0;
	char bit_name[640] = {0};
	upc_node_cb *node = NULL;
	char *cp_name[] = {"LOAD","OVRL","EPFAR","SSET","BUNDL","MPAS","ARDR","SPARE"};
	char *up_name[] = {"SPARE","SPARE","SPARE","SPARE","SPARE","SPARE","SPARE","SPARE",
  				       "ATSSS-LL","QFQM","GPQM","MT-EDT","CIOT","ETHAR","SPARE","SPARE",
  				       "MPAS","RTTL","VTIME","NORP","IPTV","IP6PL","TSCU","MPTCP",
  				       "DPDRA","ADPDP","UEIP","SSET","MNOP","MTE","BUNDL","GCOM",
  				       "EMPU","PDIU","UDBC","QUOAC","TRACE","FRRT","PFDE","EPFAR",
  				       "BUCP","DDND","DLBD","TRST","FTUP","PFDM","HEEU","TREU",
  				       "SPARE","SPARE","SPARE","SPARE","SPARE","SPARE","SPARE","SPARE",
  				       "SPARE","SPARE","SPARE","SPARE","SPARE","SPARE","SPARE","SPARE"};


	up_value = upc_get_up_features();
	up_low = (unsigned int *)&up_value;
	up_height = up_low+1;
	//LOG(UPC,RUNNING,"UP:%ld",up_value);
	//LOG(UPC,RUNNING,"up_height:%d up_low:%d",*up_height,*up_low);

	if(flag)
	{
		node = upc_node_cb_get_public(index);
		if(node == NULL)
		{
			LOG(UPC,ERR,"%s[%d]can't get node",__FUNCTION__,__LINE__);
			return -1;
		}

		cp_value = node->assoc_config.cp_features.value;
		for(i = 0; i < sizeof(cp_name)/sizeof(cp_name[0]); i++)
		{
			if(!strcmp(cp_name[i],"SPARE"))
				continue;
			if(i < sizeof(cp_name)/sizeof(cp_name[0]))
				bit = (cp_value >> i) & 1;

			if(bit)
				offset += sprintf(bit_name + offset,"%s ",cp_name[i]);
		}
		cli_print(cli,"CP%9s %s",":",bit_name);
		offset = 0;
		memset(bit_name,0,sizeof(bit_name));
		for(i = 0; i < sizeof(up_name)/sizeof(up_name[0]); i++)
		{
			if(!strcmp(up_name[i],"SPARE"))
				continue;
#if BYTE_ORDER == BIG_ENDIAN
			if(i < (sizeof(up_name)/sizeof(up_name[0])) / 2)
				bit = (*up_height >> i) & 1;
			else
				bit = (*up_low >> (i-32)) & 1;
#else
			if(i < (sizeof(up_name)/sizeof(up_name[0])) / 2)
				bit = (*up_low >> i) & 1;
			else
				bit = (*up_height >> (i-32)) & 1;
#endif
			if(bit)
				offset += sprintf(bit_name + offset,"%s ",up_name[i]);
		}
	}
	else
	{

		for(i = 0; i < sizeof(up_name)/sizeof(up_name[0]); i++)
		{
			if(!strcmp(up_name[i],"SPARE"))
				continue;
#if BYTE_ORDER == BIG_ENDIAN
			if(i < (sizeof(up_name)/sizeof(up_name[0])) / 2)
				bit = (*up_height >> i) & 1;
			else
				bit = (*up_low >> (i-32)) & 1;
#else
			if(i < (sizeof(up_name)/sizeof(up_name[0])) / 2)
				bit = (*up_low >> i) & 1;
			else
				bit = (*up_height >> (i-32)) & 1;
#endif
			if(bit)
				offset += sprintf(bit_name + offset,"%s ",up_name[i]);
		}
	}
	cli_print(cli,"UP%9s %s",":",bit_name);
	return 0;
}

int upc_node_show(struct cli_def *cli)
{
	int node_count = 0,session_count = 0;
	int index = 0;
	upc_node_cb *node = NULL;
	const char *str = NULL;
	char node_id[PFCP_MAX_NODE_ID_LEN] = {0};

	if(cli == NULL)
		return -1;
	for(index = 0; index < upc_node_mng.node_max; index++)
	{
		node = upc_node_cb_get_public(index);
		if(node == NULL)
			continue;

		if(node->status == UPC_NODE_STATUS_INIT || node->status == UPC_NODE_STATUS_BUTT)
			continue;

		switch(node->status)
		{
			case UPC_NODE_STATUS_SETUP: str = "SETUP";
										break;
		    case UPC_NODE_STATUS_RUN:   str = "RUN";
										break;
		    case UPC_NODE_STATUS_REPORT:str = "REPORT";
										break;
		    case UPC_NODE_STATUS_SHUT:	str = "SHUT";
										break;
		}

		cli_print(cli, "-----------------------node[%d]-----------------------",node->index);
		cli_print(cli, "Status%5s %s",":",str);
		upc_node_show_up_cp(cli,index,1);
		cli_print(cli, "SessionNum: %d", ros_atomic32_read(&node->session_num));
		if(node->peer_id.type.value == UPF_NODE_TYPE_IPV4)
		{
			cli_print(cli, "Node ID: %d.%d.%d.%d", node->peer_id.node_id[0],
				node->peer_id.node_id[1], node->peer_id.node_id[2], node->peer_id.node_id[3]);
		}
		else if(node->peer_id.type.value == UPF_NODE_TYPE_IPV6)
		{
            if (NULL == inet_ntop(AF_INET6, node->peer_id.node_id, node_id, sizeof(node_id))) {
                LOG(STUB, ERR, "inet_ntop failed, error: %s.", strerror(errno));
            }
			cli_print(cli, "Node ID: %s", node_id);
		}
		else if(node->peer_id.type.value == UPF_NODE_TYPE_FQDN)
		{
			cli_print(cli,"Node ID: %s", node->peer_id.node_id);
		}

		node_count++;
		session_count += ros_atomic32_read(&node->session_num);
	}
	cli_print(cli,"---------------------------------------");
	cli_print(cli,"total node:%9d",node_count);
	cli_print(cli,"total session_nume:%d",session_count);
	return node_count;
}

int upc_node_update()
{
	int i = 0;
	int run_node = 0;
	upc_node_cb *node = NULL;

	for(i = 0; i < upc_node_mng.node_max; i++)
	{
		node = upc_node_cb_get_public(i);
		if(node == NULL)
			continue;

		if(node->status == UPC_NODE_STATUS_RUN)
		{
			run_node++;
			pfcp_build_association_update_request(node, 0, 0, 0);
		}
	}

	return run_node;
}

int upc_node_update_release(struct cli_def *cli,uint32_t ipv4)
{
	int i = 0;
	upc_node_cb *node = NULL;
	uint32_t ip = 0;

	if(ipv4 == 0)
	{
		for(i = 0; i < upc_node_mng.node_max; i++)
		{
			node = upc_node_cb_get_public(i);
			if(node == NULL)
			{
				cli_print(cli,"can't get node node_index:%d",i);
				return -1;
			}

			if(node->status == UPC_NODE_STATUS_RUN)
			{
				pfcp_build_association_update_request(node, 1, 1, 0);
			}
		}
		return 0;
	}


	for(i = 0; i < upc_node_mng.node_max; i++)
	{
		node = upc_node_cb_get_public(i);
		if(node == NULL)
		{
			cli_print(cli,"can't get node node_index:%d",i);
			return -1;
		}

		if(node->status == UPC_NODE_STATUS_RUN)
		{
			memcpy(&ip,node->peer_id.node_id,sizeof(uint32_t));
			if(ip == ipv4)
				pfcp_build_association_update_request(node, 1, 1, 0);
		}

	}
	return 0;
}

int upc_node_set_up(const uint64_t up_value)
{
	int i = 0;
	upc_node_cb *node = NULL;
	for(i = 0; i < upc_node_mng.node_max; i++)
	{
		node = upc_node_cb_get_public(i);
		if(node == NULL)
			continue;

		node->assoc_config.up_features.value = up_value;
	}
	return 0;
}

int upc_set_hb_time(uint32_t sec)
{
	int i = 0;
	upc_node_cb *node;

	for (i = 0; i < upc_node_mng.node_max; i++) {
		node = upc_node_cb_get_public(i);
		if (node == NULL)
			continue;

        ros_timer_reset_time(node->hb_timer, sec * ROS_TIMER_TICKS_PER_SEC);
	}

	return 0;
}

int upc_node_del_cli(struct cli_def *cli)
{
	int i = 0,ret = 0;
	upc_node_cb *node = NULL;
	for(i = 0; i < upc_node_mng.node_max; i++)
	{
		node = upc_node_cb_get_public(i);
		if(node == NULL)
			continue;

		if(node->status != UPC_NODE_STATUS_INIT)
		{
			ret = upc_node_del(node);
			if(ret != 0)
				cli_print(cli,"can't del %d node",i);
			upc_node_clear_param(node);
		}
	}
	return 0;
}

int upc_node_release_cli(struct cli_def *cli, int argc, char *argv[])
{
    upc_node_cb *nd_cb;
    uint8_t node_type = UPF_NODE_TYPE_IPV4;
    uint32_t node_ipv4;
    uint8_t node_ipv6[IPV6_ALEN];
    uint8_t *node_id;

    if (argc < 1) {
        cli_print(cli, "Parameter too few.");
        goto help;
    }

    if (argc > 1) {
        node_type = atoi(argv[1]);
    }

    switch (node_type) {
        case UPF_NODE_TYPE_IPV4:
            if (1 != inet_pton(AF_INET, argv[0], &node_ipv4)) {
                cli_print(cli, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
            node_id = (uint8_t *)&node_ipv4;
            break;

        case UPF_NODE_TYPE_IPV6:
            if (1 != inet_pton(AF_INET6, argv[0], node_ipv6)) {
                cli_print(cli, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
            node_id = (uint8_t *)&node_ipv6;
            break;

        default:
            cli_print(cli, "Unsupport node type: %d", node_type);
            return -1;
    }

    nd_cb = upc_node_get(node_type, node_id);
    if (NULL == nd_cb) {
        cli_print(cli, "no matched node found.");
        return -1;
    }

    pfcp_build_association_release_request(nd_cb);

    return 0;

help:

    cli_print(cli, "release_node <NODE-ID> [NODE-TYPE]");
    cli_print(cli, "NODE-TYPE:  0: IPv4 default use IPv4");
    cli_print(cli, "            1: IPv6");
    cli_print(cli, "            2: FQDN");
    cli_print(cli, "e.g     release_node 10.8.14.200 0");
    cli_print(cli, "e.g     release_node 10.8.126.32");
    return 0;
}

