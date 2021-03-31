/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "session_msg.h"
#include "bar_mgmt.h"
#include "session_audit.h"
#include "session_teid.h"
#include "session_instance.h"
#include "far_mgmt.h"
#include "sp_backend_mgmt.h"

#include "local_parse.h"


struct far_table_head far_tbl_head;
struct fsm_audit far_audit_4am;
struct fsm_audit far_audit_simple;


void far_table_show(struct far_table *far_tbl)
{
#ifdef FAR_DUPL_ENABLE
    uint8_t cnt = 0;
#endif

    LOG(SESSION, RUNNING, "--------------far--------------");
    LOG(SESSION, RUNNING, "index: %u", far_tbl->index);

    LOG(SESSION, RUNNING, "forwarding policy: %s",
        far_tbl->far_priv.forwarding_policy);
    LOG(SESSION, RUNNING, "traffic endpoint id: %d",
        far_tbl->far_priv.traffic_endpoint_id);
    LOG(SESSION, RUNNING, "proxying: %d",
        far_tbl->far_priv.proxying.value);
    if (far_tbl->far_priv.bar_id_present) {
        LOG(SESSION, RUNNING, "bar id: %d", far_tbl->far_priv.bar_id);
    }

    LOG(SESSION, RUNNING, "far id: %d", far_tbl->far_cfg.far_id);
    LOG(SESSION, RUNNING, "action value: %d",
        far_tbl->far_cfg.action.value);
    LOG(SESSION, RUNNING, "forw interface: %d",
        far_tbl->far_cfg.forw_if);
    LOG(SESSION, RUNNING, "choose value: 0x%04x",
        far_tbl->far_cfg.choose.value);

    LOG(SESSION, RUNNING, "forward create outhead type value: %d",
        far_tbl->far_cfg.forw_cr_outh.type.value);
    LOG(SESSION, RUNNING, "forward create outhead port: %d",
        far_tbl->far_cfg.forw_cr_outh.port);
    LOG(SESSION, RUNNING, "forward create outhead teid: %u",
        far_tbl->far_cfg.forw_cr_outh.teid);
    LOG(SESSION, RUNNING, "forward create outhead ipv4: 0x%08x",
        far_tbl->far_cfg.forw_cr_outh.ipv4);
    LOG(SESSION, RUNNING, "forward create outhead ipv6: "
        "0x%08x %08x %08x %08x",
        far_tbl->far_cfg.forw_cr_outh.ipv6.__in6_u.__u6_addr32[0],
        far_tbl->far_cfg.forw_cr_outh.ipv6.__in6_u.__u6_addr32[1],
        far_tbl->far_cfg.forw_cr_outh.ipv6.__in6_u.__u6_addr32[2],
        far_tbl->far_cfg.forw_cr_outh.ipv6.__in6_u.__u6_addr32[3]);
    LOG(SESSION, RUNNING, "forward create outhead ctag flags: 0x%x, value: 0x%x",
        far_tbl->far_cfg.forw_cr_outh.ctag.vlan_flag.value,
        far_tbl->far_cfg.forw_cr_outh.ctag.vlan_value.data);
    LOG(SESSION, RUNNING, "forward create outhead stag flags: 0x%x, value: 0x%x",
        far_tbl->far_cfg.forw_cr_outh.stag.vlan_flag.value,
        far_tbl->far_cfg.forw_cr_outh.stag.vlan_value.data);

    switch (far_tbl->far_cfg.choose.d.flag_redirect) {
        case 1:
            {
                char ip_str[256];
                uint32_t tmp_addr = htonl(far_tbl->far_cfg.forw_redirect.ipv4_addr);

                if (NULL == inet_ntop(AF_INET, &tmp_addr, ip_str, sizeof(ip_str))) {
                    LOG(SESSION, RUNNING, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                LOG(SESSION, RUNNING, "redirect IPv4:     %s\n", ip_str);
            }
            break;

        case 2:
            {
                char ip_str[256];

                if (NULL == inet_ntop(AF_INET6, far_tbl->far_cfg.forw_redirect.ipv6_addr,
                    ip_str, sizeof(ip_str))) {
                    LOG(SESSION, RUNNING, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                LOG(SESSION, RUNNING, "redirect IPv6:     %s\n", ip_str);
            }
            break;

        case 3:
            LOG(SESSION, RUNNING, "redirect URL:      %s\n", far_tbl->far_cfg.forw_redirect.url);
            break;

        case 4:
            LOG(SESSION, RUNNING, "redirect SIP URL:  %s\n", far_tbl->far_cfg.forw_redirect.sip_url);
            break;

        case 5:
            {
                char ip_str[256];
                uint32_t tmp_addr = htonl(far_tbl->far_cfg.forw_redirect.v4_v6.ipv4);

                if (NULL == inet_ntop(AF_INET, &tmp_addr, ip_str, sizeof(ip_str))) {
                    LOG(SESSION, RUNNING, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                LOG(SESSION, RUNNING, "redirect IPv4:     %s\n", ip_str);

                if (NULL == inet_ntop(AF_INET6, far_tbl->far_cfg.forw_redirect.v4_v6.ipv6,
                    ip_str, sizeof(ip_str))) {
                    LOG(SESSION, RUNNING, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                LOG(SESSION, RUNNING, "redirect IPv6:     %s\n", ip_str);
            }
            break;
    }
    LOG(SESSION, RUNNING, "forward trans tos: %d",
        far_tbl->far_cfg.forw_trans.tos);
    LOG(SESSION, RUNNING, "forward trans mask: %d",
        far_tbl->far_cfg.forw_trans.mask);

    LOG(SESSION, RUNNING, "header enrich name: %s",
        far_tbl->far_cfg.forw_enrich.name);
    LOG(SESSION, RUNNING, "header enrich name len: %d",
        far_tbl->far_cfg.forw_enrich.name_length);
    LOG(SESSION, RUNNING, "header enrich value: %s",
        far_tbl->far_cfg.forw_enrich.value);
    LOG(SESSION, RUNNING, "header enrich value len: %d",
        far_tbl->far_cfg.forw_enrich.value_length);

#ifdef FAR_DUPL_ENABLE
    for (cnt = 0; cnt < far_tbl->far_cfg.choose.d.section_dupl_num; ++cnt) {
        LOG(SESSION, RUNNING, "dupl interface: %d",
            far_tbl->far_cfg.dupl_cfg[cnt].dupl_if);
        if (far_tbl->far_cfg.dupl_cfg[cnt].choose.d.flag_transport_level){
            LOG(SESSION, RUNNING, "dupl trans tos: %d",
                far_tbl->far_cfg.dupl_cfg[cnt].trans.tos);
            LOG(SESSION, RUNNING, "dupl trans mask: %d",
                far_tbl->far_cfg.dupl_cfg[cnt].trans.mask);
        }

        if (far_tbl->far_cfg.dupl_cfg[cnt].choose.d.flag_out_header){
            LOG(SESSION, RUNNING, "dupl create outhead type value: %d",
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.type.value);
            LOG(SESSION, RUNNING, "dupl create outhead port: %d",
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.port);
            LOG(SESSION, RUNNING, "dupl create outhead teid: %u",
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.teid);
            LOG(SESSION, RUNNING, "dupl create outhead ipv4: 0x%08x",
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.ipv4);

            LOG(SESSION, RUNNING, "dupl create outhead ipv6: "
                "0x%08x %08x %08x %08x",
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.ipv6.
                    __in6_u.__u6_addr32[0],
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.ipv6.
                    __in6_u.__u6_addr32[1],
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.ipv6.
                    __in6_u.__u6_addr32[2],
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.ipv6.
                    __in6_u.__u6_addr32[3]);
            LOG(SESSION, RUNNING, "dupl create outhead ctag flags: 0x%x, value:0x%x",
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.ctag.vlan_flag.value,
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.ctag.vlan_value.data);
            LOG(SESSION, RUNNING, "dupl create outhead stag flags: 0x%x, value:0x%x",
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.stag.vlan_flag.value,
                far_tbl->far_cfg.dupl_cfg[cnt].cr_outh.stag.vlan_value.data);
        }
    }
#endif
    LOG(SESSION, RUNNING, "far choose: ");
    LOG(SESSION, RUNNING, "entry_num: %d",
        far_tbl->far_cfg.choose.d.entry_num);
#ifdef FAR_DUPL_ENABLE
    LOG(SESSION, RUNNING, "section_dupl_num: %d",
        far_tbl->far_cfg.choose.d.section_dupl_num);
#endif
    LOG(SESSION, RUNNING, "section_bar: %d",
        far_tbl->far_cfg.choose.d.section_bar);
    LOG(SESSION, RUNNING, "flag_out_header1: %d",
        far_tbl->far_cfg.choose.d.flag_out_header1);
    LOG(SESSION, RUNNING, "flag_header_enrich: %d",
        far_tbl->far_cfg.choose.d.flag_header_enrich);
    LOG(SESSION, RUNNING, "flag_forward_policy1: %d",
        far_tbl->far_cfg.choose.d.flag_forward_policy1);
    LOG(SESSION, RUNNING, "flag_transport_level1: %d",
        far_tbl->far_cfg.choose.d.flag_transport_level1);
    LOG(SESSION, RUNNING, "flag_redirect: %d",
        far_tbl->far_cfg.choose.d.flag_redirect);
    LOG(SESSION, RUNNING, "section_forwarding: %d",
        far_tbl->far_cfg.choose.d.section_forwarding);

    LOG(SESSION, RUNNING, "bar index: %u", far_tbl->far_cfg.bar_index);
}

inline struct far_table_head *far_get_head(void)
{
    return &far_tbl_head;
}

struct far_table *far_get_table(uint32_t index)
{
    if (index < far_tbl_head.max_num)
        return &far_tbl_head.far_table[index];
    else
        return NULL;
}

struct far_table *far_public_get_table(uint32_t index)
{
    if (unlikely(index >= far_tbl_head.max_num)) {
        LOG(SESSION, ERR, "Get far table failed, index: %u invalid.", index);
        return NULL;
    }

    return &far_tbl_head.far_table[index];
}

inline uint16_t far_get_pool_id(void)
{
    return far_tbl_head.pool_id;
}

inline uint32_t far_get_max(void)
{
    return far_tbl_head.max_num;
}

inline struct fsm_audit *far_get_audit_simple(void)
{
    return &far_audit_simple;
}

inline struct fsm_audit *far_get_audit_4am(void)
{
    return &far_audit_4am;
}

static int far_id_compare(struct rb_node *node, void *key)
{
    struct far_table *far_node = (struct far_table *)node;
    uint32_t id = *(uint32_t *)key;

    if (id < far_node->far_cfg.far_id) {
        return -1;
    }
    else if (id > far_node->far_cfg.far_id) {
        return 1;
    }

    return 0;
}

struct far_table *far_table_search(struct session_t *sess, uint32_t id)
{
    struct far_table *far_tbl = NULL;
    uint32_t far_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "root is NULL.");
        return NULL;
    }

    ros_rwlock_read_lock(&sess->lock);/* lock */
    far_tbl = (struct far_table *)rbtree_search(&sess->session.far_root,
        &far_id, far_id_compare);
    ros_rwlock_read_unlock(&sess->lock);/* unlock */
    if (NULL == far_tbl) {
        LOG(SESSION, ERR,
            "The entry with id %u does not exist.", far_id);
        return NULL;
    }

    return far_tbl;
}

struct far_table *far_table_create(struct session_t *sess, uint32_t id)
{
    struct far_table_head *far_head = far_get_head();
    struct far_table *far_tbl = NULL;
    uint32_t key = 0, index = 0, far_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    if (G_FAILURE == Res_Alloc(far_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            far_head->pool_id);
        return NULL;
    }

    far_tbl = far_get_table(index);
    if (!far_tbl) {
        Res_Free(far_head->pool_id, key, index);
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return NULL;
    }
    ros_rwlock_write_lock(&far_tbl->lock);/* lock */
    memset(&far_tbl->far_cfg, 0, sizeof(comm_msg_far_config));
    memset(&far_tbl->far_priv, 0, sizeof(struct far_sp_private));

    far_tbl->far_cfg.far_id = far_id;
    ros_rwlock_write_unlock(&far_tbl->lock);/* unlock */

    ros_rwlock_write_lock(&sess->lock);/* lock */
    /* insert node to session tree root*/
    if (rbtree_insert(&sess->session.far_root, &far_tbl->far_node,
        &far_id, far_id_compare) < 0) {
        ros_rwlock_write_unlock(&sess->lock);/* unlock */
        Res_Free(far_head->pool_id, key, index);
        LOG(SESSION, ERR,
            "rb tree insert failed, id: %u.", far_id);
        return NULL;
    }
    ros_rwlock_write_unlock(&sess->lock);/* unlock */

    ros_atomic32_add(&far_head->use_num, 1);

    LOG(SESSION, RUNNING, "create far %u success.", far_id);

    return far_tbl;
}

struct far_table *far_table_create_local(uint32_t id)
{
    struct far_table_head *far_head = far_get_head();
    struct far_table *far_tbl = NULL;
    uint32_t key = 0, index = 0, far_id = id;

    if (G_FAILURE == Res_Alloc(far_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            far_head->pool_id);
        return NULL;
    }

    far_tbl = far_get_table(index);
    if (!far_tbl) {
        Res_Free(far_head->pool_id, key, index);
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return NULL;
    }
    ros_rwlock_write_lock(&far_tbl->lock);/* lock */
    memset(&far_tbl->far_cfg, 0, sizeof(comm_msg_far_config));
    memset(&far_tbl->far_priv, 0, sizeof(struct far_sp_private));

    far_tbl->far_cfg.far_id = far_id;
    ros_rwlock_write_unlock(&far_tbl->lock);/* unlock */

    ros_atomic32_add(&far_head->use_num, 1);

    LOG(SESSION, RUNNING, "create far %u success.", far_id);

    return far_tbl;
}

inline void far_config_hton(comm_msg_far_config *far_cfg)
{
#ifdef FAR_DUPL_ENABLE
    uint8_t cnt;
#endif

    far_cfg->far_id = htonl(far_cfg->far_id);
    far_cfg->choose.value = htons(far_cfg->choose.value);
    far_cfg->forw_cr_outh.type.value = htons(far_cfg->forw_cr_outh.type.value);
    far_cfg->forw_cr_outh.port = htons(far_cfg->forw_cr_outh.port);
    far_cfg->forw_cr_outh.teid = htonl(far_cfg->forw_cr_outh.teid);
    far_cfg->forw_cr_outh.ipv4 = htonl(far_cfg->forw_cr_outh.ipv4);
    far_cfg->forw_cr_outh.ctag.vlan_value.data =
        htons(far_cfg->forw_cr_outh.ctag.vlan_value.data);
    far_cfg->forw_cr_outh.stag.vlan_value.data =
        htons(far_cfg->forw_cr_outh.stag.vlan_value.data);
    switch (far_cfg->choose.d.flag_redirect) {
        case 1:
            far_cfg->forw_redirect.ipv4_addr = htonl(far_cfg->forw_redirect.ipv4_addr);
            break;

        case 5:
            far_cfg->forw_redirect.v4_v6.ipv4 = htonl(far_cfg->forw_redirect.v4_v6.ipv4);
            break;
    }
    far_cfg->forw_enrich.name_length = htons(far_cfg->forw_enrich.name_length);
    far_cfg->forw_enrich.value_length = htons(far_cfg->forw_enrich.value_length);

#ifdef FAR_DUPL_ENABLE
    for (cnt = 0; cnt < far_cfg->choose.d.section_dupl_num; ++cnt) {
        far_cfg->dupl_cfg[cnt].cr_outh.type.value = htons(
            far_cfg->dupl_cfg[cnt].cr_outh.type.value);
        far_cfg->dupl_cfg[cnt].cr_outh.port =
            htons(far_cfg->dupl_cfg[cnt].cr_outh.port);
        far_cfg->dupl_cfg[cnt].cr_outh.teid =
            htonl(far_cfg->dupl_cfg[cnt].cr_outh.teid);
        far_cfg->dupl_cfg[cnt].cr_outh.ipv4 =
            htonl(far_cfg->dupl_cfg[cnt].cr_outh.ipv4);
        far_cfg->dupl_cfg[cnt].cr_outh.ctag.vlan_value.data =
            htons(far_cfg->dupl_cfg[cnt].cr_outh.ctag.vlan_value.data);
        far_cfg->dupl_cfg[cnt].cr_outh.stag.vlan_value.data =
            htons(far_cfg->dupl_cfg[cnt].cr_outh.stag.vlan_value.data);
    }
#endif
    far_cfg->bar_index = htonl(far_cfg->bar_index);
}

inline void far_config_ntoh(comm_msg_far_config *far_cfg)
{
#ifdef FAR_DUPL_ENABLE
    uint8_t cnt;
#endif

    far_cfg->far_id = ntohl(far_cfg->far_id);
    far_cfg->choose.value = ntohs(far_cfg->choose.value);
    far_cfg->forw_cr_outh.type.value = ntohs(far_cfg->forw_cr_outh.type.value);
    far_cfg->forw_cr_outh.port = ntohs(far_cfg->forw_cr_outh.port);
    far_cfg->forw_cr_outh.teid = ntohl(far_cfg->forw_cr_outh.teid);
    far_cfg->forw_cr_outh.ipv4 = ntohl(far_cfg->forw_cr_outh.ipv4);
    far_cfg->forw_cr_outh.ctag.vlan_value.data =
        ntohs(far_cfg->forw_cr_outh.ctag.vlan_value.data);
    far_cfg->forw_cr_outh.stag.vlan_value.data =
        ntohs(far_cfg->forw_cr_outh.stag.vlan_value.data);
    switch (far_cfg->choose.d.flag_redirect) {
        case 1:
            far_cfg->forw_redirect.ipv4_addr = ntohl(far_cfg->forw_redirect.ipv4_addr);
            break;

        case 5:
            far_cfg->forw_redirect.v4_v6.ipv4 = ntohl(far_cfg->forw_redirect.v4_v6.ipv4);
            break;
    }

#ifdef FAR_DUPL_ENABLE
    for (cnt = 0; cnt < far_cfg->choose.d.section_dupl_num; ++cnt) {
        far_cfg->dupl_cfg[cnt].cr_outh.type.value = ntohs(
            far_cfg->dupl_cfg[cnt].cr_outh.type.value);
        far_cfg->dupl_cfg[cnt].cr_outh.port =
            ntohs(far_cfg->dupl_cfg[cnt].cr_outh.port);
        far_cfg->dupl_cfg[cnt].cr_outh.teid =
            ntohl(far_cfg->dupl_cfg[cnt].cr_outh.teid);
        far_cfg->dupl_cfg[cnt].cr_outh.ipv4 =
            ntohl(far_cfg->dupl_cfg[cnt].cr_outh.ipv4);
        far_cfg->dupl_cfg[cnt].cr_outh.ctag.vlan_value.data =
            ntohs(far_cfg->dupl_cfg[cnt].cr_outh.ctag.vlan_value.data);
        far_cfg->dupl_cfg[cnt].cr_outh.stag.vlan_value.data =
            ntohs(far_cfg->dupl_cfg[cnt].cr_outh.stag.vlan_value.data);
    }
#endif
    far_cfg->bar_index = ntohl(far_cfg->bar_index);
}

int far_fp_add_or_mod(uint32_t *index_arr, uint32_t index_num, uint8_t is_add, int fd)
{
    uint8_t                     buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                    buf_len = 0;
    comm_msg_header_t           *msg;
    comm_msg_rules_ie_t         *ie = NULL;
    struct far_table            *entry = NULL;
    uint32_t                    cnt = 0, data_cnt = 0;
    comm_msg_far_ie_data        *ie_data = NULL;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_far_ie_data);

    if (unlikely(0 == index_num)) {
        LOG(SESSION, ERR, "parameter is invalid, index number: %u.",
            index_num);
        return -1;
    }

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    if (is_add) {
        ie->cmd = htons(EN_COMM_MSG_UPU_FAR_ADD);
    } else {
        ie->cmd = htons(EN_COMM_MSG_UPU_FAR_MOD);
    }
    ie_data     = (comm_msg_far_ie_data *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        entry = far_get_table(index_arr[cnt]);
        if (NULL == entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", index_arr[cnt]);
            continue;
        }

        ie_data[data_cnt].index = htonl(entry->index);
        ros_memcpy(&ie_data[data_cnt].cfg, &entry->far_cfg, sizeof(comm_msg_far_config));
        far_config_hton(&ie_data[data_cnt].cfg);
        ++data_cnt;

        if (data_cnt >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_far_ie_data) * data_cnt;
            ie->rules_num = htonl(data_cnt);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > session_msg_send_to_fp((char *)buf, buf_len, fd)) {
                LOG(UPC, ERR, "Send buffer to backend failed.");
                return -1;
            }
            data_cnt = 0;
        }
    }

    if (data_cnt > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_far_ie_data) * data_cnt;
        ie->rules_num = htonl(data_cnt);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > session_msg_send_to_fp((char *)buf, buf_len, fd)) {
            LOG(UPC, ERR, "Send buffer to backend failed.");
            return -1;
        }
        data_cnt = 0;
    }

    return 0;
}

int far_insert(struct session_t *sess, session_far_create *parse_far_arr,
    uint32_t far_num, uint32_t *fail_id)
{
    struct far_table *far_tbl = NULL;
	session_far_create *far_arr = NULL;
    uint32_t index_cnt = 0;

    if (NULL == sess || (NULL == parse_far_arr && far_num)) {
        LOG(SESSION, ERR, "insert failed, sess(%p), parse_far_arr(%p),"
			" far_num: %u.", sess, parse_far_arr, far_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < far_num; ++index_cnt) {
		//取far_id最高位，如果是1则表示是预定义规则，在本地配置
		far_arr=(session_far_create *)parse_far_arr;
		if (far_arr[index_cnt].far_id & 0x80000000)
			continue;

        far_tbl = far_add(sess, parse_far_arr, index_cnt, fail_id);
        if (NULL == far_tbl) {
            LOG(SESSION, ERR, "far add failed.");
            return -1;
        }

        if (far_tbl->far_priv.bar_id_present) {
            struct bar_table *bar_tbl =
                bar_table_search(sess, far_tbl->far_priv.bar_id);
            if (NULL == bar_tbl) {
                uint32_t rm_far_id = far_tbl->far_cfg.far_id;

                far_remove(sess, &rm_far_id, 1, NULL);

                LOG(SESSION, ERR, "search bar table failed, bar id: %d.",
                    far_tbl->far_priv.bar_id);
                *fail_id = rm_far_id;
                return -1;
            }
            ros_rwlock_write_lock(&far_tbl->lock);  /* lock */
            far_tbl->far_cfg.choose.d.section_bar = 1;
            far_tbl->far_cfg.bar_index = bar_tbl->index;
            ros_rwlock_write_unlock(&far_tbl->lock);  /* unlock */
        }
    }

    return 0;
}

int far_table_delete_local(uint32_t *arr, uint8_t index_num)
{
    struct far_table_head *far_head = far_get_head();
    struct far_table *far_tbl = NULL;
	uint32_t index_arr[MAX_FAR_NUM], index_cnt = 0;
    uint32_t success_cnt = 0;

	if (NULL == arr) {
        LOG(SESSION, ERR, "far remove failed, arr(%p)",arr);
        return -1;
    }

    for (index_cnt = 0; index_cnt < index_num; ++index_cnt) {
		far_tbl = far_get_table(arr[index_cnt]);

        ros_rwlock_write_lock(&far_tbl->lock);/* lock */
        if (far_tbl->far_cfg.choose.d.flag_out_header1) {
            if (0 > session_gtpu_delete(&far_tbl->far_cfg.forw_cr_outh)) {
                LOG(SESSION, ERR, "far delete gtpu entry failed.");
                /* don't return first */
            }
            if (0 > session_peer_fteid_delete(&far_tbl->far_cfg.forw_cr_outh)) {
                LOG(SESSION, ERR, "far delete peer f-teid entry failed.");
                /* don't return first */
            }
        }
	    ros_atomic32_sub(&far_head->use_num, 1);
        Res_Free(far_head->pool_id, 0, far_tbl->index);
        ros_rwlock_write_unlock(&far_tbl->lock);/* unlock */

		index_arr[success_cnt] = far_tbl->index;
		++success_cnt;
	}

    if (success_cnt) {
	    if (-1 == rules_fp_del(index_arr, success_cnt, EN_COMM_MSG_UPU_FAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
	        LOG(SESSION, ERR, "fp remove failed.");
	    }
    }

    return 0;
}

int far_remove(struct session_t *sess, uint32_t *id_arr, uint8_t id_num, uint32_t *ret_index_arr)
{
    struct far_table_head *far_head = far_get_head();
    struct far_table *far_tbl = NULL;
	uint32_t index_arr[MAX_URR_NUM], index_cnt = 0;

    if (NULL == sess || (NULL == id_arr && id_num)) {
        LOG(SESSION, ERR, "remove failed, sess(%p), id_arr(%p),"
			" id_num: %d.", sess, id_arr, id_num);
        return -1;
    }

	for (index_cnt = 0; index_cnt < id_num; ++index_cnt) {
	    ros_rwlock_write_lock(&sess->lock);/* lock */
	    far_tbl = (struct far_table *)rbtree_delete(&sess->session.far_root,
	        &id_arr[index_cnt], far_id_compare);
	    ros_rwlock_write_unlock(&sess->lock);/* unlock */
	    if (NULL == far_tbl) {
	        LOG(SESSION, ERR, "remove failed, not exist, id: %u.",
				id_arr[index_cnt]);
            return -1;
	    }

        ros_rwlock_write_lock(&far_tbl->lock);/* lock */
        if (far_tbl->far_cfg.choose.d.flag_out_header1) {
            if (0 > session_gtpu_delete(&far_tbl->far_cfg.forw_cr_outh)) {
                LOG(SESSION, ERR, "far delete gtpu entry failed.");
                /* don't return first */
            }
            if (0 > session_peer_fteid_delete(&far_tbl->far_cfg.forw_cr_outh)) {
                LOG(SESSION, ERR, "far delete peer f-teid entry failed.");
                /* don't return first */
            }
        }
	    ros_atomic32_sub(&far_head->use_num, 1);
        Res_Free(far_head->pool_id, 0, far_tbl->index);
        ros_rwlock_write_unlock(&far_tbl->lock);/* unlock */

		index_arr[index_cnt] = far_tbl->index;
        if (NULL != ret_index_arr) {
            ret_index_arr[index_cnt] = far_tbl->index;
        }
	}

    if (NULL == ret_index_arr && index_cnt) {
	    if (-1 == rules_fp_del(index_arr, index_cnt, EN_COMM_MSG_UPU_FAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
	        LOG(SESSION, ERR, "fp remove failed.");
	    }
    }

    return 0;
}

int far_gtpu_tunnel_add(struct pfcp_session *sess_cfg,
    struct far_table *far_tbl)
{
    comm_msg_outh_cr_t *ohc = &far_tbl->far_cfg.forw_cr_outh;

    switch (ohc->type.value) {
        case 0x100:
            if (0 > session_gtpu_insert(&ohc->ipv4, SESSION_IP_V4,
                far_tbl->far_cfg.forw_if, sess_cfg->node_index)) {
                LOG(SESSION, ERR, "insert gtpu entry failed.");
                return -1;
            }
            if (0 > session_peer_fteid_insert(&ohc->ipv4, SESSION_IP_V4,
                ohc->teid, sess_cfg)) {
                LOG(SESSION, ERR, "insert peer f-teid entry failed.");
                return -1;
            }
            break;

        case 0x200:
            if (0 > session_gtpu_insert(ohc->ipv6.s6_addr, SESSION_IP_V6,
                far_tbl->far_cfg.forw_if, sess_cfg->node_index)) {
                LOG(SESSION, ERR, "insert gtpu entry failed.");
                return -1;
            }
            if (0 > session_peer_fteid_insert(ohc->ipv6.s6_addr, SESSION_IP_V6,
                ohc->teid, sess_cfg)) {
                LOG(SESSION, ERR, "insert peer f-teid entry failed.");
                return -1;
            }
            break;

        case 0x300:
            if (0 > session_gtpu_insert(&ohc->ipv4, SESSION_IP_V4,
                far_tbl->far_cfg.forw_if, sess_cfg->node_index)) {
                LOG(SESSION, ERR, "insert gtpu entry failed.");
                return -1;
            }
            if (0 > session_peer_fteid_insert(&ohc->ipv4, SESSION_IP_V4,
                ohc->teid, sess_cfg)) {
                LOG(SESSION, ERR, "insert peer f-teid entry failed.");
                return -1;
            }

            if (0 > session_gtpu_insert(ohc->ipv6.s6_addr, SESSION_IP_V6,
                far_tbl->far_cfg.forw_if, sess_cfg->node_index)) {
                LOG(SESSION, ERR, "insert gtpu entry failed.");
                return -1;
            }
            if (0 > session_peer_fteid_insert(ohc->ipv6.s6_addr, SESSION_IP_V6,
                ohc->teid, sess_cfg)) {
                LOG(SESSION, ERR, "insert peer f-teid entry failed.");
                return -1;
            }
            break;

        default:
            return 0;
    }

    return 0;
}

/* Send endMarker packet and delete gtpu entry */
int far_gtpu_em_and_del(uint32_t node_index, comm_msg_outh_cr_t *ohc,
    uint8_t SNDEM)
{
    session_up_features up_features = {.value = upc_get_up_features()};

    if (up_features.d.EMPU && SNDEM) {
        if (0 > session_gtpu_end_marker(ohc)) {
            LOG(SESSION, ERR, "Send endMarker failed.");
            return -1;
        }
    }

    if (0 > session_gtpu_delete(ohc)) {
        LOG(SESSION, ERR, "Delete gtpu entry failed.");
        return -1;
    }

    if (0 > session_peer_fteid_delete(ohc)) {
        LOG(SESSION, ERR, "Delete peer f-teid entry failed.");
        return -1;
    }

    return 0;
}

int far_modify(struct session_t *sess, session_far_update *parse_far_arr,
    uint32_t far_num, uint32_t *fail_id)
{
    struct far_table *far_tbl = NULL;
    uint32_t index_arr[MAX_FAR_NUM], index_cnt = 0;
	uint32_t success_cnt = 0;

    if (NULL == sess || (NULL == parse_far_arr && far_num)) {
        LOG(SESSION, ERR, "insert failed, sess(%p), parse_far_arr(%p),"
			" far_num: %u.", sess, parse_far_arr, far_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < far_num; ++index_cnt) {

        far_tbl = far_update(sess, parse_far_arr, index_cnt, fail_id);
        if (NULL == far_tbl) {
            LOG(SESSION, ERR, "far update failed.");
            return -1;
        }

        index_arr[success_cnt] = far_tbl->index;
		++success_cnt;
    }

    if (success_cnt) {
        if (0 > far_fp_add_or_mod(index_arr, success_cnt, 0, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "fp modify failed.");
        }
    }
    return 0;
}

uint32_t far_sum(void)
{
    struct far_table_head *far_head = far_get_head();
    uint32_t entry_sum = 0;

    entry_sum = ros_atomic32_read(&far_head->use_num);

    return entry_sum;
}

/* clear all far rules releated the current pfcp session */
int far_clear(struct session_t *sess,
	uint8_t fp_sync, struct session_rules_index * rules)
{
    struct far_table_head *far_head = far_get_head();
    struct far_table *far_tbl = NULL;
    uint32_t id = 0;
    uint32_t far_index[MAX_FAR_NUM], far_cnt = 0;

    if (NULL == sess || (0 == fp_sync && NULL == rules)) {
        LOG(SESSION, ERR, "clear failed, root is null.");
        return -1;
    }

    ros_rwlock_write_lock(&sess->lock);/* lock */
    far_tbl = (struct far_table *)rbtree_first(&sess->session.far_root);
    while (NULL != far_tbl) {
        id = far_tbl->far_cfg.far_id;
        far_tbl = (struct far_table *)rbtree_delete(&sess->session.far_root,
            &id, far_id_compare);
        if (NULL == far_tbl) {
            LOG(SESSION, ERR, "clear failed, id: %u.", id);
            far_tbl = (struct far_table *)rbtree_next(&far_tbl->far_node);
            continue;
        }
        ros_rwlock_write_lock(&far_tbl->lock);/* lock */
        if (far_tbl->far_cfg.choose.d.flag_out_header1) {
            if (0 > session_gtpu_delete(&far_tbl->far_cfg.forw_cr_outh)) {
                LOG(SESSION, ERR, "far delete gtpu entry failed.");
                /* don't return first */
            }
            if (0 > session_peer_fteid_delete(&far_tbl->far_cfg.forw_cr_outh)) {
                LOG(SESSION, ERR, "far delete peer f-teid entry failed.");
                /* don't return first */
            }
        }

        Res_Free(far_head->pool_id, 0, far_tbl->index);
        ros_atomic32_sub(&far_head->use_num, 1);
        ros_rwlock_write_unlock(&far_tbl->lock);/* unlock */

        if (fp_sync) {
            far_index[far_cnt] = far_tbl->index;
            ++far_cnt;
        } else {
            rules->index_arr[EN_RULE_FAR][rules->index_num[EN_RULE_FAR]] =
                far_tbl->index;
            ++rules->index_num[EN_RULE_FAR];

			if (rules->index_num[EN_RULE_FAR] >=
                SESSION_RULE_INDEX_LIMIT) {
				rules->overflow.d.rule_far = 1;
			}
        }

        far_tbl = (struct far_table *)rbtree_next(&far_tbl->far_node);
    }
    ros_rwlock_write_unlock(&sess->lock);/* unlock */

    if (fp_sync) {
		if (far_cnt) {
	        if (-1 == rules_fp_del(far_index, far_cnt, EN_COMM_MSG_UPU_FAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
	            LOG(SESSION, ERR, "fp del failed.");
	            return -1;
	        }
		}
    }

    return 0;
}

uint32_t far_check_all(comm_msg_ie_t *ie, int fd)
{
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    struct far_table *entry = NULL;
    comm_msg_far_ie_data *ie_data = NULL;
    uint32_t cnt = 0;
    uint32_t mod_arr[ONCE_CHANGE_NUMBER_MAX], mod_num = 0;

    if (NULL == ie) {
        LOG(SESSION, ERR, "parameter is invalid, ie(%p).",
            ie);
        return -1;
    }

    ie_data = (comm_msg_far_ie_data *)rule_ie->data;
    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t index = ntohl(ie_data[cnt].index);

        if (G_FALSE == Res_IsAlloced(far_get_pool_id(), 0, index)) {
            LOG(SESSION, ERR, "entry is invalid, index: %u.",
                index);
            continue;
        }

        far_config_ntoh(&ie_data[cnt].cfg);
        entry = far_get_table(index);
        if (!entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", index);
            continue;
        }

        ros_rwlock_read_lock(&entry->lock);// lock
        if (ros_memcmp(&ie_data[cnt].cfg, &entry->far_cfg, sizeof(comm_msg_far_config))) {
            ros_rwlock_read_unlock(&entry->lock);// unlock
            if (mod_num == ONCE_CHANGE_NUMBER_MAX) {
                if (0 > far_fp_add_or_mod(mod_arr, mod_num, 0, fd)) {
                    LOG(SESSION, ERR, "Modify fpu entry failed.");
                    return -1;
                }
                mod_num = 0;
            }
            mod_arr[mod_num] = index;
            ++mod_num;
        } else {
            ros_rwlock_read_unlock(&entry->lock);// unlock
        }
    }

    if (mod_num > 0) {
        if (0 > far_fp_add_or_mod(mod_arr, mod_num, 0, fd)) {
            LOG(SESSION, ERR, "Modify fpu entry failed.");
            return -1;
        }
    }

    return 0;
}

int far_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd)
{
    uint32_t field_num = 0, cnt = 0, fp_del = 0, fp_add = 0, diff = 0;
    uint32_t remainder = 0;
    uint32_t del_arr[ONCE_CHANGE_NUMBER_MAX], del_num = 0;
    uint32_t add_arr[ONCE_CHANGE_NUMBER_MAX], add_num = 0;
    uint8_t val_data[SERVICE_BUF_TOTAL_LEN];
    comm_msg_entry_val_config_t *sp_val_cfg = (comm_msg_entry_val_config_t *)val_data;

    LOG(SESSION, RUNNING, "validity action start.");

    if (NULL == fp_val_cfg) {
        LOG(SESSION, ERR, "Abnormal parameter, fp_val_cfg(%p).", fp_val_cfg);
        return -1;
    }

    if (0 > session_val_ntoh(fp_val_cfg)) {
        LOG(SESSION, ERR, "Abnormal parameters, invalid 'val config'.");
        return -1;
    }

    if (G_SUCCESS != Res_GetRangeField(far_get_pool_id(), 0,
        fp_val_cfg->start, fp_val_cfg->entry_num, sp_val_cfg->data)) {
        LOG(SESSION, ERR, "Get range field failed, start: %u, entry_num: %u.",
            fp_val_cfg->start, fp_val_cfg->entry_num);
        return -1;
    }

    field_num = fp_val_cfg->entry_num >> RES_PART_LEN_BIT;
    for (cnt = 0; cnt < field_num; ++cnt) {
        diff = sp_val_cfg->data[cnt] ^ fp_val_cfg->data[cnt];
        if (diff) {
            uint32_t start_bit = fp_val_cfg->start + (cnt << RES_PART_LEN_BIT);

            fp_add = (sp_val_cfg->data[cnt] & diff) ^ diff;
            fp_del = (fp_val_cfg->data[cnt] & diff) ^ diff;

            if (fp_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_FAR_DEL, fd);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_del,
                    del_arr, &del_num);
            }
            if (fp_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    far_fp_add_or_mod(add_arr, add_num, 1, fd);
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_add,
                    add_arr, &add_num);
            }
        }
    }

    remainder = fp_val_cfg->entry_num & RES_PART_LEN_MASK;
    if (remainder) {
        diff = sp_val_cfg->data[cnt] ^ fp_val_cfg->data[cnt];
        diff &= ~((1 << (RES_PART_LEN - remainder)) - 1);
        if (diff) {
            uint32_t start_bit = fp_val_cfg->start + (cnt << RES_PART_LEN_BIT);

            fp_add = (sp_val_cfg->data[cnt] & diff) ^ diff;
            fp_del = (fp_val_cfg->data[cnt] & diff) ^ diff;

            if (fp_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_FAR_DEL, fd);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_del,
                    del_arr, &del_num);
            }
            if (fp_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    far_fp_add_or_mod(add_arr, add_num, 1, fd);
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_add,
                    add_arr, &add_num);
            }
        }
    }

    if (del_num > 0) {
        rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_FAR_DEL, fd);
    }
    if (add_num > 0) {
        far_fp_add_or_mod(add_arr, add_num, 1, fd);
    }

    return 0;
}

int64_t far_table_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct far_table *far_tbl = NULL;
    uint32_t max_num = 0;
    int64_t size = 0;

    if (0 == session_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, session_num: %u.", session_num);
        return -1;
    }

    max_num = session_num * MAX_FAR_NUM;
    size = sizeof(struct far_table) * max_num;
    far_tbl = ros_malloc(size);
    if (NULL == far_tbl) {
        LOG(SESSION, ERR,
            "init pdr failed, no enough memory, max number: %u ="
            " session_num: %u * %d.", max_num,
            session_num, MAX_FAR_NUM);
        return -1;
    }
    ros_memset(far_tbl, 0, sizeof(struct far_table) * max_num);

    for (index = 0; index < max_num; ++index) {
        far_tbl[index].index = index;
        ros_rwlock_init(&far_tbl[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        return -1;
    }

    far_tbl_head.pool_id = pool_id;
    far_tbl_head.far_table = far_tbl;
    far_tbl_head.max_num = max_num;
	ros_rwlock_init(&far_tbl_head.lock);
    ros_atomic32_set(&far_tbl_head.use_num, 0);

    /* add orphan far entry */
    if (G_FAILURE == Res_AllocTarget(far_tbl_head.pool_id, 0, 0)) {
        LOG(SESSION, ERR, "create orphan far failed.");
        return -1;
    }
    far_tbl[0].far_cfg.far_id = 0;
    far_tbl[0].far_cfg.action.d.drop = 1;
    ros_atomic32_add(&far_tbl_head.use_num, 1);

    /* init 4am audit */
    if (0 > audit_4am_init(&far_audit_4am, EN_FAR_AUDIT)) {
        LOG(SESSION, ERR, "audit_4am_init failed.");
        return -1;
    }

    /* init sample audit */
    if (0 > audit_simple_init(&far_audit_simple, EN_FAR_AUDIT)) {
        LOG(SESSION, ERR, "Simple audit init failed.");
        return -1;
    }

    LOG(SESSION, MUST, "far init success.");
    return size;
}

