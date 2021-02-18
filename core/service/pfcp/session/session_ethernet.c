/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "session_ethernet.h"


struct session_ethernet_table g_session_eth_table;

static inline struct session_ethernet_table *se_get_table(void)
{
    return &g_session_eth_table;
}

static inline struct session_ethernet_entry *se_get_entry(uint32_t index)
{
    return &g_session_eth_table.eth_entry[index];
}

static int se_key_compare(struct rb_node *node, void *key)
{
    struct session_ethernet_entry *eth_entry = (struct session_ethernet_entry *)node;

    return memcmp(eth_entry->ue_mac, key, ETH_ALEN);
}

int se_entry_insert(struct session_t *sess, uint8_t *ue_mac)
{
    struct session_ethernet_table *eth_tbl = se_get_table();
    struct session_ethernet_entry *eth_entry;
    uint32_t key, index;

    if (NULL == sess || NULL == ue_mac) {
        LOG(SESSION, ERR, "Abnormal parameters, sess(%p), ue_mac(%p)",
            sess, ue_mac);
        return -1;
    }

    LOG(SESSION, RUNNING, "Insert UE MAC address(%02x:%02x:%02x:%02x:%02x:%02x) to session[%u]",
        ue_mac[0], ue_mac[1], ue_mac[2], ue_mac[3], ue_mac[4], ue_mac[5], sess->index);

    if (G_FAILURE == Res_Alloc(eth_tbl->pool_id, &key, &index, EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR, "Session ethernet resource alloc fail.");
        return -1;
    }
    eth_entry = se_get_entry(index);

    ros_rwlock_write_lock(&eth_entry->lock); /* lock */
    ros_memcpy(eth_entry->ue_mac, ue_mac, ETH_ALEN);
    eth_entry->session = sess;
    ros_rwlock_write_unlock(&eth_entry->lock); /* unlock */

    ros_rwlock_write_lock(&eth_tbl->lock); /* lock */
    /* Insert golbel tree */
    if (0 > rbtree_insert(&eth_tbl->eth_root, &eth_entry->eth_node, eth_entry->ue_mac,
        se_key_compare)) {
        LOG(SESSION, ERR, "Session ethernet insert to RB tree fail.");
        Res_Free(eth_tbl->pool_id, key, index);
        ros_rwlock_write_unlock(&eth_tbl->lock); /* unlock */

        return -1;
    }

    /* Add session list */
    dl_list_add_tail(&sess->ue_mac_head, &eth_entry->sess_node);

    ros_rwlock_write_unlock(&eth_tbl->lock); /* unlock */

    return 0;
}

int se_entry_delete(struct session_t *sess)
{
    struct session_ethernet_table *eth_tbl = se_get_table();
    struct session_ethernet_entry *eth_entry;
    struct dl_list *pos, *next;

    if (NULL == sess) {
        LOG(SESSION, ERR, "Abnormal parameters, sess(%p)", sess);
        return -1;
    }

    ros_rwlock_write_lock(&eth_tbl->lock); /* lock */

    dl_list_for_each_safe(pos, next, &sess->ue_mac_head) {
        eth_entry = (struct session_ethernet_entry *)container_of(pos,
                struct session_ethernet_entry, sess_node);

        rbtree_erase(&eth_entry->eth_node, &eth_tbl->eth_root);
        dl_list_del(&eth_entry->sess_node);

        eth_entry->session = NULL;
        Res_Free(eth_tbl->pool_id, 0, eth_entry->index);
    }

    ros_rwlock_write_unlock(&eth_tbl->lock); /* unlock */

    return 0;
}

struct session_ethernet_entry *se_entry_search(uint8_t *ue_mac)
{
    struct session_ethernet_table *eth_tbl = se_get_table();
    struct session_ethernet_entry *eth_entry;

    if (NULL == ue_mac) {
        LOG(SESSION, ERR, "Abnormal parameters, ue_mac(%p)", ue_mac);
        return NULL;
    }

    LOG(SESSION, RUNNING, "Search UE MAC address(%02x:%02x:%02x:%02x:%02x:%02x)",
        ue_mac[0], ue_mac[1], ue_mac[2], ue_mac[3], ue_mac[4], ue_mac[5]);

    ros_rwlock_write_lock(&eth_tbl->lock); /* lock */
    eth_entry = (struct session_ethernet_entry *)rbtree_search(&eth_tbl->eth_root, ue_mac, se_key_compare);
    ros_rwlock_write_unlock(&eth_tbl->lock); /* unlock */
    if (NULL == eth_entry) {
        LOG(SESSION, RUNNING,
            "Session UE MAC address(%02x:%02x:%02x:%02x:%02x:%02x) search fail, no such entry.",
            ue_mac[0], ue_mac[1], ue_mac[2], ue_mac[3], ue_mac[4], ue_mac[5]);
    }

    return eth_entry;
}

int64_t se_table_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct session_ethernet_entry *eth_entry = NULL;
    uint32_t max_num = 0;
    int64_t size = 0;

    if (0 == session_num) {
        LOG(SESSION, ERR, "Abnormal parameter, session_num: %u.", session_num);
        return -1;
    }

    max_num = session_num * MAX_PDR_NUM;
    size = sizeof(struct session_ethernet_entry) * max_num;
    eth_entry = ros_malloc(size);
    if (NULL == eth_entry) {
        LOG(SESSION, ERR,
            "Init session ethernet table failed, no enough memory, max number: %u ="
            " session_num: %u * %d.", max_num,
            session_num, MAX_PDR_NUM);
        return -1;
    }
    ros_memset(eth_entry, 0, size);

    for (index = 0; index < max_num; ++index) {
        eth_entry[index].index = index;
        ros_rwlock_init(&eth_entry[index].lock);
        dl_list_init(&eth_entry[index].sess_node);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Create resource pool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR, "Add resource Section failed.");
        return -1;
    }

    g_session_eth_table.eth_root    = RB_ROOT_INIT_VALUE;
    g_session_eth_table.pool_id     = pool_id;
    g_session_eth_table.eth_entry   = eth_entry;
    g_session_eth_table.max_num     = max_num;
	ros_rwlock_init(&g_session_eth_table.lock);

    LOG(SESSION, MUST, "session ethernet table init success.");

    return size;
}


