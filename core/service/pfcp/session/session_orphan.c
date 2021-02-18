/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session.h"
#include "pdr_mgmt.h"
#include "session_instance.h"
#include "session_orphan.h"
#include "mar_mgmt.h"
#include "session_match.h"

struct sp_orphan_table_head g_orphan_table_head;

static void session_orphan_recycle(void);

static inline struct sp_orphan_table_head *session_orphan_get_head(void)
{
    return &g_orphan_table_head;
}

static inline struct sp_fast_entry *session_orphan_get_entry(
    uint32_t index)
{
    return &g_orphan_table_head.fast_entry[index];
}

static int session_orphan_fteid_v4_compare(struct rb_node *node, void *key)
{
    struct sp_fast_entry *node_tbl = (struct sp_fast_entry *)node;
    struct pdr_key *key_cfg = (struct pdr_key *)key;

    if (node_tbl->key.ip_addr.ipv4 < key_cfg->ip_addr.ipv4) {
        return -1;
    } else if (node_tbl->key.ip_addr.ipv4 > key_cfg->ip_addr.ipv4) {
        return 1;
    }

    if (node_tbl->key.teid < key_cfg->teid) {
        return -1;
    } else if (node_tbl->key.teid > key_cfg->teid) {
        return 1;
    }

    return 0;
}

static int session_orphan_fteid_v6_compare(struct rb_node *node, void *key)
{
    struct sp_fast_entry *node_tbl = (struct sp_fast_entry *)node;
    struct pdr_key *key_cfg = (struct pdr_key *)key;

    if (node_tbl->key.ip_addr.ipv6.d.key1 < key_cfg->ip_addr.ipv6.d.key1) {
        return -1;
    } else if (node_tbl->key.ip_addr.ipv6.d.key1 >
        key_cfg->ip_addr.ipv6.d.key1) {
        return 1;
    }

    if (node_tbl->key.ip_addr.ipv6.d.key2 < key_cfg->ip_addr.ipv6.d.key2) {
        return -1;
    } else if (node_tbl->key.ip_addr.ipv6.d.key2 >
        key_cfg->ip_addr.ipv6.d.key2) {
        return 1;
    }

    if (node_tbl->key.teid < key_cfg->teid) {
        return -1;
    } else if (node_tbl->key.teid > key_cfg->teid) {
        return 1;
    }

    return 0;
}

static int session_orphan_ueip_v4_compare(struct rb_node *node, void *key)
{
    struct sp_fast_entry *node_tbl = (struct sp_fast_entry *)node;
    struct pdr_key *key_cfg = (struct pdr_key *)key;

    if (node_tbl->key.ip_addr.ipv4 < key_cfg->ip_addr.ipv4) {
        return -1;
    } else if (node_tbl->key.ip_addr.ipv4 > key_cfg->ip_addr.ipv4) {
        return 1;
    }

    return 0;
}

static int session_orphan_ueip_v6_compare(struct rb_node *node, void *key)
{
    struct sp_fast_entry *node_tbl = (struct sp_fast_entry *)node;
    struct pdr_key *key_cfg = (struct pdr_key *)key;

    if (node_tbl->key.ip_addr.ipv6.d.key1 < key_cfg->ip_addr.ipv6.d.key1) {
        return -1;
    } else if (node_tbl->key.ip_addr.ipv6.d.key1 >
        key_cfg->ip_addr.ipv6.d.key1) {
        return 1;
    }

    if (node_tbl->key.ip_addr.ipv6.d.key2 < key_cfg->ip_addr.ipv6.d.key2) {
        return -1;
    } else if (node_tbl->key.ip_addr.ipv6.d.key2 >
        key_cfg->ip_addr.ipv6.d.key2) {
        return 1;
    }

    return 0;
}

static int session_orphan_ue_mac_compare(struct rb_node *node, void *key)
{
    struct sp_fast_entry *node_tbl = (struct sp_fast_entry *)node;

    return memcmp(node_tbl->ue_mac, key, ETH_ALEN);
}

static struct sp_fast_entry *session_orphan_fast_alloc(uint32_t fast_id,
    void *p_key, uint8_t pkt_type)
{
    struct sp_orphan_table_head *orphan_head = session_orphan_get_head();
    struct sp_fast_entry *fast_tbl = NULL;
    uint32_t key = 0, index = 0, oph_th = orphan_head->max_num / 10 * 8;

    if (NULL == p_key) {
        LOG(SESSION, ERR, "parameter error, p_key(%p).", p_key);
        return NULL;
    }

    if (ros_atomic32_read(&orphan_head->use_num) >= oph_th) {
        session_orphan_recycle();
    }

    if (G_FAILURE == Res_Alloc(orphan_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            orphan_head->pool_id);
        return NULL;
    }

    fast_tbl = session_orphan_get_entry(index);

    fast_tbl->fast_id = fast_id;
    fast_tbl->pkt_type = pkt_type;
    switch (pkt_type) {
        case EN_PKT_TYPE_ETH:
            ros_memcpy(&fast_tbl->ue_mac, p_key, ETH_ALEN);
            break;

        default:
            ros_memcpy(&fast_tbl->key, p_key, sizeof(struct pdr_key));
            break;
    }

    ros_atomic32_add(&orphan_head->use_num, 1);

    return fast_tbl;
}

static int session_orphan_fast_free(struct sp_fast_entry *fast_tbl)
{
    struct sp_orphan_table_head *orphan_head = session_orphan_get_head();

    if (NULL == fast_tbl) {
        LOG(SESSION, ERR, "fast_tbl is NULL.");
        return -1;
    }

    if (G_FALSE == Res_IsAlloced(orphan_head->pool_id, 0, fast_tbl->index)) {
        LOG(SESSION, ERR,
            "free fast ipv4 entry failed, entry is invalid, index: %u.",
            fast_tbl->index);
        return -1;
    }

    Res_Free(orphan_head->pool_id, 0, fast_tbl->index);
    ros_atomic32_sub(&orphan_head->use_num, 1);

    return 0;
}

/*
*   清除二叉树上某个节点队列
*/
static void session_orphan_clean_node(struct rb_node *queue_node,
    struct rb_root *root_node)
{
    struct sp_fast_entry *queue_tbl, *cur_tbl;
    struct dl_list *pos = NULL;
	struct dl_list *next = NULL;

    queue_tbl = (struct sp_fast_entry *)container_of(queue_node,
        struct sp_fast_entry, oph_node);
    dl_list_for_each_safe(pos, next, &queue_tbl->list_node) {
        cur_tbl = (struct sp_fast_entry *)container_of(pos,
            struct sp_fast_entry, list_node);

        if (0 > session_remove_orphan_fast(cur_tbl, cur_tbl->pkt_type)) {
            LOG(SESSION, ERR, "fast: %u remove failed.", cur_tbl->fast_id);
        }
        dl_list_del(&cur_tbl->list_node);
        if (0 > session_orphan_fast_free(cur_tbl)) {
            LOG(SESSION, ERR, "fast: %u free failed.", cur_tbl->fast_id);
        }
    }
    if (0 > session_remove_orphan_fast(queue_tbl, queue_tbl->pkt_type)) {
        LOG(SESSION, ERR, "fast: %u change failed.", queue_tbl->fast_id);
    }
    rbtree_erase(queue_node, root_node);
    if (0 > session_orphan_fast_free(queue_tbl)) {
        LOG(SESSION, ERR, "fast: %u change failed.", queue_tbl->fast_id);
    }
}

int session_orphan_insert(uint32_t fast_id, uint8_t is_gtpu,
    uint8_t pkt_type, void *p_key)
{
    struct sp_orphan_table_head *orphan_head = session_orphan_get_head();
    struct sp_fast_entry *queue_tbl = NULL;
    int ret = 0;
    struct sp_fast_entry *fast_tbl = NULL;

    if (NULL == p_key) {
        LOG(SESSION, ERR, "Abnormal parameter, p_key (%p).", p_key);
        return -1;
    }

    fast_tbl = session_orphan_fast_alloc(fast_id, p_key, pkt_type);
    if (NULL == fast_tbl) {
        LOG(SESSION, ERR, "alloc fast table failed.");
        return -1;
    }

    ros_rwlock_write_lock(&orphan_head->lock); /* lock */
    if (!is_gtpu) {
        LOG(SESSION, RUNNING,
            "insert fast to ueip root, fast id %u.", fast_tbl->fast_id);

        switch (pkt_type) {
            case EN_PKT_TYPE_IPV4:
                {
                    struct pdr_key key;
                    struct rb_node *queue_node;

                    ros_memcpy(&key, p_key, sizeof(struct pdr_key));

                    queue_node = rbtree_search(&orphan_head->oph_ueip_v4_root,
                        &key, session_orphan_ueip_v4_compare);
                    if (NULL == queue_node) {
                        dl_list_init(&fast_tbl->list_node);
                        ret = rbtree_insert(&orphan_head->oph_ueip_v4_root,
                            &fast_tbl->oph_node, &key, session_orphan_ueip_v4_compare);
                        if (-1 == ret) {
                            ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */
                            LOG(SESSION, ERR,
                                "insert fast to orphan failed, fast id %u.",
                                fast_tbl->fast_id);
                            return -1;
                        }
                    } else {
                        queue_tbl = (struct sp_fast_entry *)container_of(queue_node,
                            struct sp_fast_entry, oph_node);
                        dl_list_add_tail(&queue_tbl->list_node, &fast_tbl->list_node);
                    }
                }
                break;

            case EN_PKT_TYPE_IPV6:
                {
                    struct pdr_key key;
                    struct rb_node *queue_node;

                    ros_memcpy(&key, p_key, sizeof(struct pdr_key));

                    queue_node = rbtree_search(&orphan_head->oph_ueip_v6_root,
                        &key, session_orphan_ueip_v6_compare);
                    if (NULL == queue_node) {
                        dl_list_init(&fast_tbl->list_node);
                        ret = rbtree_insert(&orphan_head->oph_ueip_v6_root,
                            &fast_tbl->oph_node, &key, session_orphan_ueip_v6_compare);
                        if (-1 == ret) {
                            ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */
                            LOG(SESSION, ERR,
                                "insert fast to orphan failed, fast id %u.",
                                fast_tbl->fast_id);
                            return -1;
                        }
                    } else {
                        queue_tbl = (struct sp_fast_entry *)container_of(queue_node,
                            struct sp_fast_entry, oph_node);
                        dl_list_add_tail(&queue_tbl->list_node, &fast_tbl->list_node);
                    }
                }
                break;

            case EN_PKT_TYPE_ETH:
                {
                    struct rb_node *queue_node = rbtree_search(&orphan_head->oph_ue_mac_root,
                        p_key, session_orphan_ue_mac_compare);
                    if (NULL == queue_node) {
                        dl_list_init(&fast_tbl->list_node);
                        ret = rbtree_insert(&orphan_head->oph_ue_mac_root,
                            &fast_tbl->oph_node, &p_key, session_orphan_ue_mac_compare);
                        if (-1 == ret) {
                            ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */
                            LOG(SESSION, ERR,
                                "insert fast to orphan failed, fast id %u.",
                                fast_tbl->fast_id);
                            return -1;
                        }
                    } else {
                        queue_tbl = (struct sp_fast_entry *)container_of(queue_node,
                            struct sp_fast_entry, oph_node);
                        dl_list_add_tail(&queue_tbl->list_node, &fast_tbl->list_node);
                    }
                }
                break;

            default:
                ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */
                    LOG(SESSION, ERR, "insert fast to orphan failed, fast id %u.",
                        fast_tbl->fast_id);
                return -1;
        }
        ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */

        return 0;
    } else {
        LOG(SESSION, RUNNING,
            "insert fast to F-TEID root, fast id %u.", fast_tbl->fast_id);

        switch (pkt_type) {
            case EN_PKT_TYPE_IPV4:
                {
                    struct pdr_key key;
                    struct rb_node *queue_node;

                    ros_memcpy(&key, p_key, sizeof(struct pdr_key));

                    queue_node = rbtree_search(&orphan_head->oph_fteid_v4_root,
                        &key, session_orphan_fteid_v4_compare);
                    if (NULL == queue_node) {
                        dl_list_init(&fast_tbl->list_node);
                        ret = rbtree_insert(&orphan_head->oph_fteid_v4_root,
                            &fast_tbl->oph_node, &key, session_orphan_fteid_v4_compare);
                        if (-1 == ret) {
                            ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */
                            LOG(SESSION, ERR,
                                "insert fast to orphan failed, fast id %u.",
                                fast_tbl->fast_id);
                            return -1;
                        }
                    } else {
                        queue_tbl = (struct sp_fast_entry *)container_of(queue_node,
                            struct sp_fast_entry, oph_node);
                        dl_list_add_tail(&queue_tbl->list_node, &fast_tbl->list_node);
                    }
                }
                break;

            case EN_PKT_TYPE_IPV6:
                {
                    struct pdr_key key;
                    struct rb_node *queue_node;

                    ros_memcpy(&key, p_key, sizeof(struct pdr_key));

                    queue_node = rbtree_search(&orphan_head->oph_fteid_v6_root,
                        &key, session_orphan_fteid_v6_compare);
                    if (NULL == queue_node) {
                        dl_list_init(&fast_tbl->list_node);
                        ret = rbtree_insert(&orphan_head->oph_fteid_v6_root,
                            &fast_tbl->oph_node, &key, session_orphan_fteid_v6_compare);
                        if (-1 == ret) {
                            ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */
                            LOG(SESSION, ERR,
                                "insert fast to orphan failed, fast id %u.",
                                fast_tbl->fast_id);
                            return -1;
                        }
                    } else {
                        queue_tbl = (struct sp_fast_entry *)container_of(queue_node,
                            struct sp_fast_entry, oph_node);
                        dl_list_add_tail(&queue_tbl->list_node, &fast_tbl->list_node);
                    }
                }
                break;

            case EN_PKT_TYPE_ETH:
                {
                    struct rb_node *queue_node = rbtree_search(&orphan_head->oph_ue_mac_root,
                        p_key, session_orphan_ue_mac_compare);
                    if (NULL == queue_node) {
                        dl_list_init(&fast_tbl->list_node);
                        ret = rbtree_insert(&orphan_head->oph_ue_mac_root,
                            &fast_tbl->oph_node, &p_key, session_orphan_ue_mac_compare);
                        if (-1 == ret) {
                            ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */
                            LOG(SESSION, ERR,
                                "insert fast to orphan failed, fast id %u.",
                                fast_tbl->fast_id);
                            return -1;
                        }
                    } else {
                        queue_tbl = (struct sp_fast_entry *)container_of(queue_node,
                            struct sp_fast_entry, oph_node);
                        dl_list_add_tail(&queue_tbl->list_node, &fast_tbl->list_node);
                    }
                }
                break;

            default:
                ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */
                    LOG(SESSION, ERR, "insert fast to orphan failed, fast id %u.",
                        fast_tbl->fast_id);
                return -1;
        }
        ros_rwlock_write_unlock(&orphan_head->lock); /* unlock */

        return 0;
    }
}

int session_orphan_modify(uint32_t *index_arr, uint32_t index_num)
{
    struct sp_orphan_table_head *orphan_head = session_orphan_get_head();
    uint8_t pdr_si = 0;
    struct pdr_key key = {.teid = 0};
    struct rb_node *queue_node;
    struct rb_root *root_node;
    uint32_t cnt = 0;
    struct session_t *sess;
    struct pkt_detection_info *pdi;
    struct pdr_table *pdr_tbl;

    if (NULL == index_arr || 0 == index_num) {
        LOG(SESSION, ERR,
            "argument ERROR, index_arr (%p), index_num: %u.",
            index_arr, index_num);
        return -1;
    }

    ros_rwlock_write_lock(&orphan_head->lock); //lock
    for (cnt = 0; cnt < index_num; ++cnt) {
        pdr_tbl = pdr_get_table_public(index_arr[cnt]);
        if (NULL == pdr_tbl) {
            LOG(SESSION, ERR, "Get PDR index(%u) failed.", index_arr[cnt]);
            continue;
        }

        queue_node = NULL;
        root_node = NULL;
        pdi = &pdr_tbl->pdr.pdi_content;
        sess = pdr_tbl->session_link;
        if (NULL == sess) {
            LOG(SESSION, ERR, "PDR session link is NULL.");
            continue;
        }
        pdr_si = pdi->si;

        if (COMM_SRC_IF_DN == pdr_si) {
            uint8_t cnt;
            struct pdr_ue_ipaddress *cur_ueip = NULL;
            struct sp_fast_entry *queue_tbl;

            key.teid = 0;

            /* UEIP */
            for (cnt = 0; cnt < pdi->ue_ipaddr_num; ++cnt) {
                cur_ueip = &pdi->ue_ipaddr[cnt];
                if (cur_ueip->ueip.ueip_flag.d.v4) {
                    key.ip_addr.ipv4 = cur_ueip->ueip.ipv4_addr;
                    queue_node = rbtree_search(&orphan_head->oph_ueip_v4_root,
                        &key, session_orphan_ueip_v4_compare);
                    root_node = &orphan_head->oph_ueip_v4_root;
                } else if (cur_ueip->ueip.ueip_flag.d.v6) {
                    ros_memcpy(&key.ip_addr.ipv6, cur_ueip->ueip.ipv6_addr, IPV6_ALEN);
                    queue_node = rbtree_search(&orphan_head->oph_ueip_v6_root,
                        &key, session_orphan_ueip_v6_compare);
                    root_node = &orphan_head->oph_ueip_v6_root;
                }
            }

            /* framed route */
            for (cnt = 0; cnt < pdi->framed_ipv4_route_num; ++cnt) {
                session_framed_route *fr_v4 = &pdi->framed_ipv4_route[cnt].route;

                queue_node = rbtree_first(&orphan_head->oph_ueip_v4_root);

                while (queue_node) {
                    queue_tbl = (struct sp_fast_entry *)container_of(queue_node,
                        struct sp_fast_entry, oph_node);

                    if ((queue_tbl->key.ip_addr.ipv4 & fr_v4->ip_mask) ==
                        (fr_v4->dest_ip & fr_v4->ip_mask)) {
                        session_orphan_clean_node(queue_node, &orphan_head->oph_ueip_v4_root);
                    }

                    queue_node = rbtree_next(queue_node);
                }
            }

            for (cnt = 0; cnt < pdi->framed_ipv6_route_num; ++cnt) {
                session_framed_route_ipv6 *fr_v6 = &pdi->framed_ipv6_route[cnt].route;

                queue_node = rbtree_first(&orphan_head->oph_ueip_v6_root);

                while (queue_node) {
                    queue_tbl = (struct sp_fast_entry *)container_of(queue_node,
                        struct sp_fast_entry, oph_node);

                    if (((*(uint64_t *)&queue_tbl->key.ip_addr.ipv6.value[0] & *(uint64_t *)&fr_v6->ip_mask[0]) ==
                        (*(uint64_t *)&fr_v6->dest_ip[0] & *(uint64_t *)&fr_v6->ip_mask[0])) &&
                        ((*(uint64_t *)&queue_tbl->key.ip_addr.ipv6.value[8] & *(uint64_t *)&fr_v6->ip_mask[8]) ==
                        (*(uint64_t *)&fr_v6->dest_ip[8] & *(uint64_t *)&fr_v6->ip_mask[8]))) {
                        session_orphan_clean_node(queue_node, &orphan_head->oph_ueip_v6_root);
                    }

                    queue_node = rbtree_next(queue_node);
                }
            }
        } else {
            uint8_t cnt;
            struct pdr_local_fteid *cur_fteid = NULL;

            for (cnt = 0; cnt < pdi->local_fteid_num; ++cnt) {
                cur_fteid = &pdi->local_fteid[cnt];

                if (cur_fteid->local_fteid.f_teid_flag.d.v4) {
                    key.ip_addr.ipv4 = cur_fteid->local_fteid.ipv4_addr;
                    key.teid = cur_fteid->local_fteid.teid;
                    queue_node = rbtree_search(&orphan_head->oph_fteid_v4_root,
                        &key, session_orphan_fteid_v4_compare);
                    root_node = &orphan_head->oph_fteid_v4_root;
                } else if (cur_fteid->local_fteid.f_teid_flag.d.v6) {
                    ros_memcpy(&key.ip_addr.ipv6, cur_fteid->local_fteid.ipv6_addr, IPV6_ALEN);
                    key.teid = cur_fteid->local_fteid.teid;
                    queue_node = rbtree_search(&orphan_head->oph_fteid_v6_root,
                        &key, session_orphan_fteid_v6_compare);
                    root_node = &orphan_head->oph_fteid_v6_root;
                }
            }
        }

        if (NULL == queue_node || NULL == root_node) {
            LOG(SESSION, RUNNING, "no orphan fast entry for the PDR, pdr id %u.\n",
                pdr_tbl->pdr.pdr_id);
            continue;
        } else {
            session_orphan_clean_node(queue_node, root_node);
        }
    }
    ros_rwlock_write_unlock(&orphan_head->lock); //unlock

    return 0;
}

static void session_orphan_recycle(void)
{
    struct sp_orphan_table_head *orphan_head = session_orphan_get_head();
    struct rb_root *root_node[] = {&orphan_head->oph_ueip_v4_root,
                                            &orphan_head->oph_ueip_v6_root,
                                            &orphan_head->oph_fteid_v4_root,
                                            &orphan_head->oph_fteid_v6_root};
    const uint32_t root_num = sizeof(root_node) / sizeof(struct rb_root *);
    struct rb_node *queue_node = NULL;
    uint32_t cnt = 0, entry_threshold = (orphan_head->max_num / 10) * 6;/* 60% */

    ros_rwlock_write_lock(&orphan_head->lock); //lock

    for (cnt = 0; cnt < root_num; ++cnt) {
        queue_node = rbtree_first(root_node[cnt]);
        if (NULL == queue_node) {
            LOG(SESSION, RUNNING, "no orphan fast entry in the ROOT.\n");
            continue;
        } else {
            while (queue_node) {
                session_orphan_clean_node(queue_node, root_node[cnt]);

                if (entry_threshold >= ros_atomic32_read(&orphan_head->use_num)) {
                    ros_rwlock_write_unlock(&orphan_head->lock); //unlock
                    LOG(SESSION, RUNNING, "Recycle orphan fast entry finish, current use: %u.\n",
                        ros_atomic32_read(&orphan_head->use_num));
                    return;
                }

                queue_node = rbtree_first(root_node[cnt]);
            }
        }

    }
    ros_rwlock_write_unlock(&orphan_head->lock); //unlock

    LOG(SESSION, RUNNING, "Recycle orphan fast entry finish, current use: %u.\n",
        ros_atomic32_read(&orphan_head->use_num));
}

int64_t session_orphan_table_init(uint32_t orphan_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct sp_fast_entry *fast_entry = NULL;
    int64_t size = 0, total_memory = 0;
    struct sp_orphan_table_head *orphan_head = session_orphan_get_head();

    if (0 == orphan_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, session_num: %u.", orphan_num);
        return -1;
    }

    size = sizeof(struct sp_fast_entry) * orphan_num;
    fast_entry = ros_malloc(size);
    if (NULL == fast_entry) {
        LOG(SESSION, ERR,
            "init fast table failed, no enough memory, max number: %u.",
            orphan_num);
        return -1;
    }
    ros_memset(fast_entry, 0, sizeof(struct sp_fast_entry) * orphan_num);

    for (index = 0; index < orphan_num; ++index) {
        fast_entry[index].index = index;
        dl_list_init(&fast_entry[index].list_node);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, orphan_num)) {
        return -1;
    }

    orphan_head->pool_id        = pool_id;
    orphan_head->fast_entry     = fast_entry;
    orphan_head->max_num        = orphan_num;
    orphan_head->oph_fteid_v4_root = RB_ROOT_INIT_VALUE;
    orphan_head->oph_ueip_v4_root  = RB_ROOT_INIT_VALUE;
    orphan_head->oph_fteid_v6_root = RB_ROOT_INIT_VALUE;
    orphan_head->oph_ueip_v6_root  = RB_ROOT_INIT_VALUE;
    orphan_head->oph_ue_mac_root   = RB_ROOT_INIT_VALUE;
    ros_rwlock_init(&orphan_head->lock);
    ros_atomic32_set(&orphan_head->use_num, 0);
    total_memory += size;

    LOG(SESSION, MUST, "session orphan init success.");

    return total_memory;
}

