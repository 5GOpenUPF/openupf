/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "lb_dpdk_cache.h"
#include "dpdk.h"
#include "lb_neighbor_cache.h"
#include "lb_neighbor.h"


static lb_neighbor_mgmt g_lb_neighbor_mgmt;


static inline lb_neighbor_mgmt *lb_neighbor_mgmt_get(void)
{
    return &g_lb_neighbor_mgmt;
}

lb_neighbor_mgmt *lb_neighbor_mgmt_get_public(void)
{
    return lb_neighbor_mgmt_get();
}

static inline lb_neighbor_entry *lb_neighbor_entry_get(uint32_t index)
{
    return &g_lb_neighbor_mgmt.entry[index];
}

lb_neighbor_entry *lb_neighbor_entry_get_public(uint32_t index)
{
    return lb_neighbor_entry_get(index);
}

static int lb_neighbor_compare(struct rb_node *rbnode, void *key)
{
    lb_neighbor_entry *entry = (lb_neighbor_entry *)rbnode;
    lb_neighbor_key *new_key = (lb_neighbor_key *)key;

    if (entry->comp_key.d.key1 < new_key->d.key1) {
        return -1;
    } else if (entry->comp_key.d.key1 > new_key->d.key1) {
        return 1;
    }

    if (entry->comp_key.d.key2 < new_key->d.key2) {
        return -1;
    } else if (entry->comp_key.d.key2 > new_key->d.key2) {
        return 1;
    }

    return 0;
}

__maybe_unused static inline lb_neighbor_entry *lb_neighbor_create(lb_neighbor_key *key, uint8_t ip_ver)
{
    lb_neighbor_mgmt *ngb_mgmt = lb_neighbor_mgmt_get();
    lb_neighbor_entry *ngb_entry = NULL;
    uint32_t res_key = 0, index = 0;

    if (G_FAILURE == Res_Alloc(ngb_mgmt->pool_id, &res_key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(LB, ERR, "alloc resource failed.");
        return NULL;
    }

    ngb_entry = lb_neighbor_entry_get(index);

    ros_rwlock_write_lock(&ngb_entry->lock);/* lock */
    ros_memcpy(&ngb_entry->comp_key, key, sizeof(lb_neighbor_key));
    //dl_list_init(&ngb_entry->wait_queue);
    //dl_list_init(&ngb_entry->timeline_node);
    ngb_entry->ip_ver = ip_ver;
    ngb_entry->timeout = ros_getime() + NEIGHBOR_WAIT_REPLY_TIMEOUT;
    ros_rwlock_write_unlock(&ngb_entry->lock);/* unlock */

    LOG(LB, RUNNING, "Insert neighbor entry, key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)ngb_entry->comp_key.value,
        *(uint32_t *)(ngb_entry->comp_key.value + 4),
        *(uint32_t *)(ngb_entry->comp_key.value + 8),
        *(uint32_t *)(ngb_entry->comp_key.value + 12));
    if (-1 == rbtree_insert(&ngb_mgmt->entry_root, &ngb_entry->key_node,
        &ngb_entry->comp_key, lb_neighbor_compare)) {
        Res_Free(ngb_mgmt->pool_id, res_key, index);
        LOG(LB, ERR, "Insert neighbor entry failed,"
            " key: 0x%08x %08x %08x %08x.",
            *(uint32_t *)ngb_entry->comp_key.value,
            *(uint32_t *)(ngb_entry->comp_key.value + 4),
            *(uint32_t *)(ngb_entry->comp_key.value + 8),
            *(uint32_t *)(ngb_entry->comp_key.value + 12));

        return NULL;
    }

    /* Insert timeline queue */
    dl_list_add_tail(&ngb_mgmt->timeline, &ngb_entry->timeline_node);

    return ngb_entry;
}

static int lb_neighbor_remove(lb_neighbor_key *key, uint8_t *mac)
{
    lb_neighbor_mgmt *ngb_mgmt = lb_neighbor_mgmt_get();
    lb_neighbor_entry *ngb_entry = NULL;
    struct dl_list *pos = NULL, *next = NULL;
    lb_dpdk_cache_node *cache_node;

    LOG(LB, RUNNING, "delete neighbor entry, key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)key->value,
        *(uint32_t *)(key->value + 4),
        *(uint32_t *)(key->value + 8),
        *(uint32_t *)(key->value + 12));
    ngb_entry = (lb_neighbor_entry *)rbtree_delete(&ngb_mgmt->entry_root,
        key, lb_neighbor_compare);
    if (NULL == ngb_entry) {
        LOG(LB, PERIOD, "delete neighbor entry failed, Maybe it has been deleted,"
            " key: 0x%08x %08x %08x %08x.",
            *(uint32_t *)key->value,
            *(uint32_t *)(key->value + 4),
            *(uint32_t *)(key->value + 8),
            *(uint32_t *)(key->value + 12));

        return -1;
    }

    /* Delete from timeline */
    dl_list_del(&ngb_entry->timeline_node);

    /* Clrean wait list */
    ros_rwlock_write_lock(&ngb_entry->lock);/* lock */
    if (NULL == mac) {
        dl_list_for_each_safe(pos, next, &ngb_entry->wait_queue) {
            cache_node = (lb_dpdk_cache_node *)container_of(pos,
                    lb_dpdk_cache_node, node);

            cache_node->proc_method = EN_CACHE_NODE_DROP;

            /* We can override the list node without deleting it */
            lb_dpdk_tx_queue_append(cache_node);
        }
    } else {
        dl_list_for_each_safe(pos, next, &ngb_entry->wait_queue) {
            cache_node = (lb_dpdk_cache_node *)container_of(pos,
                    lb_dpdk_cache_node, node);

            cache_node->proc_method = EN_CACHE_NODE_DIRECT_SEND;
            lb_mac_updating_public(cache_node->data,
                lb_get_local_port_mac(EN_LB_PORT_EXT),
                mac);

            /* We can override the list node without deleting it */
            lb_dpdk_tx_queue_append(cache_node);
        }
    }
    dl_list_init(&ngb_entry->wait_queue);
    ros_rwlock_write_unlock(&ngb_entry->lock);/* unlock */

    Res_Free(ngb_mgmt->pool_id, 0, ngb_entry->index);

    return 0;
}

static inline int lb_neighbor_update(lb_neighbor_key *key, uint8_t *mac)
{
    lb_neighbor_mgmt *ngb_mgmt = lb_neighbor_mgmt_get();

    LOG(LB, RUNNING, "Update neighbor entry, key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)key->value,
        *(uint32_t *)(key->value + 4),
        *(uint32_t *)(key->value + 8),
        *(uint32_t *)(key->value + 12));
    ros_rwlock_write_lock(&ngb_mgmt->lock);/* lock */
    if (0 > lb_neighbor_remove(key, mac)) {
        ros_rwlock_write_unlock(&ngb_mgmt->lock);/* unlock */
        LOG(LB, PERIOD, "There is no entry to update.");
        return -1;
    }
    ros_rwlock_write_unlock(&ngb_mgmt->lock);/* unlock */

    return 0;
}

void lb_neighbor_recv_arp(uint32_t net_ip, uint8_t *mac, uint8_t port)
{
    lb_neighbor_key comp_key = {.v4_value = net_ip};

    if (unlikely(NULL == mac)) {
        LOG(LB, ERR, "Parameter abnormal, mac(%p).", mac);
        return;
    }

    if (0 > lb_neighbor_cache_create(&comp_key, mac, port, SESSION_IP_V4)) {
        LOG(LB, ERR, "Create neighbor cache failed.");
    }

    LOG(LB, RUNNING, "Update neighbor, key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)comp_key.value,
        *(uint32_t *)(comp_key.value + 4),
        *(uint32_t *)(comp_key.value + 8),
        *(uint32_t *)(comp_key.value + 12));
#if (LB_NEIGHBOR_ENABLED == 1)
    if (-1 == lb_neighbor_update(&comp_key, mac)) {
        LOG(LB, DEBUG, "Maybe the timeout has been handled.");
    }
#endif
}

int lb_neighbor_wait_reply(lb_neighbor_key *key, uint8_t ip_ver, void *buf)
{
#if (LB_NEIGHBOR_ENABLED == 1)
    lb_neighbor_mgmt *ngb_mgmt = lb_neighbor_mgmt_get();
    lb_neighbor_entry *entry;
    lb_dpdk_cache_node *cache_node;
    uint8_t send_arp_request = G_FALSE;

    LOG(LB, RUNNING, "Create cache entry, key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)key->value, *(uint32_t *)(key->value + 4),
        *(uint32_t *)(key->value + 8), *(uint32_t *)(key->value + 12));

    cache_node = lb_dpdk_cache_alloc();
    if (NULL == cache_node) {
        LOG(LB, ERR, "Allocate cache node failed.");
        return -1;
    }

    ros_rwlock_write_lock(&ngb_mgmt->lock);/* lock */
    entry = (lb_neighbor_entry *)rbtree_search(&ngb_mgmt->entry_root,
        key, lb_neighbor_compare);
    if (NULL == entry) {
        entry = lb_neighbor_create(key, ip_ver);
        if (NULL == entry) {
            ros_rwlock_write_unlock(&ngb_mgmt->lock);/* unlock */
            lb_dpdk_cache_free(cache_node);
            LOG(LB, ERR, "Create neighbor failed.");
            return -1;
        } else {
            send_arp_request = G_TRUE;
        }
    }

    cache_node->core_id     = rte_lcore_id();
    cache_node->data        = buf;
    cache_node->proc_method = EN_CACHE_NODE_DIRECT_SEND;

    ros_rwlock_write_lock(&entry->lock); /* Lock */
    dl_list_add_tail(&entry->wait_queue, &cache_node->node);
    ros_rwlock_write_unlock(&entry->lock); /* Unlock */
    ros_rwlock_write_unlock(&ngb_mgmt->lock);/* unlock */

    if (send_arp_request) {
        struct rte_mbuf *mbuf_arp;
        uint32_t data_len;

        /* Alloc buffer */
        if (rte_lcore_id() == LCORE_ID_ANY) {
            LOG(LB, MUST, "This print should not appear.");
        }
        mbuf_arp = dpdk_alloc_mbuf();
        if (NULL == mbuf_arp) {
            LOG(LB, ERR, "Allocate DPDK mbuf failed, ARP request cannot be issued.");
            return 0; /* Return 0, Wait for automatic timeout delete */
        }

        /* Copy content and set length */
        switch (ip_ver) {
            case SESSION_IP_V4:
                data_len = lb_neighbor_build_arp_request(rte_pktmbuf_mtod(mbuf_arp, char *),
                    key->v4_value);
                break;

            case SESSION_IP_V6:
                LOG(LB, DEBUG, "IPv6 Neighbor Discovery is not supported at present.");
                lb_free_pkt(mbuf_arp);
                return 0;

            default:
                LOG(LB, ERR, "Unknown condition, please check the program.");
                lb_free_pkt(mbuf_arp);
                return 0;
        }
        pkt_buf_set_len(mbuf_arp, data_len);

        lb_fwd_to_external_network_public(mbuf_arp);
    }

    return 0;
#else
    return -1;
#endif
}

void *lb_neighbor_timeout_task(void *arg)
{
    lb_neighbor_mgmt *ngb_mgmt = lb_neighbor_mgmt_get();
    uint32_t cur_time;
    struct dl_list *pos = NULL, *next = NULL;
    lb_neighbor_entry *ngb_entry = NULL;

    for (;;) {
        cur_time = ros_getime();

        if (!dl_list_empty(&ngb_mgmt->timeline)) {
            ros_rwlock_write_lock(&ngb_mgmt->lock);/* lock */
            dl_list_for_each_safe(pos, next, &ngb_mgmt->timeline) {
                ngb_entry = (lb_neighbor_entry *)container_of(pos,
                        lb_neighbor_entry, timeline_node);

                if (cur_time >= ngb_entry->timeout) {
                    lb_neighbor_remove(&ngb_entry->comp_key, NULL);
                } else {
                    break;
                }
            }
            ros_rwlock_write_unlock(&ngb_mgmt->lock);/* unlock */
        }

        sleep(1);
    }

    return NULL;
}

int64_t lb_neighbor_init(uint32_t neighbor_number)
{
    lb_neighbor_mgmt *neighbor_mgmt = lb_neighbor_mgmt_get();
    uint32_t index = 0;
    int64_t size = 0, total_mem = 0;
    lb_neighbor_entry *entry = NULL;
    int pool_id = -1;
    pthread_t pthr_id;

    /* Save a copy of configure */
    if (0 == neighbor_number) {
        LOG(LB, ERR,
            "parameter neighbor_number (%d) is invalid.", neighbor_number);
        return -1;
    }

    /* Entry */
    size = neighbor_number * sizeof(lb_neighbor_entry);
    entry = (lb_neighbor_entry *)ros_malloc(size);
    if (!entry) {
        LOG(LB, ERR,
            "alloc msg entry memory failed, total size:%ld.", size);
        return -1;
    }
    ros_memset(entry, 0, size);
    total_mem += size;
    for (index = 0; index < neighbor_number; ++index) {
        entry[index].index = index;
        dl_list_init(&entry[index].wait_queue);
        dl_list_init(&entry[index].timeline_node);
        ros_rwlock_init(&entry[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(LB, ERR, "Res_CreatePool failed.\n");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, neighbor_number)) {
        LOG(LB, ERR, "Res_AddSection failed.\n");
        return -1;
    }

    neighbor_mgmt->entry        = entry;
    neighbor_mgmt->max_num      = neighbor_number;
    neighbor_mgmt->pool_id      = pool_id;
    neighbor_mgmt->entry_root   = RB_ROOT_INIT_VALUE;
    dl_list_init(&neighbor_mgmt->timeline);
    ros_rwlock_init(&neighbor_mgmt->lock);

    /* Init neighbor cache */
    size = lb_neighbor_cache_init(neighbor_number);
    if (size < 0) {
       LOG(LB, ERR, "Neighbor cache init failed.");
       return -1;
    }
    total_mem += size;

    /* Init cache node */
    size = lb_dpdk_cache_init(neighbor_number);
    if (size < 0) {
       LOG(LB, ERR, "Neighbor cache node init failed.");
       return -1;
    }
    total_mem += size;

    if (0 != pthread_create(&pthr_id, NULL, lb_neighbor_timeout_task, NULL)) {
		LOG(LB, ERR, "create neighbor timeout task failed.");
        return -1;
	}

    LOG(LB, MUST, "Init success.\n");

    return total_mem;
}

