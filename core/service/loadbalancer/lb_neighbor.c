/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "lb_neighbor.h"


lb_neighbor_cache_mgmt g_lb_neighbor_cache_mgmt = {.max_num = 500};


static int lb_neighbor_cache_remove(lb_neighbor_comp_key *key);

static inline lb_neighbor_cache_mgmt *lb_neighbor_cache_mgmt_get(void)
{
    return &g_lb_neighbor_cache_mgmt;
}

static inline lb_neighbor_cache *lb_neighbor_cache_get(uint32_t index)
{
    return &g_lb_neighbor_cache_mgmt.entry[index];
}

static int lb_neighbor_cache_compare(struct rb_node *rbnode, void *key)
{
    lb_neighbor_cache *entry = (lb_neighbor_cache *)rbnode;
    lb_neighbor_comp_key *new_key = (lb_neighbor_comp_key *)key;

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

static int lb_neighbor_cache_create(lb_neighbor_comp_key *key, uint8_t *mac,
    uint8_t port_type, uint8_t ip_ver)
{
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();
    lb_neighbor_cache *entry = NULL;
    uint32_t res_key = 0, index = 0;

    if (NULL == key) {
        LOG(LB, ERR,
            "abnormal parameter, key(%p).", key);
        return -1;
    }

    LOG(LB, RUNNING, "Create neighbor cache,"
        " key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)key->value,
        *(uint32_t *)(key->value + 4),
        *(uint32_t *)(key->value + 8),
        *(uint32_t *)(key->value + 12));

    ros_rwlock_read_lock(&cache_mgmt->lock);/* lock */
    entry = (lb_neighbor_cache *)rbtree_search(&cache_mgmt->entry_root,
        key, lb_neighbor_cache_compare);
    ros_rwlock_read_unlock(&cache_mgmt->lock);/* unlock */
    if (NULL != entry) {
        LOG(LB, RUNNING, "neighbor cache is existence, update it,"
            " key: 0x%08x %08x %08x %08x.",
            *(uint32_t *)key->value,
            *(uint32_t *)(key->value + 4),
            *(uint32_t *)(key->value + 8),
            *(uint32_t *)(key->value + 12));

        ros_rwlock_read_lock(&entry->lock);/* lock */
        entry->create_time = ros_getime();
        ros_memcpy(entry->next_hop, mac, ETH_ALEN);
        entry->port_type = port_type;
        entry->ip_version = ip_ver;
        entry->renew_times = 0;
        ros_rwlock_read_unlock(&entry->lock);/* unlock */

        return 0;
    }

    if (Res_GetAlloced(cache_mgmt->pool_id) >= cache_mgmt->max_num) {
        struct dl_list *pos = NULL, *next = NULL;
        uint32_t cnt = 0;

        dl_list_for_each_safe(pos, next, &cache_mgmt->aging_list) {
            ++cnt;
            entry = (lb_neighbor_cache *)container_of(pos,
                    lb_neighbor_cache, aging_node);
            if (0 > lb_neighbor_cache_remove(&entry->comp_key)) {
                LOG(LB, ERR, "Delete neighbor cache entry failed.");
            }
            if (cnt >= cache_mgmt->aging_num) {
                break;
            }
        }
    }

    if (G_FAILURE == Res_Alloc(cache_mgmt->pool_id, &res_key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(LB, ERR, "alloc resource failed.");
        return -1;
    }

    entry = lb_neighbor_cache_get(index);

    ros_rwlock_write_lock(&entry->lock);/* lock */
    entry->comp_key.d.key1 = key->d.key1;
    entry->comp_key.d.key2 = key->d.key2;
    entry->create_time = ros_getime();
    entry->port_type = port_type;
    entry->ip_version = ip_ver;
    entry->renew_times = 0;
    ros_memcpy(entry->next_hop, mac, ETH_ALEN);
    ros_rwlock_write_unlock(&entry->lock);/* unlock */

    ros_rwlock_write_lock(&cache_mgmt->lock);/* lock */
    if (-1 == rbtree_insert(&cache_mgmt->entry_root, &entry->key_node,
        &entry->comp_key, lb_neighbor_cache_compare)) {
        ros_rwlock_write_unlock(&cache_mgmt->lock);/* unlock */
        Res_Free(cache_mgmt->pool_id, 0, index);
        LOG(LB, ERR, "insert neighbor entry failed, key: 0x%08x %08x %08x %08x.",
            *(uint32_t *)entry->comp_key.value,
            *(uint32_t *)(entry->comp_key.value + 4),
            *(uint32_t *)(entry->comp_key.value + 8),
            *(uint32_t *)(entry->comp_key.value + 12));

        return -1;
    }
    dl_list_add_tail(&cache_mgmt->aging_list, &entry->aging_node);
    ros_rwlock_write_unlock(&cache_mgmt->lock);/* unlock */

    return 0;
}

static int lb_neighbor_cache_remove(lb_neighbor_comp_key *key)
{
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();
    lb_neighbor_cache *entry = NULL;

    if (NULL == key) {
        LOG(LB, ERR, "abnormal parameter, key(%p).", key);
        return -1;
    }

    LOG(LB, RUNNING, "Neighbor cache remove: 0x%08x %08x %08x %08x.",
            *(uint32_t *)key->value,
            *(uint32_t *)(key->value + 4),
            *(uint32_t *)(key->value + 8),
            *(uint32_t *)(key->value + 12));

    ros_rwlock_write_lock(&cache_mgmt->lock);/* lock */
    entry = (lb_neighbor_cache *)rbtree_delete(&cache_mgmt->entry_root,
        key, lb_neighbor_cache_compare);
    if (NULL == entry) {
        ros_rwlock_write_unlock(&cache_mgmt->lock);/* unlock */
        LOG(LB, ERR, "delete neighbor entry failed,"
            " key: 0x%08x %08x %08x %08x.",
            *(uint32_t *)key->value,
            *(uint32_t *)(key->value + 4),
            *(uint32_t *)(key->value + 8),
            *(uint32_t *)(key->value + 12));

        return -1;
    }
    dl_list_del(&entry->aging_node);
    Res_Free(cache_mgmt->pool_id, 0, entry->index);
    ros_rwlock_write_unlock(&cache_mgmt->lock);/* unlock */

    return 0;
}

uint8_t *lb_neighbor_cache_get_mac(lb_neighbor_comp_key *key)
{
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();
    lb_neighbor_cache *entry = NULL;

    if (NULL == key) {
        LOG(LB, ERR, "Abnormal parameter, key(%p).", key);
        return NULL;
    }

    ros_rwlock_read_lock(&cache_mgmt->lock);/* lock */
    entry = (lb_neighbor_cache *)rbtree_search(&cache_mgmt->entry_root,
        key, lb_neighbor_cache_compare);
    ros_rwlock_read_unlock(&cache_mgmt->lock);/* unlock */
    if (NULL == entry) {
        LOG(LB, RUNNING, "No neighbor cache matches,"
            " key: 0x%08x %08x %08x %08x.",
            *(uint32_t *)key->value,
            *(uint32_t *)(key->value + 4),
            *(uint32_t *)(key->value + 8),
            *(uint32_t *)(key->value + 12));

        return NULL;
    }

#if 0
    ros_rwlock_read_lock(&entry->lock);/* lock */
    if ((entry->create_time + NEIGHBOR_CACHE_AGING_TIME) < ros_getime()) {
        ros_rwlock_read_unlock(&entry->lock);/* unlock */
        if (0 > lb_neighbor_cache_remove(key)) {
            LOG(LB, ERR, "Remove neighbor cache failed.");
        }

        return NULL;
    } else {
        ros_rwlock_read_unlock(&entry->lock);/* unlock */

        return entry->next_hop;
    }
#else

    return entry->next_hop;

#endif


}

void lb_neighbor_recv_arp(uint32_t net_ip, uint8_t *mac, uint8_t port)
{
    lb_neighbor_comp_key comp_key = {.v4_value = net_ip};

    if (unlikely(NULL == mac)) {
        LOG(LB, ERR, "Parameter abnormal, mac(%p).", mac);
        return;
    }

    if (0 > lb_neighbor_cache_create(&comp_key, mac, port, SESSION_IP_V4)) {
        LOG(LB, ERR, "Create neighbor cache failed.");
    }
}

static void *lb_neighbor_cache_renew_task(void *arg)
{
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();
    struct dl_list *pos = NULL, *next = NULL;
    lb_neighbor_cache *entry;

    for (;;) {
        /* 不加锁也问题不大 */
        dl_list_for_each_safe(pos, next, &cache_mgmt->aging_list) {
            entry = (lb_neighbor_cache *)container_of(pos,
                    lb_neighbor_cache, aging_node);
            if (entry->renew_times < LB_NEIGHBOR_CACHE_RENEW_MAX) {
                switch (entry->ip_version) {
                    case SESSION_IP_V4:
                        //gw_send_arp_request_public(entry->port_type, entry->comp_key.v4_value);
                        //++entry->renew_times;
                        break;

                    case SESSION_IP_V6:
                        break;
                }
            } else {
                if (0 > lb_neighbor_cache_remove(&entry->comp_key)) {
                    LOG(LB, ERR, "Delete neighbor cache entry failed.");
                }
            }
        }

        sleep(LB_NEIGHBOR_CACHE_AGING_TIME);
    }

    return NULL;
}

int64_t lb_neighbor_init(uint32_t neighbor_number)
{
    lb_neighbor_cache_mgmt *neighbor_cache_mgmt = lb_neighbor_cache_mgmt_get();
    uint32_t                index = 0;
    int64_t                 size = 0, total_mem = 0;
    lb_neighbor_cache *entry = NULL;
    int                     pool_id = -1;
    pthread_t               thr_id;

    /* Save a copy of configure */
    if (0 == neighbor_number) {
        LOG(LB, MUST, "Parameter neighbor_number:%d is invalid, use default value:%d.",
            neighbor_number, neighbor_cache_mgmt->max_num);
        neighbor_number = neighbor_cache_mgmt->max_num;
    }

    /* ARP Entry */
    size = neighbor_number * sizeof(lb_neighbor_cache);
    entry = (lb_neighbor_cache *)ros_malloc(size);
    if (NULL == entry) {
        LOG(LB, ERR, "alloc neighbor cache entry memory failed, total size:%ld.", size);
        return -1;
    }
    ros_memset(entry, 0, size);
    total_mem += size;
    for (index = 0; index < neighbor_number; ++index) {
        entry[index].index = index;
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

    neighbor_cache_mgmt->entry      = entry;
    neighbor_cache_mgmt->max_num    = neighbor_number;
    neighbor_cache_mgmt->pool_id    = pool_id;
    neighbor_cache_mgmt->entry_root = RB_ROOT_INIT_VALUE;
    dl_list_init(&neighbor_cache_mgmt->aging_list);
    ros_rwlock_init(&neighbor_cache_mgmt->lock);

    if (neighbor_cache_mgmt->max_num > 1000) {
        neighbor_cache_mgmt->aging_num = neighbor_cache_mgmt->max_num * 3 / 100;
    } else if (neighbor_cache_mgmt->max_num > 500) {
        neighbor_cache_mgmt->aging_num = neighbor_cache_mgmt->max_num * 4 / 100;
    } else if (neighbor_cache_mgmt->max_num > 100) {
        neighbor_cache_mgmt->aging_num = neighbor_cache_mgmt->max_num * 5 / 100;
    } else if (neighbor_cache_mgmt->max_num > 10) {
        neighbor_cache_mgmt->aging_num = neighbor_cache_mgmt->max_num * 20 / 100;
    } else {
        neighbor_cache_mgmt->aging_num = 1;
    }

    /* Create simple ARP renew task */
    if (0 != pthread_create(&thr_id, NULL, lb_neighbor_cache_renew_task, NULL)) {
		LOG(LB, ERR, "create arp renew task pthread failed.");
        return -1;
	}

    LOG(LB, ERR, "init success.\n");

    return total_mem;
}

int lb_neighbor_cache_show(struct cli_def *cli,int argc, char **argv)
{
    lb_neighbor_cache_mgmt *ngb_cache_mgmt = lb_neighbor_cache_mgmt_get();
    struct dl_list *pos = NULL, *next = NULL;
    lb_neighbor_cache *entry;
    char ip_str[256], *port_str[EN_PORT_BUTT];
    uint32_t tmp_ipv4, cnt_no = 0;

    port_str[EN_PORT_N3] = "N3";
    port_str[EN_PORT_N4] = "N4";
    port_str[EN_PORT_N6] = "N6";
    port_str[EN_PORT_N9] = "N9";

    cli_print(cli,"No          PORT     IP-address                                      Next-Hop MAC\n");

    dl_list_for_each_safe(pos, next, &ngb_cache_mgmt->aging_list) {
        entry = (lb_neighbor_cache *)container_of(pos,
                lb_neighbor_cache, aging_node);

        switch (entry->ip_version) {
            case SESSION_IP_V4:
                tmp_ipv4 = entry->comp_key.v4_value;
                if (NULL == inet_ntop(AF_INET, &tmp_ipv4, ip_str, sizeof(ip_str))) {
                    cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                break;

            case SESSION_IP_V6:
                if (NULL == inet_ntop(AF_INET6, entry->comp_key.value, ip_str, sizeof(ip_str))) {
                    cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                break;

            default:
                cli_print(cli, "Abnormal neighbor cache, IP version: %d", entry->ip_version);
                break;
        }
        cli_print(cli, "%-8u    %-2s       %-40s        %02x:%02x:%02x:%02x:%02x:%02x\n",
            ++cnt_no, port_str[entry->port_type], ip_str,
            entry->next_hop[0], entry->next_hop[1], entry->next_hop[2],
            entry->next_hop[3], entry->next_hop[4], entry->next_hop[5]);
    }

    return 0;
}


