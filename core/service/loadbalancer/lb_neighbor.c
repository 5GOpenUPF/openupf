/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "lb_dpdk_cache.h"
#include "dpdk.h"
#include "lb_neighbor.h"

lb_neighbor_cache_mgmt g_lb_neighbor_cache_mgmt = {.max_num = 500};


static int lb_neighbor_cache_remove(lb_neighbor_comp_key *key);

static int lb_neighbor_remove(lb_neighbor_comp_key *key, uint8_t *mac);

static inline lb_neighbor_cache_mgmt *lb_neighbor_cache_mgmt_get(void)
{
    return &g_lb_neighbor_cache_mgmt;
}

lb_neighbor_cache_mgmt *lb_neighbor_cache_mgmt_get_public(void)
{
    return lb_neighbor_cache_mgmt_get();
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
    if (entry) {
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

    LOG(LB, RUNNING, "Get neighbor cache: 0x%08x %08x %08x %08x.",
        *(uint32_t *)key->value, *(uint32_t *)(key->value + 4),
        *(uint32_t *)(key->value + 8), *(uint32_t *)(key->value + 12));

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

    LOG(LB, RUNNING, "Update neighbor, key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)comp_key.value,
        *(uint32_t *)(comp_key.value + 4),
        *(uint32_t *)(comp_key.value + 8),
        *(uint32_t *)(comp_key.value + 12));
    if (-1 == lb_neighbor_remove(&comp_key, mac)) {
        LOG(LB, DEBUG, "Maybe the timeout has been handled.");
    }
}

static uint32_t lb_neighbor_build_arp_request(char *buf, uint32_t dest_net_ip)
{
    uint32_t buf_len = 0;
    struct pro_eth_hdr *eth = NULL;
    struct pro_arp_hdr *buf_arp_hdr = NULL;
    uint8_t *upf_mac;

    LOG(SESSION, RUNNING, "Build ARP request, target ip: 0x%08x.", ntohl(dest_net_ip));

    upf_mac = lb_get_local_port_mac(EN_LB_PORT_EXT);

    eth = (struct pro_eth_hdr *)buf;
    buf_len += sizeof(struct pro_eth_hdr);

    memset(eth->dest, 0xFF, ETH_ALEN);
    memcpy(eth->source, upf_mac, ETH_ALEN);
    eth->eth_type = htons(ETH_PRO_ARP);

    buf_arp_hdr = (struct pro_arp_hdr *)(buf + buf_len);
    buf_arp_hdr->ar_hrd = htons(1);
    buf_arp_hdr->ar_pro = htons(ETH_PRO_IP);
    buf_arp_hdr->ar_hln = 6;
    buf_arp_hdr->ar_pln = 4;
    buf_arp_hdr->ar_op  = htons(1);
    memcpy(buf_arp_hdr->ar_sha, upf_mac, ETH_ALEN);
    *(uint32_t *)(buf_arp_hdr->ar_sip) = lb_get_local_net_ipv4(EN_PORT_N3);
    memset(buf_arp_hdr->ar_tha, 0, ETH_ALEN);
    *(uint32_t *)(buf_arp_hdr->ar_tip) = dest_net_ip;
    buf_len += sizeof(struct pro_arp_hdr);

    return buf_len;
}

static void *lb_neighbor_cache_renew_task(void *arg)
{
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();
    struct dl_list *pos = NULL, *next = NULL;
    lb_neighbor_cache *entry;

    for (;;) {
        dl_list_for_each_safe(pos, next, &cache_mgmt->aging_list) {
            entry = (lb_neighbor_cache *)container_of(pos,
                    lb_neighbor_cache, aging_node);
            if (entry->renew_times < LB_NEIGHBOR_CACHE_RENEW_MAX) {
                switch (entry->ip_version) {
                    case SESSION_IP_V4:
                        {
                            lb_dpdk_cache_node *cache_node;
                            lb_buffer_block *buffer_blk;

                            cache_node = lb_dpdk_cache_alloc();
                            if (NULL == cache_node) {
                                LOG(LB, ERR, "Allocate cache node failed.");
                                continue;
                            }

                            buffer_blk = lb_buffer_block_alloc();
                            if (NULL == buffer_blk) {
                                lb_dpdk_cache_free(cache_node);
                                LOG(LB, ERR, "Allocate buffer block failed.");
                                continue;
                            }

                            buffer_blk->data_len = lb_neighbor_build_arp_request(buffer_blk->data, entry->comp_key.v4_value);

                            cache_node->core_id     = dpdk_get_first_core_id();
                            cache_node->data        = (void *)buffer_blk;
                            cache_node->proc_method = EN_CACHE_NODE_COPY_SEND;

                            lb_dpdk_tx_queue_append(cache_node);

                            ++entry->renew_times;
                        }
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

static int64_t lb_neighbor_cache_init(uint32_t neighbor_number)
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

/************************* Neighbor Discovery ****************************/
lb_neighbor_mgmt g_lb_neighbor_mgmt;


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

static int lb_neighbor_compare(struct rb_node *rbnode, void *key)
{
    lb_neighbor_entry *entry = (lb_neighbor_entry *)rbnode;
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

static lb_neighbor_entry *lb_neighbor_create(lb_neighbor_comp_key *key, uint8_t ip_ver)
{
    lb_neighbor_mgmt *ngb_mgmt = lb_neighbor_mgmt_get();
    lb_neighbor_entry *ngb_entry = NULL;
    uint32_t res_key = 0, index = 0;

    if (NULL == key) {
        LOG(LB, ERR, "abnormal parameter, key(%p).", key);
        return NULL;
    }

    if (G_FAILURE == Res_Alloc(ngb_mgmt->pool_id, &res_key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(LB, ERR, "alloc resource failed.");
        return NULL;
    }

    ngb_entry = lb_neighbor_entry_get(index);

    ros_rwlock_write_lock(&ngb_entry->lock);/* lock */
    ros_memcpy(&ngb_entry->comp_key, key, sizeof(lb_neighbor_comp_key));
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
    ros_rwlock_write_lock(&ngb_mgmt->lock);/* lock */
    if (-1 == rbtree_insert(&ngb_mgmt->entry_root, &ngb_entry->key_node,
        &ngb_entry->comp_key, lb_neighbor_compare)) {
        ros_rwlock_write_unlock(&ngb_mgmt->lock);/* unlock */
        Res_Free(ngb_mgmt->pool_id, 0, index);
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
    ros_rwlock_write_unlock(&ngb_mgmt->lock);/* unlock */

    return ngb_entry;
}

static inline lb_neighbor_entry *lb_neighbor_search(lb_neighbor_comp_key *key)
{
    lb_neighbor_mgmt *ngb_mgmt = lb_neighbor_mgmt_get();
    lb_neighbor_entry *ngb_entry = NULL;

    LOG(LB, RUNNING, "search neighbor entry, key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)key->value, *(uint32_t *)(key->value + 4),
        *(uint32_t *)(key->value + 8), *(uint32_t *)(key->value + 12));

    ros_rwlock_read_lock(&ngb_mgmt->lock);/* lock */
    ngb_entry = (lb_neighbor_entry *)rbtree_search(&ngb_mgmt->entry_root,
        key, lb_neighbor_compare);
    ros_rwlock_read_unlock(&ngb_mgmt->lock);/* unlock */

    return ngb_entry;
}

static int lb_neighbor_remove(lb_neighbor_comp_key *key, uint8_t *mac)
{
    lb_neighbor_mgmt *ngb_mgmt = lb_neighbor_mgmt_get();
    lb_neighbor_entry *ngb_entry = NULL;
    struct dl_list *pos = NULL, *next = NULL;
    lb_dpdk_cache_node *cache_node;

    if (NULL == key) {
        LOG(LB, ERR, "abnormal parameter, key(%p).", key);
        return -1;
    }

    LOG(LB, RUNNING, "delete neighbor entry, key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)key->value,
        *(uint32_t *)(key->value + 4),
        *(uint32_t *)(key->value + 8),
        *(uint32_t *)(key->value + 12));
    ros_rwlock_write_lock(&ngb_mgmt->lock);/* lock */
    ngb_entry = (lb_neighbor_entry *)rbtree_delete(&ngb_mgmt->entry_root,
        key, lb_neighbor_compare);
    if (NULL == ngb_entry) {
        ros_rwlock_write_unlock(&ngb_mgmt->lock);/* unlock */
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
    ros_rwlock_write_unlock(&ngb_mgmt->lock);/* unlock */

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
    ros_rwlock_write_unlock(&ngb_entry->lock);/* unlock */

    dl_list_init(&ngb_entry->wait_queue);
    Res_Free(ngb_mgmt->pool_id, 0, ngb_entry->index);

    return 0;
}

int lb_neighbor_wait_reply(lb_neighbor_comp_key *key, uint8_t ip_ver, void *buf)
{
    lb_neighbor_entry *entry;
    lb_dpdk_cache_node *cache_node;
    uint8_t send_arp_request = G_FALSE;

    cache_node = lb_dpdk_cache_alloc();
    if (NULL == cache_node) {
        LOG(LB, ERR, "Allocate cache node failed.");
        return -1;
    }

    entry = lb_neighbor_search(key);
    if (NULL == entry) {
        entry = lb_neighbor_create(key, ip_ver);
        if (NULL == entry) {
            /* Extreme cases */
            entry = lb_neighbor_search(key);
            if (NULL == entry) {
                lb_dpdk_cache_free(cache_node);
                LOG(LB, ERR, "Create neighbor failed.");
                return -1;
            }
        }
        send_arp_request = G_TRUE;
    }

    cache_node->core_id     = rte_lcore_id();
    cache_node->data        = buf;
    cache_node->proc_method = EN_CACHE_NODE_DIRECT_SEND;

    ros_rwlock_write_lock(&entry->lock); /* Lock */
    dl_list_add_tail(&entry->wait_queue, &cache_node->node);
    ros_rwlock_write_unlock(&entry->lock); /* Unlock */

    if (send_arp_request) {
        struct rte_mbuf *mbuf_arp;
        uint32_t data_len;

        /* Alloc buffer */
        mbuf_arp = dpdk_alloc_mbuf();
        if (NULL == mbuf_arp) {
            LOG(LB, ERR, "Allocate DPDK mbuf failed, ARP request cannot be issued.");
            return 0; /* Return 0, Wait for automatic timeout delete */
        }

        /* Copy content and set length */
        switch (ip_ver) {
            case SESSION_IP_V4:
                data_len = lb_neighbor_build_arp_request(rte_pktmbuf_mtod(mbuf_arp, char *), key->v4_value);
                break;

            case SESSION_IP_V6:
                LOG(LB, ERR, "IPv6 Neighbor Discovery is not supported at present.");
                dpdk_free_mbuf(mbuf_arp);
                return 0;

            default:
                LOG(LB, ERR, "Unknown condition, please check the program.");
                dpdk_free_mbuf(mbuf_arp);
                return 0;
        }
        pkt_buf_set_len(mbuf_arp, data_len);

        lb_fwd_to_external_network_public(mbuf_arp);
    }

    return 0;
}

void *lb_neighbor_timeout_task(void *arg)
{
    lb_neighbor_mgmt *ngb_mgmt = lb_neighbor_mgmt_get();
    uint32_t cur_time;
    struct dl_list *pos = NULL, *next = NULL;
    lb_neighbor_entry *ngb_entry = NULL;

    for (;;) {
        cur_time = ros_getime();
        dl_list_for_each_safe(pos, next, &ngb_mgmt->timeline) {
            ngb_entry = (lb_neighbor_entry *)container_of(pos,
                    lb_neighbor_entry, timeline_node);

            if (cur_time >= ngb_entry->timeout) {
                lb_neighbor_remove(&ngb_entry->comp_key, NULL);
            } else {
                break;
            }
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

