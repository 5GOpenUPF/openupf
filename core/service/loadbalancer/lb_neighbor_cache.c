/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "dpdk.h"
#include "lb_dpdk_cache.h"
#include "lb_neighbor_cache.h"

static lb_neighbor_cache_mgmt g_lb_neighbor_cache_mgmt = {.max_num = 500};


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
    lb_neighbor_key *new_key = (lb_neighbor_key *)key;

    /*if (entry->comp_key.d.key1 < new_key->d.key1) {
        return -1;
    } else if (entry->comp_key.d.key1 > new_key->d.key1) {
        return 1;
    }

    if (entry->comp_key.d.key2 < new_key->d.key2) {
        return -1;
    } else if (entry->comp_key.d.key2 > new_key->d.key2) {
        return 1;
    }

    return 0;*/
    return ros_memcmp(&entry->comp_key, new_key, sizeof(lb_neighbor_key));
}

int lb_neighbor_cache_create(lb_neighbor_key *key, uint8_t *mac,
    uint8_t port_type, uint8_t ip_ver)
{
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();
    lb_neighbor_cache *entry = NULL;
    uint32_t res_key = 0, index = 0;

    if (NULL == key) {
        LOG(LB, ERR, "Abnormal parameter, key(%p).", key);
        return -1;
    }

    LOG(LB, RUNNING, "Create neighbor cache, key: 0x%08x %08x %08x %08x.",
        *(uint32_t *)key->value,
        *(uint32_t *)(key->value + 4),
        *(uint32_t *)(key->value + 8),
        *(uint32_t *)(key->value + 12));

    ros_rwlock_write_lock(&cache_mgmt->lock);/* lock */
    entry = (lb_neighbor_cache *)rbtree_search(&cache_mgmt->entry_root,
        key, lb_neighbor_cache_compare);
    if (entry) {
        LOG(LB, RUNNING, "neighbor cache is existence, update it,"
            " key: 0x%08x %08x %08x %08x.",
            *(uint32_t *)key->value,
            *(uint32_t *)(key->value + 4),
            *(uint32_t *)(key->value + 8),
            *(uint32_t *)(key->value + 12));

        ros_rwlock_write_lock(&entry->lock);/* lock */
        ros_memcpy(entry->next_hop, mac, ETH_ALEN);
        //entry->port_type = port_type;
        entry->renew_times = 0;
        ros_rwlock_write_unlock(&entry->lock);/* unlock */
    } else {

        /* Create new entry */
        if (G_FAILURE == Res_Alloc(cache_mgmt->pool_id, &res_key, &index,
            EN_RES_ALLOC_MODE_OC)) {
            ros_rwlock_write_unlock(&cache_mgmt->lock);/* unlock */
            LOG(LB, ERR, "alloc resource failed.");
            return -1;
        }
        entry = lb_neighbor_cache_get(index);

        ros_rwlock_write_lock(&entry->lock);/* lock */
        ros_memcpy(&entry->comp_key, key, sizeof(lb_neighbor_key));
        entry->last_used_time = ros_getime();
        entry->port_type = port_type;
        entry->ip_version = ip_ver;
        entry->renew_times = 0;
        ros_memcpy(entry->next_hop, mac, ETH_ALEN);
        ros_rwlock_write_unlock(&entry->lock);/* unlock */

        if (-1 == rbtree_insert(&cache_mgmt->entry_root, &entry->key_node,
            &entry->comp_key, lb_neighbor_cache_compare)) {
            Res_Free(cache_mgmt->pool_id, res_key, index);
            ros_rwlock_write_unlock(&cache_mgmt->lock);/* unlock */
            LOG(LB, ERR, "insert neighbor entry failed, key: 0x%08x %08x %08x %08x.",
                *(uint32_t *)entry->comp_key.value,
                *(uint32_t *)(entry->comp_key.value + 4),
                *(uint32_t *)(entry->comp_key.value + 8),
                *(uint32_t *)(entry->comp_key.value + 12));

            return -1;
        }
    }
    ros_rwlock_write_unlock(&cache_mgmt->lock);/* unlock */

    return 0;
}

static void lb_neighbor_cache_delete(lb_neighbor_cache *entry)
{
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();

    LOG(LB, RUNNING, "Neighbor cache delete: 0x%08x %08x %08x %08x.",
            *(uint32_t *)entry->comp_key.value,
            *(uint32_t *)(entry->comp_key.value + 4),
            *(uint32_t *)(entry->comp_key.value + 8),
            *(uint32_t *)(entry->comp_key.value + 12));

    ros_rwlock_write_lock(&cache_mgmt->lock);/* lock */
    //rbtree_delete(&cache_mgmt->entry_root, &entry->comp_key, lb_neighbor_cache_compare);
    rbtree_erase(&entry->key_node, &cache_mgmt->entry_root);
    Res_Free(cache_mgmt->pool_id, 0, entry->index);
    ros_rwlock_write_unlock(&cache_mgmt->lock);/* unlock */
}

int lb_neighbor_cache_remove(lb_neighbor_key *key)
{
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();
    lb_neighbor_cache *entry = NULL;

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
    Res_Free(cache_mgmt->pool_id, 0, entry->index);
    ros_rwlock_write_unlock(&cache_mgmt->lock);/* unlock */

    return 0;
}

int lb_neighbor_cache_get_mac(lb_neighbor_key *key, uint8_t *dest_mac)
{
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();
    lb_neighbor_cache *entry = NULL;

    if (NULL == key || NULL == dest_mac) {
        LOG(LB, ERR, "Abnormal parameter, key(%p), dest_mac(%p).", key, dest_mac);
        return -1;
    }

    LOG(LB, PERIOD, "Get neighbor cache: 0x%08x %08x %08x %08x.",
        *(uint32_t *)key->value, *(uint32_t *)(key->value + 4),
        *(uint32_t *)(key->value + 8), *(uint32_t *)(key->value + 12));

    ros_rwlock_read_lock(&cache_mgmt->lock);/* lock */
    entry = (lb_neighbor_cache *)rbtree_search(&cache_mgmt->entry_root,
        key, lb_neighbor_cache_compare);
    if (NULL == entry) {
        ros_rwlock_read_unlock(&cache_mgmt->lock);/* unlock */
        LOG(LB, RUNNING, "No neighbor cache matches, key: 0x%08x %08x %08x %08x.",
            *(uint32_t *)key->value,
            *(uint32_t *)(key->value + 4),
            *(uint32_t *)(key->value + 8),
            *(uint32_t *)(key->value + 12));

        return -1;
    }
    ros_memcpy(dest_mac, entry->next_hop, ETH_ALEN);

    /* Update frequency of last used time, defaule 2s */
    if (entry->last_used_time < ros_getime()) {
        entry->last_used_time = ros_getime() + 2;
    }
    ros_rwlock_read_unlock(&cache_mgmt->lock);/* unlock */

    return 0;
}

uint32_t lb_neighbor_build_arp_request(char *buf, uint32_t dest_net_ip)
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

static void *lb_neighbor_cache_maintenance_task(void *arg)
{
#if (LB_NEIGHBOR_ENABLED == 1)
    lb_neighbor_cache_mgmt *cache_mgmt = lb_neighbor_cache_mgmt_get();
    lb_neighbor_cache *entry;
    int32_t cur_index;

    for (;;) {

        cur_index = -1;
        while (-1 != (cur_index = Res_GetAvailableInBand(cache_mgmt->pool_id, cur_index + 1, cache_mgmt->max_num))) {
            entry = lb_neighbor_cache_get(cur_index);

            if ((entry->renew_times < LB_NEIGHBOR_CACHE_RENEW_MAX) &&
                ((entry->last_used_time + LB_NEIGHBOR_CACHE_AGING_TIME) > ros_getime())) {
                switch (entry->ip_version) {
                    case SESSION_IP_V4:
                        {
                            lb_dpdk_cache_node *cache_node;
                            lb_buffer_block *buffer_blk;

                            cache_node = lb_dpdk_cache_alloc();
                            if (NULL == cache_node) {
                                LOG(LB, ERR, "Allocate cache node failed.");
                                break;
                            }

                            buffer_blk = lb_buffer_block_alloc();
                            if (NULL == buffer_blk) {
                                lb_dpdk_cache_free(cache_node);
                                LOG(LB, ERR, "Allocate buffer block failed.");
                                break;
                            }

                            buffer_blk->data_len = lb_neighbor_build_arp_request(buffer_blk->data,
                                entry->comp_key.v4_value);

                            cache_node->core_id     = dpdk_get_first_core_id();
                            cache_node->data        = (void *)buffer_blk;
                            cache_node->proc_method = EN_CACHE_NODE_COPY_SEND;

                            lb_dpdk_tx_queue_append(cache_node);

                            ros_rwlock_write_lock(&entry->lock);/* lock */
                            ++entry->renew_times;
                            ros_rwlock_write_unlock(&entry->lock);/* unlock */
                        }
                        break;

                    case SESSION_IP_V6:
                        break;
                }
            } else {
                lb_neighbor_cache_delete(entry);
            }
        }

        sleep(LB_NEIGHBOR_CACHE_UPDATE_TIME);
    }
#endif

    return NULL;
}

int64_t lb_neighbor_cache_init(uint32_t neighbor_number)
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

    /* Entry */
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
    ros_rwlock_init(&neighbor_cache_mgmt->lock);

    /* Create simple ARP renew task */
    if (0 != pthread_create(&thr_id, NULL, lb_neighbor_cache_maintenance_task, NULL)) {
		LOG(LB, ERR, "create arp renew task pthread failed.");
        return -1;
	}
    LOG(LB, ERR, "init success.\n");

    return total_mem;
}

int lb_neighbor_cache_show(struct cli_def *cli,int argc, char **argv)
{
    lb_neighbor_cache_mgmt *ngb_cache_mgmt = lb_neighbor_cache_mgmt_get();
    lb_neighbor_cache *entry;
    char ip_str[256], *port_str[EN_PORT_BUTT];
    uint32_t tmp_ipv4, cnt_no;
    int cur_index;

    port_str[EN_PORT_N3] = "N3";
    port_str[EN_PORT_N4] = "N4";
    port_str[EN_PORT_N6] = "N6";
    port_str[EN_PORT_N9] = "N9";

    cli_print(cli,"No       PORT   Dest IP-address                                 Next-Hop MAC       TTL\n");

    cnt_no = 0;
    cur_index = -1;
    while (-1 != (cur_index = Res_GetAvailableInBand(ngb_cache_mgmt->pool_id,
        cur_index + 1, ngb_cache_mgmt->max_num))) {

        entry = lb_neighbor_cache_get(cur_index);

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
        cli_print(cli, "%-5u    %-2s     %-40s        %02x:%02x:%02x:%02x:%02x:%02x  %u\n",
            ++cnt_no, port_str[entry->port_type], ip_str,
            entry->next_hop[0], entry->next_hop[1], entry->next_hop[2],
            entry->next_hop[3], entry->next_hop[4], entry->next_hop[5],
            (entry->last_used_time + LB_NEIGHBOR_CACHE_AGING_TIME) - ros_getime());
    }

    return 0;
}
