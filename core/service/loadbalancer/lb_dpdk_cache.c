/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include <rte_mbuf.h>
#include <rte_meter.h>

#include "dpdk.h"
#include "lb_dpdk_cache.h"

/* LB cache queue */
static lb_dpdk_tx_queue g_lb_dpdk_cache_mgmt;


static inline lb_dpdk_tx_queue *lb_dpdk_cache_mgmt_get(void)
{
    return &g_lb_dpdk_cache_mgmt;
}

lb_dpdk_tx_queue *lb_dpdk_cache_mgmt_get_public(void)
{
    return lb_dpdk_cache_mgmt_get();
}

static inline lb_dpdk_cache_node *lb_dpdk_cache_node_get(uint32_t index)
{
    return &g_lb_dpdk_cache_mgmt.cache_array[index];
}

static inline lb_buffer_block *lb_buffer_block_get(uint32_t index)
{
    return &g_lb_dpdk_cache_mgmt.block_array[index];
}

lb_dpdk_cache_node *lb_dpdk_cache_alloc(void)
{
    lb_dpdk_tx_queue *cache_mgmt = lb_dpdk_cache_mgmt_get();
    uint32_t res_key = 0, index = 0;

    if (G_FAILURE == Res_Alloc(cache_mgmt->cache_pool_id, &res_key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(LB, ERR, "alloc resource failed.");
        return NULL;
    }

    return lb_dpdk_cache_node_get(index);
}

void lb_dpdk_cache_free(lb_dpdk_cache_node *entry)
{
    lb_dpdk_tx_queue *cache_mgmt = lb_dpdk_cache_mgmt_get();

    if (NULL == entry) {
        LOG(LB, ERR, "abnormal parameter, entry(%p).", entry);
        return;
    }

    Res_Free(cache_mgmt->cache_pool_id, 0, entry->index);
    entry->data = NULL;
}

lb_buffer_block *lb_buffer_block_alloc(void)
{
    lb_dpdk_tx_queue *cache_mgmt = lb_dpdk_cache_mgmt_get();
    uint32_t res_key = 0, index = 0;

    if (G_FAILURE == Res_Alloc(cache_mgmt->blk_pool_id, &res_key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(LB, ERR, "alloc resource failed.");
        return NULL;
    }

    return lb_buffer_block_get(index);
}

void lb_buffer_block_free(lb_buffer_block *entry)
{
    lb_dpdk_tx_queue *cache_mgmt = lb_dpdk_cache_mgmt_get();

    if (NULL == entry) {
        LOG(LB, ERR, "abnormal parameter, entry(%p).", entry);
        return;
    }

    Res_Free(cache_mgmt->blk_pool_id, 0, entry->index);
    entry->data_len = 0;
}

void lb_dpdk_tx_queue_append(lb_dpdk_cache_node *entry)
{
    uint16_t core_id;

    if (NULL == entry) {
        LOG(LB, ERR, "abnormal parameter, entry(%p).", entry);
        return;
    }

    core_id = entry->core_id;
    ros_rwlock_write_lock(&g_lb_dpdk_cache_mgmt.dpdk_tx_lock[core_id]);
    dl_list_add_tail(&g_lb_dpdk_cache_mgmt.dpdk_tx_lst[core_id], &entry->node);
    ros_rwlock_write_unlock(&g_lb_dpdk_cache_mgmt.dpdk_tx_lock[core_id]);
}

void lb_dpdk_tx_queue_proc(uint32_t lcore_id)
{
#if (LB_NEIGHBOR_ENABLED == 1)
    lb_dpdk_cache_node *cache_node;
    struct dl_list *pos = NULL, *next = NULL;

    ros_rwlock_write_lock(&g_lb_dpdk_cache_mgmt.dpdk_tx_lock[lcore_id]); /* Lock */
    dl_list_for_each_safe(pos, next, &g_lb_dpdk_cache_mgmt.dpdk_tx_lst[lcore_id]) {
        cache_node = (lb_dpdk_cache_node *)container_of(pos, lb_dpdk_cache_node, node);

        switch (cache_node->proc_method) {
            case EN_CACHE_NODE_DIRECT_SEND:
                lb_fwd_to_external_network_public((struct rte_mbuf *)cache_node->data);
                break;

            case EN_CACHE_NODE_COPY_SEND:
                {
                    struct rte_mbuf *mbuf;
                    lb_buffer_block *buffer_blk = (lb_buffer_block *)cache_node->data;

                    /* Alloc buffer */
                    mbuf = dpdk_alloc_mbuf();
                    if (unlikely(NULL == mbuf)) {
                        LOG(LB, ERR, "Allocate DPDK mbuf failed.");
                        lb_buffer_block_free(buffer_blk);
                        break;
                    }

                    /* Copy content and set length */
                    rte_memcpy(rte_pktmbuf_mtod(mbuf, void *), buffer_blk->data, buffer_blk->data_len);
                    pkt_buf_set_len(mbuf, buffer_blk->data_len);

                    lb_buffer_block_free(buffer_blk);

                    lb_fwd_to_external_network_public(mbuf);
                }
                break;

            default:
                lb_free_pkt((struct rte_mbuf *)cache_node->data);
                break;
        }

        /* Free cache node */
        dl_list_del(&cache_node->node);
        lb_dpdk_cache_free(cache_node);
    }
    ros_rwlock_write_unlock(&g_lb_dpdk_cache_mgmt.dpdk_tx_lock[lcore_id]); /* Unlock */
#endif
}

void lb_dpdk_cache_init_prepare(void)
{
    lb_dpdk_tx_queue *cache_mgmt = lb_dpdk_cache_mgmt_get();
    uint32_t index;

    for (index = 0; index < COMM_MSG_MAX_DPDK_CORE_NUM; ++index) {
        ros_rwlock_init(&cache_mgmt->dpdk_tx_lock[index]);
        dl_list_init(&cache_mgmt->dpdk_tx_lst[index]);
    }
}

int64_t lb_dpdk_cache_init(uint32_t neighbor_number)
{
    lb_dpdk_tx_queue *cache_mgmt = lb_dpdk_cache_mgmt_get();
    uint32_t index = 0, max_num;
    int64_t size = 0, total_mem = 0;
    lb_dpdk_cache_node *entry = NULL;
    lb_buffer_block *buffer_blk;
    int pool_id = -1;

    /* Cache node */
    max_num = neighbor_number * LB_PER_NEIGHBOR_CACHE_NODE_NUM;
    size = max_num * sizeof(lb_dpdk_cache_node);
    entry = (lb_dpdk_cache_node *)ros_malloc(size);
    if (NULL == entry) {
        LOG(LB, ERR, "Allocate neighbor cache entry memory failed, total size:%ld.", size);
        return -1;
    }
    ros_memset(entry, 0, size);
    total_mem += size;
    for (index = 0; index < max_num; ++index) {
        entry[index].index = index;
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(LB, ERR, "Res_CreatePool failed.\n");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(LB, ERR, "Res_AddSection failed.\n");
        return -1;
    }

    cache_mgmt->cache_array     = entry;
    cache_mgmt->max_num         = max_num;
    cache_mgmt->cache_pool_id   = pool_id;

    /* Buffer block */
    max_num = neighbor_number;
    size = max_num * sizeof(lb_buffer_block);
    buffer_blk = (lb_buffer_block *)ros_malloc(size);
    if (NULL == buffer_blk) {
        LOG(LB, ERR, "Allocate buffer block memory failed, total size:%ld.", size);
        return -1;
    }
    ros_memset(buffer_blk, 0, size);
    total_mem += size;
    for (index = 0; index < max_num; ++index) {
        buffer_blk[index].index = index;
        buffer_blk[index].data_len = 0;
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(LB, ERR, "Res_CreatePool failed.\n");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(LB, ERR, "Res_AddSection failed.\n");
        return -1;
    }

    cache_mgmt->block_array     = buffer_blk;
    cache_mgmt->blk_pool_id     = pool_id;

    LOG(LB, MUST, "DPKD cache mode init success.");

    return total_mem;
}

