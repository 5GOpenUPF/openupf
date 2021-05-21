/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LB_DPDK_CACHE_H__
#define _LB_DPDK_CACHE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define LB_ENABLE_DPDK_CACHE

#define LB_PER_NEIGHBOR_CACHE_NODE_NUM          50


#define lb_free_pkt(buf)    dpdk_free_mbuf(buf)


typedef enum tag_EN_CACHE_NODE_PROCESS_METHOD {
    EN_CACHE_NODE_DIRECT_SEND       = 1,
    EN_CACHE_NODE_COPY_SEND         = 2,
    EN_CACHE_NODE_DROP              = 3,
}EN_CACHE_NODE_PROCESS_METHOD;

typedef struct tag_lb_buffer_block
{
    char            data[256];
    uint32_t        data_len;
    uint32_t        index;
}lb_buffer_block;

typedef struct tag_lb_dpdk_cache_node
{
    struct dl_list      node;
    void                *data;
    uint32_t            index;
    uint16_t            core_id;
    uint8_t             proc_method; /* Refer EN_CACHE_NODE_PROCESS_METHOD */
    uint8_t             spare;
}lb_dpdk_cache_node;

typedef struct tag_lb_dpdk_tx_queue
{
    ros_rwlock_t        dpdk_tx_lock[COMM_MSG_MAX_DPDK_CORE_NUM];
    struct dl_list      dpdk_tx_lst[COMM_MSG_MAX_DPDK_CORE_NUM];    /* DPDK send packet queue */
    lb_dpdk_cache_node  *cache_array;
    lb_buffer_block     *block_array;
    uint16_t            blk_pool_id;    /* Resource pool ID */
    uint16_t            cache_pool_id;  /* Resource pool ID */
    uint32_t            max_num;        /* Max supported entry number */
}lb_dpdk_tx_queue;


lb_dpdk_tx_queue *lb_dpdk_cache_mgmt_get_public(void);
lb_dpdk_cache_node *lb_dpdk_cache_alloc(void);
void lb_dpdk_cache_free(lb_dpdk_cache_node *entry);
lb_buffer_block *lb_buffer_block_alloc(void);
void lb_buffer_block_free(lb_buffer_block *entry);
void lb_dpdk_tx_queue_append(lb_dpdk_cache_node *entry);
void lb_dpdk_tx_queue_proc(uint32_t lcore_id);
void lb_dpdk_cache_init_prepare(void);
int64_t lb_dpdk_cache_init(uint32_t neighbor_number);


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _LB_DPDK_CACHE_H__ */

