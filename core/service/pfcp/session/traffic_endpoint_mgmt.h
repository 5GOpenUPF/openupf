/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __TRAFFIC_ENDPOINT_H
#define __TRAFFIC_ENDPOINT_H

struct traffic_endpoint_table {
    struct rb_node              te_node;    /* Link session */
    session_tc_endpoint         te;
    uint32_t                    index;
    ros_rwlock_t                lock;
};

struct traffic_endpoint_table_head {
    struct traffic_endpoint_table       *te_table;
    uint32_t                            max_num;
    ros_rwlock_t                        lock;
    uint16_t                            pool_id;
};

int64_t traffic_endpoint_table_init(uint32_t session_num);
struct traffic_endpoint_table *traffic_endpoint_table_search(struct session_t *sess, uint8_t id);
struct traffic_endpoint_table *traffic_endpoint_table_create(struct session_t *sess, uint8_t id);
int traffic_endpoint_insert(struct session_t *sess, void *parse_te_arr, uint8_t te_num);
int traffic_endpoint_remove(struct session_t *sess, uint8_t *te_id_arr, uint8_t te_id_num,
    uint32_t *rm_pdr_index_arr, uint32_t *rm_pdr_num);
int traffic_endpoint_modify(struct session_t *sess, void *parse_te_arr, uint8_t parse_te_num);
int traffic_endpoint_clear(struct session_t *sess);

#endif
