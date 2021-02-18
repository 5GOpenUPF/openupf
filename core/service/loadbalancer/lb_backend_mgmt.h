/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LB_BACKEND_MGMT_H__
#define _LB_BACKEND_MGMT_H__

#ifdef __cplusplus
extern "C" {
#endif

#define LB_MAX_CTRL_USE_CPUS    (8)

#define LB_HASH_1_NUMBER        (256)
#define LB_HASH_2_NUMBER        (65536)


#define LB_BACKEND_TIMEOUT_MAX      (3)

typedef struct tag_lb_backend_config {
    struct rb_node      be_node;
    uint8_t             be_mac[ETH_ALEN];
    ros_atomic16_t      valid;  /* 0:invalid  1:valid */
    ros_atomic32_t      assign_count;
    uint32_t            index;
    int                 fd;     /* Currently valid connections */
    ros_rwlock_t        lock;
    uint64_t            be_key;
}lb_backend_config;

typedef struct tag_lb_backend_mgmt {
    struct rb_root          be_root;
    lb_backend_config       backend_table[COMM_MSG_BACKEND_NUMBER]; /* Index 0 is invalid */
    int                     be_pool_id;
    int                     mb_fd;
    comm_msg_channel_server mb_mgmt_server;
    ros_atomic32_t          mb_heartbeat_cnt;
    ros_rwlock_t            lock;
}lb_backend_mgmt;

/* 同步数据 */
/* hash table config */
typedef struct tag_lb_sync_hash_config {
    uint8_t                 hash_1;
    uint8_t                 be_index;
    uint16_t                hash_2;
} lb_sync_hash_config;

typedef struct tag_lb_sync_backend_config {
    uint8_t             be_mac[ETH_ALEN];
    uint8_t             valid;  /* 0:invalid  1:valid */
    uint8_t             be_index;
    int32_t             assign_count;
} lb_sync_backend_config;


comm_msg_channel_server *lb_get_backend_mgmt_server(void);
uint64_t lb_get_local_flag_key(void);
void lb_set_peer_flag_key(uint64_t vlu);
uint64_t lb_get_peer_flag_key(void);
void lb_reset_mb_heartbeat_count(void);

lb_backend_config *lb_get_backend_config_public(uint8_t be_index);
int lb_get_backend_pool_public(void);
uint8_t lb_get_hash_vlaue(uint8_t hash1, uint16_t hash2);
void lb_hash_table_update(uint8_t hash1, uint16_t hash2, uint8_t be_index);
void lb_backend_table_update(lb_sync_backend_config *be_data);

void lb_ha_tell_backend_change_active_mac(uint8_t local_active);
void lb_backend_heartbeat_reply(int fd);
void lb_backend_validity(int fd);

uint8_t *lb_match_backend(uint32_t hash);
lb_backend_config *lb_backend_register(comm_msg_heartbeat_config *reg_cfg);
void lb_backend_activate(uint8_t be_index);
void lb_backend_unregister(uint8_t be_index);
lb_backend_config *lb_backend_search(uint64_t be_key);
int32_t lb_backend_init(lb_system_config *system_cfg);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _LB_BACKEND_MGMT_H__ */



