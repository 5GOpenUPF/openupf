/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LB_NEIGHBOR_H__
#define _LB_NEIGHBOR_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Wait time, Unit:Second */
#define NEIGHBOR_WAIT_REPLY_TIMEOUT     2

/* Aging time, Unit:Second */
#define NEIGHBOR_CACHE_AGING_TIME       10

/* Renew times of maximum */
#define NEIGHBOR_CACHE_RENEW_MAX        1


typedef struct tag_lb_neighbor_entry {
    struct rb_node              key_node;   /* RB tree node */
    uint32_t                    index;      /* Index in table */
    ros_rwlock_t                lock;       /* RW lock */
    lb_neighbor_key             comp_key;
    struct dl_list              wait_queue;
    struct dl_list              timeline_node;
    uint32_t                    timeout;
    uint8_t                     ip_ver;     /* SESSION_IP_V4 | SESSION_IP_V6 */
    uint8_t                     spare[3];
} lb_neighbor_entry;

typedef struct tag_lb_neighbor_mgmt {
    lb_neighbor_entry       *entry;
    struct rb_root          entry_root;
    struct dl_list          timeline;
    ros_rwlock_t            lock;       /* RW lock */
    uint32_t                max_num;    /* Max supported entry number */
    uint16_t                pool_id;    /* resource pool id */
} lb_neighbor_mgmt;


lb_neighbor_mgmt *lb_neighbor_mgmt_get_public(void);
lb_neighbor_entry *lb_neighbor_entry_get_public(uint32_t index);
int64_t lb_neighbor_init(uint32_t neighbor_number);
void lb_neighbor_recv_arp(uint32_t net_ip, uint8_t *mac, uint8_t port);

int lb_neighbor_wait_reply(lb_neighbor_key *key, uint8_t ip_ver, void *buf);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _LB_NEIGHBOR_H__ */

