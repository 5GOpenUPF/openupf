/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LB_NEIGHBOR_H__
#define _LB_NEIGHBOR_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Neighbor cache number */
#define LB_NEIGHBOR_CACHE_NUMBER        1000

/* ARP cache aging time */
#define LB_NEIGHBOR_CACHE_AGING_TIME    20

/* Renew times of maximum */
#define LB_NEIGHBOR_CACHE_RENEW_MAX     3

typedef union tag_lb_neighbor_comp_key {
    uint32_t    v4_value; /* Network */
    struct {
        uint64_t    key1;
        uint64_t    key2;
    } d;
    uint8_t     value[IPV6_ALEN];
} lb_neighbor_comp_key;

/* Neighbor cache */
typedef struct  tag_lb_neighbor_cache {
    struct rb_node              key_node;   /* RB tree node */
    struct dl_list              aging_node; /* Insert by creation time */
    uint32_t                    index;      /* Index in table */
    uint32_t                    create_time;/* Create time */
    ros_rwlock_t                lock;       /* RW lock */
    uint32_t                    ip_version; /* LB_IP_TYPE  1: IPv4  2: IPv6 */
    lb_neighbor_comp_key        comp_key;
    uint8_t                     next_hop[ETH_ALEN];
    uint8_t                     port_type; /* EN_PORT_TYPE */
    uint8_t                     renew_times; /* Send arp request times */
} lb_neighbor_cache;

typedef struct tag_lb_neighbor_cache_mgmt {
    lb_neighbor_cache       *entry;
    struct rb_root          entry_root;
    struct dl_list          aging_list; /* Arrange by creation time */
    ros_rwlock_t            lock;       /* RW lock */
    uint32_t                max_num;    /* Max supported entry number */
    uint32_t                aging_num;  /* The quantity that needs to be aged immediately
                                            when the resources are insufficient */
    uint16_t                pool_id;    /* res pool id */
} lb_neighbor_cache_mgmt;


/************************* Neighbor Discovery **************************/
/* Wait time */
#define NEIGHBOR_WAIT_REPLY_TIMEOUT     (2 * ROS_TIMER_TICKS_PER_SEC)

/* Aging time */
#define NEIGHBOR_CACHE_AGING_TIME       10

/* Renew times of maximum */
#define NEIGHBOR_CACHE_RENEW_MAX        1

typedef struct  tag_lb_neighbor_entry {
    struct rb_node              key_node;   /* RB tree node */
    uint32_t                    index;      /* Index in table */
    ros_rwlock_t                lock;       /* RW lock */
    lb_neighbor_comp_key        comp_key;
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


lb_neighbor_cache_mgmt *lb_neighbor_cache_mgmt_get_public(void);
lb_neighbor_mgmt *lb_neighbor_mgmt_get_public(void);
int64_t lb_neighbor_init(uint32_t neighbor_number);
void lb_neighbor_recv_arp(uint32_t net_ip, uint8_t *mac, uint8_t port);

uint8_t *lb_neighbor_cache_get_mac(lb_neighbor_comp_key *key);

int lb_neighbor_wait_reply(lb_neighbor_comp_key *key, uint8_t ip_ver, void *buf);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _LB_NEIGHBOR_H__ */

