/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LB_NEIGHBOR_CACHE_H__
#define _LB_NEIGHBOR_CACHE_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Neighbor cache number */
#define LB_NEIGHBOR_CACHE_NUMBER        1000

/* ARP cache Update time, in seconds */
#define LB_NEIGHBOR_CACHE_UPDATE_TIME   30

/* ARP cache aging time, in seconds */
#define LB_NEIGHBOR_CACHE_AGING_TIME    200

/* Renew times of maximum */
#define LB_NEIGHBOR_CACHE_RENEW_MAX     3

typedef union tag_lb_neighbor_comp_key {
    uint32_t    v4_value; /* Network */
    struct {
        uint64_t    key1;
        uint64_t    key2;
    } d;
    uint8_t     value[IPV6_ALEN];
} lb_neighbor_key;

/* Neighbor cache */
typedef struct  tag_lb_neighbor_cache {
    struct rb_node              key_node;   /* RB tree node */
    uint32_t                    index;      /* Index in table */
    volatile uint32_t           last_used_time; /* Last used time */
    ros_rwlock_t                lock;       /* RW lock */
    uint32_t                    ip_version; /* SESSION_IP_V4 | SESSION_IP_V6 */
    lb_neighbor_key             comp_key;
    uint8_t                     next_hop[ETH_ALEN];
    uint8_t                     port_type; /* EN_PORT_TYPE */
    volatile uint8_t            renew_times; /* Send arp request times */
} lb_neighbor_cache;

typedef struct tag_lb_neighbor_cache_mgmt {
    lb_neighbor_cache       *entry;
    struct rb_root          entry_root;
    ros_rwlock_t            lock;       /* RW lock */
    uint32_t                max_num;    /* Max supported entry number */
    int                     pool_id;    /* res pool id */
} lb_neighbor_cache_mgmt;


lb_neighbor_cache_mgmt *lb_neighbor_cache_mgmt_get_public(void);
int64_t lb_neighbor_cache_init(uint32_t neighbor_number);

uint32_t lb_neighbor_build_arp_request(char *buf, uint32_t dest_net_ip);

int lb_neighbor_cache_get_mac(lb_neighbor_key *key, uint8_t *dest_mac);
int lb_neighbor_cache_create(lb_neighbor_key *key, uint8_t *mac,
    uint8_t port_type, uint8_t ip_ver);


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _LB_NEIGHBOR_CACHE_H__ */


