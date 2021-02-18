/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _UPC_UEIP_H__
#define _UPC_UEIP_H__

#ifdef __cplusplus
extern "C" {
#endif

#define UEIP_SECTION_RES_BIT        (0x10)
#define UEIP_SECTION_RES_MASK       (0x0000FFFF)
#define UEIP_SECTION_KEY_MASK       (0xFFFF0000)

struct ueip_pool_info {
    union {
        uint32_t    ipv4;
        uint8_t     ipv6[IPV6_ALEN];
    } net_segment; /* Network segment of Pool */
    uint8_t prefix;
    uint8_t ip_ver; /* 1: ipv4, 2: ipv6 */
};

/* UE IP address Pool */
struct ueip_addr_pool {
    struct rb_node          tree_node;
    struct dl_list          lst_node;
    char                    pool_name[NETWORK_INSTANCE_LEN]; /* Pool Identity */
    struct ueip_pool_info   ip_info;
    uint16_t                node_index; /* Owner */
    uint16_t                pool_id;    /* RES Pool id */
    uint32_t                index;
    uint32_t                next_sec_key; /* Next effective section key */
    uint32_t                frist_sec_key; /* The first effective section key */
    uint32_t                last_sec_key; /* The last effective section key */
    uint32_t                sec_res_num; /* Number of resources per section */
    ros_atomic32_t          use_num; /* Number of IP addresses allocated */
    ros_rwlock_t            lock;
};

/* UE IP address Pool table */
struct ueip_pool_table {
    struct ueip_addr_pool   *pool_arr;
    struct rb_root          tree_root;
    ros_atomic32_t          use_num; /* Number of IP Pool allocated */
    ros_rwlock_t            lock;
    uint16_t                ip_pool_num; /* Number of valid IP pools */
    uint16_t                pool_id;    /* RES Pool id */
};

struct ueip_pool_table *ueip_pool_mgmt_get(void);

struct ueip_addr_pool *ueip_get_pool_by_name(char *pool_name);
/* Query pool index through pool name */
int ueip_pool_index_get(uint32_t *pool_index, char *pool_name);
/* Query pool name through pool index */
int ueip_pool_name_get(char *pool_name, uint32_t max_len, uint32_t pool_index);
int ueip_addr_alloc(uint32_t pool_index, session_ue_ip *ueip);
int ueip_addr_free(uint32_t pool_index, session_ue_ip *ueip);
int64_t ueip_pool_init(struct ueip_pool_info *ip_pool_arr, uint32_t pool_num);

struct ueip_addr_pool *ueip_addr_pool_get(uint32_t index);
int ueip_res_alloc_target_ip(uint32_t key, uint32_t index,
    struct ueip_addr_pool *pool);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _UPC_UEIP_H__ */


