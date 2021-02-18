/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "pfcp_def.h"
#include "upc_node.h"

#include "upc_ueip.h"
#include "upc_seid.h"

#define UEIP_POOL_NAME      "ueip_pool"

struct ueip_pool_table g_ueip_pool_mgmt = {NULL};


struct ueip_pool_table *ueip_pool_mgmt_get(void)
{
    return &g_ueip_pool_mgmt;
}

struct ueip_addr_pool *ueip_addr_pool_get(uint32_t index)
{
    return &g_ueip_pool_mgmt.pool_arr[index];
}

static void ueip_addr_pool_show(struct ueip_addr_pool *pool)
{
    char v6_addr[128] = {0};

    LOG(UPC, DEBUG, "Pool name:                 %s", pool->pool_name);
    LOG(UPC, DEBUG, "Pool ID:                   %d", pool->pool_id);
    LOG(UPC, DEBUG, "Assoc NODE:                %u", pool->node_index);
    LOG(UPC, DEBUG, "Pool index:                %u", pool->index);
    LOG(UPC, DEBUG, "Next SEC key:              0x%08x", pool->next_sec_key);
    LOG(UPC, DEBUG, "Frist SEC key:             0x%08x", pool->frist_sec_key);
    LOG(UPC, DEBUG, "Last SEC key:              0x%08x", pool->last_sec_key);
    LOG(UPC, DEBUG, "SEC resources number:      %u", pool->sec_res_num);
    LOG(UPC, DEBUG, "Resources used number:     %d",
        ros_atomic32_read(&pool->use_num));
    LOG(UPC, DEBUG, "Pool IP version:           %d", pool->ip_info.ip_ver);
    if (SESSION_IP_V4 == pool->ip_info.ip_ver) {
        LOG(UPC, DEBUG, "Pool IP network segment:   0x%08x/%d",
            pool->ip_info.net_segment.ipv4, pool->ip_info.prefix);
    } else if (SESSION_IP_V6 == pool->ip_info.ip_ver) {

        if (NULL == inet_ntop(AF_INET6, pool->ip_info.net_segment.ipv6,
            v6_addr, sizeof(v6_addr))) {
            LOG(UPC, ERR, "Failed to convert IPv6 address.");
        } else {
            LOG(UPC, DEBUG, "Pool IP network segment:   %s/%d",
                v6_addr, pool->ip_info.prefix);
        }
    }
}

struct ueip_addr_pool *ueip_get_pool_by_name(char *pool_name)
{
    struct ueip_pool_table *ueip_mgmt = ueip_pool_mgmt_get();
    uint32_t cnt = 0;
    struct ueip_addr_pool *pool = NULL;

    if (NULL == pool_name) {
        LOG(UPC, ERR, "Parameter abnormal, pool_name(%p).",
            pool_name);
        return NULL;
    }

    ros_rwlock_write_lock(&ueip_mgmt->lock); /* lock */
    for (cnt = 0; cnt < ueip_mgmt->ip_pool_num; ++cnt) {
        if (0 == strcmp(pool_name, ueip_mgmt->pool_arr[cnt].pool_name)) {
            pool = &ueip_mgmt->pool_arr[cnt];
            break;
        }
    }
    ros_rwlock_write_unlock(&ueip_mgmt->lock); /* unlock */

    return pool;
}

/* Query pool index through pool name */
int ueip_pool_index_get(uint32_t *pool_index, char *pool_name)
{
    struct ueip_pool_table *ueip_mgmt = ueip_pool_mgmt_get();
    uint32_t cnt = 0;

    if (NULL == pool_name || NULL == pool_index) {
        LOG(UPC, ERR, "Parameter abnormal, pool_name(%p), pool_index(%p).",
            pool_name, pool_index);
        return -1;
    }

    ros_rwlock_write_lock(&ueip_mgmt->lock); /* lock */
    for (cnt = 0; cnt < ueip_mgmt->ip_pool_num; ++cnt) {
        if (0 == strcmp(pool_name, ueip_mgmt->pool_arr[cnt].pool_name)) {
            ros_rwlock_write_unlock(&ueip_mgmt->lock); /* unlock */
            *pool_index = cnt;
            return 0;
        }
    }
    ros_rwlock_write_unlock(&ueip_mgmt->lock); /* unlock */

    return -1;
}

/* Query pool name through pool index */
int ueip_pool_name_get(char *pool_name, uint32_t max_len, uint32_t pool_index)
{
    struct ueip_pool_table *ueip_mgmt = ueip_pool_mgmt_get();
    struct ueip_addr_pool *ueip_pool = NULL;

    if (NULL == pool_name || pool_index >= ueip_mgmt->ip_pool_num) {
        LOG(UPC, ERR, "Parameter abnormal, pool_name(%p), pool_index: %u.",
            pool_name, pool_index);
        return -1;
    }

    ueip_pool = ueip_addr_pool_get(pool_index);
    ros_rwlock_write_lock(&ueip_pool->lock); /* lock */
    if (max_len < strlen(ueip_pool->pool_name)) {
        ros_rwlock_write_unlock(&ueip_pool->lock); /* unlock */
        LOG(UPC, ERR, "Parameter abnormal, max_len: %u > pool_name_len: %u.",
            max_len, (uint32_t)strlen(ueip_pool->pool_name));
        return -1;
    }
    strcpy(pool_name, ueip_pool->pool_name);
    ros_rwlock_write_unlock(&ueip_pool->lock); /* unlock */

    return 0;
}

inline int ueip_res_add_section(struct ueip_addr_pool *pool)
{
    uint32_t frist_num = 0, max_num = pool->sec_res_num;

    if (pool->last_sec_key >= pool->next_sec_key) {
        if (pool->last_sec_key == pool->next_sec_key) {
            /* Remove broadcast addresses */
            --max_num;
        }

        if (pool->frist_sec_key == pool->next_sec_key) {
            /* Remove Network Address */
            frist_num = 1;
            --max_num;
        }

        LOG(UPC, DEBUG,
            "Addsection, pool id: %d, sec key: %u,"
            " frist number: %u, max number: %u.",
            pool->pool_id, pool->next_sec_key, frist_num, max_num);
        if (G_FAILURE == Res_AddSection(pool->pool_id, pool->next_sec_key,
            frist_num, max_num)) {
            LOG(UPC, ERR, "Res_AddSection failed.");
            return -1;
        }
        LOG(UPC, RUNNING, "Add UEIP section: 0x%08x ~ 0x%08x, max number: %u.",
            pool->next_sec_key + frist_num, pool->next_sec_key + max_num,
            max_num);

        ++pool->next_sec_key;
    } else {
        LOG(UPC, ERR, "UEIP is exhausted.");
        return -1;
    }

    return 0;
}

inline int ueip_res_alloc_ip(uint32_t *key, uint32_t *index,
    struct ueip_addr_pool *pool)
{
    if (G_FAILURE == Res_Alloc(pool->pool_id, key, index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(UPC, RUNNING, "ready add section.");
        if (0 > ueip_res_add_section(pool)) {
            LOG(UPC, ERR,
                "Alloc ueip address failed, UEIP add section failed.");
            return -1;
        }

        if (G_FAILURE == Res_Alloc(pool->pool_id, key, index,
            EN_RES_ALLOC_MODE_OC)) {
            LOG(UPC, ERR, "Alloc ueip address failed, Not enough resources.");
            return -1;
        }
    }

    LOG(UPC, RUNNING,
        "Alloc ip address success, pool id: %d, key: %u, index: %u.",
        pool->pool_id, *key, *index);
    return 0;
}

int ueip_res_alloc_target_ip(uint32_t key, uint32_t index,
    struct ueip_addr_pool *pool)
{
    if (key >= pool->next_sec_key) {
        if (0 > ueip_res_add_section(pool)) {
            LOG(UPC, ERR,
                "Alloc ueip address failed, UEIP add section failed.");
            return -1;
        }
    }

    if (G_FAILURE == Res_AllocTarget(pool->pool_id, key, index)) {
        LOG(UPC, ERR, "AllocTarget ueip address failed.");
        return -1;
    }

    LOG(UPC, RUNNING,
        "AllocTarget ip address success, pool id: %d, key: %u, index: %u.",
        pool->pool_id, key, index);
    return 0;
}

int ueip_addr_alloc(uint32_t pool_index, session_ue_ip *ueip)
{
    struct ueip_pool_table *ueip_mgmt = ueip_pool_mgmt_get();
    struct ueip_addr_pool *ueip_pool = NULL;
    session_up_features up_features = {.value = 0};
    uint32_t index = 0, key = 0;

    if (NULL == ueip || pool_index >= ueip_mgmt->ip_pool_num) {
        LOG(UPC, ERR, "Parameter abnormal, ueip(%p), pool_index: %u.",
            ueip, pool_index);
        return -1;
    }

    /* Get up features */
    up_features.value = upc_get_up_features();

    if (0 == up_features.d.UEIP) {
        LOG(UPC, ERR, "UPF not supprot UEIP featrues.");
        return -1;
    }

    ueip_pool = ueip_addr_pool_get(pool_index);

    ros_rwlock_write_lock(&ueip_pool->lock); /* lock */
    if (0 > ueip_res_alloc_ip(&key, &index, ueip_pool)) {
        ros_rwlock_write_unlock(&ueip_pool->lock); /* unlock */
        LOG(UPC, ERR, "Alloc ueip address failed, Not enough resources.");
        return -1;
    }

    if (ueip->ueip_flag.d.chv4 && SESSION_IP_V4 == ueip_pool->ip_info.ip_ver) {
		//upf分配ip之后，v4标志也要置为1，否则pdr_map_insert插不进去
		ueip->ueip_flag.d.v4 = 1;
        ueip->ipv4_addr = key + index;
        LOG(UPC, RUNNING, "Assign ipv4 address: 0x%08x.", ueip->ipv4_addr);
    } else if (ueip->ueip_flag.d.chv6 &&
    SESSION_IP_V6 == ueip_pool->ip_info.ip_ver) {
        uint32_t *suffix_u32 = NULL;

		ueip->ueip_flag.d.v6 = 1;
        ros_memcpy(ueip->ipv6_addr, ueip_pool->ip_info.net_segment.ipv6,
            IPV6_ALEN);
        suffix_u32 = (uint32_t *)(ueip->ipv6_addr + 12);
        *suffix_u32 = htonl(key + index);
        LOG(UPC, RUNNING, "Assign ipv6 address: 0x%08x %08x %08x %08x.",
            ntohl(*(uint32_t *)(ueip->ipv6_addr)),
            ntohl(*(uint32_t *)(ueip->ipv6_addr + 4)),
            ntohl(*(uint32_t *)(ueip->ipv6_addr + 8)),
            ntohl(*(uint32_t *)(ueip->ipv6_addr + 12)));
    } else {
        Res_Free(ueip_pool->pool_id, key, index);
        ros_rwlock_write_unlock(&ueip_pool->lock); /* unlock */
        LOG(UPC, ERR,
            "Alloc ip address failed, UEIP flag is %d,"
            " But UEIP address pool version is %d.",
            ueip->ueip_flag.value, ueip_pool->ip_info.ip_ver);
        return -1;
    }
    ros_atomic32_add(&ueip_pool->use_num, 1);

    ros_rwlock_write_unlock(&ueip_pool->lock); /* unlock */

    return 0;
}

int ueip_addr_free(uint32_t pool_index, session_ue_ip *ueip)
{
    struct ueip_pool_table *ueip_mgmt = ueip_pool_mgmt_get();
    struct ueip_addr_pool *ueip_pool = NULL;
    session_up_features up_features = {.value = 0};
    uint32_t index = 0, key = 0;

    if (NULL == ueip || pool_index >= ueip_mgmt->ip_pool_num) {
        LOG(UPC, ERR, "Parameter abnormal, ueip(%p), pool_index: %u.",
            ueip, pool_index);
        return -1;
    }

    /* Get up features */
    up_features.value = upc_get_up_features();

    if (0 == up_features.d.UEIP) {
        LOG(UPC, ERR, "UPF not supprot UEIP featrues.");
        return -1;
    }

    ueip_pool = ueip_addr_pool_get(pool_index);

    ros_rwlock_write_lock(&ueip_pool->lock); /* lock */

    if (ueip->ueip_flag.d.v4 && SESSION_IP_V4 == ueip_pool->ip_info.ip_ver) {
        LOG(UPC, RUNNING, "Ready free ipv4 address.");
        key = ueip->ipv4_addr & UEIP_SECTION_KEY_MASK;
        index = ueip->ipv4_addr & UEIP_SECTION_RES_MASK;

    } else if (ueip->ueip_flag.d.v6 &&
    SESSION_IP_V6 == ueip_pool->ip_info.ip_ver) {
        uint32_t suffix_u32 = ntohl(*(uint32_t *)(ueip->ipv6_addr + 12));

        LOG(UPC, RUNNING, "Ready free ipv6 address.");

        key = suffix_u32 & UEIP_SECTION_KEY_MASK;
        index = suffix_u32 & UEIP_SECTION_RES_MASK;

    } else {
        ros_rwlock_write_unlock(&ueip_pool->lock); /* unlock */
        LOG(UPC, ERR,
            "Free ip address failed, UEIP flag is %d,"
            " But UEIP address pool version is %d.",
            ueip->ueip_flag.value, ueip_pool->ip_info.ip_ver);
        return -1;
    }
    Res_Free(ueip_pool->pool_id, key, index);

    ros_atomic32_sub(&ueip_pool->use_num, 1);
    ros_rwlock_write_unlock(&ueip_pool->lock); /* unlock */

    return 0;
}

int ueip_pool_show(struct cli_def *cli,int argc, char **argv)
{
    struct ueip_pool_table *ueip_mgmt = ueip_pool_mgmt_get();
    uint32_t cnt = 0, pool_index = 0;
    uint8_t search_success = 0;

    if (argc < 1) {
        cli_print(cli,"Parameters abnormal!\r\n\te.g. ueip ueip_pool_1\n");
        return -1;
    }


    ros_rwlock_write_lock(&ueip_mgmt->lock); /* lock */
    for (cnt = 0; cnt < ueip_mgmt->ip_pool_num; ++cnt) {
        if (0 == strcmp(argv[0], ueip_mgmt->pool_arr[cnt].pool_name)) {
            pool_index = cnt;
            search_success = 0;

            break;
        }
    }
    ros_rwlock_write_unlock(&ueip_mgmt->lock); /* unlock */

    if (search_success) {
        struct ueip_addr_pool *pool = ueip_addr_pool_get(pool_index);

        ueip_addr_pool_show(pool);
    } else {
        LOG(UPC, ERR, "No such pool, pool name: %s.", argv[0]);
        return -1;
    }

    return 0;
}

static int ueip_pool_compare(struct rb_node *node, void *key)
{
    struct ueip_addr_pool *ueip_pool = (struct ueip_addr_pool *)node;
    uint32_t node_index = *(uint32_t *)key;

    if (ueip_pool->node_index < node_index) {
        return 1;
    } else if (ueip_pool->node_index > node_index) {
        return -1;
    }

    return 0;
}

int ueip_pool_alloc(uint32_t node_index, uint32_t *pool_index,
    char *pool_name, uint32_t max_len)
{
    struct ueip_pool_table *ueip_mgmt = ueip_pool_mgmt_get();
    struct ueip_addr_pool *ueip_pool = NULL, *exist_ueip_pool = NULL;
    uint32_t index = 0, key = 0;

    if (NULL == pool_index) {
        LOG(UPC, ERR, "Parameter abnormal, pool_index(%p).", pool_index);
        return -1;
    }

    if (G_FAILURE == Res_Alloc(ueip_mgmt->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(UPC, ERR, "Alloc ueip address pool failed, Not enough resources.");
        return -1;
    }

    ueip_pool = ueip_addr_pool_get(index);

    ros_rwlock_write_lock(&ueip_pool->lock); /* lock */
    dl_list_init(&ueip_pool->lst_node);
    *pool_index = index;
    if (max_len < strlen(ueip_pool->pool_name)) {
        Res_Free(ueip_mgmt->pool_id, key, index);
        ros_rwlock_write_unlock(&ueip_pool->lock); /* unlock */
        LOG(UPC, ERR,
            "Alloc UE IP pool failed, max_len: %u > pool_name_len: %u.",
            max_len, (uint32_t)strlen(ueip_pool->pool_name));
        return -1;
    }
    strcpy(pool_name, ueip_pool->pool_name);

    ros_rwlock_write_unlock(&ueip_pool->lock); /* unlock */

    ros_rwlock_write_lock(&ueip_mgmt->lock); /* lock */
    exist_ueip_pool = (struct ueip_addr_pool *)rbtree_search(&ueip_mgmt->tree_root,
        &node_index, ueip_pool_compare);
    if (NULL == exist_ueip_pool) {
        if (0 > rbtree_insert(&ueip_mgmt->tree_root, &ueip_pool->tree_node,
            &node_index, ueip_pool_compare)) {
            ros_rwlock_write_unlock(&ueip_mgmt->lock); /* unlock */
            Res_Free(ueip_mgmt->pool_id, key, index);
            LOG(UPC, ERR, "Insert IP pool to rb_tree failed.");
            return -1;
        }
    } else {
        dl_list_add_tail(&exist_ueip_pool->lst_node, &ueip_pool->lst_node);
    }
    ros_rwlock_write_unlock(&ueip_mgmt->lock); /* unlock */

    ros_atomic32_add(&ueip_mgmt->use_num, 1);

    return 0;
}

int ueip_pool_free(uint32_t node_index, uint32_t pool_index)
{
    struct ueip_pool_table *ueip_mgmt = ueip_pool_mgmt_get();
    struct ueip_addr_pool *ueip_pool = NULL;

    ros_rwlock_write_lock(&ueip_mgmt->lock); /* lock */
    ueip_pool = (struct ueip_addr_pool *)rbtree_search(&ueip_mgmt->tree_root,
        &node_index, ueip_pool_compare);
    if (ueip_pool) {
        if (ueip_pool->index == pool_index) {
            if (dl_list_empty(&ueip_pool->lst_node)) {
                if (NULL == rbtree_delete(&ueip_mgmt->tree_root,
                    &node_index, ueip_pool_compare)) {
                    ros_rwlock_write_unlock(&ueip_mgmt->lock); /* unlock */
                    LOG(UPC, ERR, "Delete IP pool from rb_tree failed");
                    return -1;
                }
            } else {
                struct ueip_addr_pool *replace_ueip_pool =
                    dl_list_entry_next(ueip_pool, lst_node);

                rbtree_replace_node(&ueip_pool->tree_node,
                    &replace_ueip_pool->tree_node, &ueip_mgmt->tree_root);
                dl_list_del(&ueip_pool->lst_node);
            }
        } else {
            struct ueip_addr_pool *pos = NULL, *next = NULL;

            dl_list_for_each_entry_safe(pos, next,
                &ueip_pool->lst_node, lst_node) {
                if (pos->index == pool_index) {
                    dl_list_del(&pos->lst_node);
                    break;
                }
            }
            ueip_pool = pos;
        }
    } else {
        ros_rwlock_write_unlock(&ueip_mgmt->lock); /* unlock */
        LOG(UPC, ERR, "Delete IP pool from rb_tree failed, no such node.");
        return -1;
    }
    Res_Free(ueip_mgmt->pool_id, 0, pool_index);
    ros_rwlock_write_unlock(&ueip_mgmt->lock); /* unlock */

    ros_atomic32_set(&ueip_pool->use_num, 0);

    ros_atomic32_sub(&ueip_mgmt->use_num, 1);

    return 0;
}

int64_t ueip_pool_init(struct ueip_pool_info *ip_pool_arr, uint32_t pool_num)
{
    uint32_t cnt = 0;
    int pool_id = -1;
    struct ueip_pool_table *ueip_mgmt = ueip_pool_mgmt_get();
    struct ueip_addr_pool *ueip_pool = NULL;
    int64_t size = 0, total_mem = 0;

    if (NULL == ip_pool_arr || 0 == pool_num) {
        LOG(UPC, ERR, "Abnormal parameter, ip_pool_arr(%p), pool_num: %u.",
            ip_pool_arr, pool_num);
        return -1;
    }
    /* init ueip mgmt */
    size = sizeof(struct ueip_addr_pool) * pool_num;
    total_mem += size;
    ueip_pool = ros_malloc(size);
    if (NULL == ueip_pool) {
        LOG(UPC, ERR,
            "ueip IP address pool init failed, no enough memory, pool_num: %u.",
            pool_num);
        return -1;
    }
    ros_memset(ueip_pool, 0, size);

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(UPC, ERR, "Res_CreatePool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, pool_num)) {
        LOG(UPC, ERR, "Res_AddSection failed.");
        return -1;
    }

    ueip_mgmt->pool_id = pool_id;
    ueip_mgmt->pool_arr = ueip_pool;
    ueip_mgmt->ip_pool_num = pool_num;
    ueip_mgmt->tree_root = RB_ROOT_INIT_VALUE;
	ros_rwlock_init(&ueip_mgmt->lock);
    ros_atomic32_set(&ueip_mgmt->use_num, 0);

    /* init pool */
    for (cnt = 0; cnt < pool_num; ++cnt) {
        struct ueip_addr_pool *pool = &ueip_pool[cnt];
        uint32_t host_bit = 0, suffix_u32 = 0;

        pool->index = cnt;
        ros_memcpy(&pool->ip_info, &ip_pool_arr[cnt],
            sizeof(struct ueip_pool_info));

        sprintf(pool->pool_name, "%s_%d", UEIP_POOL_NAME, cnt + 1);

        /* init UEIP section */
        if (SESSION_IP_V4 == pool->ip_info.ip_ver) {
            host_bit = 32 - pool->ip_info.prefix;
            suffix_u32 = pool->ip_info.net_segment.ipv4;
        } else if (SESSION_IP_V6 == pool->ip_info.ip_ver) {
            suffix_u32 = ntohl(*(uint32_t *)(
                pool->ip_info.net_segment.ipv6 + 12));
            host_bit = 128 - pool->ip_info.prefix;
        }
        if (host_bit > 32)
            host_bit = 32;

        if (host_bit > UEIP_SECTION_RES_BIT) {
            pool->frist_sec_key = suffix_u32 & UEIP_SECTION_KEY_MASK;
            pool->next_sec_key = pool->frist_sec_key;
            pool->last_sec_key = suffix_u32 +
                (((1 << (host_bit - UEIP_SECTION_RES_BIT)) - 1) <<
                UEIP_SECTION_RES_BIT);
            pool->sec_res_num = (1 << UEIP_SECTION_RES_BIT) - 1;
        } else {
            pool->frist_sec_key = suffix_u32 & UEIP_SECTION_KEY_MASK;
            pool->next_sec_key = pool->frist_sec_key;
            pool->last_sec_key = pool->next_sec_key;
            pool->sec_res_num = (1 << host_bit) - 1;
        }

		ros_atomic32_set(&pool->use_num, 0);
        ros_rwlock_init(&pool->lock);

        pool_id = Res_CreatePool();
        if (pool_id < 0) {
            LOG(UPC, ERR, "Res_CreatePool failed.");
            return -1;
        }
        pool->pool_id = pool_id;

        /* The assigned IP address starts from 1 */
        if (G_FAILURE == ueip_res_add_section(pool)) {
            LOG(UPC, ERR, "Res_AddSection failed.");
            return -1;
        }
    }

    LOG(UPC, RUNNING, "UE IP address Pool init success.");
    return total_mem;
}


