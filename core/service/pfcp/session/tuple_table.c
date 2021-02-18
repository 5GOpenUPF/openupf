/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "tuple_table.h"

static tuple_table_head g_tuple_table_header;

static inline void tuple_table_recovery(void);

static inline tuple_table_head *tuple_head_get(void)
{
    return &g_tuple_table_header;
}

static inline tuple_table_entry *tuple_entry_get(uint32_t index)
{
    return &g_tuple_table_header.tuple_entry[index];
}

tuple_table_head *tuple_head_get_public(void)
{
    return &g_tuple_table_header;
}

static inline void tuple_url_update(tuple_table_entry *entry, char *url)
{
    if (url) {
        if (strlen(url) < MAX_BUFFER_URL_LEN) {
            strcpy(entry->url, url);
            entry->url_present = 1;
        } else {
            LOG(SESSION, ERR, "URL length too long, It should be less than %d", MAX_BUFFER_URL_LEN);
            strncpy(entry->url, url, MAX_BUFFER_URL_LEN - 1);
            entry->url_present = 1;
        }
    } else {
        entry->url_present = 0;
    }
}

static int tuple_table_compare(struct rb_node *node, void *key)
{
    tuple_table_entry *node_entry = (tuple_table_entry *)node;

    return memcmp(&node_entry->key, key, sizeof(tuple_key));
}

static int tuple_table_insert(tuple_key *_5_tuple, char *url)
{
    tuple_table_head *head = tuple_head_get();
    tuple_table_entry *entry = NULL;
    uint32_t res_key = 0, res_index = 0;

    if (G_FAILURE == Res_Alloc(head->pool_id, &res_key,
        &res_index, EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR, "Res_Alloc tuple entry failed, pool_id: %u.",
            head->pool_id);
        return -1;
    }

    entry = tuple_entry_get(res_index);

    ros_rwlock_write_lock(&entry->lock); /* lock */
    ros_memcpy(&entry->key, _5_tuple, sizeof(tuple_key));
    tuple_url_update(entry, url);
    entry->create_time = ros_getime();
    ros_rwlock_write_unlock(&entry->lock); /* unlock */

    ros_rwlock_write_lock(&head->lock); /* lock */
    if (0 > rbtree_insert(&head->tuple_root, &entry->tuple_node,
        &entry->key, tuple_table_compare)) {
        Res_Free(head->pool_id, res_key, res_index);
        ros_rwlock_write_unlock(&head->lock); /* unlock */
        LOG(SESSION, ERR, "Tuple entry insert failed.");
        return -1;
    }
    dl_list_add_tail(&head->recov_list, &entry->tuple_list);
    ros_rwlock_write_unlock(&head->lock); /* unlock */

    LOG(SESSION, DEBUG,
        "5 tuple info: sip: 0x%08x %08x %08x %08x, dip: 0x%08x %08x %08x %08x",
        *(uint32_t *)&_5_tuple->sipv6[0], *(uint32_t *)&_5_tuple->sipv6[4],
        *(uint32_t *)&_5_tuple->sipv6[8], *(uint32_t *)&_5_tuple->sipv6[12],
        *(uint32_t *)&_5_tuple->dipv6[0], *(uint32_t *)&_5_tuple->dipv6[4],
        *(uint32_t *)&_5_tuple->dipv6[8], *(uint32_t *)&_5_tuple->dipv6[12]);
    LOG(SESSION, DEBUG, "sport: %d, dport: %d, protocol: %d", _5_tuple->sport,
        _5_tuple->dport, _5_tuple->protocol);

    return 0;
}

static inline void tuple_table_delete(tuple_table_entry *entry)
{
    tuple_table_head *head = tuple_head_get();

    /* 需要在外部加二叉树的锁 */
    rbtree_erase(&entry->tuple_node, &head->tuple_root);
    dl_list_del(&entry->tuple_list);
    entry->url_present = 0;
    Res_Free(head->pool_id, 0, entry->index);
}

static inline void tuple_table_recovery(void)
{
    tuple_table_head *head = tuple_head_get();
    tuple_table_entry *entry;
    struct dl_list *pos, *next;
    uint32_t cur_time = ros_getime() - TUPLE_TABLE_RECOVERY_CYCLE;

    ros_rwlock_write_lock(&head->lock); /* lock */
    dl_list_for_each_safe(pos, next, &head->recov_list) {
        entry = (tuple_table_entry *)container_of(pos,
            tuple_table_entry, tuple_list);
        if (cur_time >= entry->create_time) {
            tuple_table_delete(entry);
            LOG(SESSION, DEBUG, "Tuple recovery");
        } else {
            break;
        }
    }
    ros_rwlock_write_unlock(&head->lock); /* unlock */
}

int tuple_table_update(tuple_key *_5_tuple, char *url)
{
    tuple_table_head *head = tuple_head_get();
    tuple_table_entry *entry = NULL;

    /* 先回收 */
    tuple_table_recovery();

    ros_rwlock_read_lock(&head->lock); /* lock */
    entry = (tuple_table_entry *)rbtree_search(&head->tuple_root, _5_tuple, tuple_table_compare);
    ros_rwlock_read_unlock(&head->lock); /* unlock */
    if (NULL == entry) {
        if (0 > tuple_table_insert(_5_tuple, url)) {
            LOG(SESSION, ERR, "Tuple table insert failed.");
            return -1;
        }
        return 0;
    } else {
        ros_rwlock_write_lock(&head->lock); /* lock */
        tuple_url_update(entry, url);
        ros_rwlock_write_unlock(&head->lock); /* unlock */
    }

    return 0;
}

/* @return  -1: no such tuple entry  0: get url success */
int tuple_table_search_url(tuple_key *_5_tuple, char *out_url)
{
    tuple_table_head *head = tuple_head_get();
    tuple_table_entry *entry = NULL;

    if (NULL == _5_tuple || NULL == out_url) {
        LOG(SESSION, ERR, "Parameters abnormal, _5_tuple(%p), out_url(%p).",
            _5_tuple, out_url);
        return -1;
    }
    LOG(SESSION, DEBUG,
        "5 tuple info: sip: 0x%08x %08x %08x %08x, dip: 0x%08x %08x %08x %08x",
        *(uint32_t *)&_5_tuple->sipv6[0], *(uint32_t *)&_5_tuple->sipv6[4],
        *(uint32_t *)&_5_tuple->sipv6[8], *(uint32_t *)&_5_tuple->sipv6[12],
        *(uint32_t *)&_5_tuple->dipv6[0], *(uint32_t *)&_5_tuple->dipv6[4],
        *(uint32_t *)&_5_tuple->dipv6[8], *(uint32_t *)&_5_tuple->dipv6[12]);
    LOG(SESSION, DEBUG, "sport: %d, dport: %d, protocol: %d", _5_tuple->sport,
        _5_tuple->dport, _5_tuple->protocol);

    ros_rwlock_read_lock(&head->lock); /* lock */
    entry = (tuple_table_entry *)rbtree_search(&head->tuple_root, _5_tuple, tuple_table_compare);
    ros_rwlock_read_unlock(&head->lock); /* unlock */
    if (NULL == entry) {
        LOG(SESSION, ERR, "Tuple entry search failed.");
        return -1;
    }

    ros_rwlock_read_lock(&entry->lock); /* lock */
    if (entry->url_present) {
        strcpy(out_url, entry->url);
    }
    ros_rwlock_read_unlock(&entry->lock); /* unlock */

#if 0
    /* 暂时先不释放，等待自动回收 */
    ros_rwlock_write_lock(&head->lock); /* lock */
    tuple_table_delete(entry);
    ros_rwlock_write_unlock(&head->lock); /* unlock */
#endif

    tuple_table_recovery();

    return 0;
}

int tuple_table_remove(tuple_key *_5_tuple)
{
    tuple_table_head *head = tuple_head_get();
    tuple_table_entry *entry = NULL;

    ros_rwlock_write_lock(&head->lock); /* lock */
    entry = (tuple_table_entry *)rbtree_delete(&head->tuple_root,
        _5_tuple, tuple_table_compare);
    dl_list_del(&entry->tuple_list);
    ros_rwlock_write_unlock(&head->lock); /* unlock */
    if (NULL == entry) {
        LOG(SESSION, ERR, "Tuple entry remove failed, no such entry.");
        return -1;
    }
    Res_Free(head->pool_id, 0, entry->index);
    entry->url_present = 0;

    tuple_table_recovery();

    return 0;
}

int64_t tuple_table_init(uint32_t fast_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    tuple_table_head *head = tuple_head_get();
    tuple_table_entry *entry = NULL;
    int64_t size = 0, total_mem = 0;

    /* init gtpu table */
    size = sizeof(tuple_table_entry) * fast_num;
    total_mem += size;
    entry = ros_malloc(size);
    if (NULL == entry) {
        LOG(SESSION, ERR,
            "Tuple table init failed, no enough memory, max_num: %u.",
            fast_num);
        return -1;
    }
    ros_memset(entry, 0, size);

    for (index = 0; index < fast_num; ++index) {
        entry[index].index = index;
        ros_rwlock_init(&entry[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Res_CreatePool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, fast_num)) {
        LOG(SESSION, ERR, "Res_AddSection failed.");
        return -1;
    }

    head->pool_id = pool_id;
    head->tuple_entry = entry;
    head->max_num = fast_num;
    head->tuple_root = RB_ROOT_INIT_VALUE;
    dl_list_init(&head->recov_list);
	ros_rwlock_init(&head->lock);

    LOG(SESSION, MUST, "Tuple table init success, %luMb memory used.",
        total_mem >> 20);
    return total_mem;
}


