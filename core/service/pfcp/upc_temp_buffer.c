/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "upc_temp_buffer.h"

upc_session_temp_mgmt g_upc_sess_temp_mgmt;

static inline upc_session_temp_mgmt *upc_get_session_temp_mgmt(void)
{
    return &g_upc_sess_temp_mgmt;
}

upc_session_temp_mgmt *upc_get_session_temp_mgmt_public(void)
{
    return &g_upc_sess_temp_mgmt;
}

static upc_session_temp_entry *upc_get_session_temp_entry(uint32_t index)
{
    return &g_upc_sess_temp_mgmt.entry[index];
}

static int upc_session_temp_compare(struct rb_node *node, void *key)
{
    upc_session_temp_entry *entry = (upc_session_temp_entry *)node;
    uint64_t value = *(uint64_t *)key;

    if (value < entry->comp_key.comp_value) {
        return -1;
    }
    else if (value > entry->comp_key.comp_value) {
        return 1;
    }

    return 0;
}

int upc_session_temp_add(void *data, uint8_t temp_type)
{
    upc_session_temp_entry *entry = NULL;
    upc_session_temp_mgmt *mgmt = upc_get_session_temp_mgmt();
    uint32_t key = 0, index = 0;

    if (NULL == data) {
        LOG(UPC, ERR, "Parameter error, sess(%p).", data);
        return -1;
    }

    if (G_FAILURE == Res_Alloc(mgmt->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(UPC, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            mgmt->pool_id);
        return -1;
    }

    entry = upc_get_session_temp_entry(index);
    entry->data_type = temp_type;
    entry->comp_key.d.type = temp_type;

    switch (temp_type) {
        case TEMP_EST:
            {
                session_content_create *sess_c = data;

                memcpy(&entry->data.est, sess_c, sizeof(session_content_create));
                entry->comp_key.d.value = (uint32_t)sess_c->local_seid;
            }
            break;

        case TEMP_MOD:
            {
                session_content_modify *sess_m = data;

                memcpy(&entry->data.mod, sess_m, sizeof(session_content_modify));
                entry->comp_key.d.value = (uint32_t)sess_m->local_seid;
            }
            break;

        case TEMP_PFD:
            {
                session_pfd_mgmt_request *pfd = data;

                memcpy(&entry->data.pfd, pfd, sizeof(session_pfd_mgmt_request));
                entry->comp_key.d.value = pfd->entry_index;
            }
            break;

        default:
            Res_Free(mgmt->pool_id, key, index);
            LOG(UPC, ERR, "Unsupported type(%d) of temp data.", temp_type);
            return -1;
    }

    ros_rwlock_write_lock(&mgmt->lock);/* lock */
    /* insert node to session tree root*/
    if (0 > rbtree_insert(&mgmt->entry_root, &entry->data_node,
        &entry->comp_key.comp_value, upc_session_temp_compare)) {
        ros_rwlock_write_unlock(&mgmt->lock);/* unlock */
        Res_Free(mgmt->pool_id, key, index);
        LOG(UPC, ERR,
            "rb tree insert failed, session_temp index: %u.", entry->index);
        return -1;
    }
    ros_rwlock_write_unlock(&mgmt->lock);/* unlock */

    return 0;
}

upc_session_temp_entry *upc_session_temp_get(uint8_t temp_type, uint32_t value)
{
    upc_session_temp_entry *entry = NULL;
    upc_session_temp_mgmt *mgmt = upc_get_session_temp_mgmt();
    upc_temp_comp_key temp_key = {.d.type = temp_type, .d.value = value};

    ros_rwlock_write_lock(&mgmt->lock);/* lock */
    entry = (upc_session_temp_entry *)rbtree_search(&mgmt->entry_root,
        &temp_key.comp_value, upc_session_temp_compare);
    ros_rwlock_write_unlock(&mgmt->lock);/* unlock */
    if (NULL == entry) {
        LOG(UPC, ERR,
            "rb tree search failed, comp_value: %luu.", temp_key.comp_value);
        return NULL;
    }

    return entry;
}

int upc_session_temp_del(uint8_t temp_type, uint32_t value)
{
    upc_session_temp_entry *entry = NULL;
    upc_session_temp_mgmt *mgmt = upc_get_session_temp_mgmt();
    upc_temp_comp_key temp_key = {.d.type = temp_type, .d.value = value};

    ros_rwlock_write_lock(&mgmt->lock);/* lock */
    entry = (upc_session_temp_entry *)rbtree_delete(&mgmt->entry_root,
        &temp_key.comp_value, upc_session_temp_compare);
    ros_rwlock_write_unlock(&mgmt->lock);/* unlock */
    if (NULL == entry) {
        LOG(UPC, RUNNING,
            "session_temp comp_value: %lu deleted.", temp_key.comp_value);
        return -1;
    }
    Res_Free(mgmt->pool_id, 0, entry->index);

    return 0;
}

int64_t upc_session_temp_init(uint32_t num)
{
    int64_t total_size = 0, size = 0;
    uint16_t cnt = 0;
    int pool_id = -1;
    upc_session_temp_mgmt *temp_mgmt = upc_get_session_temp_mgmt();

    if (num == 0) {
        LOG(UPC, ERR, "Parameter error, num: %u.", num);
        return -1;
    }

    /* Init synchronous data table */
    size = sizeof(upc_session_temp_entry) * num;
    temp_mgmt->entry = ros_malloc(size);
    if (NULL == temp_mgmt->entry) {
        LOG(UPC, ERR, "Malloc session temp entry failed.");
        return -1;
    }
    memset(temp_mgmt->entry, 0, size);

    for (cnt = 0; cnt < num; ++cnt) {
        temp_mgmt->entry[cnt].index = cnt;
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(UPC, ERR, "Res_CreatePool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, num)) {
        LOG(UPC, ERR, "Res_AddSection failed.");
        return -1;
    }

    temp_mgmt->entry_root   = RB_ROOT_INIT_VALUE;
    temp_mgmt->max_num      = num;
    ros_rwlock_init(&temp_mgmt->lock);
    temp_mgmt->pool_id      = pool_id;

    total_size += size;

    return total_size;
}


