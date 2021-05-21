/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "urr_mgmt.h"
#include "pdr_mgmt.h"
#include "far_mgmt.h"
#include "qer_mgmt.h"
#include "parse_session_config.h"
#include "predefine_rule_mgmt.h"

predefined_rules_table g_predef_rules_table;

static inline predefined_rules_table *predef_get_table(void)
{
    return &g_predef_rules_table;
}

predefined_rules_table *predef_get_table_public(void)
{
    return predef_get_table();
}

static inline predefined_pdr_entry *predef_get_pdr_entry(uint32_t index)
{
    return &g_predef_rules_table.pdr_arr[index];
}

static inline predefined_far_entry *predef_get_far_entry(uint32_t index)
{
    return &g_predef_rules_table.far_arr[index];
}

static inline predefined_qer_entry *predef_get_qer_entry(uint32_t index)
{
    return &g_predef_rules_table.qer_arr[index];
}

static inline predefined_urr_entry *predef_get_urr_entry(uint32_t index)
{
    return &g_predef_rules_table.urr_arr[index];
}

static int predef_pdr_compare(struct rb_node *node, void *key)
{
    predefined_pdr_entry *pdr_entry = (predefined_pdr_entry *)node;
    char *predef_name = (char *)key;

    return strcmp(pdr_entry->pdr_cfg.act_pre_arr[0].rules_name, predef_name);
}

static int predef_far_compare(struct rb_node *node, void *key)
{
    predefined_far_entry *far_entry = (predefined_far_entry *)node;
    uint32_t id = *(uint32_t *)key;

    if (id < far_entry->far_cfg.far_id) {
        return -1;
    } else if (id > far_entry->far_cfg.far_id) {
        return 1;
    }

    return 0;
}

static int predef_qer_compare(struct rb_node *node, void *key)
{
    predefined_qer_entry *qer_entry = (predefined_qer_entry *)node;
    uint32_t id = *(uint32_t *)key;

    if (id < qer_entry->qer_cfg.qer_id) {
        return -1;
    } else if (id > qer_entry->qer_cfg.qer_id) {
        return 1;
    }

    return 0;
}

static int predef_urr_compare(struct rb_node *node, void *key)
{
    predefined_urr_entry *urr_entry = (predefined_urr_entry *)node;
    uint32_t id = *(uint32_t *)key;

    if (id < urr_entry->urr_cfg.urr_id) {
        return -1;
    } else if (id > urr_entry->urr_cfg.urr_id) {
        return 1;
    }

    return 0;
}

predefined_pdr_entry *predef_rules_search(char *predef_name)
{
    predefined_rules_table *predef_table = predef_get_table();
    predefined_pdr_entry *pdr_entry = NULL;

    ros_rwlock_write_lock(&predef_table->pdr_lock); /* lock */
    pdr_entry = (predefined_pdr_entry *)rbtree_search(&predef_table->pdr_root, predef_name, predef_pdr_compare);
    ros_rwlock_write_unlock(&predef_table->pdr_lock); /* unlock */
    if (pdr_entry) {
        return pdr_entry;
    }

    LOG(SESSION, DEBUG, "The predefined rule \"%s\" was not found.", predef_name);
    return NULL;
}

predefined_far_entry *predef_far_search(uint32_t far_id)
{
    predefined_rules_table *predef_table = predef_get_table();
    predefined_far_entry *far_entry = NULL;

    ros_rwlock_write_lock(&predef_table->far_lock); /* lock */
    far_entry = (predefined_far_entry *)rbtree_search(&predef_table->far_root, &far_id, predef_far_compare);
    ros_rwlock_write_unlock(&predef_table->far_lock); /* unlock */
    if (far_entry) {
        return far_entry;
    }

    LOG(SESSION, ERR, "Search pre-defined FAR fail, no such ID: %u", far_id);
    return NULL;
}

predefined_qer_entry *predef_qer_search(uint32_t qer_id)
{
    predefined_rules_table *predef_table = predef_get_table();
    predefined_qer_entry *qer_entry = NULL;

    ros_rwlock_write_lock(&predef_table->qer_lock); /* lock */
    qer_entry = (predefined_qer_entry *)rbtree_search(&predef_table->qer_root, &qer_id, predef_qer_compare);
    ros_rwlock_write_unlock(&predef_table->qer_lock); /* unlock */
    if (qer_entry) {
        return qer_entry;
    }

    LOG(SESSION, ERR, "Search pre-defined QER fail, no such ID: %u", qer_id);
    return NULL;
}

predefined_urr_entry *predef_urr_search(uint32_t urr_id)
{
    predefined_rules_table *predef_table = predef_get_table();
    predefined_urr_entry *urr_entry = NULL;

    ros_rwlock_write_lock(&predef_table->urr_lock); /* lock */
    urr_entry = (predefined_urr_entry *)rbtree_search(&predef_table->urr_root, &urr_id, predef_urr_compare);
    ros_rwlock_write_unlock(&predef_table->urr_lock); /* unlock */
    if (urr_entry) {
        return urr_entry;
    }

    LOG(SESSION, ERR, "Search pre-defined URR fail, no such ID: %u", urr_id);
    return NULL;
}

/* Generate the predefined rules into the corresponding session */
int predef_rules_generate(struct session_t *sess, char *predef_name)
{
    predefined_pdr_entry *pdr_entry;
    uint8_t cnt;
    session_emd_response resp;

    pdr_entry = predef_rules_search(predef_name);
    if (NULL == pdr_entry) {
        LOG(SESSION, ERR, "Activate pre-defined rules failed, no such name: %s",
            predef_name);
        return -1;
    }

    /* Add FAR */
    if (pdr_entry->pdr_cfg.member_flag.d.far_id_present) {
        predefined_far_entry *far_entry;

        far_entry = predef_far_search(pdr_entry->pdr_cfg.far_id);
        if (NULL == far_entry) {
            LOG(SESSION, ERR, "Pre-defined FAR ID: %u does not exist", pdr_entry->pdr_cfg.far_id);
            goto cleanup;
        }

        if (0 > far_insert(sess, &far_entry->far_cfg, 1, &resp.failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "Create FAR failed.");

            goto cleanup;
        }
    }

    /* Add QER */
    for (cnt = 0; cnt < pdr_entry->pdr_cfg.qer_id_number; ++cnt) {
        predefined_qer_entry *qer_entry;

        qer_entry = predef_qer_search(pdr_entry->pdr_cfg.qer_id_array[cnt]);
        if (NULL == qer_entry) {
            LOG(SESSION, ERR, "Pre-defined QER ID: %u does not exist", pdr_entry->pdr_cfg.qer_id_array[cnt]);
            goto cleanup;
        }

        if (0 > qer_insert(sess, &qer_entry->qer_cfg, 1, &resp.failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "Create QER failed.");

            goto cleanup;
        }
    }

    /* Add URR */
    for (cnt = 0; cnt < pdr_entry->pdr_cfg.urr_id_number; ++cnt) {
        predefined_urr_entry *urr_entry;

        urr_entry = predef_urr_search(pdr_entry->pdr_cfg.urr_id_array[cnt]);
        if (NULL == urr_entry) {
            LOG(SESSION, ERR, "Pre-defined URR ID: %u does not exist", pdr_entry->pdr_cfg.urr_id_array[cnt]);
            goto cleanup;
        }

        if (0 > urr_insert(sess, &urr_entry->urr_cfg, 1, &resp.failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "Create URR failed.");

            goto cleanup;
        }
    }

    return 0;

cleanup:

    predef_rules_erase(sess, predef_name);

    return -1;
}

/* Erase the predefined rules from the corresponding session */
int predef_rules_erase(struct session_t *sess, char *predef_name)
{
    predefined_pdr_entry *pdr_entry;

    pdr_entry = predef_rules_search(predef_name);
    if (NULL == pdr_entry) {
        LOG(SESSION, ERR, "Deactivate pre-defined rules failed, no such name: %s",
            predef_name);
        return -1;
    }

    /* Remove FAR */
    if (pdr_entry->pdr_cfg.member_flag.d.far_id_present) {
        if (0 > far_remove(sess, &pdr_entry->pdr_cfg.far_id, 1, NULL, NULL)) {
            LOG(SESSION, ERR, "Remove FAR failed.");
            /* Keep going */
        }
    }

    /* Remove URR */
    if (pdr_entry->pdr_cfg.urr_id_number > 0) {
        if (0 > urr_remove(sess, pdr_entry->pdr_cfg.urr_id_array, pdr_entry->pdr_cfg.urr_id_number,
            NULL, NULL)) {
            LOG(SESSION, ERR, "Remove URR failed.");
            /* Keep going */
        }
    }

    /* Remove QER */
    if (pdr_entry->pdr_cfg.qer_id_number > 0) {
        if (0 > qer_remove(sess, pdr_entry->pdr_cfg.qer_id_array, pdr_entry->pdr_cfg.qer_id_number,
            NULL, NULL)) {
            LOG(SESSION, ERR, "Remove QER failed.");
            /* Keep going */
        }
    }

    return 0;
}

int predef_rules_add(session_content_create *sess)
{
    predefined_rules_table *predef_table = predef_get_table();
    uint8_t cnt;
    uint32_t key = 0, index = 0;

    if (NULL == sess) {
        LOG(SESSION, ERR, "Abnormal parameter, sess(%p)", sess);
        return -1;
    }

    /* PDR */
    for (cnt = 0; cnt < sess->pdr_num; ++cnt) {
        predefined_pdr_entry *pdr_entry;

        if (G_FAILURE == Res_Alloc(predef_table->pdr_pool_id, &key, &index,
            EN_RES_ALLOC_MODE_OC)) {
            LOG(SESSION, ERR, "create failed, Resource exhaustion, pool id: %d.",
                predef_table->pdr_pool_id);
            goto rollback;
        }

        pdr_entry = predef_get_pdr_entry(index);
        ros_rwlock_write_lock(&pdr_entry->lock); /* Lock */
        ros_memcpy(&pdr_entry->pdr_cfg, &sess->pdr_arr[cnt], sizeof(session_pdr_create));
        ros_rwlock_write_unlock(&pdr_entry->lock); /* Unlock */

        ros_rwlock_write_lock(&predef_table->pdr_lock);/* lock */
        if (0 > rbtree_insert(&predef_table->pdr_root, &pdr_entry->node,
            pdr_entry->pdr_cfg.act_pre_arr[0].rules_name, predef_pdr_compare)) {
            ros_rwlock_write_unlock(&predef_table->pdr_lock);/* unlock */
            Res_Free(predef_table->pdr_pool_id, key, index);
            LOG(SESSION, ERR, "Pre-defined PDR insert failed, name: %s.",
                pdr_entry->pdr_cfg.act_pre_arr[0].rules_name);
            goto rollback;
        }
        ros_rwlock_write_unlock(&predef_table->pdr_lock);/* unlock */
    }

    /* FAR */
    for (cnt = 0; cnt < sess->far_num; ++cnt) {
        predefined_far_entry *far_entry;

        if (G_FAILURE == Res_Alloc(predef_table->far_pool_id, &key, &index,
            EN_RES_ALLOC_MODE_OC)) {
            LOG(SESSION, ERR, "create failed, Resource exhaustion, pool id: %d.",
                predef_table->far_pool_id);
            goto rollback;
        }

        far_entry = predef_get_far_entry(index);
        ros_rwlock_write_lock(&far_entry->lock); /* Lock */
        ros_memcpy(&far_entry->far_cfg, &sess->far_arr[cnt], sizeof(session_far_create));
        ros_rwlock_write_unlock(&far_entry->lock); /* Unlock */

        ros_rwlock_write_lock(&predef_table->far_lock);/* lock */
        if (0 > rbtree_insert(&predef_table->far_root, &far_entry->node,
            &far_entry->far_cfg.far_id, predef_far_compare)) {
            ros_rwlock_write_unlock(&predef_table->far_lock);/* unlock */
            Res_Free(predef_table->far_pool_id, key, index);
            LOG(SESSION, ERR, "Pre-defined FAR insert failed, ID: %u",
                far_entry->far_cfg.far_id);
            goto rollback;
        }
        ros_rwlock_write_unlock(&predef_table->far_lock);/* unlock */
    }

    /* QER */
    for (cnt = 0; cnt < sess->qer_num; ++cnt) {
        predefined_qer_entry *qer_entry;

        if (G_FAILURE == Res_Alloc(predef_table->qer_pool_id, &key, &index,
            EN_RES_ALLOC_MODE_OC)) {
            LOG(SESSION, ERR, "create failed, Resource exhaustion, pool id: %d.",
                predef_table->qer_pool_id);
            goto rollback;
        }

        qer_entry = predef_get_qer_entry(index);
        ros_rwlock_write_lock(&qer_entry->lock); /* Lock */
        ros_memcpy(&qer_entry->qer_cfg, &sess->qer_arr[cnt], sizeof(session_qos_enforcement_rule));
        ros_rwlock_write_unlock(&qer_entry->lock); /* Unlock */

        ros_rwlock_write_lock(&predef_table->qer_lock);/* lock */
        if (0 > rbtree_insert(&predef_table->qer_root, &qer_entry->node,
            &qer_entry->qer_cfg.qer_id, predef_qer_compare)) {
            ros_rwlock_write_unlock(&predef_table->qer_lock);/* unlock */
            Res_Free(predef_table->qer_pool_id, key, index);
            LOG(SESSION, ERR, "Pre-defined QER insert failed, ID: %u",
                qer_entry->qer_cfg.qer_id);
            goto rollback;
        }
        ros_rwlock_write_unlock(&predef_table->qer_lock);/* unlock */
    }

    /* URR */
    for (cnt = 0; cnt < sess->urr_num; ++cnt) {
        predefined_urr_entry *urr_entry;

        if (G_FAILURE == Res_Alloc(predef_table->urr_pool_id, &key, &index,
            EN_RES_ALLOC_MODE_OC)) {
            LOG(SESSION, ERR, "create failed, Resource exhaustion, pool id: %d.",
                predef_table->urr_pool_id);
            goto rollback;
        }

        urr_entry = predef_get_urr_entry(index);
        ros_rwlock_write_lock(&urr_entry->lock); /* Lock */
        ros_memcpy(&urr_entry->urr_cfg, &sess->urr_arr[cnt], sizeof(session_usage_report_rule));
        ros_rwlock_write_unlock(&urr_entry->lock); /* Unlock */

        ros_rwlock_write_lock(&predef_table->urr_lock);/* lock */
        if (0 > rbtree_insert(&predef_table->urr_root, &urr_entry->node,
            &urr_entry->urr_cfg.urr_id, predef_urr_compare)) {
            ros_rwlock_write_unlock(&predef_table->urr_lock);/* unlock */
            Res_Free(predef_table->urr_pool_id, key, index);
            LOG(SESSION, ERR, "Pre-defined URR insert failed, ID: %u",
                urr_entry->urr_cfg.urr_id);
            goto rollback;
        }
        ros_rwlock_write_unlock(&predef_table->urr_lock);/* unlock */
    }

    return 0;

rollback:

    predef_rules_del(sess);

    return -1;
}

int predef_rules_del(session_content_create *sess)
{
    predefined_rules_table *predef_table = predef_get_table();
    uint8_t cnt;

    if (NULL == sess) {
        LOG(SESSION, ERR, "Abnormal parameter, sess(%p)", sess);
        return -1;
    }

    /* PDR */
    for (cnt = 0; cnt < sess->pdr_num; ++cnt) {
        session_pdr_create *remove_pdr = &sess->pdr_arr[cnt];
        predefined_pdr_entry *pdr_entry;

        ros_rwlock_write_lock(&predef_table->pdr_lock);/* lock */
        pdr_entry = (predefined_pdr_entry *)rbtree_delete(&predef_table->pdr_root,
            remove_pdr->act_pre_arr[0].rules_name, predef_pdr_compare);
        ros_rwlock_write_unlock(&predef_table->pdr_lock);/* unlock */
        if (NULL == pdr_entry) {
            LOG(SESSION, ERR, "Pre-defined PDR delete failed, no such rule: %s",
                remove_pdr->act_pre_arr[0].rules_name);
            /* Keep going */
        } else {
            Res_Free(predef_table->pdr_pool_id, 0, pdr_entry->index);
        }
    }

    /* FAR */
    for (cnt = 0; cnt < sess->far_num; ++cnt) {
        session_far_create *remove_far = &sess->far_arr[cnt];
        predefined_far_entry *far_entry;

        ros_rwlock_write_lock(&predef_table->far_lock);/* lock */
        far_entry = (predefined_far_entry *)rbtree_delete(&predef_table->far_root,
            &remove_far->far_id, predef_far_compare);
        ros_rwlock_write_unlock(&predef_table->far_lock);/* unlock */
        if (NULL == far_entry) {
            LOG(SESSION, ERR, "Pre-defined FAR delete failed, no such rule ID: %u",
                remove_far->far_id);
            /* Keep going */
        } else {
            Res_Free(predef_table->far_pool_id, 0, far_entry->index);
        }
    }

    /* QER */
    for (cnt = 0; cnt < sess->qer_num; ++cnt) {
        session_qos_enforcement_rule *remove_qer = &sess->qer_arr[cnt];
        predefined_qer_entry *qer_entry;

        ros_rwlock_write_lock(&predef_table->qer_lock);/* lock */
        qer_entry = (predefined_qer_entry *)rbtree_delete(&predef_table->qer_root,
            &remove_qer->qer_id, predef_qer_compare);
        ros_rwlock_write_unlock(&predef_table->qer_lock);/* unlock */
        if (NULL == qer_entry) {
            LOG(SESSION, ERR, "Pre-defined QER delete failed, no such rule ID: %u",
                remove_qer->qer_id);
            /* Keep going */
        } else {
            Res_Free(predef_table->qer_pool_id, 0, qer_entry->index);
        }
    }

    /* URR */
    for (cnt = 0; cnt < sess->urr_num; ++cnt) {
        session_usage_report_rule *remove_urr = &sess->urr_arr[cnt];
        predefined_urr_entry *urr_entry;

        ros_rwlock_write_lock(&predef_table->urr_lock);/* lock */
        urr_entry = (predefined_urr_entry *)rbtree_delete(&predef_table->urr_root,
            &remove_urr->urr_id, predef_urr_compare);
        ros_rwlock_write_unlock(&predef_table->urr_lock);/* unlock */
        if (NULL == urr_entry) {
            LOG(SESSION, ERR, "Pre-defined URR delete failed, no such rule ID: %u",
                remove_urr->urr_id);
            /* Keep going */
        } else {
            Res_Free(predef_table->urr_pool_id, 0, urr_entry->index);
        }
    }

    return 0;
}

int64_t predef_rules_table_init(uint32_t rules_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    predefined_rules_table *predef_table = predef_get_table();
    predefined_pdr_entry *pdr_entry;
    predefined_far_entry *far_entry;
    predefined_urr_entry *urr_entry;
    predefined_qer_entry *qer_entry;
    uint32_t max_num = 0;
    int64_t size = 0;

    if (0 == rules_num) {
        LOG(SESSION, ERR, "Abnormal parameter, rules_num: %u.", rules_num);
        return -1;
    }

    /* PDR */
    max_num = rules_num;
    size = sizeof(predefined_pdr_entry) * max_num;
    pdr_entry = ros_malloc(size);
    if (NULL == pdr_entry) {
        LOG(SESSION, ERR, "No enough memory.");
        return -1;
    }
    ros_memset(pdr_entry, 0, size);
    for (index = 0; index < max_num; ++index) {
        pdr_entry[index].index = index;
        ros_rwlock_init(&pdr_entry[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Create resource pool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR, "Create resource section failed.");
        return -1;
    }

    predef_table->pdr_pool_id = pool_id;
    predef_table->pdr_arr = pdr_entry;
    predef_table->max_pdr_num = max_num;
	ros_rwlock_init(&predef_table->pdr_lock);

    /* FAR */
    max_num = rules_num;
    size = sizeof(predefined_far_entry) * max_num;
    far_entry = ros_malloc(size);
    if (NULL == far_entry) {
        LOG(SESSION, ERR, "No enough memory.");
        return -1;
    }
    ros_memset(far_entry, 0, size);
    for (index = 0; index < max_num; ++index) {
        far_entry[index].index = index;
        ros_rwlock_init(&far_entry[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Create resource pool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR, "Create resource section failed.");
        return -1;
    }

    predef_table->far_pool_id = pool_id;
    predef_table->far_arr = far_entry;
    predef_table->max_far_num = max_num;
	ros_rwlock_init(&predef_table->far_lock);

    /* QER */
    max_num = rules_num;
    size = sizeof(predefined_qer_entry) * max_num;
    qer_entry = ros_malloc(size);
    if (NULL == qer_entry) {
        LOG(SESSION, ERR, "No enough memory.");
        return -1;
    }
    ros_memset(qer_entry, 0, size);
    for (index = 0; index < max_num; ++index) {
        qer_entry[index].index = index;
        ros_rwlock_init(&qer_entry[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Create resource pool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR, "Create resource section failed.");
        return -1;
    }

    predef_table->qer_pool_id = pool_id;
    predef_table->qer_arr = qer_entry;
    predef_table->max_qer_num = max_num;
	ros_rwlock_init(&predef_table->qer_lock);

    /* URR */
    max_num = rules_num;
    size = sizeof(predefined_urr_entry) * max_num;
    urr_entry = ros_malloc(size);
    if (NULL == urr_entry) {
        LOG(SESSION, ERR, "No enough memory.");
        return -1;
    }
    ros_memset(urr_entry, 0, size);
    for (index = 0; index < max_num; ++index) {
        urr_entry[index].index = index;
        ros_rwlock_init(&urr_entry[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Create resource pool failed.");
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR, "Create resource section failed.");
        return -1;
    }

    predef_table->urr_pool_id = pool_id;
    predef_table->urr_arr = urr_entry;
    predef_table->max_urr_num = max_num;
	ros_rwlock_init(&predef_table->urr_lock);

    LOG(SESSION, MUST, "Pre-defined rules init success.");
    return size;
}

