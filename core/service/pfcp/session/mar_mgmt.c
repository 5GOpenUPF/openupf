/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "pdr_mgmt.h"
#include "far_mgmt.h"

#include "local_parse.h"
#include "mar_mgmt.h"


struct mar_table_head mar_tbl_head;

void mar_table_show(struct mar_table *mar_tbl)
{
    LOG(SESSION, RUNNING, "--------------mar--------------");
    LOG(SESSION, RUNNING, "index: %u", mar_tbl->index);
    LOG(SESSION, RUNNING, "mar_id: %d", mar_tbl->mar.mar_id);
    LOG(SESSION, RUNNING, "steer_func: %d", mar_tbl->mar.steer_func);
    LOG(SESSION, RUNNING, "steer_mod: %d", mar_tbl->mar.steer_mod);
    LOG(SESSION, RUNNING, "afai_1_validity: %d", mar_tbl->mar.afai_1_validity);
    if (mar_tbl->mar.afai_1_validity) {
        uint8_t cnt = 0;

        LOG(SESSION, RUNNING, "member_flag: 0x%x",
            mar_tbl->mar.afai_1.member_flag.value);
        LOG(SESSION, RUNNING, "far_id: %u", mar_tbl->mar.afai_1.far_id);
        LOG(SESSION, RUNNING, "weight: %d", mar_tbl->mar.afai_1.weight);
        LOG(SESSION, RUNNING, "priority: %d", mar_tbl->mar.afai_1.priority);
        LOG(SESSION, RUNNING, "urr_num: %d", mar_tbl->mar.afai_1.urr_num);
        for (cnt = 0; cnt < mar_tbl->mar.afai_1.urr_num; ++cnt) {
            LOG(SESSION, RUNNING, "urr_id: %u",
                mar_tbl->mar.afai_1.urr_id_arr[cnt]);
        }
    }

    LOG(SESSION, RUNNING, "afai_2_validity: %d", mar_tbl->mar.afai_2_validity);
    if (mar_tbl->mar.afai_2_validity) {
        uint8_t cnt = 0;

        LOG(SESSION, RUNNING, "member_flag: 0x%x",
            mar_tbl->mar.afai_2.member_flag.value);
        LOG(SESSION, RUNNING, "far_id: %u", mar_tbl->mar.afai_2.far_id);
        LOG(SESSION, RUNNING, "weight: %d", mar_tbl->mar.afai_2.weight);
        LOG(SESSION, RUNNING, "priority: %d", mar_tbl->mar.afai_2.priority);
        LOG(SESSION, RUNNING, "urr_num: %d", mar_tbl->mar.afai_2.urr_num);
        for (cnt = 0; cnt < mar_tbl->mar.afai_2.urr_num; ++cnt) {
            LOG(SESSION, RUNNING, "urr_id: %u",
                mar_tbl->mar.afai_2.urr_id_arr[cnt]);
        }
    }
}

inline struct mar_table_head *mar_get_head(void)
{
    return &mar_tbl_head;
}

inline struct mar_table *mar_get_table(uint32_t index)
{
    return &mar_tbl_head.mar_table[index];
}

inline uint16_t mar_get_pool_id(void)
{
    return mar_tbl_head.pool_id;
}

inline uint32_t mar_get_max(void)
{
    return mar_tbl_head.max_num;
}

static int mar_id_compare(struct rb_node *node, void *key)
{
    struct mar_table *mar_node = (struct mar_table *)node;
    uint16_t id = *(uint16_t *)key;

    if (id < mar_node->mar.mar_id) {
        return -1;
    }
    else if (id > mar_node->mar.mar_id) {
        return 1;
    }

    return 0;
}

struct mar_table *mar_table_search(struct session_t *sess, uint16_t id)
{
    struct mar_table *mar_tbl = NULL;
    uint16_t mar_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "root is NULL.");
        return NULL;
    }

    ros_rwlock_read_lock(&sess->lock);/* lock */
    mar_tbl = (struct mar_table *)rbtree_search(&sess->session.mar_root,
        &mar_id, mar_id_compare);
    ros_rwlock_read_unlock(&sess->lock);/* unlock */
    if (NULL == mar_tbl) {
        LOG(SESSION, ERR,
            "The entry with id %u does not exist.", mar_id);
        return NULL;
    }

    return mar_tbl;
}

struct mar_table *mar_table_create(struct session_t *sess, uint16_t id)
{
    struct mar_table_head *mar_head = mar_get_head();
    struct mar_table *mar_tbl = NULL;
    uint32_t key = 0, index = 0;
    uint16_t mar_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    if (G_FAILURE == Res_Alloc(mar_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            mar_head->pool_id);
        return NULL;
    }

    mar_tbl = mar_get_table(index);
    ros_rwlock_write_lock(&mar_tbl->lock);/* lock */
    memset(&mar_tbl->mar, 0, sizeof(session_mar_create));

    mar_tbl->mar.mar_id = mar_id;
    mar_tbl->valid = G_TRUE;
    ros_rwlock_write_unlock(&mar_tbl->lock);/* unlock */

    ros_rwlock_write_lock(&sess->lock);/* lock */
    /* insert node to session tree root*/
    if (rbtree_insert(&sess->session.mar_root, &mar_tbl->mar_node,
        &mar_id, mar_id_compare) < 0) {
        ros_rwlock_write_unlock(&sess->lock);/* unlock */
        Res_Free(mar_head->pool_id, key, index);
        mar_tbl->valid = G_FALSE;
        LOG(SESSION, ERR,
            "rb tree insert failed, id: %u.", mar_id);
        return NULL;
    }
    ros_rwlock_write_unlock(&sess->lock);/* unlock */

    ros_atomic32_add(&mar_head->use_num, 1);

    return mar_tbl;
}

int mar_insert(struct session_t *sess, void *parse_mar_arr,
    uint32_t mar_num, uint32_t *fail_id)
{
    struct mar_table *mar_tbl = NULL;
    uint32_t index_cnt = 0;

    if (NULL == sess || NULL == parse_mar_arr || 0 == mar_num) {
        LOG(SESSION, ERR, "insert failed, sess(%p), parse_mar_arr(%p),"
			" mar_num: %u.", sess, parse_mar_arr, mar_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < mar_num; ++index_cnt) {

        mar_tbl = mar_add(sess, parse_mar_arr, index_cnt, fail_id);
        if (NULL == mar_tbl) {
            LOG(SESSION, ERR, "mar add failed.");
            return -1;
        }

    }

    return 0;
}

int mar_remove(struct session_t *sess, uint16_t *id_arr, uint8_t id_num, uint32_t *fail_id)
{
    struct mar_table_head *mar_head = mar_get_head();
    struct mar_table *mar_tbl = NULL;
	uint32_t index_cnt = 0;

    if (NULL == sess || (NULL == id_arr && id_num)) {
        LOG(SESSION, ERR, "remove failed, sess(%p), id_arr(%p),"
			" id_num: %d.", sess, id_arr, id_num);
        return -1;
    }

	for (index_cnt = 0; index_cnt < id_num; ++index_cnt) {
	    ros_rwlock_write_lock(&sess->lock);/* lock */
	    mar_tbl = (struct mar_table *)rbtree_delete(&sess->session.mar_root,
	        &id_arr[index_cnt], mar_id_compare);
	    ros_rwlock_write_unlock(&sess->lock);/* unlock */
	    if (NULL == mar_tbl) {
	        LOG(SESSION, ERR, "remove failed, not exist, id: %d.",
				id_arr[index_cnt]);
            if (fail_id)
                *fail_id = id_arr[index_cnt];
            return -1;
	    }
	    Res_Free(mar_head->pool_id, 0, mar_tbl->index);
        ros_rwlock_write_lock(&mar_tbl->lock);/* lock */
	    ros_atomic32_sub(&mar_head->use_num, 1);
        mar_tbl->valid = G_FALSE;
        ros_rwlock_write_unlock(&mar_tbl->lock);/* unlock */

	}

    return 0;
}

int mar_modify(struct session_t *sess, void *parse_mar_arr,
    uint32_t mar_num, uint32_t *fail_id)
{
    struct mar_table *mar_tbl = NULL;
    uint32_t index_cnt = 0;

    if (NULL == sess || (NULL == parse_mar_arr && mar_num)) {
        LOG(SESSION, ERR, "insert failed, sess(%p), parse_mar_arr(%p),"
			" mar_num: %u.", sess, parse_mar_arr, mar_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < mar_num; ++index_cnt) {

        mar_tbl = mar_update(sess, parse_mar_arr, index_cnt, fail_id);
        if (NULL == mar_tbl) {
            LOG(SESSION, ERR, "mar update failed.");
            return -1;
        }
    }

    return 0;
}

int mar_get(uint32_t index, session_mar_create *mar)
{
    struct mar_table *entry = NULL;

    if ((index >= mar_get_max()) || (NULL == mar)) {
        LOG(SESSION, ERR, "parameter is invalid, index: %u.",
            index);
        return -1;
    }

    entry = mar_get_table(index);
    ros_rwlock_read_lock(&entry->lock);/* lock */

    if (G_FALSE == entry->valid) {
        ros_rwlock_read_unlock(&entry->lock);/* unlock */
        LOG(SESSION, ERR, "entry is invalid, index: %u.", index);
        return -1;
    }

    ros_memcpy(mar, &entry->mar, sizeof(session_mar_create));
    ros_rwlock_read_unlock(&entry->lock);/* unlock */

    return 0;
}

uint32_t mar_sum(void)
{
    struct mar_table_head *mar_head = mar_get_head();
    uint32_t entry_sum = 0;

    entry_sum = ros_atomic32_read(&mar_head->use_num);

    return entry_sum;
}

/* clear all mar rules releated the current pfcp session */
int mar_clear(struct session_t *sess)
{
    struct mar_table_head *mar_head = mar_get_head();
    struct mar_table *mar_tbl = NULL;
    uint32_t id = 0;

    if (NULL == sess) {
        LOG(SESSION, ERR, "Abnormal parameter, sess(%p).", sess);
        return -1;
    }

    ros_rwlock_write_lock(&sess->lock);/* lock */
    mar_tbl = (struct mar_table *)rbtree_first(&sess->session.mar_root);
    while (NULL != mar_tbl) {
        id = mar_tbl->mar.mar_id;
        mar_tbl = (struct mar_table *)rbtree_delete(&sess->session.mar_root,
            &id, mar_id_compare);
        if (NULL == mar_tbl) {
            LOG(SESSION, ERR, "clear failed, id: %u.", id);
            mar_tbl = (struct mar_table *)rbtree_next(&mar_tbl->mar_node);
            continue;
        }
        ros_rwlock_write_lock(&mar_tbl->lock);/* lock */
        Res_Free(mar_head->pool_id, 0, mar_tbl->index);
        ros_atomic32_sub(&mar_head->use_num, 1);
        mar_tbl->valid = G_FALSE;
        ros_rwlock_write_unlock(&mar_tbl->lock);/* unlock */

        mar_tbl = (struct mar_table *)rbtree_next(&mar_tbl->mar_node);
    }
    ros_rwlock_write_unlock(&sess->lock);/* unlock */

    return 0;
}

uint32_t mar_get_far_index(struct session_t *sess, uint32_t index)
{
    struct mar_table *entry = NULL;
    uint32_t ret_id = 0;
    uint32_t search_id = 0;
    struct far_table *far_tbl = NULL;

    if (NULL == sess || index >= mar_get_max()) {
        LOG(SESSION, ERR, "parameter is invalid, sess(%p), index: %u.",
            sess, index);
        return 0;
    }

    entry = mar_get_table(index);
    ros_rwlock_read_lock(&entry->lock);/* lock */

    if (G_FALSE == entry->valid) {
        ros_rwlock_read_unlock(&entry->lock);/* unlock */
        LOG(SESSION, ERR, "entry is invalid, index: %u.", index);
        return 0;
    }

    switch (entry->mar.steer_mod) {
        case 0:
        case 3:
            if (entry->mar.afai_1_validity) {
                if (entry->mar.afai_2_validity) {
                    if (entry->mar.afai_1.priority <
                        entry->mar.afai_2.priority) {
                        /* afai 1 is active, afai 2 is standby */
                        search_id = entry->mar.afai_1.far_id;
                    } else {
                        /* afai 2 is active, afai 1 is standby */
                        search_id = entry->mar.afai_2.far_id;
                    }
                } else {
                    /* only afai 1 active */
                    search_id = entry->mar.afai_1.far_id;
                }

            } else if (entry->mar.afai_2_validity) {
                search_id = entry->mar.afai_2.far_id;
            } else {
                /* abnormal */
                LOG(SESSION, ERR, "Abnormal case, no active afai.");
                ret_id = 0;
                break;
            }

            far_tbl = far_table_search(sess, search_id);
            if (NULL == far_tbl) {
                LOG(SESSION, ERR,
                    "search far table failed, far id: %u.",
                    search_id);
                ret_id = 0;
                break;
            }
            ret_id = far_tbl->index;
            break;

        case 1:
            break;

        case 2:
            if (entry->mar.afai_1_validity) {
                if (entry->mar.afai_2_validity) {
                    if (entry->mar.cur_weight[0] > entry->mar.cur_weight[1]) {
                        /* afai 1 is active, afai 2 is standby */
                        search_id = entry->mar.afai_1.far_id;
                        entry->mar.cur_weight[0] -= MAR_WEIGHT_SUM;
                    } else {
                        /* afai 2 is active, afai 1 is standby */
                        search_id = entry->mar.afai_2.far_id;
                        entry->mar.cur_weight[1] -= MAR_WEIGHT_SUM;
                    }

                    entry->mar.cur_weight[0] += entry->mar.afai_1.weight;
                    entry->mar.cur_weight[1] += entry->mar.afai_2.weight;
                } else {
                    /* only afai 1 active */
                    search_id = entry->mar.afai_1.far_id;
                }

            } else if (entry->mar.afai_2_validity) {
                search_id = entry->mar.afai_2.far_id;
            } else {
                /* abnormal */
                LOG(SESSION, ERR, "Abnormal case, no active afai.");
                ret_id = 0;
                break;
            }

            far_tbl = far_table_search(sess, search_id);
            if (NULL == far_tbl) {
                LOG(SESSION, ERR,
                    "search far table failed, far id: %u.",
                    search_id);
                ret_id = 0;
                break;
            }
            ret_id = far_tbl->index;
            break;

        default:
            break;
    }

    ros_rwlock_read_unlock(&entry->lock);/* unlock */

    return ret_id;
}

/* Fill the INST table with the FAR index of the MAR */
int mar_fill_far_index(struct session_t *sess, uint32_t index,
    comm_msg_inst_config *inst_cfg)
{
    struct mar_table *entry = NULL;
    uint32_t search_id = 0;
    struct far_table *far_tbl = NULL;

    if (NULL == sess || index >= mar_get_max() || NULL == inst_cfg) {
        LOG(SESSION, ERR,
            "parameter is invalid, sess(%p), index: %u, inst_cfg(%p).",
            sess, index, inst_cfg);
        return 0;
    }

    entry = mar_get_table(index);
    ros_rwlock_read_lock(&entry->lock);/* lock */

    if (G_FALSE == entry->valid) {
        ros_rwlock_read_unlock(&entry->lock);/* unlock */
        LOG(SESSION, ERR, "entry is invalid, index: %u.", index);
        return 0;
    }

    if (entry->mar.afai_1_validity) {
        search_id = entry->mar.afai_1.far_id;
        far_tbl = far_table_search(sess, search_id);
        if (NULL == far_tbl) {
            ros_rwlock_read_unlock(&entry->lock);/* unlock */
            LOG(SESSION, ERR,
                "search far table failed, far id: %u.", search_id);
            return -1;
        }
        inst_cfg->choose.d.flag_far1 = 1;
        inst_cfg->far_index1 = far_tbl->index;
    }

    if (entry->mar.afai_2_validity) {
        search_id = entry->mar.afai_2.far_id;
        far_tbl = far_table_search(sess, search_id);
        if (NULL == far_tbl) {
            ros_rwlock_read_unlock(&entry->lock);/* unlock */
            LOG(SESSION, ERR,
                "search far table failed, far id: %u.", search_id);
            return -1;
        }
        inst_cfg->choose.d.flag_far2 = 1;
        inst_cfg->far_index2 = far_tbl->index;
    }

    ros_rwlock_read_unlock(&entry->lock);/* unlock */

    return 0;
}

int64_t mar_table_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct mar_table *mar_tbl = NULL;
    uint32_t max_num = 0;
    int64_t size = 0;

    if (0 == session_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, session_num: %u.", session_num);
        return -1;
    }

    max_num = session_num * MAX_MAR_NUM;
    size = sizeof(struct mar_table) * max_num;
    mar_tbl = ros_malloc(size);
    if (NULL == mar_tbl) {
        LOG(SESSION, ERR,
            "init pdr failed, no enough memory, max number: %u ="
            " session_num: %u * %d.", max_num,
            session_num, MAX_MAR_NUM);
        return -1;
    }
    ros_memset(mar_tbl, 0, size);

    for (index = 0; index < max_num; ++index) {
        mar_tbl[index].index = index;
        mar_tbl[index].valid = G_FALSE;
        ros_rwlock_init(&mar_tbl[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        return -1;
    }

    mar_tbl_head.pool_id = pool_id;
    mar_tbl_head.mar_table = mar_tbl;
    mar_tbl_head.max_num = max_num;
	ros_rwlock_init(&mar_tbl_head.lock);
    ros_atomic32_set(&mar_tbl_head.use_num, 0);

    LOG(SESSION, MUST, "mar init success.");
    return size;
}


