/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "session_instance.h"
#include "session_orphan.h"
#include "session_teid.h"
#include "far_mgmt.h"
#include "session_report.h"

#include "local_parse.h"
#include "pdr_mgmt.h"
#include "traffic_endpoint_mgmt.h"


struct traffic_endpoint_table_head traffic_endpoint_tbl_head;

static inline struct traffic_endpoint_table_head *traffic_endpoint_get_head(void)
{
    return &traffic_endpoint_tbl_head;
}

static inline struct traffic_endpoint_table *traffic_endpoint_get_table(uint32_t index)
{
    return &traffic_endpoint_tbl_head.te_table[index];
}

static int traffic_endpoint_id_compare(struct rb_node *node, void *key)
{
    struct traffic_endpoint_table *te_node = (struct traffic_endpoint_table *)node;
    uint8_t id = *(uint8_t *)key;

    if (id < te_node->te.endpoint_id) {
        return -1;
    }
    else if (id > te_node->te.endpoint_id) {
        return 1;
    }

    return 0;
}

struct traffic_endpoint_table *traffic_endpoint_table_search(struct session_t *sess, uint8_t id)
{
    struct traffic_endpoint_table *te_tbl = NULL;
    uint8_t te_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    ros_rwlock_read_lock(&sess->lock);// lock
    te_tbl = (struct traffic_endpoint_table *)rbtree_search(&sess->session.tc_endpoint_root,
        &te_id, traffic_endpoint_id_compare);
    ros_rwlock_read_unlock(&sess->lock);// unlock
    if (NULL == te_tbl) {
        LOG(SESSION, ERR, "The entry with id %u does not exist.", te_id);
        return NULL;
    }

    return te_tbl;
}

struct traffic_endpoint_table *traffic_endpoint_table_create(struct session_t *sess, uint8_t id)
{
    struct traffic_endpoint_table_head *te_head = traffic_endpoint_get_head();
    struct traffic_endpoint_table *te_tbl = NULL;
    uint32_t key = 0, index = 0;
    uint8_t te_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    if (G_FAILURE == Res_Alloc(te_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.", te_head->pool_id);
        return NULL;
    }

    te_tbl = traffic_endpoint_get_table(index);
    if (!te_tbl) {
        Res_Free(te_head->pool_id, key, index);
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return NULL;
    }
    memset(&te_tbl->te, 0, sizeof(session_tc_endpoint));
    te_tbl->te.endpoint_id = te_id;

    ros_rwlock_write_lock(&sess->lock);// lock
    /* insert node to session tree root*/
    if (rbtree_insert(&sess->session.tc_endpoint_root, &te_tbl->te_node,
        &te_id, traffic_endpoint_id_compare) < 0) {
        ros_rwlock_write_unlock(&sess->lock);// unlock
        Res_Free(te_head->pool_id, key, index);
        LOG(SESSION, ERR, "rb tree insert failed, id: %u.", te_id);
        return NULL;
    }
    ros_rwlock_write_unlock(&sess->lock);// unlock

    return te_tbl;
}

static void traffic_endpoint_clean_pdr(struct session_t *sess, uint8_t *te_id_arr, uint8_t te_id_num,
    uint32_t *rm_pdr_index_arr, uint32_t *rm_pdr_num)
{
    struct pdr_table *pdr_tbl = NULL;
    uint16_t index_arr[MAX_PDR_NUM];
    uint8_t index_cnt = 0, cnt_l1, cnt_l2;

    /* É¾³ý¹ØÁªµÄPDR */
    ros_rwlock_read_lock(&sess->lock);/* lock */
    for (cnt_l1 = 0; cnt_l1 < te_id_num; ++cnt_l1) {
        pdr_tbl = (struct pdr_table *)rbtree_first(&sess->session.pdr_root);
        while (NULL != pdr_tbl) {
            for (cnt_l2 = 0; cnt_l2 < pdr_tbl->pdr.pdi_content.traffic_endpoint_num; ++cnt_l2) {
                if (te_id_arr[cnt_l1] == pdr_tbl->pdr.pdi_content.traffic_endpoint_id[cnt_l2]) {
                    index_arr[index_cnt++] = pdr_tbl->pdr.pdr_id;
                    break;
                }
            }

            pdr_tbl = (struct pdr_table *)rbtree_next(&pdr_tbl->pdr_node);
        }
    }
    ros_rwlock_read_unlock(&sess->lock);/* unlock */

    if (0 > pdr_remove(sess, index_arr, index_cnt, rm_pdr_index_arr, rm_pdr_num)) {
        LOG(SESSION, ERR, "Delete PDR exception referencing TE.");
    }
}

int traffic_endpoint_insert(struct session_t *sess, void *parse_te_arr,
    uint8_t te_num)
{
    struct traffic_endpoint_table *te_tbl = NULL;
    uint8_t index_cnt = 0;

    if (NULL == sess || NULL == parse_te_arr || 0 == te_num) {
        LOG(SESSION, ERR, "traffic_endpoint insert failed, sess(%p), parse_te_arr(%p), te_num: %d.",
            sess, parse_te_arr, te_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < te_num; ++index_cnt) {
        te_tbl = traffic_endpoint_add(sess, parse_te_arr, index_cnt);
        if (NULL == te_tbl) {
            LOG(SESSION, ERR, "traffic_endpoint add failed.");
            return -1;
        }
    }

    return 0;
}

int traffic_endpoint_remove(struct session_t *sess, uint8_t *te_id_arr, uint8_t te_id_num,
    uint32_t *rm_pdr_index_arr, uint32_t *rm_pdr_num)
{
    struct traffic_endpoint_table *te_tbl = NULL;
    struct traffic_endpoint_table_head *te_head = traffic_endpoint_get_head();
    uint8_t id, cnt;

    if (NULL == sess || NULL == te_id_arr) {
        LOG(SESSION, ERR, "traffic_endpoint remove failed, sess(%p), te_id_arr(%p).",
            sess, te_id_arr);
        return -1;
    }

    for (cnt = 0; cnt < te_id_num; ++cnt) {
        id = te_id_arr[cnt];

        ros_rwlock_write_lock(&sess->lock);// lock
        te_tbl = (struct traffic_endpoint_table *)rbtree_delete(&sess->session.tc_endpoint_root, &id,
            traffic_endpoint_id_compare);
        ros_rwlock_write_unlock(&sess->lock);// unlock
        if (NULL == te_tbl) {
            LOG(SESSION, ERR, "remove failed, not exist, id: %u.", id);
            return -1;
        }

        Res_Free(te_head->pool_id, 0, te_tbl->index);
    }
    traffic_endpoint_clean_pdr(sess, te_id_arr, te_id_num, rm_pdr_index_arr, rm_pdr_num);

    return 0;
}

int traffic_endpoint_modify(struct session_t *sess, void *parse_te_arr, uint8_t parse_te_num)
{
    struct traffic_endpoint_table *te_tbl = NULL;
    uint8_t cnt = 0;

    if (NULL == sess || NULL == parse_te_arr) {
        LOG(SESSION, ERR, "traffic_endpoint modify failed, sess(%p), parse_te_arr(%p).",
            sess, parse_te_arr);
        return -1;
    }

    for (cnt = 0; cnt < parse_te_num; ++cnt) {
        te_tbl = traffic_endpoint_update(sess, parse_te_arr, cnt);
        if (NULL == te_tbl) {
            LOG(SESSION, ERR, "traffic_endpoint update failed.");
            return -1;
        }
    }

    return 0;
}

/* clear all traffic_endpoint rules releated the current pfcp session */
int traffic_endpoint_clear(struct session_t *sess)
{
    struct traffic_endpoint_table *te_tbl = NULL;
    struct traffic_endpoint_table_head *te_head = traffic_endpoint_get_head();
    uint8_t id = 0;
    uint8_t id_arr[MAX_TC_ENDPOINT_NUM], id_num = 0;

    if (NULL == sess) {
        LOG(SESSION, ERR, "clear failed, sess is null.");
        return -1;
    }

    ros_rwlock_write_lock(&sess->lock);// lock
    te_tbl = (struct traffic_endpoint_table *)rbtree_first(&sess->session.tc_endpoint_root);
    while (NULL != te_tbl) {
        id = te_tbl->te.endpoint_id;
        te_tbl = (struct traffic_endpoint_table *)rbtree_delete(&sess->session.tc_endpoint_root,
            &id, traffic_endpoint_id_compare);
        if (NULL == te_tbl) {
            LOG(SESSION, ERR, "clear failed, id: %u.", id);
            te_tbl = (struct traffic_endpoint_table *)rbtree_next(&te_tbl->te_node);
            continue;
        }

        id_arr[id_num++] = id;
        Res_Free(te_head->pool_id, 0, te_tbl->index);

        te_tbl = (struct traffic_endpoint_table *)rbtree_next(&te_tbl->te_node);
    }
    ros_rwlock_write_unlock(&sess->lock);// unlock

    traffic_endpoint_clean_pdr(sess, id_arr, id_num, NULL, NULL);

    return 0;
}

int64_t traffic_endpoint_table_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct traffic_endpoint_table *te_tbl = NULL;
    uint32_t max_num = 0;
    int64_t size = 0;

    if (0 == session_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, session_num: %u.", session_num);
        return -1;
    }

    max_num = session_num * MAX_TC_ENDPOINT_NUM;
    size = sizeof(struct traffic_endpoint_table) * max_num;
    te_tbl = ros_malloc(size);
    if (NULL == te_tbl) {
        LOG(SESSION, ERR,
            "init pdr failed, no enough memory, max number: %u ="
            " session_num: %u * %d.", max_num,
            session_num, MAX_TC_ENDPOINT_NUM);
        return -1;
    }
    ros_memset(te_tbl, 0, size);

    for (index = 0; index < max_num; ++index) {
        te_tbl[index].index = index;
        ros_rwlock_init(&te_tbl[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        return -1;
    }

    traffic_endpoint_tbl_head.pool_id = pool_id;
    traffic_endpoint_tbl_head.te_table = te_tbl;
    traffic_endpoint_tbl_head.max_num = max_num;
	ros_rwlock_init(&traffic_endpoint_tbl_head.lock);

    LOG(SESSION, MUST, "traffic_endpoint init success.");
    return size;
}

