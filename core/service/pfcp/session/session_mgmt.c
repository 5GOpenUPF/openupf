/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "pdr_mgmt.h"
#include "urr_mgmt.h"
#include "qer_mgmt.h"
#include "bar_mgmt.h"
#include "traffic_endpoint_mgmt.h"
#include "session_orphan.h"

#include "session_instance.h"
#include "session_mgmt.h"
#include "far_mgmt.h"
#include "session_ethernet.h"
#include "mar_mgmt.h"
#include "upc_node.h"
#include "local_parse.h"


static struct session_mgmt_cb sess_mgmt_cb;

/* Last load info */
static uint8_t g_last_load_metric = 0;

inline struct session_mgmt_cb *session_mgmt_head(void)
{
    return &sess_mgmt_cb;
}

static inline struct session_t *session_table_entry(uint32_t index)
{
    return &sess_mgmt_cb.session_table[index];
}

void session_table_show(struct pfcp_session *sess_tbl)
{
#ifdef LOG_MODE_DEBUG
    struct pdr_table *pdr_tbl = NULL;
    struct far_table *far_tbl = NULL;
    struct urr_table *urr_tbl = NULL;
    struct qer_table *qer_tbl = NULL;
    struct bar_table *bar_tbl = NULL;
    struct mar_table *mar_tbl = NULL;

    if (NULL == sess_tbl) {
        LOG(SESSION, ERR,
            "abnormal parameter, sess_tbl(%p).\n", sess_tbl);
        return;
    }

    LOG(SESSION, DEBUG, "local seid: 0x%lx.", sess_tbl->local_seid);
    LOG(SESSION, DEBUG, "cp seid: 0x%lx.", sess_tbl->cp_seid);
    LOG(SESSION, DEBUG, "pdn type: %d.", sess_tbl->pdn_type);
    LOG(SESSION, DEBUG, "inactivity_timer: %u.",
        sess_tbl->inactivity_timer);

    /* show pdr */
    pdr_tbl = (struct pdr_table *)rbtree_first(&sess_tbl->pdr_root);
    while (NULL != pdr_tbl) {
        pdr_table_show(pdr_tbl);

        pdr_tbl = (struct pdr_table *)rbtree_next(&pdr_tbl->pdr_node);
    }

    /* show far */
    far_tbl = (struct far_table *)rbtree_first(&sess_tbl->far_root);
    while (NULL != far_tbl) {
        far_table_show(far_tbl);

        far_tbl = (struct far_table *)rbtree_next(&far_tbl->far_node);
    }

    /* show urr */
    urr_tbl = (struct urr_table *)rbtree_first(&sess_tbl->urr_root);
    while (NULL != urr_tbl) {
        urr_table_show(urr_tbl);

        urr_tbl = (struct urr_table *)rbtree_next(&urr_tbl->urr_node);
    }

    /* show qer */
    qer_tbl = (struct qer_table *)rbtree_first(&sess_tbl->qer_root);
    while (NULL != qer_tbl) {
        qer_table_show(qer_tbl);

        qer_tbl = (struct qer_table *)rbtree_next(&qer_tbl->qer_node);
    }

    /* show bar */
    bar_tbl = (struct bar_table *)rbtree_first(&sess_tbl->bar_root);
    while (NULL != bar_tbl) {
        bar_table_show(bar_tbl);

        bar_tbl = (struct bar_table *)rbtree_next(&bar_tbl->bar_node);
    }

    /* show mar */
    mar_tbl = (struct mar_table *)rbtree_first(&sess_tbl->mar_root);
    while (NULL != mar_tbl) {
        mar_table_show(mar_tbl);

        mar_tbl = (struct mar_table *)rbtree_next(&mar_tbl->mar_node);
    }

    LOG(SESSION, DEBUG, "show session info finish.\n");
#endif
}

/* session key compare function */
static int session_seid_compare(struct rb_node *node, void *key)
{
    struct session_t *sess_node = (struct session_t *)node;
    struct session_key *sess_key = (struct session_key *)key;

    if (sess_key->local_seid < sess_node->session.local_seid) {
        return -1;
    }
    else if (sess_key->local_seid > sess_node->session.local_seid) {
        return 1;
    }

    if (sess_key->cp_seid < sess_node->session.cp_seid) {
        return -1;
    }
    else if (sess_key->cp_seid > sess_node->session.cp_seid) {
        return 1;
    }

    return 0;
}

static uint8_t session_calc_load_metric(void)
{
    struct session_mgmt_cb *session_head = session_mgmt_head();
    uint32_t use_num = ros_atomic32_read(&session_head->use_num);
    uint32_t total_num = session_head->max_num;
    uint8_t metric = (use_num * 100) / total_num;

    return metric;
}

void session_fill_load_info(session_emd_response *resp)
{
    uint8_t metric = session_calc_load_metric(), flag = 0;
    upc_node_cb *node;

    if (NULL == resp) {
        LOG(SESSION, ERR, "Error parameter, resp(%p).", resp);
        return;
    }

    node = upc_node_cb_get_public(resp->msg_header.node_id_index);

    if (node->assoc_config.cp_features.d.load) {
        if (g_last_load_metric < 100) {
            if (metric > g_last_load_metric && metric > g_last_load_metric + 5) {
                flag = 1;
            } else if (metric < g_last_load_metric && metric + 5 < g_last_load_metric) {
                flag = 1;
            } else if (metric == 100) {
                flag = 1;
            }

            if (flag) {
                resp->member_flag.d.load_ctl_info_present = 1;
                resp->load_ctl_info.sequence_number = ros_getime();
                resp->load_ctl_info.load_metric = metric;
                g_last_load_metric = metric;
            }
        }
    }

    if (node->assoc_config.cp_features.d.ovrl) {
        if (metric > 95 && metric < 98) {
            resp->member_flag.d.overload_ctl_info_present = 1;
            resp->overload_ctl_info.sequence_number = ros_getime();
            resp->overload_ctl_info.overload_reduc_metric = 0;
            resp->overload_ctl_info.timer.d.unit = 3;
            resp->overload_ctl_info.timer.d.value = 3;
            resp->overload_ctl_info.oci_flag.d.AOCI = 1;
        } else if (metric > 97) {
            resp->member_flag.d.overload_ctl_info_present = 1;
            resp->overload_ctl_info.sequence_number = ros_getime();
            resp->overload_ctl_info.overload_reduc_metric = 5;
            resp->overload_ctl_info.timer.d.unit = 3;
            resp->overload_ctl_info.timer.d.value = 3;
            resp->overload_ctl_info.oci_flag.d.AOCI = 1;
        }
    }
}

/* session mgmt init, initialize session list head */
int64_t session_mgmt_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct session_t *session_tbl = NULL;
    int64_t size = 0, total_mem = 0;

    if (0 == session_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, session_num: %u.", session_num);
        return -1;
    }

    size = sizeof(struct session_t) * session_num;
    session_tbl = ros_malloc(size);
    if (NULL == session_tbl) {
        LOG(SESSION, ERR,
            "init failed, no enough memory, session_num: %u.", session_num);
        return -1;
    }
    ros_memset(session_tbl, 0, sizeof(struct session_t) * session_num);

    for (index = 0; index < session_num; ++index) {
        session_tbl[index].index = index;
        dl_list_init(&session_tbl[index].ue_mac_head);
        dl_list_init(&session_tbl[index].eth_dl_head);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, session_num)) {
        return -1;
    }

    sess_mgmt_cb.pool_id = pool_id;
    sess_mgmt_cb.session_table = session_tbl;
    sess_mgmt_cb.max_num = session_num;
    ros_atomic32_set(&sess_mgmt_cb.use_num, 0);
    sess_mgmt_cb.session_tree_root = RB_ROOT_INIT_VALUE;
    total_mem += size;

    LOG(SESSION, MUST, "session mgmt init success.");

    return total_mem;
}

/* create session table with seid, add session table to session list */
struct session_t *session_table_create(struct session_key *key)
{
    struct session_mgmt_cb *session_head = session_mgmt_head();
    struct session_t *sess_tbl = NULL;
    uint32_t res_key = 0, index = 0;

    if (G_FAILURE == Res_Alloc(session_head->pool_id, &res_key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            session_head->pool_id);
        return NULL;
    }

    sess_tbl = session_table_entry(index);

    ros_rwlock_write_lock(&sess_tbl->lock);// lock
    memset(&sess_tbl->session, 0, sizeof(struct pfcp_session));

	if(sess_tbl->inactivity_timer_id){
		ros_timer_del(sess_tbl->inactivity_timer_id);
		sess_tbl->inactivity_timer_id = NULL;
	}

    /* init rb tree root */
    sess_tbl->session.pdr_root = RB_ROOT_INIT_VALUE;
    sess_tbl->session.far_root = RB_ROOT_INIT_VALUE;
    sess_tbl->session.urr_root = RB_ROOT_INIT_VALUE;
    sess_tbl->session.qer_root = RB_ROOT_INIT_VALUE;
    sess_tbl->session.bar_root = RB_ROOT_INIT_VALUE;
    sess_tbl->session.tc_endpoint_root = RB_ROOT_INIT_VALUE;
    sess_tbl->session.mar_root = RB_ROOT_INIT_VALUE;
    sess_tbl->session.sdf_root = RB_ROOT_INIT_VALUE;
    sess_tbl->session.eth_root = RB_ROOT_INIT_VALUE;
    dl_list_init(&sess_tbl->ue_mac_head);
    dl_list_init(&sess_tbl->eth_dl_head);

    sess_tbl->session.local_seid = key->local_seid;
    sess_tbl->session.cp_seid = key->cp_seid;
    ros_rwlock_write_unlock(&sess_tbl->lock);// unlock
    /* insert node to session tree root*/
    ros_rwlock_write_lock(&session_head->lock);// lock
    if (rbtree_insert(&session_head->session_tree_root, &sess_tbl->session_node,
            key, session_seid_compare) < 0) {
        ros_rwlock_write_unlock(&session_head->lock);// unlock
        Res_Free(session_head->pool_id, res_key, index);
        LOG(SESSION, DEBUG,
            "rb tree insert failed, seid:0x%016lx:0x%016lx, already exists.",
            key->local_seid, key->cp_seid);
        return NULL;
    }
    ros_rwlock_write_unlock(&session_head->lock);// unlock

    ros_atomic32_inc(&session_head->use_num);

    LOG(SESSION, RUNNING, "create success, seid:0x%016lx:0x%016lx.",
            key->local_seid, key->cp_seid);
    return sess_tbl;
}

/* search session table with seid in session list */
struct session_t *session_table_search(struct session_key *key)
{
    struct session_mgmt_cb *session_head = session_mgmt_head();
    struct session_t *sess_tbl = NULL;

    if (NULL == key) {
        LOG(SESSION, ERR, "key is NULL.");
        return NULL;
    }

    ros_rwlock_read_lock(&session_head->lock);// lock
    sess_tbl = (struct session_t *)rbtree_search(&session_head->session_tree_root,
          key, session_seid_compare);
    ros_rwlock_read_unlock(&session_head->lock);// unlock
    if (NULL == sess_tbl) {
        LOG(SESSION, ERR, "search session failed, local seid: 0x%lx "
            "cp seid: 0x%lx.", key->local_seid, key->cp_seid);
        return NULL;
    }

    return sess_tbl;
}

struct session_t *session_table_remove(struct session_key *key)
{
    struct session_mgmt_cb *session_head = session_mgmt_head();
    struct session_t *sess_tbl = NULL;

    if (NULL == key) {
        LOG(SESSION, ERR, "key is NULL.");
        return NULL;
    }

    ros_rwlock_write_lock(&session_head->lock);// lock
    sess_tbl = (struct session_t *)rbtree_delete(&session_head->session_tree_root,
        key, session_seid_compare);
    ros_rwlock_write_unlock(&session_head->lock);// unlock
    if (NULL == sess_tbl) {
        LOG(SESSION, ERR,
            "session remove failed, no such session, seid:0x%016lx:0x%016lx.",
            key->local_seid, key->cp_seid);
        return NULL;
    }

    Res_Free(session_head->pool_id, 0, sess_tbl->index);

    ros_atomic32_sub(&session_head->use_num, 1);

    return sess_tbl;
}

struct session_t *session_table_replace(struct session_key *src_key, struct session_key *dest_key)
{
    struct session_mgmt_cb *session_head = session_mgmt_head();
    struct session_t *sess_tbl = NULL;

    if (NULL == src_key || NULL == dest_key) {
        LOG(SESSION, ERR, "Parameters abnormal, src_key(%p), dest_key(%p).", src_key, dest_key);
        return NULL;
    }

    ros_rwlock_write_lock(&session_head->lock);/* lock */
    sess_tbl = (struct session_t *)rbtree_delete(&session_head->session_tree_root,
        src_key, session_seid_compare);
    if (NULL == sess_tbl) {
        ros_rwlock_write_unlock(&session_head->lock);/* unlock */
        LOG(SESSION, ERR, "Replace session failed, local seid: 0x%lx "
            "cp seid: 0x%lx.", src_key->local_seid, src_key->cp_seid);
        return NULL;
    }

    ros_rwlock_write_lock(&sess_tbl->lock);/* lock */
    sess_tbl->session.local_seid = dest_key->local_seid;
    sess_tbl->session.cp_seid = dest_key->cp_seid;
    ros_rwlock_write_unlock(&sess_tbl->lock);/* unlock */

    if (0 > rbtree_insert(&session_head->session_tree_root, &sess_tbl->session_node,
        dest_key, session_seid_compare)) {
        ros_rwlock_write_unlock(&session_head->lock);/* unlock */
        LOG(SESSION, ERR,
            "Replace create failed, rb tree insert failed, seid:0x%016lx:0x%016lx.",
            dest_key->local_seid, dest_key->cp_seid);
        return NULL;
    }
    ros_rwlock_write_unlock(&session_head->lock);/* unlock */

    return sess_tbl;
}

/* session establish process, create table and fill item */
int session_establish(session_content_create *session_content, session_emd_response *resp)
{
    struct session_key key = {0,};
    struct session_t *sess_tbl = NULL;

    if (unlikely(NULL == session_content || NULL == resp)) {
        LOG(SESSION, ERR, "session establish failed,"
			" content(%p), resp(%p).", session_content, resp);
        return -1;
    }

    key.local_seid  = session_content->local_seid;
    key.cp_seid     = session_content->cp_f_seid.seid;

    resp->local_seid = session_content->local_seid;
    resp->cp_seid = session_content->cp_f_seid.seid;
    resp->cause = SESS_REQUEST_ACCEPTED;

    /* 1. create session table */
    sess_tbl = session_table_create(&key);
    if (NULL == sess_tbl) {
        LOG(SESSION, ERR,
            "session table create failed, seid:0x%016lx:0x%016lx.",
            key.local_seid, key.cp_seid);
        resp->cause = SESS_REQUEST_REJECTED;
        return -1;
    }

    sess_tbl->session.node_index = session_content->node_index;

    /* 2. bar */
    if (session_content->member_flag.d.bar_present) {
        if (0 > bar_insert(sess_tbl, &session_content->bar)) {
            LOG(SESSION, ERR, "bar_insert failed.");

            resp->failed_rule_id.rule_id = session_content->bar.bar_id;
            resp->failed_rule_id.rule_type = SESS_FAILED_BAR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            goto err;
        }
    }

    /* 3. far */
    if (0 < session_content->far_num) {
        if (0 > far_insert(sess_tbl, session_content->far_arr,
    		session_content->far_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "far_insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_FAR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            goto err;
        }
    }

    /* 4. qer */
    if (0 < session_content->qer_num) {
        if (0 > qer_insert(sess_tbl, session_content->qer_arr,
    		session_content->qer_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "qer_insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_QER;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            goto err;
        }
    }

    /* 5. urr */
    if (0 < session_content->urr_num) {
        if (0 > urr_insert(sess_tbl, session_content->urr_arr,
    		session_content->urr_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "urr_insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_URR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            goto err;
        }
    }

    /* 6. trafficEndpoint */
    if (0 < session_content->tc_endpoint_num) {
        if (0 > traffic_endpoint_insert(sess_tbl, session_content->tc_endpoint_arr,
    		session_content->tc_endpoint_num)) {
            LOG(SESSION, ERR, "traffic_endpoint insert failed.");

            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            goto err;
        }
    }

    /* 7. mar */
    if (0 < session_content->mar_num) {
        if (0 > mar_insert(sess_tbl, session_content->mar_arr,
    		session_content->mar_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "mar_insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_MAR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            goto err;
        }
    }

    /* 8. traceInfo */
    if (session_content->member_flag.d.trace_info_present) {
        if (G_TRUE ==
            upc_node_features_validity_query(UF_TRACE)) {
            sess_tbl->session.trace_info_present = 1;
            ros_memcpy(&sess_tbl->session.trace_info,
                &session_content->trace_info, sizeof(session_trace_info));
        } else {
            LOG(SESSION, ERR, "TRACE feature not support,"
                " trace info invalid.");

            goto err;
        }
    }

    /* 9. other */
    sess_tbl->session.pdn_type = session_content->pdn_type;
    if (session_content->member_flag.d.inactivity_timer_present) {
        sess_tbl->session.inactivity_timer = session_content->inactivity_timer;

		sess_tbl->inactivity_timer_id = ros_timer_create(ROS_TIMER_MODE_ONCE,
            sess_tbl->session.inactivity_timer * ROS_TIMER_TICKS_PER_SEC, (uint64_t)sess_tbl,
            session_inactivity_timer_cb);

        ros_timer_start(sess_tbl->inactivity_timer_id);

    }

	if (session_content->member_flag.d.user_id_present) {
        ros_memcpy(&sess_tbl->session.user_id, &session_content->user_id,
            sizeof(session_user_id));
    }

	if (session_content->member_flag.d.apn_dnn_present) {
        ros_memcpy(&sess_tbl->session.apn_dnn, &session_content->apn_dnn,
            sizeof(session_apn_dnn));
    }

	ros_memcpy(&sess_tbl->session.rat_type, &session_content->rat_type,
            sizeof(session_rat_type));
	ros_memcpy(&sess_tbl->session.user_local_info, &session_content->user_local_info,
            sizeof(session_user_location_info));

    /* 10. fill and add pdr */
    if (0 < session_content->pdr_num) {
        if (0 > pdr_insert(sess_tbl, session_content->pdr_arr,
            session_content->pdr_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "pdr_insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_PDR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            goto err;
        }
    }

	if (sess_tbl->session.user_id.sig_trace) {
		session_send_sigtrace_ueip_to_fp(sess_tbl);
		LOG(SESSION, ERR, "sig trace open, send ueip to fp.");
	}

    LOG(SESSION, RUNNING, "session establish finish.\r\n");

    session_table_show(&sess_tbl->session);

    return 0;

err:
    {
        session_emd_response del_resp;

        if (0 > session_delete(key.local_seid, key.cp_seid,
            &del_resp, 1, NULL)) {
            LOG(SESSION, ERR, "session establish rollback failed.\r\n");
        }

        return -1;
    }
}

void session_establish_to_fp(session_content_create *session_content)
{
    if (unlikely(NULL == session_content)) {
        LOG(SESSION, ERR, "session establish failed, content(%p).", session_content);
        return;
    }

    /* Bar */
    if (session_content->member_flag.d.bar_present) {
        if (0 > bar_fp_add_or_mod(&session_content->bar.bar_index, 1, TRUE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent BAR config to fp failed.");
        }
    }

    /* Far */
    if (0 < session_content->far_num) {
        uint32_t index_arr[MAX_FAR_NUM], index_cnt;

        for (index_cnt = 0; index_cnt < session_content->far_num; ++index_cnt) {
            index_arr[index_cnt] = session_content->far_arr[index_cnt].far_index;
        }

        if (-1 == far_fp_add_or_mod(index_arr, index_cnt, TRUE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent FAR config to fp failed.");
        }
    }

    /* Qer */
    if (0 < session_content->qer_num) {
        uint32_t index_arr[MAX_QER_NUM], index_cnt;

        for (index_cnt = 0; index_cnt < session_content->qer_num; ++index_cnt) {
            index_arr[index_cnt] = session_content->qer_arr[index_cnt].qer_index;
        }

        if (-1 == qer_fp_add_or_mod(index_arr, index_cnt, TRUE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent QER config to fp failed.");
        }
    }

    /* Pdr */
    if (0 < session_content->pdr_num) {
        uint32_t index_arr[MAX_PDR_NUM], index_cnt, valid_cnt = 0;
        struct session_inst_entry *entry;

        for (index_cnt = 0; index_cnt < session_content->pdr_num; ++index_cnt) {
            entry = session_instance_get_entry(session_content->pdr_arr[index_cnt].pdr_index);
            if (NULL == entry) {
                continue;
            }

            ros_rwlock_read_lock(&entry->rwlock);// lock
            if (entry->valid) {
                index_arr[valid_cnt++] = entry->index;
            }
            ros_rwlock_read_unlock(&entry->rwlock);// unlock
        }

        if (-1 == session_instance_fp_add_or_mod(index_arr, valid_cnt, TRUE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent Instance config to fp failed.");
        }

        if (-1 == session_orphan_modify(index_arr, valid_cnt)) {
            LOG(SESSION, ERR, "remove fast entry for orphan tree failed.");
        }
    }

    LOG(SESSION, RUNNING, "session establish to fp finish.\r\n");
}

/* session modify process, search table and update item */
int session_modify(session_content_modify *session_content, session_emd_response *resp)
{
    struct session_key key = {0,};
    struct session_t *sess_tbl = NULL;

    if (NULL == session_content || NULL == resp) {
        LOG(SESSION, ERR, "session establish failed,"
			" content(%p), resp(%p).",
			session_content, resp);
        return -1;
    }

    key.local_seid  = session_content->local_seid;
    key.cp_seid     = session_content->cp_seid;

    resp->local_seid = session_content->local_seid;
    resp->cp_seid = session_content->cp_seid;
    resp->cause = SESS_REQUEST_ACCEPTED;

    /* 1. Search session table */
    if (session_content->member_flag.d.update_cp_seid_present) {
        struct session_key new_key = {.local_seid = session_content->local_seid,
            .cp_seid = session_content->update_cp_fseid.seid};

        sess_tbl = session_table_replace(&key, &new_key);
        if (NULL == sess_tbl) {
            LOG(SESSION, ERR,
                "session table replace failed, seid:0x%lx:0x%lx.",
                key.local_seid, key.cp_seid);
            resp->cause = SESS_SESSION_CONTEXT_NOT_FOUND;
            return -1;
        }
    } else {
        sess_tbl = session_table_search(&key);
        if (NULL == sess_tbl) {
            LOG(SESSION, ERR,
                "session table search failed, seid:0x%lx:0x%lx.",
                key.local_seid, key.cp_seid);
            resp->cause = SESS_SESSION_CONTEXT_NOT_FOUND;
            return -1;
        }
    }

	//sess_tbl->session.node_index = session_content->node_index;

    /*********************** Remove rules ***************************/
    /* Bar remove */
    if (session_content->member_flag.d.remove_bar_present) {
        if (0 > bar_remove(sess_tbl, session_content->remove_bar, &session_content->remove_bar_index)) {
            LOG(SESSION, ERR, "bar remove failed.");

            resp->failed_rule_id.rule_id = session_content->update_bar.bar_id;
            resp->failed_rule_id.rule_type = SESS_FAILED_BAR;
            resp->cause = SESS_REQUEST_REJECTED;

            return -1;
        }
    }
    /* Far remove */
    if (0 < session_content->remove_far_num) {
    	if (0 > far_remove(sess_tbl, session_content->remove_far_arr,
    		session_content->remove_far_num, session_content->remove_far_index_arr)) {
            LOG(SESSION, ERR, "far_remove failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_FAR;
            resp->cause = SESS_REQUEST_REJECTED;

            return -1;
        }
    }
    /* Qer remove */
    if (0 < session_content->remove_qer_num) {
    	if (0 > qer_remove(sess_tbl, session_content->remove_qer_arr,
    		session_content->remove_qer_num, session_content->remove_qer_index_arr)) {
            LOG(SESSION, ERR, "qer_remove failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_QER;
            resp->cause = SESS_REQUEST_REJECTED;

            return -1;
        }
    }
    /* Urr remove */
    if (0 < session_content->remove_urr_num) {
    	if (0 > urr_remove(sess_tbl, session_content->remove_urr_arr,
    		session_content->remove_urr_num, session_content->remove_urr_arr)) {
            LOG(SESSION, ERR, "urr_remove failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_URR;
            resp->cause = SESS_REQUEST_REJECTED;

            return -1;
        }
    }
    /* Mar remove */
    if (0 < session_content->remove_mar_num) {
        if (0 > mar_remove(sess_tbl, session_content->remove_mar_arr,
    		session_content->remove_mar_num)) {
            LOG(SESSION, ERR, "mar_remove failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_MAR;
            resp->cause = SESS_REQUEST_REJECTED;

            return -1;
        }
    }
    /* Pdr remove */
    if (0 < session_content->remove_pdr_num) {
    	if (0 > pdr_remove(sess_tbl, session_content->remove_pdr_arr, session_content->remove_pdr_num,
            session_content->remove_pdr_index_arr, &session_content->remove_pdr_index_num)) {
            LOG(SESSION, ERR, "Pdr remove failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_PDR;
            resp->cause = SESS_REQUEST_REJECTED;

            return -1;
        }
    }
    /* TrafficEndpoint remove */
    if (session_content->remove_tc_endpoint_num) {
        if (0 > traffic_endpoint_remove(sess_tbl, session_content->remove_tc_endpoint_arr,
    		session_content->remove_tc_endpoint_num, session_content->remove_pdr_index_arr,
    		&session_content->remove_pdr_index_num)) {
            LOG(SESSION, ERR, "traffic_endpoint_remove failed.");

            resp->cause = SESS_REQUEST_REJECTED;

            return -1;
        }
    }

    /*********************** Update rules ***************************/
    /* Bar update */
    if (session_content->member_flag.d.update_bar_present) {
        if (0 > bar_modify(sess_tbl, &session_content->update_bar)) {
            LOG(SESSION, ERR, "BAR modify failed.");

            resp->failed_rule_id.rule_id = session_content->update_bar.bar_id;
            resp->failed_rule_id.rule_type = SESS_FAILED_BAR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Far update */
    if (0 < session_content->update_far_num) {
        if (0 > far_modify(sess_tbl, session_content->update_far_arr,
            session_content->update_far_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "FAR modify failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_FAR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Qer update */
    if (0 < session_content->update_qer_num) {
        if (0 > qer_modify(sess_tbl, session_content->update_qer_arr,
    		session_content->update_qer_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "QER modify failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_QER;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Urr update */
    if (0 < session_content->update_urr_num) {
        if (0 > urr_modify(sess_tbl, session_content->update_urr_arr,
    		session_content->update_urr_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "URR modify failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_URR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Mar update */
    if (0 < session_content->update_mar_num) {
        if (0 > mar_modify(sess_tbl, session_content->update_mar_arr,
    		session_content->update_mar_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "MAR update failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_MAR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Pdr update */
    if (0 < session_content->update_pdr_num) {
        if (0 > pdr_modify(sess_tbl, session_content->update_pdr_arr,
            session_content->update_pdr_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "PDR modify failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_PDR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* TrafficEndpoint update */
    if (session_content->update_tc_endpoint_num) {
        if (0 > traffic_endpoint_modify(sess_tbl, session_content->update_tc_endpoint_arr,
    		session_content->update_tc_endpoint_num)) {
            LOG(SESSION, ERR, "Traffic endpoint modify failed.");

            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }

    /*********************** Create rules ***************************/
    /* Bar create */
    if (session_content->member_flag.d.create_bar_present) {
        if (0 > bar_insert(sess_tbl, &session_content->create_bar)) {
            LOG(SESSION, ERR, "BAR insert failed.");

            resp->failed_rule_id.rule_id = session_content->create_bar.bar_id;
            resp->failed_rule_id.rule_type = SESS_FAILED_BAR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Far create */
    if (0 < session_content->create_far_num) {
    	if (0 > far_insert(sess_tbl, session_content->create_far_arr,
    		session_content->create_far_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "FAR insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_FAR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Qer create */
    if (0 < session_content->create_qer_num) {
    	if (0 > qer_insert(sess_tbl, session_content->create_qer_arr,
    		session_content->create_qer_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "QER insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_QER;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Urr create */
    if (0 < session_content->create_urr_num) {
    	if (0 > urr_insert(sess_tbl, session_content->create_urr_arr,
    		session_content->create_urr_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "URR insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_URR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Mar create */
    if (0 < session_content->create_mar_num) {
        if (0 > mar_insert(sess_tbl, session_content->create_mar_arr,
    		session_content->create_mar_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "MAR insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_MAR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* Pdr create */
    if (0 < session_content->create_pdr_num) {
    	if (0 > pdr_insert(sess_tbl, session_content->create_pdr_arr,
            session_content->create_pdr_num, &resp->failed_rule_id.rule_id)) {
            LOG(SESSION, ERR, "PDR insert failed.");

            resp->failed_rule_id.rule_type = SESS_FAILED_PDR;
            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }
    /* TrafficEndpoint create */
    if (session_content->create_tc_endpoint_num) {
        if (0 > traffic_endpoint_insert(sess_tbl, session_content->create_tc_endpoint_arr,
    		session_content->create_tc_endpoint_num)) {
            LOG(SESSION, ERR, "Traffic endpoint insert failed.");

            resp->cause = SESS_RULE_CREATION_MODIFICATION_FAILURE;

            return -1;
        }
    }

    /******************************* Other *******************************/
    /* TraceInfo */
    if (session_content->member_flag.d.trace_info_present) {
        if (G_TRUE ==
            upc_node_features_validity_query(UF_TRACE)) {
            sess_tbl->session.trace_info_present = 1;
            ros_memcpy(&sess_tbl->session.trace_info,
                &session_content->trace_info, sizeof(session_trace_info));
        } else {
            LOG(SESSION, ERR, "TRACE feature not support, trace info invalid.");

            return -1;
        }
    }

    /* Inactivity timer */
    if (session_content->member_flag.d.inactivity_timer_present) {
        sess_tbl->session.inactivity_timer = session_content->inactivity_timer;

		if (!sess_tbl->inactivity_timer_id) {
			sess_tbl->inactivity_timer_id = ros_timer_create(ROS_TIMER_MODE_ONCE,
	            sess_tbl->session.inactivity_timer * ROS_TIMER_TICKS_PER_SEC, (uint64_t)sess_tbl,
	            session_inactivity_timer_cb);
	        ros_timer_start(sess_tbl->inactivity_timer_id);

		} else {
			ros_timer_reset(sess_tbl->inactivity_timer_id, sess_tbl->session.inactivity_timer * ROS_TIMER_TICKS_PER_SEC,
				ROS_TIMER_MODE_ONCE, (uint64_t)sess_tbl, session_inactivity_timer_cb);
		}
    }

    LOG(SESSION, RUNNING, "session modification finish.\r\n");

    session_table_show(&sess_tbl->session);

    return 0;
}

void session_modify_to_fp(session_content_modify *session_content)
{
    if (unlikely(NULL == session_content)) {
        LOG(SESSION, ERR, "session establish failed, content(%p).", session_content);
        return;
    }

    /*********************** Remove rules ***************************/
    /* Bar remove */
    if (session_content->member_flag.d.remove_bar_present) {
        if (0 > rules_fp_del(&session_content->remove_bar_index, 1, EN_COMM_MSG_UPU_BAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent BAR config to fp failed.");
        }
    }
    /* Far remove */
    if (0 < session_content->remove_far_num) {
    	if (-1 == rules_fp_del(session_content->remove_far_index_arr, session_content->remove_far_num,
            EN_COMM_MSG_UPU_FAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent FAR config to fp failed.");
        }
    }
    /* Qer remove */
    if (0 < session_content->remove_qer_num) {
    	if (-1 == rules_fp_del(session_content->remove_qer_index_arr, session_content->remove_qer_num,
            EN_COMM_MSG_UPU_QER_DEL, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent QER config to fp failed.");
        }
    }
    /* Pdr remove */
    if (0 < session_content->remove_pdr_num) {
    	if (-1 == rules_fp_del(session_content->remove_pdr_index_arr,
            session_content->remove_pdr_index_num, EN_COMM_MSG_UPU_INST_DEL, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent instance config to fp failed.");
        }
    }

    /*********************** Update rules ***************************/
    /* Bar update */
    if (session_content->member_flag.d.update_bar_present) {
        if (0 > bar_fp_add_or_mod(&session_content->update_bar.bar_index, 1, FALSE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent BAR config to fp failed.");
        }
    }
    /* Far update */
    if (0 < session_content->update_far_num) {
        uint32_t index_arr[MAX_FAR_NUM], index_cnt;

        for (index_cnt = 0; index_cnt < session_content->update_far_num; ++index_cnt) {
            index_arr[index_cnt] = session_content->update_far_arr[index_cnt].far_index;
        }

        if (-1 == far_fp_add_or_mod(index_arr, index_cnt, FALSE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent FAR config to fp failed.");
        }
    }
    /* Qer update */
    if (0 < session_content->update_qer_num) {
        uint32_t index_arr[MAX_QER_NUM], index_cnt;

        for (index_cnt = 0; index_cnt < session_content->update_qer_num; ++index_cnt) {
            index_arr[index_cnt] = session_content->update_qer_arr[index_cnt].qer_index;
        }

        if (-1 == qer_fp_add_or_mod(index_arr, index_cnt, FALSE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent QER config to fp failed.");
        }
    }
    /* Pdr update */
    if (0 < session_content->update_pdr_num) {
        uint32_t index_arr[MAX_PDR_NUM], index_cnt, valid_cnt = 0;
        struct session_inst_entry *entry;

        for (index_cnt = 0; index_cnt < session_content->update_pdr_num; ++index_cnt) {
            entry = session_instance_get_entry(session_content->update_pdr_arr[index_cnt].pdr_index);
            if (NULL == entry) {
                continue;
            }

            ros_rwlock_read_lock(&entry->rwlock);// lock
            if (entry->valid) {
                index_arr[valid_cnt++] = entry->index;
            }
            ros_rwlock_read_unlock(&entry->rwlock);// unlock
        }

        if (-1 == session_instance_fp_add_or_mod(index_arr, valid_cnt, FALSE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent Instance config to fp failed.");
        }

        if (-1 == session_orphan_modify(index_arr, valid_cnt)) {
            LOG(SESSION, ERR, "remove fast entry for orphan tree failed.");
        }
    }

    /*********************** Create rules ***************************/
    /* Bar create */
    if (session_content->member_flag.d.create_bar_present) {
        if (0 > bar_fp_add_or_mod(&session_content->create_bar.bar_index, 1, TRUE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent BAR config to fp failed.");
        }
    }
    /* Far create */
    if (0 < session_content->create_far_num) {
    	uint32_t index_arr[MAX_FAR_NUM], index_cnt;

        for (index_cnt = 0; index_cnt < session_content->create_far_num; ++index_cnt) {
            index_arr[index_cnt] = session_content->create_far_arr[index_cnt].far_index;
        }

        if (-1 == far_fp_add_or_mod(index_arr, index_cnt, TRUE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent FAR config to fp failed.");
        }
    }
    /* Qer create */
    if (0 < session_content->create_qer_num) {
    	uint32_t index_arr[MAX_QER_NUM], index_cnt;

        for (index_cnt = 0; index_cnt < session_content->create_qer_num; ++index_cnt) {
            index_arr[index_cnt] = session_content->create_qer_arr[index_cnt].qer_index;
        }

        if (-1 == qer_fp_add_or_mod(index_arr, index_cnt, TRUE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent QER config to fp failed.");
        }
    }
    /* Pdr create */
    if (0 < session_content->create_pdr_num) {
        uint32_t index_arr[MAX_PDR_NUM], index_cnt, valid_cnt = 0;
        struct session_inst_entry *entry;

        for (index_cnt = 0; index_cnt < session_content->create_pdr_num; ++index_cnt) {
            entry = session_instance_get_entry(session_content->create_pdr_arr[index_cnt].pdr_index);
            if (NULL == entry) {
                continue;
            }

            ros_rwlock_read_lock(&entry->rwlock);// lock
            if (entry->valid) {
                index_arr[valid_cnt++] = entry->index;
            }
            ros_rwlock_read_unlock(&entry->rwlock);// unlock
        }

        if (-1 == session_instance_fp_add_or_mod(index_arr, valid_cnt, TRUE, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "Sent Instance config to fp failed.");
        }

        if (-1 == session_orphan_modify(index_arr, valid_cnt)) {
            LOG(SESSION, ERR, "remove fast entry for orphan tree failed.");
        }
    }

    LOG(SESSION, RUNNING, "session modification to fp finish.\r\n");
}


/* session delete process, search table and delete table */
int session_delete(uint64_t local_seid, uint64_t cp_seid,
    session_emd_response *resp, uint8_t fp_sync,
    struct session_rules_index *rules)
{
    struct session_t *sess_tbl = NULL;
    struct session_key key;

    if (NULL == resp || (0 == fp_sync && NULL == rules)) {
        LOG(SESSION, ERR, "clear rules failed, resp(%p), "
			"fp_sync(%d), rules(%p).",
			resp, fp_sync, rules);
        return -1;
    }

    key.local_seid  = local_seid;
    key.cp_seid     = cp_seid;

    resp->local_seid = local_seid;
    resp->cp_seid = cp_seid;
    resp->cause = SESS_REQUEST_ACCEPTED;

    sess_tbl = session_table_remove(&key);
    if (NULL == sess_tbl) {
        LOG(SESSION, ERR, "delete failed, no such session, seid:0x%016lx:0x%016lx.",
            key.local_seid, key.cp_seid);
        resp->cause = SESS_SESSION_CONTEXT_NOT_FOUND;
        return -1;
    }

    /* release rule releation configure */
    if (pdr_clear(sess_tbl, fp_sync, rules) < 0) {
        LOG(SESSION, ERR, "pdr clear failed");
        resp->cause = SESS_SYSTEM_FAILURE;
    }

    if (mar_clear(sess_tbl) < 0) {
        LOG(SESSION, ERR, "mar clear failed");
        resp->cause = SESS_SYSTEM_FAILURE;
    }

    if (far_clear(sess_tbl, fp_sync, rules) < 0) {
        LOG(SESSION, ERR, "far clear failed");
        resp->cause = SESS_SYSTEM_FAILURE;
    }

    if (qer_clear(sess_tbl, fp_sync, rules) < 0) {
        LOG(SESSION, ERR, "qer clear failed");
        resp->cause = SESS_SYSTEM_FAILURE;
    }

    if (urr_clear(sess_tbl, fp_sync, rules, resp) < 0) {
        LOG(SESSION, ERR, "urr clear failed");
        resp->cause = SESS_SYSTEM_FAILURE;
    }

    if (bar_clear(sess_tbl, fp_sync, rules) < 0) {
        LOG(SESSION, ERR, "bar clear failed");
        resp->cause = SESS_SYSTEM_FAILURE;
    }

	if (sess_tbl->inactivity_timer_id) {
		ros_timer_del(sess_tbl->inactivity_timer_id);
		sess_tbl->inactivity_timer_id = NULL;
	}

    if (traffic_endpoint_clear(sess_tbl) < 0) {
        LOG(SESSION, ERR, "traffic endpoint clear failed");
        resp->cause = SESS_SYSTEM_FAILURE;
    }

    if (0 > se_entry_delete(sess_tbl)) {
        LOG(SESSION, ERR, "Session UE MAC clear failed");
    }

    LOG(SESSION, RUNNING,
        "sesssion delete finish, seid:0x%016lx:0x%016lx.\r\n",
        key.local_seid, key.cp_seid);
    return 0;
}

/* Check packet rate status report */
/*
*   return 0(直接删除不需要去fpu查询qer的packet rate status)
*   return >0(需要去fpu查询qer的packet rate status)
*   return -1(异常情况，不应该出现)
*/
int session_check_prsr(uint64_t local_seid, uint64_t cp_seid, uint8_t node_index,
    uint32_t seq_num, uint8_t msg_type, uint32_t *qer_arr)
{
    struct session_t *sess_tbl = NULL;
    struct session_key key = {.local_seid = local_seid, .cp_seid = cp_seid};
    int qer_num;

    if (G_TRUE == upc_node_features_validity_query(UF_CIOT)) {
        sess_tbl = session_table_search(&key);
        if (NULL == sess_tbl) {
            LOG(SESSION, ERR, "search failed, no such session, seid:0x%016lx:0x%016lx.",
                key.local_seid, key.cp_seid);
            return -1;
        }
        sess_tbl->seq_num = seq_num;
        sess_tbl->msg_type = msg_type;

        qer_num = qer_check_rcsr(sess_tbl, qer_arr);
        if (qer_num > 0) {
            memcpy(sess_tbl->qer_index_arr, qer_arr, sizeof(uint32_t) * qer_num);
            sess_tbl->qer_index_nums = qer_num;
        }

        return qer_num;
    }

    return 0;
}

int session_reply_timer_stop(uint64_t local_seid, uint64_t cp_seid)
{
    struct session_t *sess_tbl = NULL;
    struct session_key key = {.local_seid = local_seid, .cp_seid = cp_seid};

    sess_tbl = session_table_search(&key);
    if (NULL == sess_tbl) {
        LOG(SESSION, ERR, "search failed, no such session, seid:0x%016lx:0x%016lx.",
            key.local_seid, key.cp_seid);
        return -1;
    }

    return 0;
}

int session_report_response_proc(session_report_response *report_resp)
{
    struct session_key key = {0,};
    struct session_t *sess_tbl = NULL;

    if (NULL == report_resp) {
        LOG(SESSION, ERR,
            "abnormal parameter, report_resp(%p).", report_resp);
        return -1;
    }

    key.local_seid  = report_resp->local_seid;
    key.cp_seid     = report_resp->cp_seid;

    /* 1. search session table */
    sess_tbl = session_table_search(&key);
    if (NULL == sess_tbl) {
        LOG(SESSION, ERR,
            "session table search failed, seid:0x%016lx:0x%016lx.",
            key.local_seid, key.cp_seid);
        return -1;
    }

    /* 2. update bar */
    if (report_resp->member_flag.d.update_bar_present) {
        if (0 > bar_report_response_modify(sess_tbl,
            &report_resp->update_bar)) {
            LOG(SESSION, ERR, "bar_report_response_modify failed.");

        }
    }

    LOG(SESSION, RUNNING, "session report response process finish.\r\n");

    return 0;
}

int session_show_info(struct cli_def *cli, const uint64_t local_seid, const uint64_t cp_seid)
{
	struct session_key key = {.local_seid = local_seid, .cp_seid = cp_seid};
	struct session_t *sess_tbl = NULL;

	sess_tbl = session_table_search(&key);
	if (sess_tbl == NULL) {
		cli_print(cli,"No such session, up_seid: %lu  cp_seid: %lu",
            key.local_seid, key.cp_seid);
		return -1;
	}
	session_table_show(&sess_tbl->session);

	return 0;
}




int session_show_ueip(struct cli_def *cli, const uint32_t ipv4, const uint8_t ip_type)
{
	struct pdr_table *pdr_table = NULL;
	struct pdr_key rb_key;

	memset(&rb_key,0,sizeof(struct pdr_key));

	rb_key.ip_addr.ipv4 = ntohl(ipv4);
	rb_key.teid = 0;

	pdr_table = pdr_ueip_match(&rb_key, 1);
	if(pdr_table == NULL)
	{
		cli_print(cli,"can't find pdr table");
		return -1;
	}
	cli_print(cli,"most infomation in spu log");
	return 0;
}

int session_show_all_seid(struct cli_def *cli, int argc, char **argv)
{
	int count = 0;
	struct session_t *sess_tbl;
    struct session_mgmt_cb *sess_head = session_mgmt_head();

	cli_print(cli, "NODE_INDEX        UP_SEID                     CP_SEID");

    sess_tbl = (struct session_t *)rbtree_first(&sess_head->session_tree_root);
    while (sess_tbl) {
        cli_print(cli, "%-2u                0x%-16lx              0x%-16lx",
            sess_tbl->session.node_index,
            sess_tbl->session.local_seid,
            sess_tbl->session.cp_seid);
		count++;
        sess_tbl = (struct session_t *)rbtree_next(&sess_tbl->session_node);
    }
	cli_print(cli,"total session:%d",count);
    return 0;
}


