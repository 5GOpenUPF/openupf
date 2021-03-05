/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "pfcp_def.h"
#include "upc_node.h"
#include "upc_session.h"
#include "upc_seid.h"
#include "upc_teid.h"
#include "session_mgmt.h"

upc_seid_table_header upc_seid_mng;


upc_seid_table_header *upc_seid_get_table_head(void)
{
    return &upc_seid_mng;
}

upc_seid_entry *upc_seid_get_entry(uint32_t index)
{
    /* 这里因为index从1开始的所以用大于判断 */
    if (index > upc_seid_mng.max_num) {
        return NULL;
    }
    return &upc_seid_mng.entry[index];
}

upc_seid_entry *upc_seid_get_predefined_entry(void)
{
    return &upc_seid_mng.entry[0];
}

uint16_t upc_seid_get_pool_id(void)
{
    return upc_seid_mng.pool_id;
}

int64_t upc_seid_table_init(uint32_t sess_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    upc_seid_entry *entry = NULL;
    int64_t size = 0, total_memory = 0;

    if (0 == sess_num) {
        LOG(UPC, ERR,
            "Abnormal parameter, session_num: %u.", sess_num);
        return -1;
    }

    size = sizeof(upc_seid_entry) * (sess_num + 1); /* start with 1 */
    entry = ros_malloc(size);
    if (NULL == entry) {
        LOG(UPC, ERR, "init seid table failed, no enough memory, entry number: %u.",
            sess_num);
        return -1;
    }
    memset(entry, 0, size);

    for (index = 0; index <= sess_num; ++index) {
        entry[index].index = index;
        ros_rwlock_init(&entry[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 1, sess_num)) {
        return -1;
    }

    upc_seid_mng.pool_id       = pool_id;
    upc_seid_mng.entry         = entry;
    upc_seid_mng.max_num       = sess_num;
    ros_rwlock_init(&upc_seid_mng.lock);
    ros_atomic32_set(&upc_seid_mng.use_num, 0);
    total_memory += size;

    LOG(UPC, RUNNING, "upc seid table init success.");

    return total_memory;
}

int upc_seid_entry_add_common(upc_seid_entry *seid_entry,
    upc_node_cb *node_cb, session_content_create *sess_content)
{
    upc_seid_table_header *seid_head = upc_seid_get_table_head();

    if (NULL == seid_entry || NULL == node_cb || NULL == sess_content) {
        LOG(UPC, ERR, "Parameters error, seid_entry(%p), node_cb(%p), sess_content(%p).",
            seid_entry, node_cb, sess_content);
        return -1;
    }

    sess_content->node_index = node_cb->index;
    sess_content->local_seid = seid_entry->index;

    ros_rwlock_write_lock(&seid_head->lock); /* lock */
	memset(&seid_entry->sig_trace, 0, sizeof(user_Signaling_trace_t));
    memcpy(&seid_entry->session_config, sess_content, sizeof(session_content_create));
    seid_entry->using = FALSE;
    seid_entry->valid = TRUE;

    /* add node id list */
    dl_list_add_tail(&node_cb->seid_list, &seid_entry->list_node);

    ros_atomic32_add(&seid_head->use_num, 1);
    ros_rwlock_write_unlock(&seid_head->lock); /* unlock */

    ros_atomic32_inc(&node_cb->session_num);

    return 0;
}

upc_seid_entry *upc_seid_entry_add_target(upc_node_cb *node_cb, session_content_create *sess)
{
    upc_seid_entry *seid_entry = NULL;
    upc_seid_table_header *seid_head = upc_seid_get_table_head();

    if (NULL == node_cb || NULL == sess) {
        LOG(UPC, ERR, "Abnormal parameter, node_cb(%p), sess(%p).", node_cb, sess);
        return NULL;
    }

    if (G_FAILURE == Res_AllocTarget(seid_head->pool_id, 0, (uint32_t)sess->local_seid)) {
        LOG(UPC, ERR, "Add seid entry failed, pool id: %d.", seid_head->pool_id);
        return NULL;
    }

    seid_entry = upc_seid_get_entry(sess->local_seid);
    if (0 > upc_seid_entry_add_common(seid_entry, node_cb, sess)) {
        LOG(UPC, ERR, "Add seid entry common failed.");
        Res_Free(seid_head->pool_id, 0, (uint32_t)sess->local_seid);
        return NULL;
    }

    return seid_entry;
}

upc_seid_entry *upc_seid_entry_alloc(void)
{
    uint32_t index = 0, res_key = 0;

    if (G_FAILURE == Res_Alloc(upc_seid_get_pool_id(), &res_key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(UPC, ERR, "Allocate seid entry failed, Resource exhaustion, pool id: %d.",
            upc_seid_get_pool_id());
        return NULL;
    }
    upc_teid_choose_mgmt_init(index);

    return upc_seid_get_entry(index);
}

int upc_seid_entry_remove(uint64_t up_seid)
{
    upc_seid_entry *seid_entry = NULL;
    upc_seid_table_header *seid_head = upc_seid_get_table_head();


    seid_entry = upc_seid_get_entry((uint32_t)up_seid);
    if (NULL == seid_entry) {
        LOG(UPC, ERR, "seid entry remove failed, no such up seid: 0x%lx.", up_seid);
        return -1;
    }

    ros_rwlock_write_lock(&seid_entry->lock); /* lock */
    if (TRUE == seid_entry->valid) {
        seid_entry->valid = FALSE;
    } else {
        LOG(UPC, ERR, "Seid entry is invalid.");
        ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */

        return -1;
    }
    ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */

    ros_rwlock_write_lock(&seid_head->lock); /* lock */
    dl_list_del(&seid_entry->list_node);
    ros_rwlock_write_unlock(&seid_head->lock); /* unlock */

    Res_Free(seid_head->pool_id, 0, seid_entry->index);
    ros_atomic32_dec(&seid_head->use_num);

    return 0;
}

upc_seid_entry *upc_seid_entry_search(uint64_t up_seid)
{
    upc_seid_entry *seid_entry = NULL;

    seid_entry = upc_seid_get_entry((uint32_t)up_seid);
    if (NULL == seid_entry) {
        LOG(UPC, ERR, "seid entry modify failed, no such up seid: 0x%lx.", up_seid);
        return NULL;
    }

    ros_rwlock_write_lock(&seid_entry->lock); /* lock */
    if (FALSE == seid_entry->valid) {
        LOG(UPC, ERR, "Seid entry is invalid.");
        ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */

        return NULL;
    }
    ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */

    return seid_entry;
}

int upc_seid_release_from_node(upc_node_cb *node_cb)
{
    struct dl_list *pos = NULL, *next = NULL;
    upc_seid_entry *seid_entry = NULL;
    upc_seid_table_header *seid_head = upc_seid_get_table_head();
    session_emd_response resp;
	struct session_rules_index rules_creator = {{.value = 0},};

    if (NULL == node_cb) {
        LOG(UPC, ERR, "Abnormal parameter, node_cb(%p).", node_cb);
        return -1;
    }

    ros_rwlock_write_lock(&seid_head->lock); /* lock */
    dl_list_for_each_safe(pos, next, &node_cb->seid_list) {
        seid_entry = (upc_seid_entry *)container_of(pos,
            upc_seid_entry, list_node);

        ros_rwlock_write_unlock(&seid_head->lock); /* unlock */

		if (0 > session_delete(seid_entry->index, seid_entry->session_config.cp_f_seid.seid,
			&resp, 0, &rules_creator)) {
			LOG(SESSION, ERR, "delete session failed.");
		}

		if (rules_creator.overflow.value) {
			/* remove instance table */
			if (rules_creator.overflow.d.rule_inst) {
				if (0 > rules_fp_del(rules_creator.index_arr[EN_RULE_INST],
					rules_creator.index_num[EN_RULE_INST], EN_COMM_MSG_UPU_INST_DEL, MB_SEND2BE_BROADCAST_FD)) {
					LOG(SESSION, ERR, "delete instance rule failed.");
				}
				rules_creator.overflow.d.rule_inst 		= 0;
				rules_creator.index_num[EN_RULE_INST] 	= 0;
			}
			/* remove far table */
			if (rules_creator.overflow.d.rule_far) {
				if (0 > rules_fp_del(rules_creator.index_arr[EN_RULE_FAR],
					rules_creator.index_num[EN_RULE_FAR], EN_COMM_MSG_UPU_FAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
					LOG(SESSION, ERR, "delete far rule failed.");
				}
				rules_creator.overflow.d.rule_far 		= 0;
				rules_creator.index_num[EN_RULE_FAR] 	= 0;
			}
			/* remove qer table */
			if (rules_creator.overflow.d.rule_qer) {
				if (0 > rules_fp_del(rules_creator.index_arr[EN_RULE_QER],
					rules_creator.index_num[EN_RULE_QER], EN_COMM_MSG_UPU_QER_DEL, MB_SEND2BE_BROADCAST_FD)) {
					LOG(SESSION, ERR, "delete qer rule failed.");
				}
				rules_creator.overflow.d.rule_qer 		= 0;
				rules_creator.index_num[EN_RULE_QER] 	= 0;
			}
			/* remove bar table */
			if (rules_creator.overflow.d.rule_bar) {
				if (0 > rules_fp_del(rules_creator.index_arr[EN_RULE_BAR],
					rules_creator.index_num[EN_RULE_BAR], EN_COMM_MSG_UPU_BAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
					LOG(SESSION, ERR, "delete bar rule failed.");
				}
				rules_creator.overflow.d.rule_bar 		= 0;
				rules_creator.index_num[EN_RULE_BAR] 	= 0;
			}
		}

        if (0 > upc_free_resources_from_deletion(&seid_entry->session_config)) {
            LOG(UPC, ERR, "Free resources failed.");
        }

        if (0 > upc_seid_entry_remove(seid_entry->index)) {
            LOG(UPC, ERR, "remove seid entry failed.");
        }

        ros_rwlock_write_lock(&seid_head->lock); /* lock */
    }

    /* send residual entry index */
	/* remove instance table */
	if (rules_creator.index_num[EN_RULE_INST]) {
		if (0 > rules_fp_del(rules_creator.index_arr[EN_RULE_INST],
			rules_creator.index_num[EN_RULE_INST], EN_COMM_MSG_UPU_INST_DEL, MB_SEND2BE_BROADCAST_FD)) {
			LOG(SESSION, ERR, "delete instance rule failed.");
		}
		rules_creator.overflow.d.rule_inst 		= 0;
		rules_creator.index_num[EN_RULE_INST] 	= 0;
	}
	/* remove far table */
	if (rules_creator.index_num[EN_RULE_FAR]) {
		if (0 > rules_fp_del(rules_creator.index_arr[EN_RULE_FAR],
			rules_creator.index_num[EN_RULE_FAR], EN_COMM_MSG_UPU_FAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
			LOG(SESSION, ERR, "delete far rule failed.");
		}
		rules_creator.overflow.d.rule_far 		= 0;
		rules_creator.index_num[EN_RULE_FAR] 	= 0;
	}
	/* remove qer table */
	if (rules_creator.index_num[EN_RULE_QER]) {
		if (0 > rules_fp_del(rules_creator.index_arr[EN_RULE_QER],
			rules_creator.index_num[EN_RULE_QER], EN_COMM_MSG_UPU_QER_DEL, MB_SEND2BE_BROADCAST_FD)) {
			LOG(SESSION, ERR, "delete qer rule failed.");
		}
		rules_creator.overflow.d.rule_qer 		= 0;
		rules_creator.index_num[EN_RULE_QER] 	= 0;
	}
	/* remove bar table */
	if (rules_creator.index_num[EN_RULE_BAR]) {
		if (0 > rules_fp_del(rules_creator.index_arr[EN_RULE_BAR],
			rules_creator.index_num[EN_RULE_BAR], EN_COMM_MSG_UPU_BAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
			LOG(SESSION, ERR, "delete bar rule failed.");
		}
		rules_creator.overflow.d.rule_bar 		= 0;
		rules_creator.index_num[EN_RULE_BAR] 	= 0;
	}

    ros_rwlock_write_unlock(&seid_head->lock); /* unlock */

    return 0;
}

