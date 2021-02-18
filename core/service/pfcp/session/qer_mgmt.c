/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "session_msg.h"
#include "session_audit.h"
#include "qer_mgmt.h"
#include "pdr_mgmt.h"
#include "sp_backend_mgmt.h"

#include "local_parse.h"

struct qer_table_head qer_tbl_head;
struct fsm_audit qer_audit_4am;
struct fsm_audit qer_audit_simple;

void qer_table_show(struct qer_table *qer_tbl)
{
    LOG(SESSION, RUNNING, "--------------qer--------------");
    LOG(SESSION, RUNNING, "index: %u", qer_tbl->index);
    LOG(SESSION, RUNNING, "qer id: %u", qer_tbl->qer_priv.qer_id);
    LOG(SESSION, RUNNING, "corr id: %u", qer_tbl->qer_priv.qer_corr_id);
    LOG(SESSION, RUNNING, "uplink gate status: %d", qer_tbl->qer.ul_gate);
    LOG(SESSION, RUNNING, "downlink gate status: %d", qer_tbl->qer.dl_gate);

    LOG(SESSION, RUNNING, "mbr downlink: %lu",
        qer_tbl->qer_priv.mbr_value.dl_mbr);
    LOG(SESSION, RUNNING, "mbr uplink: %lu",
        qer_tbl->qer_priv.mbr_value.ul_mbr);

    LOG(SESSION, RUNNING, "gbr downlink: %lu",
        qer_tbl->qer_priv.gbr_value.dl_gbr);
    LOG(SESSION, RUNNING, "gbr uplink: %lu",
        qer_tbl->qer_priv.gbr_value.ul_gbr);

    LOG(SESSION, RUNNING, "packet rate status flag: %d",
        qer_tbl->qer_priv.pkt_rate_status.flag.value);
    LOG(SESSION, RUNNING, "packet rate status remain ul: %d",
        qer_tbl->qer_priv.pkt_rate_status.remain_ul_packets);
    LOG(SESSION, RUNNING, "packet rate status remain dl: %d",
        qer_tbl->qer_priv.pkt_rate_status.remain_dl_packets);
    LOG(SESSION, RUNNING, "packet rate status add remain ul: %d",
        qer_tbl->qer_priv.pkt_rate_status.addit_remain_ul_packets);
    LOG(SESSION, RUNNING, "packet rate status add remain dl: %d",
        qer_tbl->qer_priv.pkt_rate_status.addit_remain_dl_packets);
        LOG(SESSION, RUNNING, "packet rate status valid time: %lu",
        qer_tbl->qer_priv.pkt_rate_status.rate_ctrl_status_time);


    LOG(SESSION, RUNNING, "qfi: %d", qer_tbl->qer_priv.qfi);
    LOG(SESSION, RUNNING, "rqi: %d", qer_tbl->qer_priv.ref_qos);
    LOG(SESSION, RUNNING, "ppi: %d",
        qer_tbl->qer_priv.paging_policy_indic);
    LOG(SESSION, RUNNING, "averag_window: %u", qer_tbl->qer_priv.averaging_window);
    LOG(SESSION, RUNNING, "qer_ctrl_indic: %d", qer_tbl->qer_priv.qer_ctrl_indic.value);
}

inline struct qer_table_head *qer_get_head(void)
{
    return &qer_tbl_head;
}

inline struct qer_table *qer_get_table(uint32_t index)
{
    if (index < qer_tbl_head.max_num)
        return &qer_tbl_head.qer_table[index];
    else
        return NULL;
}

inline uint16_t qer_get_pool_id(void)
{
    return qer_tbl_head.pool_id;
}

inline uint32_t qer_get_max(void)
{
    return qer_tbl_head.max_num;
}

inline struct fsm_audit *qer_get_audit_simple(void)
{
    return &qer_audit_simple;
}

inline struct fsm_audit *qer_get_audit_4am(void)
{
    return &qer_audit_4am;
}

static int qer_id_compare(struct rb_node *node, void *key)
{
    struct qer_table *qer_node = (struct qer_table *)node;
    uint32_t id = *(uint32_t *)key;

    if (id < qer_node->qer_priv.qer_id) {
        return -1;
    }
    else if (id > qer_node->qer_priv.qer_id) {
        return 1;
    }

    return 0;
}

int qer_id_compare_externel(struct rb_node *node, void *key)
{
    return qer_id_compare(node,key);
}

struct qer_table *qer_table_search(struct session_t *sess, uint32_t id)
{
    struct qer_table *qer_tbl = NULL;
    uint32_t qer_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    ros_rwlock_read_lock(&sess->lock);// lock
    qer_tbl = (struct qer_table *)rbtree_search(&sess->session.qer_root,
        &qer_id, qer_id_compare);
    ros_rwlock_read_unlock(&sess->lock);// unlock
    if (NULL == qer_tbl) {
        LOG(SESSION, ERR,
            "The entry with id %u does not exist.", qer_id);
        return NULL;
    }

    return qer_tbl;
}

struct qer_table *qer_table_create(struct session_t *sess, uint32_t id)
{
    struct qer_table_head *qer_head = qer_get_head();
    struct qer_table *qer_tbl = NULL;
    uint32_t key = 0, index = 0, qer_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    if (G_FAILURE == Res_Alloc(qer_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            qer_head->pool_id);
        return NULL;
    }

    ros_rwlock_write_lock(&sess->lock);/* lock */
    qer_tbl = qer_get_table(index);
    if (!qer_tbl) {
        ros_rwlock_write_unlock(&sess->lock);/* unlock */
        Res_Free(qer_head->pool_id, key, index);
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return NULL;
    }
    memset(&qer_tbl->qer, 0, sizeof(comm_msg_qer_config));
    memset(&qer_tbl->qer_priv, 0, sizeof(struct qer_private));

    qer_tbl->qer_priv.qer_id = qer_id;

    /* insert node to session tree root*/
    if (rbtree_insert(&sess->session.qer_root, &qer_tbl->qer_node,
        &qer_id, qer_id_compare) < 0) {
        ros_rwlock_write_unlock(&sess->lock);/* unlock */
        Res_Free(qer_head->pool_id, key, index);
        LOG(SESSION, ERR,
            "rb tree insert failed, id: %u.", qer_id);
        return NULL;
    }
    ros_rwlock_write_unlock(&sess->lock);/* unlock */

    ros_atomic32_add(&qer_head->use_num, 1);

    return qer_tbl;
}

struct qer_table *qer_table_create_local(uint32_t id)
{
    struct qer_table_head *qer_head = qer_get_head();
    struct qer_table *qer_tbl = NULL;
    uint32_t key = 0, index = 0, qer_id = id;

    if (G_FAILURE == Res_Alloc(qer_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            qer_head->pool_id);
        return NULL;
    }

    qer_tbl = qer_get_table(index);
    if (!qer_tbl) {
        Res_Free(qer_head->pool_id, key, index);
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return NULL;
    }
    memset(&qer_tbl->qer, 0, sizeof(comm_msg_qer_config));
    memset(&qer_tbl->qer_priv, 0, sizeof(struct qer_private));
    qer_tbl->qer_priv.qer_id = qer_id;

    ros_atomic32_add(&qer_head->use_num, 1);

    return qer_tbl;
}

inline void qer_config_hton(comm_msg_qer_config *qer_cfg)
{
    qer_cfg->ul_mbr = htonll(qer_cfg->ul_mbr);
    qer_cfg->ul_gbr = htonll(qer_cfg->ul_gbr);
    qer_cfg->ul_pkt_max = htonl(qer_cfg->ul_pkt_max);

    qer_cfg->dl_mbr = htonll(qer_cfg->dl_mbr);
    qer_cfg->dl_gbr = htonll(qer_cfg->dl_gbr);
    qer_cfg->dl_pkt_max = htonl(qer_cfg->dl_pkt_max);

    qer_cfg->valid_time = htonl(qer_cfg->valid_time);
}

inline void qer_config_ntoh(comm_msg_qer_config *qer_cfg)
{
    qer_cfg->ul_mbr = ntohl(qer_cfg->ul_mbr);
    qer_cfg->ul_gbr = ntohl(qer_cfg->ul_gbr);
    qer_cfg->ul_pkt_max = ntohl(qer_cfg->ul_pkt_max);

    qer_cfg->dl_mbr = ntohl(qer_cfg->dl_mbr);
    qer_cfg->dl_gbr = ntohl(qer_cfg->dl_gbr);
    qer_cfg->dl_pkt_max = ntohl(qer_cfg->dl_pkt_max);

    qer_cfg->valid_time = ntohl(qer_cfg->valid_time);
}

int qer_fp_add_or_mod(uint32_t *index_arr, uint32_t index_num, uint8_t is_add, int fd)
{
    uint8_t                     buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                    buf_len = 0;
    comm_msg_header_t           *msg;
    comm_msg_rules_ie_t         *ie = NULL;
    struct qer_table            *entry = NULL;
    uint32_t                    cnt = 0, data_cnt = 0;
    comm_msg_qer_ie_data        *ie_data = NULL;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_qer_ie_data);

    if (unlikely(0 == index_num)) {
        LOG(SESSION, ERR, "parameter is invalid, index number: %u.",
            index_num);
        return -1;
    }

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    if (is_add) {
        ie->cmd = htons(EN_COMM_MSG_UPU_QER_ADD);
    } else {
        ie->cmd = htons(EN_COMM_MSG_UPU_QER_MOD);
    }
    ie_data     = (comm_msg_qer_ie_data *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        entry = qer_get_table(index_arr[cnt]);
        if (NULL == entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", index_arr[cnt]);
            continue;
        }

        ie_data[data_cnt].index = htonl(entry->index);
        ros_memcpy(&ie_data[data_cnt].cfg, &entry->qer, sizeof(comm_msg_qer_config));
        qer_config_hton(&ie_data[data_cnt].cfg);
        ++data_cnt;

        if (data_cnt >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_qer_ie_data) * data_cnt;
            ie->rules_num = htonl(data_cnt);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > session_msg_send_to_fp((char *)buf, buf_len, fd)) {
                LOG(UPC, ERR, "Send buffer to backend failed.");
                return -1;
            }
            data_cnt = 0;
        }
    }

    if (data_cnt > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_qer_ie_data) * data_cnt;
        ie->rules_num = htonl(data_cnt);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > session_msg_send_to_fp((char *)buf, buf_len, fd)) {
            LOG(UPC, ERR, "Send buffer to backend failed.");
            return -1;
        }
        data_cnt = 0;
    }

    return 0;
}

int qer_insert(struct session_t *sess, void *parse_qer_arr,
    uint32_t qer_num, uint32_t *fail_id)
{
    struct qer_table *qer_tbl = NULL;
    uint32_t index_cnt = 0;

    if (NULL == sess || (NULL == parse_qer_arr && qer_num)) {
        LOG(SESSION, ERR,
			"insert failed, sess(%p), parse_qer_arr(%p), qer_num: %u.",
			sess, parse_qer_arr, qer_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < qer_num; ++index_cnt) {

        qer_tbl = qer_add(sess, parse_qer_arr, index_cnt, fail_id);
        if (NULL == qer_tbl) {
            LOG(SESSION, ERR, "qer add failed.");
            return -1;
        }
    }

    return 0;
}

int qer_table_delete_local(uint32_t *arr, uint8_t index_num)
{
	struct qer_table *qer_tbl = NULL;
    struct qer_table_head *qer_head = qer_get_head();
	uint32_t index_arr[MAX_QER_NUM], index_cnt = 0;
    uint32_t success_cnt = 0;

	if (NULL == arr) {
        LOG(SESSION, ERR, "qer remove failed, arr(%p)",arr);
        return -1;
    }

    for (index_cnt = 0; index_cnt < index_num; ++index_cnt) {
		qer_tbl = qer_get_table(arr[index_cnt]);

	    Res_Free(qer_head->pool_id, 0, qer_tbl->index);
	    ros_atomic32_sub(&qer_head->use_num, 1);

		index_arr[success_cnt] = qer_tbl->index;
		++success_cnt;
	}

	if (success_cnt) {
	    if (-1 == rules_fp_del(index_arr, success_cnt, EN_COMM_MSG_UPU_QER_DEL, MB_SEND2BE_BROADCAST_FD)) {
	        LOG(SESSION, ERR, "fp del failed.");
	    }
	}

    return 0;
}

int qer_remove(struct session_t *sess, uint32_t *id_arr, uint8_t id_num, uint32_t *ret_index_arr)
{
    struct qer_table *qer_tbl = NULL;
    struct qer_table_head *qer_head = qer_get_head();
	uint32_t index_arr[MAX_URR_NUM], index_cnt = 0;

    if (NULL == sess || (NULL == id_arr && id_num)) {
        LOG(SESSION, ERR, "remove failed, sess(%p), id_arr(%p),"
			" id_num: %d.", sess, id_arr, id_num);
        return -1;
    }

	for (index_cnt = 0; index_cnt < id_num; ++index_cnt) {
	    ros_rwlock_write_lock(&sess->lock);// lock
	    qer_tbl = (struct qer_table *)rbtree_delete(&sess->session.qer_root,
	        &id_arr[index_cnt], qer_id_compare);
	    ros_rwlock_write_unlock(&sess->lock);// unlock
	    if (NULL == qer_tbl) {
	        LOG(SESSION, ERR, "remove failed, not exist, id: %u.",
				id_arr[index_cnt]);
            return -1;
	    }
	    Res_Free(qer_head->pool_id, 0, qer_tbl->index);
	    ros_atomic32_sub(&qer_head->use_num, 1);

		index_arr[index_cnt] = qer_tbl->index;
        if (NULL != ret_index_arr) {
            ret_index_arr[index_cnt] = qer_tbl->index;
        }
	}

	if (index_cnt) {
	    if (-1 == rules_fp_del(index_arr, index_cnt, EN_COMM_MSG_UPU_QER_DEL, MB_SEND2BE_BROADCAST_FD)) {
	        LOG(SESSION, ERR, "fp del failed.");
	    }
	}
    return 0;
}

int qer_modify(struct session_t *sess, void *parse_qer_arr,
    uint32_t qer_num, uint32_t *fail_id)
{
    struct qer_table *qer_tbl = NULL;
    uint32_t index_arr[MAX_QER_NUM], index_cnt = 0;
	uint32_t success_cnt = 0;

    if (NULL == sess || (NULL == parse_qer_arr && qer_num)) {
        LOG(SESSION, ERR,
			"insert failed, sess(%p), parse_qer_arr(%p), qer_num: %u.",
			sess, parse_qer_arr, qer_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < qer_num; ++index_cnt) {

        qer_tbl = qer_update(sess, parse_qer_arr, index_cnt, fail_id);
        if (NULL == qer_tbl) {
            LOG(SESSION, ERR, "qer update failed.");
            return -1;
        }

        index_arr[success_cnt] = qer_tbl->index;
		++success_cnt;
    }

    if (success_cnt) {
        if (-1 == qer_fp_add_or_mod(index_arr, success_cnt, 0, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "fp modify failed.");
        }
    }
    return 0;
}

uint32_t qer_sum(void)
{
    struct qer_table_head *qer_head = qer_get_head();
    uint32_t entry_sum = 0;

    entry_sum = ros_atomic32_read(&qer_head->use_num);

    return entry_sum;
}

/* clear all qer rules releated the current pfcp session */
int qer_clear(struct session_t *sess,
	uint8_t fp_sync, struct session_rules_index * rules)
{
    struct qer_table *qer_tbl = NULL;
    struct qer_table_head *qer_head = qer_get_head();
    uint32_t id = 0;
    uint32_t index_arr[MAX_QER_NUM], index_cnt = 0;

    if (NULL == sess || (0 == fp_sync && NULL == rules)) {
        LOG(SESSION, ERR, "clear failed, sess is null.");
        return -1;
    }

    ros_rwlock_write_lock(&sess->lock);// lock
    qer_tbl = (struct qer_table *)rbtree_first(&sess->session.qer_root);
    while (NULL != qer_tbl) {
        id = qer_tbl->qer_priv.qer_id;
		//取qer_id最高位，如果是1则表示是预定义规则，不需要删除
		if(((id & 0x80000000)>>31))
		{
			qer_tbl = (struct qer_table *)rbtree_next(&qer_tbl->qer_node);
			continue;
		}

        qer_tbl = (struct qer_table *)rbtree_delete(&sess->session.qer_root,
            &id, qer_id_compare);
        if (NULL == qer_tbl) {
            LOG(SESSION, ERR, "clear failed, id: %u.", id);
            qer_tbl = (struct qer_table *)rbtree_next(&qer_tbl->qer_node);
            continue;
        }
        Res_Free(qer_head->pool_id, 0, qer_tbl->index);
        ros_atomic32_sub(&qer_head->use_num, 1);

        if (fp_sync) {
            index_arr[index_cnt] = qer_tbl->index;
            ++index_cnt;
        } else {
            rules->index_arr[EN_RULE_QER][rules->index_num[EN_RULE_QER]] = qer_tbl->index;
            ++rules->index_num[EN_RULE_QER];

            if (rules->index_num[EN_RULE_QER] >= SESSION_RULE_INDEX_LIMIT) {
                rules->overflow.d.rule_qer = 1;
            }
        }

        qer_tbl = (struct qer_table *)rbtree_next(&qer_tbl->qer_node);
    }
    ros_rwlock_write_unlock(&sess->lock);// unlock

    if (0 < index_cnt) {
		if (fp_sync) {
	        if (-1 == rules_fp_del(index_arr, index_cnt, EN_COMM_MSG_UPU_QER_DEL, MB_SEND2BE_BROADCAST_FD)) {
	            LOG(SESSION, ERR, "fp del failed.");
	            return -1;
	        }
		}
    }
    return 0;
}

/* 检查session上的qer是否存在设置了QER Control Indications IE中的RCSR
*
*  返回值为0表示没有QER设置了RCSR
*  返回值大于0表示设置了RCSR的QER的数量
*  返回值为-1表示异常情况
*/
int qer_check_rcsr(struct session_t *sess, uint32_t *qer_arr)
{
    struct qer_table *qer_tbl = NULL;
    uint8_t qer_cnt = 0;

    if (NULL == sess || NULL == qer_arr) {
        LOG(SESSION, ERR, "Abnormal parameters, sess(%p), qer_arr(%p).",
            sess, qer_arr);
        return -1;
    }

    ros_rwlock_read_lock(&sess->lock);// lock
    qer_tbl = (struct qer_table *)rbtree_first(&sess->session.qer_root);
    while (NULL != qer_tbl) {
        if (qer_tbl->qer_priv.qer_ctrl_indic.d.RCSR) {
            qer_arr[qer_cnt] = qer_tbl->index;
            ++qer_cnt;
        }

        qer_tbl = (struct qer_table *)rbtree_next(&qer_tbl->qer_node);
    }
    ros_rwlock_read_unlock(&sess->lock);// unlock

    return qer_cnt;
}

uint32_t qer_check_all(comm_msg_ie_t *ie, int fd)
{
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    struct qer_table *entry = NULL;
    comm_msg_qer_ie_data *ie_data = NULL;
    uint32_t cnt = 0;
    uint32_t mod_arr[ONCE_CHANGE_NUMBER_MAX], mod_num = 0;

    if (NULL == ie) {
        LOG(SESSION, ERR, "parameter is invalid, ie(%p).",
            ie);
        return -1;
    }

    ie_data = (comm_msg_qer_ie_data *)rule_ie->data;
    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t index = ntohl(ie_data[cnt].index);

        if (G_FALSE == Res_IsAlloced(qer_get_pool_id(), 0, index)) {
            LOG(SESSION, ERR, "entry is invalid, index: %u.",
                index);
            continue;
        }

        qer_config_ntoh(&ie_data[cnt].cfg);
        entry = qer_get_table(index);
        if (!entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", index);
            continue;
        }
        ros_rwlock_read_lock(&entry->lock);// lock
        if (ros_memcmp(&ie_data[cnt].cfg, &entry->qer, sizeof(comm_msg_qer_config))) {
            ros_rwlock_read_unlock(&entry->lock);// unlock
            if (mod_num == ONCE_CHANGE_NUMBER_MAX) {
                if (0 > qer_fp_add_or_mod(mod_arr, mod_num, 0, fd)) {
                    LOG(SESSION, ERR, "Modify fpu entry failed.");
                    return -1;
                }
                mod_num = 0;
            }
            mod_arr[mod_num] = index;
            ++mod_num;
        } else {
            ros_rwlock_read_unlock(&entry->lock);// unlock
        }
    }

    if (mod_num > 0) {
        if (0 > qer_fp_add_or_mod(mod_arr, mod_num, 0, fd)) {
            LOG(SESSION, ERR, "Modify fpu entry failed.");
            return -1;
        }
    }

    return 0;
}

int qer_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd)
{
    uint32_t field_num = 0, cnt = 0, fp_del = 0, fp_add = 0, diff = 0;
    uint32_t remainder = 0;
    uint32_t del_arr[ONCE_CHANGE_NUMBER_MAX], del_num = 0;
    uint32_t add_arr[ONCE_CHANGE_NUMBER_MAX], add_num = 0;
    uint8_t val_data[SERVICE_BUF_TOTAL_LEN];
    comm_msg_entry_val_config_t *sp_val_cfg = (comm_msg_entry_val_config_t *)val_data;

    LOG(SESSION, RUNNING, "validity action start.");

    if (NULL == fp_val_cfg) {
        LOG(SESSION, ERR, "Abnormal parameter, fp_val_cfg(%p).", fp_val_cfg);
        return -1;
    }

    if (0 > session_val_ntoh(fp_val_cfg)) {
        LOG(SESSION, ERR, "Abnormal parameters, invalid 'val config'.");
        return -1;
    }

    if (G_SUCCESS != Res_GetRangeField(qer_get_pool_id(), 0,
        fp_val_cfg->start, fp_val_cfg->entry_num, sp_val_cfg->data)) {
        LOG(SESSION, ERR, "Get range field failed, start: %u, entry_num: %u.",
            fp_val_cfg->start, fp_val_cfg->entry_num);
        return -1;
    }

    LOG(SESSION, RUNNING, "Entry number: %u, entry start: %u.",
        fp_val_cfg->entry_num, fp_val_cfg->start);
    field_num = fp_val_cfg->entry_num >> RES_PART_LEN_BIT;
    for (cnt = 0; cnt < field_num; ++cnt) {
        diff = sp_val_cfg->data[cnt] ^ fp_val_cfg->data[cnt];
        if (diff) {
            uint32_t start_bit = fp_val_cfg->start + (cnt << RES_PART_LEN_BIT);

            fp_add = (sp_val_cfg->data[cnt] & diff) ^ diff;
            fp_del = (fp_val_cfg->data[cnt] & diff) ^ diff;

            if (fp_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_QER_DEL, fd);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_del,
                    del_arr, &del_num);
            }
            if (fp_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    qer_fp_add_or_mod(add_arr, add_num, 1, fd);
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_add,
                    add_arr, &add_num);
            }
        }
    }

    remainder = fp_val_cfg->entry_num & RES_PART_LEN_MASK;
    if (remainder) {
        diff = sp_val_cfg->data[cnt] ^ fp_val_cfg->data[cnt];
        diff &= ~((1 << (RES_PART_LEN - remainder)) - 1);
        if (diff) {
            uint32_t start_bit = fp_val_cfg->start + (cnt << RES_PART_LEN_BIT);

            fp_add = (sp_val_cfg->data[cnt] & diff) ^ diff;
            fp_del = (fp_val_cfg->data[cnt] & diff) ^ diff;

            if (fp_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_QER_DEL, fd);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_del,
                    del_arr, &del_num);
            }
            if (fp_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    qer_fp_add_or_mod(add_arr, add_num, 1, fd);
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_add,
                    add_arr, &add_num);
            }
        }
    }

    if (del_num > 0) {
        rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_QER_DEL, fd);
    }
    if (add_num > 0) {
        qer_fp_add_or_mod(add_arr, add_num, 1, fd);
    }

    return 0;
}

int64_t qer_table_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct qer_table *qer_tbl = NULL;
    uint32_t max_num = 0;
    int64_t size = 0;

    if (0 == session_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, session_num: %u.", session_num);
        return -1;
    }

    max_num = session_num * MAX_QER_NUM;
    size = sizeof(struct qer_table) * max_num;
    qer_tbl = ros_malloc(size);
    if (NULL == qer_tbl) {
        LOG(SESSION, ERR,
            "init pdr failed, no enough memory, max number: %u ="
            " session_num: %u * %d.", max_num,
            session_num, MAX_QER_NUM);
        return -1;
    }
    ros_memset(qer_tbl, 0, sizeof(struct qer_table) * max_num);

    for (index = 0; index < max_num; ++index) {
        qer_tbl[index].index = index;
        ros_rwlock_init(&qer_tbl[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        return -1;
    }

    qer_tbl_head.pool_id = pool_id;
    qer_tbl_head.qer_table = qer_tbl;
    qer_tbl_head.max_num = max_num;
	ros_rwlock_init(&qer_tbl_head.lock);
    ros_atomic32_set(&qer_tbl_head.use_num, 0);

    /* init 4am audit */
    if (0 > audit_4am_init(&qer_audit_4am, EN_QER_AUDIT)) {
        LOG(SESSION, ERR, "audit_4am_init failed.");
        return -1;
    }

    /* init sample audit */
    if (0 > audit_simple_init(&qer_audit_simple, EN_QER_AUDIT)) {
        LOG(SESSION, ERR, "Simple audit init failed.");
        return -1;
    }

    LOG(SESSION, MUST, "qer init success.");
    return size;
}

