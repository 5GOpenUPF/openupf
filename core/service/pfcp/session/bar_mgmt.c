/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "session_msg.h"
#include "session_audit.h"
#include "bar_mgmt.h"
#include "pdr_mgmt.h"
#include "upc_node.h"
#include "sp_backend_mgmt.h"

#include "local_parse.h"


struct bar_table_head bar_tbl_head;
struct fsm_audit bar_audit_4am;
struct fsm_audit bar_audit_simple;

void bar_table_show(struct bar_table *bar_tbl)
{
    LOG(SESSION, RUNNING, "--------------bar--------------");
    LOG(SESSION, RUNNING, "index: %u", bar_tbl->index);
    LOG(SESSION, RUNNING, "bar id: %d", bar_tbl->bar.bar_id);
    LOG(SESSION, RUNNING, "notify delay: %d", bar_tbl->bar.notify_delay);
    LOG(SESSION, RUNNING, "packet max: %d", bar_tbl->bar.pkts_max);
    LOG(SESSION, RUNNING, "time max: %d", bar_tbl->bar.time_max);
    LOG(SESSION, RUNNING, "buff packets time: %d",
        bar_tbl->bar_priv.buff_pkts_time);
}

inline struct bar_table_head *bar_get_head(void)
{
    return &bar_tbl_head;
}

inline struct bar_table *bar_get_table(uint32_t index)
{
    if (index < bar_tbl_head.max_num)
        return &bar_tbl_head.bar_table[index];
    else
        return NULL;
}

inline uint16_t bar_get_pool_id(void)
{
    return bar_tbl_head.pool_id;
}

inline uint32_t bar_get_max(void)
{
    return bar_tbl_head.max_num;
}

inline struct fsm_audit *bar_get_audit_simple(void)
{
    return &bar_audit_simple;
}

inline struct fsm_audit *bar_get_audit_4am(void)
{
    return &bar_audit_4am;
}

static int bar_id_compare(struct rb_node *node, void *key)
{
    struct bar_table *bar_node = (struct bar_table *)node;
    uint8_t id = *(uint8_t *)key;

    if (id < bar_node->bar.bar_id) {
        return -1;
    }
    else if (id > bar_node->bar.bar_id) {
        return 1;
    }

    return 0;
}

struct bar_table *bar_table_search(struct session_t *sess, uint8_t id)
{
    struct bar_table *bar_tbl = NULL;
    uint8_t bar_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    ros_rwlock_read_lock(&sess->lock);// lock
    bar_tbl = (struct bar_table *)rbtree_search(&sess->session.bar_root,
        &bar_id, bar_id_compare);
    ros_rwlock_read_unlock(&sess->lock);// unlock
    if (NULL == bar_tbl) {
        LOG(SESSION, ERR,
            "The entry with id %u does not exist.", bar_id);
        return NULL;
    }

    return bar_tbl;
}

struct bar_table *bar_table_create(struct session_t *sess, uint8_t id)
{
    struct bar_table_head *bar_head = bar_get_head();
    struct bar_table *bar_tbl = NULL;
    uint32_t key = 0, index = 0;
    uint8_t bar_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    if (G_FAILURE == Res_Alloc(bar_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            bar_head->pool_id);
        return NULL;
    }

    bar_tbl = bar_get_table(index);
    if (!bar_tbl) {
        Res_Free(bar_head->pool_id, key, index);
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return NULL;
    }
    memset(&bar_tbl->bar, 0, sizeof(comm_msg_bar_config));
    bar_tbl->bar.bar_id = bar_id;

    ros_rwlock_write_lock(&sess->lock);// lock
    /* insert node to session tree root*/
    if (rbtree_insert(&sess->session.bar_root, &bar_tbl->bar_node,
        &bar_id, bar_id_compare) < 0) {
        ros_rwlock_write_unlock(&sess->lock);// unlock
        Res_Free(bar_head->pool_id, key, index);
        LOG(SESSION, ERR,
            "rb tree insert failed, id: %u.", bar_id);
        return NULL;
    }
    ros_rwlock_write_unlock(&sess->lock);// unlock

    ros_atomic32_add(&bar_head->use_num, 1);

    return bar_tbl;
}

struct bar_table *bar_table_create_local(uint8_t id)
{
    struct bar_table_head *bar_head = bar_get_head();
    struct bar_table *bar_tbl = NULL;
    uint32_t key = 0, index = 0;
    uint8_t bar_id = id;

    if (G_FAILURE == Res_Alloc(bar_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            bar_head->pool_id);
        return NULL;
    }

    bar_tbl = bar_get_table(index);
    if (!bar_tbl) {
        Res_Free(bar_head->pool_id, key, index);
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return NULL;
    }
    memset(&bar_tbl->bar, 0, sizeof(comm_msg_bar_config));
    bar_tbl->bar.bar_id = bar_id;

    ros_atomic32_add(&bar_head->use_num, 1);

    return bar_tbl;
}

inline void bar_config_hton(comm_msg_bar_config *bar_cfg)
{
    bar_cfg->pkts_max = htons(bar_cfg->pkts_max);
    bar_cfg->time_max = htonl(bar_cfg->time_max);
}

inline void bar_config_ntoh(comm_msg_bar_config *bar_cfg)
{
    bar_cfg->pkts_max = ntohs(bar_cfg->pkts_max);
    bar_cfg->time_max = ntohl(bar_cfg->time_max);
}

int bar_fp_add_or_mod(uint32_t *index_arr, uint32_t index_num, uint8_t is_add, int fd)
{
    uint8_t                     buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                    buf_len = 0;
    comm_msg_header_t           *msg;
    comm_msg_rules_ie_t         *ie = NULL;
    struct bar_table            *entry = NULL;
    uint32_t                    cnt = 0, data_cnt = 0;
    comm_msg_bar_ie_data        *ie_data = NULL;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_bar_ie_data);

    if (unlikely(0 == index_num)) {
        LOG(SESSION, ERR, "parameter is invalid, index number: %u.",
            index_num);
        return -1;
    }

    msg = upc_fill_msg_header(buf);

    ie = COMM_MSG_GET_RULES_IE(msg);
    if (is_add) {
        ie->cmd = htons(EN_COMM_MSG_UPU_BAR_ADD);
    } else {
        ie->cmd = htons(EN_COMM_MSG_UPU_BAR_MOD);
    }
    ie_data     = (comm_msg_bar_ie_data *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        entry = bar_get_table(index_arr[cnt]);
        if (NULL == entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", index_arr[cnt]);
            continue;
        }

        ie_data[data_cnt].index = htonl(entry->index);
        ros_memcpy(&ie_data[data_cnt].cfg, &entry->bar, sizeof(comm_msg_bar_config));
        bar_config_hton(&ie_data[data_cnt].cfg);
        ++data_cnt;


        if (data_cnt >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_bar_ie_data) * data_cnt;
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
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_bar_ie_data) * data_cnt;
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

int bar_insert(struct session_t *sess, session_buffer_action_rule *parse_bar)
{
    struct bar_table *bar_tbl = NULL;

    if (NULL == sess || NULL == parse_bar) {
        LOG(SESSION, ERR, "bar insert failed, sess(%p), parse_bar(%p).",
            sess, parse_bar);
        return -1;
    }

    if (parse_bar->member_flag.d.notify_delay_present) {
        if (G_FALSE == upc_node_features_validity_query(UF_DDND)) {
            LOG(SESSION, ERR, "DDND feature not support, Downlink Data Notification Delay invalid.");
            return -1;
        }
    }
    if (parse_bar->member_flag.d.buffer_pkts_cnt_present) {
        if (G_FALSE == upc_node_features_validity_query(UF_UDBC)) {
            LOG(SESSION, ERR, "UDBC feature not support,"
                " Suggested Buffering Packets Count invalid.");
            return -1;
        }
    }

    bar_tbl = bar_table_create(sess, parse_bar->bar_id);
    if (NULL == bar_tbl) {
        LOG(SESSION, ERR, "bar table create failed, bar_id %u.", parse_bar->bar_id);
        return -1;
    }

    ros_rwlock_write_lock(&bar_tbl->lock);// lock
    bar_tbl->bar.notify_delay = parse_bar->notify_delay;
    bar_tbl->bar.pkts_max = parse_bar->buffer_pkts_cnt;
    bar_tbl->bar.time_max = 0;
    ros_rwlock_write_unlock(&bar_tbl->lock);// unlock

    parse_bar->bar_index = bar_tbl->index;

    return 0;
}

int bar_table_delete_local(uint32_t index)
{
	struct bar_table_head *bar_head = bar_get_head();

	Res_Free(bar_head->pool_id, 0, index);
	ros_atomic32_sub(&bar_head->use_num, 1);

	if (-1 == rules_fp_del(&index, 1, EN_COMM_MSG_UPU_BAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
		LOG(SESSION, ERR, "Tell FPU delete BAR failed.");
		return -1;
	}
	return 0;
}

int bar_remove(struct session_t *sess, uint8_t bar_id, uint32_t *bar_index)
{
    struct bar_table *bar_tbl = NULL;
    struct bar_table_head *bar_head = bar_get_head();
    uint8_t id = bar_id;
    uint32_t index = 0;

    if (NULL == sess) {
        LOG(SESSION, ERR, "bar remove failed, sess(%p).", sess);
        return -1;
    }

    ros_rwlock_write_lock(&sess->lock);// lock
    bar_tbl = (struct bar_table *)rbtree_delete(&sess->session.bar_root, &id,
        bar_id_compare);
    ros_rwlock_write_unlock(&sess->lock);// unlock
    if (NULL == bar_tbl) {
        LOG(SESSION, ERR, "remove failed, not exist, id: %u.", id);
        return -1;
    }
    Res_Free(bar_head->pool_id, 0, bar_tbl->index);
    ros_atomic32_sub(&bar_head->use_num, 1);

    *bar_index = bar_tbl->index;

    index = bar_tbl->index;
    if (-1 == rules_fp_del(&index, 1, EN_COMM_MSG_UPU_BAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
        LOG(SESSION, ERR, "Tell FPU delete BAR failed.");
    }
    return 0;
}

int bar_modify(struct session_t *sess, session_buffer_action_rule *parse_bar)
{
    struct bar_table *bar_tbl = NULL;
    uint32_t bar_index = 0;

    if (NULL == sess || NULL == parse_bar) {
        LOG(SESSION, ERR, "bar modify failed, sess(%p), parse_bar(%p).",
            sess, parse_bar);
        return -1;
    }

    if (parse_bar->member_flag.d.notify_delay_present) {
        if (G_FALSE == upc_node_features_validity_query(UF_DDND)) {
            LOG(SESSION, ERR, "DDND feature not support,"
                " Downlink Data Notification Delay invalid.");
            return -1;
        }
    }
    if (parse_bar->member_flag.d.buffer_pkts_cnt_present) {
        if (G_FALSE == upc_node_features_validity_query(UF_UDBC)) {
            LOG(SESSION, ERR, "UDBC feature not support,"
                " Suggested Buffering Packets Count invalid.");
            return -1;
        }
    }

    bar_tbl = bar_table_search(sess, parse_bar->bar_id);
    if (NULL == bar_tbl) {
        LOG(SESSION, ERR, "bar table search failed, bar_id %u.",
			parse_bar->bar_id);
        return -1;
    }

    ros_rwlock_write_lock(&bar_tbl->lock);// lock
    bar_tbl->bar.notify_delay = parse_bar->notify_delay;
    bar_tbl->bar.pkts_max = parse_bar->buffer_pkts_cnt;
    ros_rwlock_write_unlock(&bar_tbl->lock);// unlock

    bar_index = bar_tbl->index;
    parse_bar->bar_index = bar_tbl->index;

    if (-1 == bar_fp_add_or_mod(&bar_index, 1, 0, MB_SEND2BE_BROADCAST_FD)) {
        LOG(SESSION, ERR, "fp modify failed.");
    }
    return 0;
}

int bar_report_response_modify(struct session_t *sess,
    session_bar_response_update *parse_bar)
{
    struct bar_table *bar_tbl = NULL;
    uint32_t bar_index = 0;

    if (NULL == sess || NULL == parse_bar) {
        LOG(SESSION, ERR, "bar modify failed, sess(%p), parse_bar(%p).",
            sess, parse_bar);
        return -1;
    }


    bar_tbl = bar_table_search(sess, parse_bar->bar_id);
    if (NULL == bar_tbl) {
        LOG(SESSION, ERR, "bar table search failed, bar_id %u.",
			parse_bar->bar_id);
        return -1;
    }

    ros_rwlock_write_lock(&bar_tbl->lock);// lock
    if (parse_bar->member_flag.d.notify_delay_present) {
        if (G_TRUE ==
            upc_node_features_validity_query(UF_DDND)) {
            bar_tbl->bar.notify_delay = parse_bar->notify_delay;
        } else {
            LOG(SESSION, ERR, "DDND feature not support,"
                " Downlink Data Notification Delay invalid.");
        }
    }
    if (parse_bar->member_flag.d.buffer_pkts_cnt_present) {
        if (G_TRUE ==
            upc_node_features_validity_query(UF_UDBC)) {
            bar_tbl->bar.pkts_max = parse_bar->buffer_pkts_cnt;
        } else {
            LOG(SESSION, ERR, "UDBC feature not support,"
                " Suggested Buffering Packets Count invalid.");
        }
    }

    if (parse_bar->member_flag.d.dl_buff_pkts_cnt_present) {
        if (G_TRUE ==
            upc_node_features_validity_query(UF_UDBC)) {
            //bar_tbl->bar.pkts_max = parse_bar->buffer_pkts_cnt;
        } else {
            LOG(SESSION, ERR, "UDBC feature not support,"
                " Suggested Buffering Packets Count invalid.");
        }
    }

    if (parse_bar->member_flag.d.dl_buff_duration_present) {
        if (G_TRUE ==
            upc_node_features_validity_query(UF_DLBD)) {
            bar_tbl->bar_priv.buff_pkts_time =
                parse_bar->dl_buff_duration.value;
            /*
            计时器值
            位5到1表示二进制编码的计时器值。
            定时器单元
            位6到8定义定时器的定时器值单位如下：
            位
            8 7 6个
            0 0 0值以2秒的倍数递增
            0 0 1值以1分钟的倍数递增
            0 1 0值以10分钟的倍数递增
            0 1 1值以1小时的倍数递增
            10 0值以10小时的倍数递增
            11 1值表示计时器是无限的
            在本协议版本中，其他值应解释为1分钟的倍数。
            定时器单位和定时器值均设置为所有“零”，应解释为定时器停止的指示。
            */
            switch(parse_bar->dl_buff_duration.d.unit) {
                case 0:
                    bar_tbl->bar.time_max =
                        parse_bar->dl_buff_duration.d.value * 2;
                    break;
                case 2:
                    bar_tbl->bar.time_max =
                        parse_bar->dl_buff_duration.d.value * 600;
                    break;
                case 3:
                    bar_tbl->bar.time_max =
                        parse_bar->dl_buff_duration.d.value * 3600;
                    break;
                case 4:
                    bar_tbl->bar.time_max =
                        parse_bar->dl_buff_duration.d.value * 36000;
                    break;
                case 7:
                    bar_tbl->bar.time_max = 0xFFFFFFFF;/*3268 year*/
                    break;
                case 5:
                case 6:
                case 1:
                    bar_tbl->bar.time_max =
                        parse_bar->dl_buff_duration.d.value * 60;
                    break;
                default:
                    bar_tbl->bar.time_max = 0xFFFFFFFF;
                    break;
            }
        } else {
            LOG(SESSION, ERR, "DLBD feature not support,"
                " DL Buffering Duration invalid.");
        }
    }
    ros_rwlock_write_unlock(&bar_tbl->lock);// unlock

    bar_index = bar_tbl->index;

    if (-1 == bar_fp_add_or_mod(&bar_index, 1, 0, MB_SEND2BE_BROADCAST_FD)) {
        LOG(SESSION, ERR, "fp modify failed.");
        return -1;
    }
    return 0;
}

uint32_t bar_sum(void)
{
    struct bar_table_head *bar_head = bar_get_head();
    uint32_t entry_sum = 0;

    entry_sum = ros_atomic32_read(&bar_head->use_num);

    return entry_sum;
}

/* clear all bar rules releated the current pfcp session */
int bar_clear(struct session_t *sess,
	uint8_t fp_sync, struct session_rules_index *rules)
{
    struct bar_table *bar_tbl = NULL;
    struct bar_table_head *bar_head = bar_get_head();
    uint8_t id = 0;
    uint32_t index_arr[MAX_BAR_NUM], index_cnt = 0;

    if (NULL == sess || (0 == fp_sync && NULL == rules)) {
        LOG(SESSION, ERR, "clear failed, sess is null.");
        return -1;
    }

    ros_rwlock_write_lock(&sess->lock);// lock
    bar_tbl = (struct bar_table *)rbtree_first(&sess->session.bar_root);
    while (NULL != bar_tbl) {
        id = bar_tbl->bar.bar_id;
        bar_tbl = (struct bar_table *)rbtree_delete(&sess->session.bar_root,
            &id, bar_id_compare);
        if (NULL == bar_tbl) {
            LOG(SESSION, ERR, "clear failed, id: %u.", id);
            bar_tbl = (struct bar_table *)rbtree_next(&bar_tbl->bar_node);
            continue;
        }
        Res_Free(bar_head->pool_id, 0, bar_tbl->index);
        ros_atomic32_sub(&bar_head->use_num, 1);

        if (fp_sync) {
            index_arr[index_cnt] = bar_tbl->index;
            ++index_cnt;
        } else {
            rules->index_arr[EN_RULE_BAR][rules->index_num[EN_RULE_BAR]] =
                bar_tbl->index;
            ++rules->index_num[EN_RULE_BAR];

			if (rules->index_num[EN_RULE_BAR] >=
                SESSION_RULE_INDEX_LIMIT) {
				rules->overflow.d.rule_bar = 1;
			}
        }

        bar_tbl = (struct bar_table *)rbtree_next(&bar_tbl->bar_node);
    }
    ros_rwlock_write_unlock(&sess->lock);// unlock

    if (0 < index_cnt) {
		if (fp_sync) {
	        if (-1 == rules_fp_del(index_arr, index_cnt, EN_COMM_MSG_UPU_BAR_DEL, MB_SEND2BE_BROADCAST_FD)) {
	            LOG(SESSION, ERR, "fp del failed.");
	            return -1;
	        }
		}
    }
    return 0;
}

int bar_check_all(comm_msg_ie_t *ie, int fd)
{
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    struct bar_table *entry = NULL;
    comm_msg_bar_ie_data *ie_data = NULL;
    uint32_t cnt = 0;
    uint32_t mod_arr[ONCE_CHANGE_NUMBER_MAX], mod_num = 0;

    if (NULL == ie) {
        LOG(SESSION, ERR, "parameter is invalid, ie(%p).",
            ie);
        return -1;
    }

    ie_data = (comm_msg_bar_ie_data *)rule_ie->data;
    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t index = ntohl(ie_data[cnt].index);

        if (G_FALSE == Res_IsAlloced(bar_get_pool_id(), 0, index)) {
            LOG(SESSION, ERR, "entry is invalid, index: %u.",
                index);
            continue;
        }

        bar_config_ntoh(&ie_data[cnt].cfg);
        entry = bar_get_table(index);
        if (!entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", index);
            continue;
        }

        ros_rwlock_read_lock(&entry->lock);// lock
        if (ros_memcmp(&ie_data[cnt].cfg, &entry->bar, sizeof(comm_msg_bar_config))) {
            ros_rwlock_read_unlock(&entry->lock);// unlock
            if (mod_num == ONCE_CHANGE_NUMBER_MAX) {
                if (0 > bar_fp_add_or_mod(mod_arr, mod_num, 0, fd)) {
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
        if (0 > bar_fp_add_or_mod(mod_arr, mod_num, 0, fd)) {
            LOG(SESSION, ERR, "Modify fpu entry failed.");
            return -1;
        }
    }

    return 0;
}

int bar_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd)
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

    if (G_SUCCESS != Res_GetRangeField(bar_get_pool_id(), 0,
        fp_val_cfg->start, fp_val_cfg->entry_num, sp_val_cfg->data)) {
        LOG(SESSION, ERR, "Get range field failed, start: %u, entry_num: %u.",
            fp_val_cfg->start, fp_val_cfg->entry_num);
        return -1;
    }

    field_num = fp_val_cfg->entry_num >> RES_PART_LEN_BIT;
    for (cnt = 0; cnt < field_num; ++cnt) {
        diff = sp_val_cfg->data[cnt] ^ fp_val_cfg->data[cnt];
        if (diff) {
            uint32_t start_bit = fp_val_cfg->start + (cnt << RES_PART_LEN_BIT);

            fp_add = (sp_val_cfg->data[cnt] & diff) ^ diff;
            fp_del = (fp_val_cfg->data[cnt] & diff) ^ diff;

            if (fp_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_BAR_DEL, fd);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_del,
                    del_arr, &del_num);
            }
            if (fp_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    bar_fp_add_or_mod(add_arr, add_num, 1, fd);
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
                    rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_BAR_DEL, fd);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_del,
                    del_arr, &del_num);
            }
            if (fp_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    bar_fp_add_or_mod(add_arr, add_num, 1, fd);
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_add,
                    add_arr, &add_num);
            }
        }
    }

    if (del_num > 0) {
        rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_BAR_DEL, fd);
    }
    if (add_num > 0) {
        bar_fp_add_or_mod(add_arr, add_num, 1, fd);
    }

    return 0;
}

int64_t bar_table_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct bar_table *bar_tbl = NULL;
    uint32_t max_num = 0;
    int64_t size = 0;

    if (0 == session_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, session_num: %u.", session_num);
        return -1;
    }

    max_num = session_num * MAX_BAR_NUM;
    size = sizeof(struct bar_table) * max_num;
    bar_tbl = ros_malloc(size);
    if (NULL == bar_tbl) {
        LOG(SESSION, ERR,
            "init pdr failed, no enough memory, max number: %u ="
            " session_num: %u * %d.", max_num,
            session_num, MAX_BAR_NUM);
        return -1;
    }
    ros_memset(bar_tbl, 0, size);

    for (index = 0; index < max_num; ++index) {
        bar_tbl[index].index = index;
        ros_rwlock_init(&bar_tbl[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        return -1;
    }

    bar_tbl_head.pool_id = pool_id;
    bar_tbl_head.bar_table = bar_tbl;
    bar_tbl_head.max_num = max_num;
	ros_rwlock_init(&bar_tbl_head.lock);
    ros_atomic32_set(&bar_tbl_head.use_num, 0);

    /* init 4am audit */
    if (0 > audit_4am_init(&bar_audit_4am, EN_BAR_AUDIT)) {
        LOG(SESSION, ERR, "audit_4am_init failed.");
        return -1;
    }

    /* init sample audit */
    if (0 > audit_simple_init(&bar_audit_simple, EN_BAR_AUDIT)) {
        LOG(SESSION, ERR, "Simple audit init failed.");
        return -1;
    }

    LOG(SESSION, MUST, "bar init success.");
    return size;
}

