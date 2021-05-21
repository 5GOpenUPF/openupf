/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __BAR_MGMT_H
#define __BAR_MGMT_H


struct bar_priv {
    uint8_t            buff_pkts_time;
};

struct bar_table {
    struct rb_node          bar_node;
    comm_msg_bar_config     bar;
    struct bar_priv         bar_priv;
    uint32_t                index;
    ros_rwlock_t            lock;
};

struct bar_table_head {
    struct bar_table        *bar_table;
    uint32_t                max_num;
    ros_atomic32_t          use_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
};

struct bar_table_head *bar_get_head(void);
struct fsm_audit *bar_get_audit_simple(void);
struct fsm_audit *bar_get_audit_4am(void);

void bar_table_show(struct bar_table *bar_tbl);
struct bar_table *bar_table_create(struct session_t *sess, uint8_t id);
struct bar_table *bar_table_search(struct session_t *sess, uint8_t id);
int bar_fp_add_or_mod(uint32_t *index_arr, uint32_t index_num, uint8_t is_add, int fd);
int bar_insert(struct session_t *sess, session_buffer_action_rule *parse_bar);
int bar_remove(struct session_t *sess, uint8_t bar_id, uint32_t *bar_index);
int bar_modify(struct session_t *sess, session_buffer_action_rule *parse_bar);
int bar_report_response_modify(struct session_t *sess,
    session_bar_response_update *parse_bar);
int bar_clear(struct session_t *sess,
	uint8_t fp_sync, struct session_rules_index * rules);
int bar_check_all(comm_msg_ie_t *ie, int fd);
int bar_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd);
int64_t bar_table_init(uint32_t session_num);
uint32_t bar_sum(void);

#endif

