/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __QER_MGMT_H
#define __QER_MGMT_H

struct qer_private {
    uint32_t                        qer_id;
    uint32_t            			qer_corr_id;
    session_mbr          			mbr_value;
    session_gbr          			gbr_value;
    session_packet_rate_status      pkt_rate_status;
    //session_qer_gate_status   		gate_status;
    session_qer_control_indications qer_ctrl_indic;
    uint8_t             			qfi;
    uint8_t             			ref_qos;/* Reflective QoS */
    uint8_t             			paging_policy_indic;
    uint32_t            			averaging_window;
};

struct qer_table {
    struct rb_node          qer_node;
    comm_msg_qer_config     qer;
	struct qer_private		qer_priv;
    ros_rwlock_t            lock;
    uint32_t                index;
};

struct qer_table_head {
    struct qer_table        *qer_table;
    uint32_t                max_num;
    ros_atomic32_t          use_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
};

struct qer_table_head *qer_get_head(void);
struct qer_table *qer_get_table(uint32_t index);
void qer_table_show(struct qer_table *qer_tbl);
struct fsm_audit *qer_get_audit_simple(void);
struct fsm_audit *qer_get_audit_4am(void);

struct qer_table *qer_table_create(struct session_t *sess, uint32_t id);
struct qer_table *qer_table_create_local(uint32_t id);
int qer_table_delete_local(uint32_t *index_arr, uint8_t index_num);
struct qer_table *qer_table_search(struct session_t *sess, uint32_t id);
int qer_id_compare_externel(struct rb_node *node, void *key);
int qer_fp_add_or_mod(uint32_t *index_arr, uint32_t index_num, uint8_t is_add, int fd);
int qer_insert(struct session_t *sess, void *parse_qer_arr,
    uint32_t qer_num, uint32_t *fail_id);
int qer_remove(struct session_t *sess, uint32_t *id_arr, uint8_t id_num, uint32_t *ret_index_arr);
int qer_modify(struct session_t *sess, void *parse_qer_arr,
    uint32_t qer_num, uint32_t *fail_id);
int qer_clear(struct session_t *sess,
	uint8_t fp_sync, struct session_rules_index * rules);
int qer_check_rcsr(struct session_t *sess, uint32_t *qer_arr);
uint32_t qer_check_all(comm_msg_ie_t *ie, int fd);
int qer_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd);
int64_t qer_table_init(uint32_t session_num);
uint32_t qer_sum(void);

#endif
