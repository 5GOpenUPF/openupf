/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LOCAL_PARSE_H__
#define _LOCAL_PARSE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define SESSION_ASYNC_CALLBACK_MAGIC    (0xFFFFFFFFFFFFFF00)

enum SESSION_ASYNC_CB_CMD {
    SESSION_ASYNC_MODIFY_ROLLBACK       = 1,
    SESSION_ASYNC_REMOVE_ROLLBACK       = 2,
    SESSION_ASYNC_CHECK_SESSION         = 3,
};

struct bar_table *bar_add(struct session_t *sess,
    session_buffer_action_rule *parse_bar);
struct bar_table * bar_update(struct session_t *sess,
    session_buffer_action_rule *parse_bar);

struct far_table *far_add(struct session_t *sess,
    session_far_create *parse_far_arr, uint32_t index, uint32_t *fail_id);
struct far_table *far_update(struct session_t *sess,
    session_far_update *parse_far_arr, uint32_t index, uint32_t *fail_id);

struct qer_table *qer_add(struct session_t *sess,
    session_qos_enforcement_rule *parse_qer_arr,
    uint32_t index, uint32_t *fail_id);
struct qer_table *qer_update(struct session_t *sess,
    session_qos_enforcement_rule *parse_qer_arr,
    uint32_t index, uint32_t *fail_id);

struct urr_table *urr_add(struct session_t *sess,
    session_usage_report_rule *parse_urr_arr,
    uint32_t index, uint32_t *fail_id);
struct urr_table *urr_update(struct session_t *sess,
    session_usage_report_rule *parse_urr_arr,
    uint32_t index, uint32_t *fail_id);

struct pdr_table *pdr_add(struct session_t *sess,
    session_pdr_create *parse_pdr_arr, uint32_t index, uint32_t *fail_id);

struct pdr_table *pdr_update(struct session_t *sess,
    session_pdr_update *parse_pdr_arr, uint32_t index, uint32_t *fail_id);

void pdr_eth_filter_content_copy(struct eth_filter *local_eth,
    session_eth_filter *parse_eth);

struct mar_table *mar_add(struct session_t *sess,
    session_mar_create *parse_mar_arr, uint32_t index, uint32_t *fail_id);
struct mar_table *mar_update(struct session_t *sess,
    session_mar_update *parse_mar_arr, uint32_t index, uint32_t *fail_id);

struct traffic_endpoint_table *traffic_endpoint_add(struct session_t *sess,
    session_tc_endpoint *parse_te_arr, uint8_t te_index);
struct traffic_endpoint_table * traffic_endpoint_update(struct session_t *sess,
    session_tc_endpoint *parse_te_arr, uint8_t te_index);

void session_reply_timeout_timer_cb(void *timer, uint64_t para);
void session_inactivity_timer_cb(void *timer, uint64_t para);

void rules_sum_check(uint32_t ret_fp, struct FSM_t fsm[], uint32_t rule);
void rules_stop_audit(uint32_t rule);
void rules_start_audit(uint32_t rule);

int pdr_predefined_activate(struct session_t *sess, struct pdr_table *common_pdr, char *predef_name);
int pdr_predefined_deactivate(struct session_t *sess, struct pdr_table *root_pdr, char *predef_name);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _LOCAL_PARSE_H__ */