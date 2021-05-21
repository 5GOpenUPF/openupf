/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_MGMT_H
#define __SESSION_MGMT_H


struct pfcp_session {
    uint64_t                    local_seid;
    uint64_t                    cp_seid;
    struct rb_root              pdr_root;               /* for create pdr */
    struct rb_root              far_root;               /* for create far */
    struct rb_root              urr_root;               /* for create urr */
    struct rb_root              qer_root;               /* for create qer */
    struct rb_root              bar_root;               /* for create bar */
    struct rb_root              tc_endpoint_root;       /* for traffic endpoint */
    struct rb_root              sdf_root;               /* for bidirectional SDF filter */
    struct rb_root              eth_root;               /* for bidirectional ETH packet failter */
    uint32_t                    node_index;
    uint32_t                    inactivity_timer;
    session_user_id             user_id;
    session_trace_info          trace_info;
    struct rb_root              mar_root;               /* for create mar */
    session_apn_dnn             apn_dnn;
    PDN_TYPE                    pdn_type;
    uint8_t                     rat_type;
    uint8_t                     trace_info_present;
};

struct session_t {
    struct rb_node                  session_node; /* session pool node */
    struct dl_list                  ue_mac_head; /* UE MAC Linked list head */
    struct dl_list                  eth_dl_head; /* Ethernet PDN type, downlink PDR list */
    uint32_t                        index;
    ros_rwlock_t                    lock;
    struct pfcp_session             session;
    /* Use timeout reply waiting for FPU  */
    uint32_t                        qer_index_arr[MAX_QER_NUM];
    uint32_t                        urr_index_arr[MAX_URR_NUM];
    uint32_t                        seq_num;        /* response sequnce number */
    uint8_t                         msg_type;       /* msg_type */
    uint8_t                         qer_index_nums;
    session_urr_reporting_trigger   trigger;
    struct ros_timer                *timeout_timer; /* FPU reply message timeout timer */
    struct ros_timer                *inactivity_timer_id;

    struct dl_list                  report_req_head;
    struct ros_timer                *report_req_timer;
};

struct session_mgmt_cb {
    struct rb_root      session_tree_root;
    struct session_t    *session_table; /* total session table */
    ros_rwlock_t        lock;
    uint32_t            max_num;
    ros_atomic32_t      use_num;
    uint16_t            pool_id;
};


struct session_mgmt_cb *session_mgmt_head(void);

void session_fill_load_info(session_emd_response *resp);
int64_t session_mgmt_init(uint32_t session_num);
struct session_t *session_table_create(struct session_key *key);
struct session_t *session_table_search(struct session_key *key);
struct session_t *session_table_remove(struct session_key *key);
struct session_t *session_table_replace(struct session_key *src_key, struct session_key *dest_key);
void session_table_show(struct pfcp_session *sess_tbl);
int session_establish(session_content_create *session_content, session_emd_response *resp);
void session_establish_to_fp(session_content_create *session_content);
int session_modify(session_content_modify *session_content, session_emd_response *resp);
void session_modify_to_fp(session_content_modify *session_content);
int session_delete(uint64_t local_seid, uint64_t cp_seid,
    session_emd_response *resp, uint8_t fp_sync,
    struct session_rules_index *rules);
int session_report_response_proc(session_report_response *report_resp);
int session_check_prsr(uint64_t local_seid, uint64_t cp_seid, uint8_t node_index,
    uint32_t seq_num, uint8_t msg_type, uint32_t *qer_arr);
int session_reply_timer_stop(uint64_t local_seid, uint64_t cp_seid);
uint32_t session_send_sigtrace_ueip_to_fp(struct session_t *sess_tbl);

#endif

