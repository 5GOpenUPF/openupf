/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_INSTANCE_H
#define __SESSION_INSTANCE_H

#include "pdr_mgmt.h"


enum {
    INSTANCE_EXCEPTION_ADD,
    INSTANCE_EXCEPTION_DEL,
    INSTANCE_EXCEPTION_MOD,
    INSTANCE_EXCEPTION_GET,
    INSTANCE_EXCEPTION_SUM,
    INSTANCE_EXCEPTION_CLR,
};

struct session_inst_control {
    uint8_t             light;          /* 0: green; 1: yellow; 2: red */
    uint8_t             urr_bnum;       /* urr_bqos number */
    uint8_t             urr_anum;       /* urr_aqos number */
    uint8_t             urr_dnum;       /* urr_dqos number */
    uint32_t            urr_bqos[MAX_URR_NUM];  /* urr list before qos */
    uint32_t            urr_aqos[MAX_URR_NUM];  /* urr list after qos */
    uint32_t            urr_drop[MAX_URR_NUM];  /* urr list of drop pkt */
};

struct session_inst_cb {
    struct session_inst_entry   *inst_entry;
    uint32_t                    max_inst_num;
    ros_atomic32_t              use_entry_num;
    ros_rwlock_t                rwlock;
};

struct session_inst_entry {
    comm_msg_inst_config        inst_config;
    comm_msg_urr_stat_t         stat;           /* stat of this instance */
    struct session_inst_control control;        /* local control block */
    ros_rwlock_t                rwlock;
    uint32_t                    index;
    uint8_t                     valid;
};

struct session_instance_local_info {
    uint32_t    ip_addr;
    uint8_t     mac_addr[6];
};

struct session_inst_entry *session_instance_get_entry(uint32_t entry_num);
void session_instance_config_show(comm_msg_inst_config *inst_config);
struct fsm_audit *session_instance_audit_simple(void);
struct fsm_audit *session_instance_audit_4am(void);
struct session_inst_entry *session_instance_get_orphan(void);
int64_t session_instance_init(uint32_t sess_num);
int session_instance_fill_far(struct session_t *sess,
    struct pdr_table *pdr_tbl, comm_msg_inst_config *inst_config);
int session_instance_fill_urr(struct session_t *sess, uint8_t urr_number,
    uint32_t *urr_array, comm_msg_inst_config *inst_config, struct session_inst_control *inst_ctrl);
int session_instance_fill_qer(struct session_t *sess, uint8_t qer_number,
    uint32_t *qer_array, comm_msg_inst_config *inst_config);
int session_instance_fill_user_info(struct session_t *sess, struct pdr_table *pdr_tbl,
	comm_msg_inst_config *inst_config);
int session_instance_fp_add_or_mod(uint32_t *index_arr, uint32_t index_num, uint8_t is_add, int fd);
int session_instance_add(uint32_t index, comm_msg_inst_config *entry_cfg,
    uint8_t fp_sync, struct session_inst_control *inst_ctrl);
int session_instance_del(uint32_t index, uint8_t fp_sync);
int session_instance_modify(uint32_t index, comm_msg_inst_config *inst_config,
    uint8_t fp_sync, struct session_inst_control *inst_ctrl);
int session_instance_modify_far(uint32_t index, uint32_t far_index, uint8_t fp_sync);
uint32_t session_instance_check_all(comm_msg_ie_t *ie, int fd);
int session_instance_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd);
uint32_t session_instance_sum(void);
int session_instance_get(uint32_t index, comm_msg_inst_config *inst_config);

#endif
