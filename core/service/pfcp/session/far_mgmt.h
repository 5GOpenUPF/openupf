/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __FAR_MGMT_H
#define __FAR_MGMT_H


struct far_sp_private {
    /* forward params */
    char                        network_instance[NETWORK_INSTANCE_LEN];
    char                        forwarding_policy[FORWARDING_POLICY_LEN];
    uint8_t                     traffic_endpoint_id_present;
    uint8_t                     traffic_endpoint_id;
    session_proxying            proxying;
    uint8_t                     bar_id_present;
    uint8_t                     bar_id;
    session_3gpp_interface_type dest_if_type;
};

struct far_table {
    struct rb_node          far_node;
    comm_msg_far_config     far_cfg;
    struct far_sp_private   far_priv;
    ros_rwlock_t            lock;
    uint32_t                index;
};

struct far_table_head {
    struct far_table        *far_table;
    uint32_t                max_num;
    ros_atomic32_t          use_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
};


struct far_table_head *far_get_head(void);
struct far_table *far_get_table(uint32_t index);
struct far_table *far_public_get_table(uint32_t index);
struct fsm_audit *far_get_audit_simple(void);
struct fsm_audit *far_get_audit_4am(void);

void far_table_show(struct far_table *far_tbl);
int far_fp_add_or_mod(uint32_t *index_arr, uint32_t index_num, uint8_t is_add, int fd);
int far_insert(struct session_t *sess, session_far_create *parse_far_arr,
    uint32_t far_num, uint32_t *fail_id);
struct far_table *far_table_create(struct session_t *sess, uint32_t id);
int far_remove(struct session_t *sess, uint32_t *id_arr, uint8_t id_num, uint32_t *ret_index_arr, uint32_t *fail_id);
int far_clear(struct session_t *sess,
	uint8_t fp_sync, struct session_rules_index * rules);
struct far_table *far_table_search(struct session_t *sess, uint32_t id);
uint32_t far_check_all(comm_msg_ie_t *ie, int fd);
int far_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd);
int64_t far_table_init(uint32_t session_num);
int far_modify(struct session_t *sess, session_far_update *parse_far_arr,
    uint32_t far_num, uint32_t *fail_id);
uint32_t far_sum(void);
int far_gtpu_tunnel_add(struct pfcp_session *sess_cfg, struct far_table *far_tbl);
int far_gtpu_em_and_del(uint32_t node_index, comm_msg_outh_cr_t *ohc,
    uint8_t SNDEM);

#endif

