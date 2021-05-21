/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __PREDEFINED_RULE_MGMT_H
#define __PREDEFINED_RULE_MGMT_H

#define MAX_PREDEFINED_RULES_NUM            100

typedef struct tag_predefined_pdr_entry {
    struct rb_node                  node;
    session_pdr_create              pdr_cfg;
    ros_rwlock_t                    lock;
    uint32_t                        index;
} predefined_pdr_entry;

typedef struct tag_predefined_far_entry {
    struct rb_node                  node;
    session_far_create              far_cfg;
    ros_rwlock_t                    lock;
    uint32_t                        index;
} predefined_far_entry;

typedef struct tag_predefined_urr_entry {
    struct rb_node                  node;
    session_usage_report_rule       urr_cfg;
    ros_rwlock_t                    lock;
    uint32_t                        index;
} predefined_urr_entry;

typedef struct tag_predefined_qer_entry {
    struct rb_node                  node;
    session_qos_enforcement_rule    qer_cfg;
    ros_rwlock_t                    lock;
    uint32_t                        index;
} predefined_qer_entry;


typedef struct tag_predefined_rules_table {
    uint32_t                        max_pdr_num;
    uint32_t                        max_far_num;
    uint32_t                        max_urr_num;
    uint32_t                        max_qer_num;

    predefined_pdr_entry            *pdr_arr;
    predefined_far_entry            *far_arr;
    predefined_urr_entry            *urr_arr;
    predefined_qer_entry            *qer_arr;

    struct rb_root                  pdr_root; /* for create pdr */
    struct rb_root                  far_root; /* for create far */
    struct rb_root                  urr_root; /* for create urr */
    struct rb_root                  qer_root; /* for create qer */

    ros_rwlock_t                    pdr_lock;
    ros_rwlock_t                    far_lock;
    ros_rwlock_t                    urr_lock;
    ros_rwlock_t                    qer_lock;
    uint16_t                        pdr_pool_id;
    uint16_t                        far_pool_id;
    uint16_t                        urr_pool_id;
    uint16_t                        qer_pool_id;
} predefined_rules_table;

predefined_rules_table *predef_get_table_public(void);

predefined_pdr_entry *predef_rules_search(char *predef_name);
int predef_rules_generate(struct session_t *sess, char *predef_name);
int predef_rules_erase(struct session_t *sess, char *predef_name);

int predef_rules_add(session_content_create *sess);
int predef_rules_del(session_content_create *sess);

int64_t predef_rules_table_init(uint32_t rules_num);

#endif
