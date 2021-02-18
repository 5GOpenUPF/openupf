/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __MAR_MGMT_H_
#define __MAR_MGMT_H_

#ifdef __cplusplus
extern "C" {
#endif


struct mar_private {
    uint16_t                            mar_id;
    uint8_t                             steer_func; /* 0:ATSSS-LL 1:MPTCP */
    uint8_t                             steer_mod;  /* 0:Active-Standby
                                                     * 1:Smallest Delay
                                                     * 2:Load Balancing
                                                     * 3:Priority-based
                                                     */
    uint8_t                             afai_1_validity;
    session_access_forwarding_action    afai_1;
    uint8_t                             afai_2_validity;
    session_access_forwarding_action    afai_2;
    int                                 cur_weight[2];  /* index 0: afai 1 */
};

struct mar_table {
    struct rb_node          mar_node;
    struct mar_private      mar;
    ros_rwlock_t            lock;
    uint32_t                index;
    uint8_t                 valid;
};

struct mar_table_head {
    struct mar_table        *mar_table;
    uint32_t                max_num;
    ros_atomic32_t          use_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
};

struct mar_table_head *mar_get_head(void);

void mar_table_show(struct mar_table *mar_tbl);
int mar_insert(struct session_t *sess, void *parse_mar_arr,
    uint32_t mar_num, uint32_t *fail_id);
int mar_remove(struct session_t *sess, uint16_t *id_arr, uint8_t id_num);
int mar_modify(struct session_t *sess, void *parse_mar_arr,
    uint32_t mar_num, uint32_t *fail_id);
int mar_get(uint32_t index, session_mar_create *mar);
uint32_t mar_sum(void);
int mar_clear(struct session_t *sess);
int64_t mar_table_init(uint32_t session_num);
struct mar_table *mar_table_search(struct session_t *sess, uint16_t id);
struct mar_table *mar_table_create(struct session_t *sess, uint16_t id);
uint32_t mar_get_far_index(struct session_t *sess, uint32_t index);
int mar_fill_far_index(struct session_t *sess, uint32_t index,
    comm_msg_inst_config *inst_cfg);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  __MAR_MGMT_H_ */

