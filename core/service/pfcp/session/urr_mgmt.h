/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __URR_MGMT_H
#define __URR_MGMT_H


typedef struct  tag_urr_mac_bucket
{
    struct rb_root          tree;           /* AVL tree node */
    comm_msg_urr_mac_t      *new_mac;       /* new mac address list */
    comm_msg_urr_mac_t      *obs_mac;       /* obsolescent mac address list */
    ros_rwlock_t            rwlock;         /* rw lock */
    ros_atomic32_t          entry_cnt;      /* how many node in table */
}urr_mac_bucket;


typedef struct  tag_urr_container
{
    uint8_t                 vol_dl_status;
    uint8_t                 vol_ul_status;
    uint8_t                 vol_tot_status;
    uint8_t                 tim_status;
    uint8_t                 eve_status;
    comm_msg_urr_vol_flag_t flag;       /* volume flag */
    uint8_t                 spare[2];
    ros_atomic64_t          vol_total;      /* total volume number */
    ros_atomic64_t          vol_dlink;      /* downlink volume number */
    ros_atomic64_t          vol_ulink;      /* uplink volume number */
    ros_atomic64_t          vol_all_total;      /* all total volume number */
    ros_atomic64_t          vol_all_dlink;      /* all downlink volume number */
    ros_atomic64_t          vol_all_ulink;      /* all uplink volume number */
    ros_atomic32_t          time;           /* remainder time in second */
    ros_atomic32_t          event;          /* remainder event number */
    ros_atomic32_t          droppkts;       /* remainder dropped packets number */
    ros_atomic32_t          dropbyte;       /* remainder dropped bytes number */
    ros_atomic32_t          first_pkt;      /* first packet reach time */
    ros_atomic32_t          last_pkt;       /* last packet reach time */
    ros_atomic32_t          start_hold;     /* quota holding timer start time */
    ros_atomic32_t          start_time;     /* monitoring start time */
    struct ros_timer        *idt_timer;     /* inactivity detection timer */
    struct ros_timer        *mon_timer;     /* monitoring timer */
    struct ros_timer        *qht_timer;     /* quota holding timer */
    struct ros_timer        *per_timer;     /* quota holding timer */
    struct ros_timer        *stp_timer;     /* traffic stop detection timer */
    struct ros_timer        *eit_timer;     /* ethernet inactivity timer */
    comm_msg_urr_mon_time_t mon_cfg;    /* current effective configuration */
}urr_container;


struct urr_table {
    struct rb_node          urr_node;
    comm_msg_urr_config     urr;
    urr_mac_bucket          mac_bucket;     /* if trace mac, for save mac info */
    urr_container           container;      /* resource container */
    ros_rwlock_t            lock;
    uint32_t                index;
    struct session_t        *sess;  /* Associated session */
};

struct urr_table_head {
    struct urr_table        *urr_table;
    uint32_t                max_num;
    ros_atomic32_t          use_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
};

struct urr_table_head *urr_get_head(void);

void urr_table_show(struct urr_table *urr_tbl);
struct urr_table *urr_get_table(uint32_t index);
struct urr_table *urr_table_search(struct session_t *sess, uint32_t id);
struct urr_table *urr_table_create(struct session_t *sess, uint32_t id);
int urr_id_compare(struct rb_node *node, void *key);
int urr_insert(struct session_t *sess, void *parse_urr_arr,
    uint32_t urr_num, uint32_t *fail_id);
int urr_remove(struct session_t *sess, uint32_t *id_arr, uint8_t id_num, uint32_t *ret_index_arr, uint32_t *fail_id);
int urr_modify(struct session_t *sess, void *parse_urr_arr,
    uint32_t urr_num, uint32_t *fail_id);
int urr_clear(struct session_t *sess,
	uint8_t fp_sync, struct session_rules_index * rules, session_emd_response *resp);
int64_t urr_table_init(uint32_t session_num);
uint32_t urr_sum(void);

#endif
