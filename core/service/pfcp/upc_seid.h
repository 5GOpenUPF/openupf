/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _UPC_SEID_H__
#define _UPC_SEID_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tag_user_Signaling_trace_t{
	user_Signaing_trace_flag	type;
	ros_rwlock_t                rwlock;
	uint8_t 					imsi[SESSION_MAX_BCD_BYTES*2];
	uint8_t						msisdn[SESSION_MAX_BCD_BYTES*2];
	uint8_t 					valid;
	uint8_t 					user_id_present;
	uint8_t 					spare[2];
} user_Signaling_trace_t;

typedef struct tag_upc_seid_entry {
    struct rb_node          node;
    struct dl_list          list_node;  /* list node of NODE ID */
    uint32_t                index; /* Also UP SEID */
    ros_rwlock_t            lock;

    uint8_t                 using;   /* Reject other requests if in use */
    uint8_t                 valid;  /* TRUE or FALSE */
    uint8_t                 spare[6];

    session_content_create  session_config;
	user_Signaling_trace_t  sig_trace;	/*sig trace by user id*/
} upc_seid_entry;

typedef struct tag_upc_seid_table_header {
    upc_seid_entry              *entry;
    struct rb_root              seid_root;  /* All valid seid */
    uint32_t                    max_num;
    ros_atomic32_t              use_num;
    ros_rwlock_t                lock;
    uint16_t                    pool_id;
    uint16_t                    spare;
} upc_seid_table_header;

upc_seid_table_header *upc_seid_get_table_head(void);
upc_seid_entry *upc_seid_get_entry(uint32_t index);
uint16_t upc_seid_get_pool_id(void);

int64_t upc_seid_table_init(uint32_t sess_num);
int upc_seid_entry_add_common(upc_seid_entry *seid_entry,
    upc_node_cb *node_cb, session_content_create *sess_content);
upc_seid_entry *upc_seid_entry_add_target(upc_node_cb *node_cb, session_content_create *sess);
upc_seid_entry *upc_seid_entry_alloc(void);
int upc_seid_entry_remove(uint64_t up_seid);
upc_seid_entry *upc_seid_entry_search(uint64_t up_seid);
int upc_seid_release_from_node(upc_node_cb *node_cb);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _UPC_SEID_H__ */

