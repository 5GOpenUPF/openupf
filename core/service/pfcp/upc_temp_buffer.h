/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _UPC_TEMP_BUFFER_H__
#define _UPC_TEMP_BUFFER_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TEMP_EST = 0,
    TEMP_MOD,
    TEMP_PFD,
} TEMP_DATA_TYPE;


typedef union tag_upc_temp_comp_key {
    struct {
        uint64_t    type    :8;
        uint64_t    value   :56;
    } d;
    uint64_t        comp_value;
} upc_temp_comp_key;

/* Session data temp buffer */
typedef struct tag_upc_session_temp_entry {
    struct rb_node      data_node;
    union {
        session_content_create est;
        session_content_modify mod;
        session_pfd_mgmt_request pfd;
    } data;
    uint8_t             data_type; /* TEMP_DATA_TYPE*/
    uint8_t             resv;
    uint16_t            index;
    upc_temp_comp_key   comp_key;
} upc_session_temp_entry;

typedef struct tag_upc_session_temp_mgmt {
    upc_session_temp_entry      *entry;
    struct rb_root              entry_root;
    ros_rwlock_t                lock;
    uint32_t                    max_num;
    uint16_t                    pool_id;
} upc_session_temp_mgmt;


upc_session_temp_mgmt *upc_get_session_temp_mgmt_public(void);
int64_t upc_session_temp_init(uint32_t num);
int upc_session_temp_add(void *sess, uint8_t temp_type);
upc_session_temp_entry *upc_session_temp_get(uint8_t temp_type, uint32_t value);
int upc_session_temp_del(uint8_t temp_type, uint32_t value);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _UPC_TEMP_BUFFER_H__ */

