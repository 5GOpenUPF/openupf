/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _SP_BACKEND_MGMT_H__
#define _SP_BACKEND_MGMT_H__

#ifdef __cplusplus
extern "C" {
#endif


#define SP_BACKEND_HEARTBEAT_INTERVAL   (2)

#define UPC_BACKEND_TIMEOUT_MAX         (3)


#define UPC_MB_HEARTBEAT_INTERVAL       3

#define UPC_MB_TIMEOUT_MAX              (2)

enum EN_UPC2LB_CHANNEL_STATE{
    EN_UPC_STATE_DISCONNECTED   = 0,
    EN_UPC_STATE_CONNECTED      = 1,
};

enum EN_BACKEND_WORK_STATE {
    EN_BACKEND_INIT         = 0,
    EN_BACKEND_SYNC,
    EN_BACKEND_RUN,
};

/* Backend audit entry */
enum AUDIT_RULES {
    EN_AUDIT_HEAD   = 0,
    EN_FAR_AUDIT    = EN_AUDIT_HEAD,
    EN_BAR_AUDIT,
    EN_QER_AUDIT,
    EN_INST_AUDIT,
    EN_DNS_AUDIT,
    EN_AUDIT_BUTT,
};

typedef struct tag_mb_management_end_config {
    pthread_t                       hb_timer_pth;   /* Heartbeat timer */
    comm_msg_channel_client         chnl_client; /* Connect to Load-balancer */
    comm_msg_channel_server         be_mgmt_server; /* Listening FPU connect */
    ros_atomic32_t                  work_state; /* Current work state */
    ros_atomic32_t                  hb_cnt;
    uint8_t                         lb_mac[EN_PORT_BUTT][ETH_ALEN]; /* Load-balancer MAC address */
    uint64_t                        local_key; /* Local flag key */
    uint64_t                        peer_key; /* Load-balancer flag key */
} upc_management_end_config;

typedef struct tag_upc_backend_config {
    struct rb_node      be_node;
    uint64_t            be_key;
    ros_rwlock_t        lock;
    uint32_t            index;
    int                 fd;     /* Currently valid connections */
    ros_atomic16_t      be_timeout_times;
    ros_atomic16_t      valid;
    ros_atomic32_t      be_state;
    struct FSM_t        fsm[EN_AUDIT_BUTT];
    uint8_t             be_mac[EN_PORT_BUTT][ETH_ALEN];
}upc_backend_config;

typedef struct tag_upc_sync_backend_config {
    uint8_t             be_mac[EN_PORT_BUTT][ETH_ALEN];
    uint64_t            be_key;
    uint8_t             action; /* EN_UPC_HA_ACTION */
} upc_sync_backend_config;

typedef struct tag_upc_backend_mgmt {
    struct rb_root          be_root;
    upc_backend_config      backend_table[COMM_MSG_BACKEND_NUMBER];
    ros_rwlock_t            lock;
    int                     pool_id;
    uint32_t                last_num; /* Last valid number of back-ends */
    uint32_t                spare;
}upc_backend_mgmt;


upc_backend_config *upc_get_backend_config_public(uint8_t be_index);
upc_backend_mgmt *upc_get_backend_mgmt_public(void);
upc_management_end_config *upc_mb_config_get_public(void);

void upc_mb_set_work_status(int16_t status);
upc_backend_config *upc_backend_register(uint8_t *mac, uint64_t fp_key, int fd);
upc_backend_config *upc_backend_search(uint64_t be_key);
void upc_backend_heartbeat_reply(int fd);
void upc_backend_activate(upc_backend_config *be_cfg);
void upc_backend_unregister(uint8_t be_index);
void upc_tell_backend_re_register(int fd);
void upc_tell_backend_change_active_mac(void);
void upc_lb_register_all_backend(void);
void upc_tell_backend_config(int fd);
void upc_get_backend_validity(int fd);
int upc_backend_compare_validity(comm_msg_entry_val_config_t *val_cfg);

void upc_mb_copy_port_mac(uint8_t port, uint8_t *mac);

int32_t upc_backend_init(upc_config_info *upc_cfg);
void upc_backend_deinit(void);

int upc_backend_init_audit_fsm(const struct FSM_table *fsm_tables, int fsm_table_num, enum AUDIT_RULES entry);

uint32_t upc_backend_get_active_num(void);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _SP_BACKEND_MGMT_H__ */



