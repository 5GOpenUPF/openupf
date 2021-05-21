/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _UPC_MAIN_H__
#define _UPC_MAIN_H__

#ifdef __cplusplus
extern "C" {
#endif

/* unit is 10ms, default 1s = 100 * 10ms */
#define _1_SECONDS_TIME  (ROS_TIMER_TICKS_PER_SEC)

#define UPC_TO_SMF_COMM_PORT                8805
#define UPC_TO_SMF_COMM_PORT_NET            25890

#define UPC_RDB_STRING_MAX_LEN          32

#define UPC_IF_NAME_LEN                 32

/** SMU health value weight
 *  The health value weight of each port needs to be greater than the sum of the health values of other factors,
 *  in order to quickly determine whether the decisive condition is healthy or not
 */
#define SMU_PORT_WEIGHT         40

/* SMU work status, Don't change the order */
enum EN_UPC_WORK_STATUS {
    HA_STATUS_INIT              = 0,
    HA_STATUS_STANDBY           = 1,
    HA_STATUS_SMOOTH2ACTIVE     = 2,
    HA_STATUS_SMOOTH2STANDBY    = 3,
    HA_STATUS_ACTIVE            = 4,
};

struct upc_ctrl_channel {
    uint32_t                    remoteip;
    uint16_t                    remoteport;
    uint16_t                    localport;
};

typedef struct tag_upc_config_info {
    session_ip_addr             upf_ip_cfg[EN_PORT_BUTT];
    char                        upc2smf_name[UPC_IF_NAME_LEN];

    /* H-A channel */
    uint32_t                    ha_remote_ip[COMM_MSG_MAX_CONNECT_CHANNEL];
    uint32_t                    ha_remote_ip_num;
    uint16_t                    ha_remote_port;
    uint16_t                    ha_local_port;
    uint32_t                    ha_sync_block_num;

    uint32_t                    teid_num;
    uint32_t                    session_num;
    session_up_features         up_features;
    uint8_t                     cpus[ROS_MAX_CPUS_NUM]; /* CPU ID array that can be used */

    uint8_t                     core_num;
    uint8_t                     default_master;
    uint8_t                     n4_local_mac[ETH_ALEN];
    uint16_t                    node_num;
    uint16_t                    restful_listen;
    uint32_t                    cblock_num;

    uint32_t                    audit_period;  /* unit:minute */
    uint16_t                    audit_switch;
    uint16_t                    fpu_mgmt_port;
    uint32_t                    fast_num;
    uint32_t                    fast_bucket_num;
    uint32_t                    block_num;
    uint32_t                    block_size;
    uint32_t                    dns_num;
    uint32_t                    orphan_number;
    uint32_t                    pfd_number;
    uint16_t                    lb_ips_num;
    uint16_t                    lb_port;
    uint32_t                    lb_ips[COMM_MSG_MAX_CONNECT_CHANNEL];

    uint64_t                    local_key; /* Local flag key */
    uint64_t                    peer_key; /* Peer flag key */
    uint8_t                     peer_smu_mac[EN_PORT_BUTT][ETH_ALEN]; /* Peer SMU MAC address */
} upc_config_info;

enum UPC_PKT_STATUS_UNIT {
    UPC_PKT_RECV_FORM_SMF,
    UPC_PKT_SEND_TO_SMF,

    UPC_PKT_SESS_EST_SEND2SMF,  /* send session establish response to smf */
    UPC_PKT_SESS_EST_RECV4SMF,  /* receive session establish request from smf */

    UPC_PKT_SESS_MDF_SEND2SMF,  /* send session modification response to smf */
    UPC_PKT_SESS_MDF_RECV4SMF,  /* receive session modification request from smf */

    UPC_PKT_SESS_DEL_SEND2SMF,  /* send session deletion response to smf */
    UPC_PKT_SESS_DEL_RECV4SMF,  /* receive session deletion request from smf */

    UPC_PKT_SESS_REPORT_SEND2SMF,  /* send session report request to smf */
    UPC_PKT_SESS_REPORT_RECV4SMF,  /* receive session report response from smf */

    UPC_PKT_NODE_CREATE_SEND2SMF,  /* send node create response to smf */
    UPC_PKT_NODE_CREATE_RECV4SMF,  /* receive node create request from smf */
    UPC_PKT_NODE_UPDATE_SEND2SMF,  /* send node update response to smf */
    UPC_PKT_NODE_UPDATE_RECV4SMF,  /* receive node update request from smf */
    UPC_PKT_NODE_REMOVE_SEND2SMF,  /* send node remove response to smf */
    UPC_PKT_NODE_REMOVE_RECV4SMF,  /* receive node remove request from smf */

    UPC_PKT_NODE_REPORT_SEND2SMF,  /* send node report request to smf */
    UPC_PKT_NODE_REPORT_RECV4SMF,  /* receive node report response from smf */

    UPC_PKT_PFD_MANAGEMENT_SEND2SMF,  /* send pfd management response to smf */
    UPC_PKT_PFD_MANAGEMENT_RECV4SMF,  /* receive pfd management request from smf */

    UPC_PKT_HEARTBEAT_REQU_SEND2SMF,  /* send PFCP heartbeat request to smf */
    UPC_PKT_HEARTBEAT_RESP_SEND2SMF,  /* send PFCP heartbeat response to smf */
    UPC_PKT_HEARTBEAT_REQU_RECV4SMF,  /* receive PFCP heartbeat request from smf */
    UPC_PKT_HEARTBEAT_RESP_RECV4SMF,  /* receive PFCP heartbeat response from smf */

    UPC_PKT_STATUS_BUTT,
};

typedef enum {
    HA_CREATE = 1,
    HA_UPDATE = 2,
    HA_REMOVE = 3,
} EN_UPC_HA_ACTION;

typedef enum {
    HA_SYNC_RECV_FROM_CP    = 1,
    HA_SYNC_SEND_TO_FPU,
    HA_SYNC_REPLY_TO_CP,
    HA_SYNC_FINAL_STATE     = HA_SYNC_REPLY_TO_CP,
} EN_UPC_HA_SYNC_STATUS;

typedef enum {
    HA_SYNC_EVENT_SUCC = 0,
    HA_SYNC_EVENT_FAIL = 1,
} EN_UPC_HA_SYNC_EVENTS;

typedef enum {
    HA_SYNC_DATA_NODE   = 1,
    HA_SYNC_DATA_SESS   = 2,
    HA_SYNC_DATA_PFD    = 3,
} EN_UPC_HA_SYNC_DATA_TYPE;

static inline comm_msg_header_t *upc_fill_msg_header(uint8_t *buf)
{
    comm_msg_header_t *msg_hdr = (comm_msg_header_t *)buf;

    msg_hdr->magic_word    = htonl(COMM_MSG_MAGIC_WORD);
    msg_hdr->comm_id       = 0;
    msg_hdr->major_version = COMM_MSG_MAJOR_VERSION;
    msg_hdr->minor_version = COMM_MSG_MINOR_VERSION;
    msg_hdr->total_len     = COMM_MSG_HEADER_LEN;

    return msg_hdr;
}

typedef int         (* UPC_SYNC_BACKEND)(uint32_t *be_index_arr, uint32_t be_index_num, uint8_t sync_act);
typedef int         (* UPC_BUILD_DATA_BLOCK)(uint8_t data_type, uint8_t action, uint8_t status,
                                             uint8_t event, void *data);
typedef int         (* UPC_CHANGE_SYNC_BLOCK_STATUS)(uint32_t index, uint8_t status, uint8_t event);
typedef uint32_t    (* UPC_HA_MSG_PROC)(void *token, comm_msg_ie_t *ie);
typedef int64_t     (* UPC_HA_INIT)(upc_config_info *cfg);
typedef void        (* UPC_HA_DEINIT)(void);
typedef int         (* UPC_HA_ASS)(void);

extern UPC_SYNC_BACKEND             upc_hk_sync_backend;
extern UPC_BUILD_DATA_BLOCK         upc_hk_build_data_block;
extern UPC_CHANGE_SYNC_BLOCK_STATUS upc_hk_change_sync_blk_status;
extern UPC_HA_MSG_PROC              upc_hk_ha_msg_proc;
extern UPC_HA_INIT                  upc_hk_ha_init;
extern UPC_HA_DEINIT                upc_hk_ha_deinit;
extern UPC_HA_ASS                   upc_hk_ha_ass;


void        upc_set_work_status(int16_t status);
int16_t     upc_get_work_status(void);
void        upc_set_standby_alive(int16_t status);
int16_t     upc_get_standby_alive(void);

upc_config_info *upc_get_config(void);
int upc_get_nat_flag(void);
void upc_set_nat_flag(int act);

void upc_pkt_status_add(int unit);

void upc_fill_ip_udp_hdr(uint8_t *buf, uint16_t *buf_len, struct sockaddr *sa);
int upc_channel_trans(uint8_t *buf, uint16_t len);

int32_t  upc_init(struct pcf_file *conf);
void upc_deinit(void);
session_ip_addr *upc_get_local_ip(void);
char *upc_get_2smf_ethname(void);
session_ip_addr *upc_get_n3_local_ip(void);
uint64_t upc_get_up_features(void);

int upc_buff_send2smf(uint8_t *buf, uint16_t len, struct sockaddr *sa);
int upc_set_up_config(const uint64_t up);

int upc_show_working_status(struct cli_def *cli,int argc, char **argv);
int upc_ha_active_standby_switch(struct cli_def *cli, int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _UPC_MAIN_H__ */

