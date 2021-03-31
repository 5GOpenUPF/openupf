/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LB_MAIN_H__
#define _LB_MAIN_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Hash of Ethernet or Non-IP bearer */
#define ETH_OR_NONIP_HASH       0xFFFFFFFF

/* LB work status, Don't change the order */
enum EN_LB_WORK_STATUS {
    LB_STATUS_INIT              = 0,
    LB_STATUS_STANDBY           = 1,
    LB_STATUS_SMOOTH2ACTIVE     = 2,
    LB_STATUS_SMOOTH2STANDBY    = 3,
    LB_STATUS_ACTIVE            = 4,
};
/* When the state is greater than this threshold, data can be forwarded */
#define LB_FORWARD_THRESHOLD    LB_STATUS_SMOOTH2ACTIVE

typedef enum tag_EN_LB_PORT {
    EN_LB_PORT_EXT,     /* External port */
    EN_LB_PORT_INT,     /* Internal port */
    EN_LB_PORT_BUTT,
}EN_LB_PORT;


typedef struct tag_lb_system_config {
    uint8_t                     cpus[ROS_MAX_CPUS_NUM]; /* CPU ID array that can be used */
    uint8_t                     core_num;
    uint8_t                     ha_remote_ip_num;
    uint8_t                     default_master; /* 是否为默认主用, 1:出现竞争时优先成为主 0:为备 */
    uint8_t                     spare;
    uint16_t                    ha_local_port;
    uint16_t                    ha_remote_port;
    uint32_t                    ha_remote_ip[COMM_MSG_MAX_CONNECT_CHANNEL];
    uint16_t                    be_mgmt_port;
    comm_msg_ip_address         upf_ip[EN_PORT_BUTT];
    uint32_t                    nexthop_net_ip[EN_PORT_BUTT];
}lb_system_config;


typedef void        (* LB_SYNC_BACKEND_TABLE)(uint8_t be_index);
typedef void        (* LB_UPDATE_DELAY_SYNC_HASH)(uint8_t hash1, uint16_t hash2, uint8_t be_index);
typedef void        (* LB_UPDATE_DELAY_SYNC_BACKEND)(uint8_t be_index);
typedef uint32_t    (* LB_HA_MSG_PROC)(void *token, comm_msg_ie_t *ie);
typedef int         (* LB_HA_INIT)(lb_system_config *cfg);
typedef void        (* LB_HA_DEINIT)(void);
typedef int         (* LB_HA_ASS)(void);

extern LB_SYNC_BACKEND_TABLE            lb_hk_sync_be_table;
extern LB_UPDATE_DELAY_SYNC_HASH        lb_hk_delay_sync_hash;
extern LB_UPDATE_DELAY_SYNC_BACKEND     lb_hk_delay_sync_be;
extern LB_HA_MSG_PROC                   lb_hk_ha_msg_proc;
extern LB_HA_INIT                       lb_hk_ha_init;
extern LB_HA_DEINIT                     lb_hk_ha_deinit;
extern LB_HA_ASS                        lb_hk_ha_ass;


void lb_mb_work_state_set(uint8_t vl);
inline uint8_t lb_mb_work_state_get_public(void);
void        lb_set_work_status(int16_t status);
int16_t     lb_get_work_status(void);
void        lb_set_standby_alive(int16_t status);
int16_t     lb_get_standby_alive(void);

uint8_t *lb_get_local_port_mac(uint8_t port);
uint32_t lb_get_local_net_ipv4(uint8_t port);
uint8_t *lb_get_peer_port_mac(uint8_t port);
comm_msg_header_t *lb_fill_msg_header(uint8_t *buf);

lb_system_config *lb_get_system_config(void);
void lb_mac_updating_public(void *m, uint8_t *src_mac, uint8_t *dest_mac);
void lb_fwd_to_external_network_public(void *m);

int32_t lb_init_prepare(struct pcf_file *conf);
int32_t lb_init(void);
int32_t lb_deinit();

int lb_ha_active_standby_switch(struct cli_def *cli,int argc, char **argv);
int lb_ha_get_lbu_status(struct cli_def *cli,int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _LB_MAIN_H__ */


