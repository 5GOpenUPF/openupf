/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _FP_BACKEND_MGMT_H__
#define _FP_BACKEND_MGMT_H__

#ifdef __cplufplus
extern "C" {
#endif


#define FP_BACKEND_HEARTBEAT_INTERVAL   (3)

#define FP_BACKEND_HB_TIMEOUT_MAX       (3)

enum {
    EN_BE_WAIT_INIT             = 0,
    EN_BE_INITIALIZING          = 1,
    EN_BE_WORKING               = 2,
};

typedef struct tag_fp_backend_config {
    comm_msg_channel_client     channel_client;
    ros_atomic32_t              work_state; /* Current work state */
    ros_atomic32_t              hb_cnt;
    uint64_t                    flag_key;
    pthread_t                   pthr_id;
    uint8_t                     loadbalancer_mac[EN_PORT_BUTT][ETH_ALEN];
} fp_backend_config;


inline void fp_be_reset_hb_cnt_public();
fp_backend_config *fp_be_get_config_public(void);
inline comm_msg_channel_common *fp_be_get_channel_cli(void);
void fp_be_copy_port_mac(uint8_t port, uint8_t *mac);
inline uint64_t fp_be_get_flag_key(void);
void fp_be_active(void);

int64_t fp_be_init(fp_connect_mb_channel_cfg *mb_chnl_cfg);

#ifdef __cplufplus
}
#endif

#endif  /* #ifndef  _FP_BACKEND_MGMT_H__ */




