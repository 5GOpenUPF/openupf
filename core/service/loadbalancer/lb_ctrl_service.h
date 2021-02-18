/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LB_CTRL_SERVICE_H__
#define _LB_CTRL_SERVICE_H__

#ifdef __cplusplus
extern "C" {
#endif

#if 0
/* Received data length */
#define LB_CTRL_BUFF_LEN        (8192)

/* Client check interval */
#define LB_CHANNEL_CLIENT_CHECK_INTERVAL        (2)

/* Maximum client connect number */
#define LB_MAX_LISTEN_NUMBER        (256)

/* Maximum effective number of client connections */
#define LB_MAX_CONNECT_CHANNEL     (4)

struct lb_ctrl_channel_server {
    pthread_t                   thread_id;      /* Recv thread id */
    int                         sock;           /* Server sock */
    uint8_t                     work_flag;      /* Work flag, normal:1, abnormal:0 */
    uint8_t                     spare;
    uint16_t                    cpu_id;         /* Bound CPU ID */
};

struct lb_ctrl_channel_client {
    pthread_t                   thread_id;      /* Recv thread id */
    uint32_t                    remote_ips[LB_MAX_CONNECT_CHANNEL];
    uint16_t                    remote_port;
    uint8_t                     remote_ips_num;
    uint8_t                     work_flag;      /* Work flag, normal:1, abnormal:0 */
    int                         fd;             /* Currently valid fd */
    ros_rwlock_t                rw_lock;
    uint16_t                    cpu_id;         /* Bound CPU ID */
    uint8_t                     spare[2];
};



int lb_create_channel_server(struct lb_ctrl_channel_server *setp, uint16_t port, uint16_t bound_cpu_id);
int lb_create_channel_client(struct lb_ctrl_channel_client *setp, uint32_t *remote_ips, uint8_t remote_ips_num,
    uint16_t remote_port, uint16_t bound_cpu_id);
int32_t lb_channel_client_send(struct lb_ctrl_channel_client *chnl_cli, char *buf, uint32_t len);
int32_t lb_channel_reply(int fd, char *buf, uint32_t len);
void lb_channel_server_shutdown(struct lb_ctrl_channel_server *server);
void lb_channel_client_shutdown(struct lb_ctrl_channel_client *client);
#endif

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _LB_CTRL_SERVICE_H__ */



