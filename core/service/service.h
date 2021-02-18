/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _SERVICE_H__
#define _SERVICE_H__

#include "common.h"
#include "util.h"
#include "platform.h"
#include "session_struct.h"
#include "key_extract.h"
#include "comm_msg.h"


#define SERVICE_USE_RQUEUE_RECV
#define SERVICE_CORE_NUM_MAX        (256)

#define SERVICE_RQ_NODE_NUM         (1024)

#define SERVICE_LISTEN_MAX          (1)

enum en_fp_offload_type
{
    EN_FP_OFFLOAD_TYPE_X86 = 0,
    EN_FP_OFFLOAD_TYPE_LIQUDIO,
    EN_FP_OFFLOAD_TYPE_BUTT,
};
typedef int (*service_process_cb_t)(char *buf, int len, void *arg);
typedef int (*service_connect_cb_t)(void *arg);
typedef int (*service_disconnect_cb_t)(void *arg);

struct service_udp {
    service_process_cb_t ssct;
    ros_rwlock_t lock;
    int fd;
    uint8_t work_flag;
    uint8_t chn_sock;                               /* fp_socket_t */
    uint8_t sock_type;                              /* socket type, tcp:0, raw:1 */

    /* Before this, keep same with struct service_header */

    uint8_t cpus[ROS_MAX_CPUS_NUM];                 /* CPU ID array */
    uint8_t core_num;                               /* Number of core id to be bound */
    uint8_t is_ipv4;
    uint8_t spare[3];
    rqueue_cb_t *rq;                                /* Ring queue */
    pthread_t rq_thr_id[SERVICE_CORE_NUM_MAX];
    int buflen;
    char buf[SERVICE_BUF_MAX_LEN];
	char ethname[128];
    struct sockaddr_in client_addr;
    uint16_t port;
    pthread_t thread_id;
    pthread_barrier_t start_barrier;
};

struct service_udp_client {
    int fd;
    struct sockaddr_in sin;
    int sin_len;
};

struct service_header {
    service_process_cb_t ssct;
    ros_rwlock_t lock;
    int fd;
    uint8_t work_flag;                              /* Work flag, normal:1, abnormal:0 */
    uint8_t chn_sock;                               /* fp_socket_t */
    uint8_t sock_type;                              /* socket type, tcp:0, raw:1 */

    /* Before this, keep same with struct service_header */
};

struct service_raw {
    service_process_cb_t ssct;
    ros_rwlock_t lock;
    int fd;
    uint8_t work_flag;                              /* Work flag, normal:1, abnormal:0 */
    uint8_t chn_sock;                               /* fp_socket_t */
    uint8_t sock_type;                              /* socket type, tcp:0, raw:1 */

    /* Before this, keep same with struct service_header */

    uint8_t cpus[ROS_MAX_CPUS_NUM];                 /* CPU ID array */
    uint8_t core_num;                               /* Number of core id to be bound */
    uint8_t spare[4];
    rqueue_cb_t *rq;                                /* Ring queue */
    pthread_t rq_thr_id[SERVICE_CORE_NUM_MAX];
    pthread_t thread_id;                            /* Recv thread id */
    int buflen;
    char buf[SERVICE_BUF_TOTAL_LEN];
    char ethname[128];
    pthread_barrier_t start_barrier;
    void *param;                                    /* Parameter for receive function */
    service_disconnect_cb_t sdct;                   /* Callback when disconnect */
    void *sdarg;
};

struct service_tcp_server {
    service_process_cb_t ssct;                      /* User recv function */
    ros_rwlock_t lock;
    int fd;
    uint8_t work_flag;                              /* Work flag, normal:1, abnormal:0 */
    uint8_t chn_sock;                               /* fp_socket_t */
    uint8_t sock_type;                              /* socket type, tcp:0, raw:1 */

    /* Before this, keep same with struct service_header */

    uint8_t  spare[7];
    uint16_t port;                                  /* Connecting port */
    uint32_t ip;                                    /* Server:0, Client:remote ip */
    pthread_t thread_id;                            /* Recv thread id */
};

struct service_tcp_client {
    int fd;
    uint32_t ip;
    uint16_t port;
};

struct service_channel_token {
    service_process_cb_t ssct;                      /* User recv function */
    ros_rwlock_t lock;
    int fd;
    uint8_t work_flag;                              /* Work flag, normal:1, abnormal:0 */
    uint8_t chn_sock;                               /* fp_socket_t */
    uint8_t sock_type;                              /* socket type, tcp:0, raw:1 */

    /* Before this, keep same with struct service_header */

    uint8_t spare[7];
    uint16_t port;                                  /* Connecting port */
    uint32_t peerip;                                /* Server:0, Client:remote ip */
    pthread_t thread_id;                            /* Recv thread id */
    service_connect_cb_t scct;                      /* Callback when reconnect */
    void *scarg;                                    /* Callback arg when reconnect */
};

struct service_local {
    service_process_cb_t ssct;
    ros_rwlock_t lock;
    int fd;
    uint8_t work_flag;
};

struct service_udp *service_register_udp(uint8_t cpus[],
                                        uint8_t core_num,
                                        uint16_t port,
                                        char *ethname,
                                        uint8_t is_ipv4,
                                        service_process_cb_t ssct);
void service_unregister_udp(struct service_udp *sdp);
struct service_raw *service_register_raw(uint8_t cpus[],
                                        uint8_t core_num,
                                        char *ethname,
                                        service_process_cb_t ssct,
                                        service_disconnect_cb_t sdct,
                                        void *sdarg);
void service_unregister_raw(struct service_raw *srw);
struct service_tcp_server *service_register_tcp_server(uint16_t port,
                                         service_process_cb_t ssct);
int service_raw_set_trans(struct service_raw *srw, void *trans_mng);
void service_unregister_tcp_server(struct service_tcp_server *sdp);
int service_register_tcp_client(uint16_t port, uint32_t ip);

void *service_channel_client_task(void *arg);
void *service_channel_server_task(void *arg);
struct service_channel_token *
service_channel_server_register(uint16_t port, service_process_cb_t ssct,
    service_connect_cb_t scct, void *scarg);
struct service_channel_token *
service_channel_client_register(uint32_t peerip, uint16_t port, service_process_cb_t ssct,
    service_connect_cb_t scct, void *scarg);

void *service_channel_recv_wraper(void *arg);
int32_t service_channel_send(void *token, char *buf, uint32_t len);

struct service_channel_token *
service_channel_register(uint32_t peerip, uint16_t port, service_process_cb_t ssct,
     service_connect_cb_t scct, void *scarg);

void service_channel_unregister(struct service_channel_token *token);
void service_channel_show(void *token);

#if (defined(PRODUCT_IS_fpu))
#include "fp_main.h"
#elif (defined(PRODUCT_IS_smu))
#include "pfcp_def.h"
#include "compress_func.h"
#include "upc_main.h"
#include "session.h"
#elif (defined(PRODUCT_IS_stub))
#include "pfcp_def.h"
#include "stub_main.h"
#elif (defined(PRODUCT_IS_lbu))
#include "lb_main.h"
#else
#error "PRODUCT_IS_XXX not defined !"
#endif
int32_t service_init(struct pcf_file *conf);
void service_deinit(void);

#endif  /* #ifndef  _SERVICE_H__ */
