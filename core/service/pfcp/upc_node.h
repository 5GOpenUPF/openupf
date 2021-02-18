/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _UPC_NODE_H__
#define _UPC_NODE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define UPC_NODE_DEFAULT_HB_TIME        (20*ROS_TIMER_TICKS_PER_SEC)    /* 20 s */
#define UPC_NODE_WAIT_RATE              100         /* 100 session per second */

/* Invalid node index */
#define UPC_NODE_INVALID_INDEX          0xFF

/* UP features */
#define UF_BUCP     0x10000000000
#define UF_DDND     0x20000000000
#define UF_DLBD     0x40000000000
#define UF_TRST     0x80000000000
#define UF_FTUP     0x100000000000
#define UF_PFDM     0x200000000000
#define UF_HEEU     0x400000000000
#define UF_TREU     0x800000000000

#define UF_EMPU     0x100000000
#define UF_PDIU     0x200000000
#define UF_UDBC     0x400000000
#define UF_QUOAC    0x800000000
#define UF_TRACE    0x1000000000
#define UF_FRRT     0x2000000000
#define UF_PFDE     0x4000000000
#define UF_EPFAR    0x8000000000

#define UF_DPDRA    0x1000000
#define UF_ADPDP    0x2000000
#define UF_UEIP     0x4000000
#define UF_SSET     0x8000000
#define UF_MNOP     0x10000000
#define UF_MTE      0x20000000
#define UF_BUNDL    0x40000000
#define UF_GCOM     0x80000000

#define UF_MPAS     0x10000
#define UF_RTTL     0x20000
#define UF_VTIME    0x40000
#define UF_NORP     0x80000
#define UF_IPTV     0x100000
#define UF_IP6PL    0x200000
#define UF_TSCU     0x400000
#define UF_MPTCP    0x800000

#define UF_ATSSS_LL 0x100
#define UF_QFQM     0x200
#define UF_GPQM     0x400
#define UF_MT_EDT   0x800
#define UF_CIOT     0x1000
#define UF_ETHAR    0x2000


typedef enum
{
    UPC_NODE_STATUS_INIT      = 0x00,   /* Keep this value is 0 */
    UPC_NODE_STATUS_SETUP     = 0x01,
    UPC_NODE_STATUS_RUN       = 0x02,
    UPC_NODE_STATUS_REPORT    = 0x03,
    UPC_NODE_STATUS_SHUT      = 0x04,
    UPC_NODE_STATUS_BUTT,
} upc_node_status;

typedef struct tag_upc_node_cb {
    uint8_t                             index;
    uint8_t                             status;
    ros_atomic16_t                      hb_timeout_cnt;
    ros_rwlock_t                        lock;

    ros_atomic32_t                      local_seq;
    ros_atomic32_t                      session_num;
    session_association_setup           assoc_config;
    union {
        struct sockaddr                 peer_sa;
        struct sockaddr_in              peer_sa_v4;
        struct sockaddr_in6             peer_sa_v6;
    }; /* Send to peer sockaddr */
    struct ros_timer                    *hb_timer;  /* heartbeat timer */
    struct dl_list                      seid_list;  /* seid list of node */
    session_globally_unique_id          guid;
    pfcp_node_id                        peer_id;
}upc_node_cb;

typedef struct tag_upc_node_header {
    upc_node_cb         *node;          /* Node control block */
    pfcp_node_id        local_idv4;     /* Local node id IPv4 */
    pfcp_node_id        local_idv6;     /* Local node id IPv6 */
    uint32_t            node_max;       /* Max number */
    uint32_t            local_stamp;    /* Local time stamp */
    uint16_t            res_no;
}upc_node_header;

upc_node_header *upc_node_mng_get(void);
uint8_t *upc_upf_guid_get(void);
upc_node_cb *upc_node_get_of_index(uint32_t index);
int64_t  upc_node_init(uint8_t node_num);
void upc_node_clear_param(upc_node_cb *node);
void upc_node_proc_timer_hb(void *timer, uint64_t para);
upc_node_cb *upc_node_get(uint8_t node_type, uint8_t *nodeid);
upc_node_cb *upc_get_node_by_sa(void *arg);
void upc_node_update_peer_sa(upc_node_cb *node_cb, struct sockaddr *sa);
upc_node_cb *upc_node_add(uint8_t node_index, uint8_t node_type, uint8_t *nodeid, struct sockaddr *sa);
int upc_node_del(upc_node_cb *node);
pfcp_node_id *upc_node_get_local_node_id(uint8_t node_type);
uint32_t upc_node_get_local_time_stamp(void);
pfcp_node_id *upc_node_get_peer_node(upc_node_cb *node_cb);
uint32_t upc_node_get_peer_ipv4(upc_node_cb *node_cb);
uint32_t upc_node_get_max_num(void);
void upc_node_merge_features(upc_node_cb *node);
uint32_t upc_node_notify_session_report(upc_node_cb *node_cb);
uint8_t  upc_node_second_to_time_struct(uint32_t time_in_sec);
uint32_t upc_node_time_struct_to_second(uint8_t time_struct);

int upc_node_hb_timer_start(void);
int upc_node_hb_timer_stop(void);

int upc_node_features_validity_query(uint64_t feature);

int upc_node_update(void);
int upc_node_update_release(struct cli_def *cli,uint32_t ipv4);
upc_node_cb *upc_node_cb_get_public(uint8_t index);
int upc_node_show_up_cp(struct cli_def * cli,int index, int flag);
int upc_node_set_up(const uint64_t up_value);
int upc_set_hb_time(uint32_t sec);
int upc_node_del_cli(struct cli_def *cli);
#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _UPC_NODE_H__ */


