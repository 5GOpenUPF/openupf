/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _SESSION_TEID_H__
#define _SESSION_TEID_H__

#ifdef __cplusplus
extern "C" {
#endif

/* unit: Second */
#define SESSION_ECHO_TIME_INTERVAL      (50)
#define SESSION_ECHO_PERIOD_TIMES       (50)
/* unit: Second */
#define SESSION_ECHO_PERIOD_INTERVAL    (SESSION_ECHO_TIME_INTERVAL/SESSION_ECHO_PERIOD_TIMES)
#define SESSION_ECHO_RETRY_TIMES        3
#define SESSION_ECHO_INVALID_CODE       233

#define GTP_IE_RECOVERY                 14
#define	GTP_IE_TEID_DATA_I              16
#define GTP_IE_PEER_ADDRESS             133
#define GTP_IE_PRVIVATE_EXTENSION       255

typedef union {
    uint32_t            ipv4;               /* ipv4 address */
    uint8_t             ipv6[IPV6_ALEN];    /* ipv6 address */
} session_gtpu_key;

struct session_gtpu_entry {
    struct rb_node              entry_node;
    ros_rwlock_t                lock;
    uint32_t                    index;
    session_gtpu_key            ip_addr;
    uint8_t                     ip_flag;        /* 1: ipv4, 2: ipv6 */
    uint8_t                     port;           /* N3 N6 N4 N9 */
    uint8_t                     node_index;     /*记录node, 用于用户平面路径故障上报时填充node_index*/
    uint8_t             		timeout_num;    /* timeout number */
    ros_atomic32_t              assoc_num;      /* The number of FARs associated with this GTPU */
};

struct session_gtpu_table {
    struct session_gtpu_entry	*gtpu_entry;
    struct rb_root              gtpu_root;  /* For Echo requeset|response */
    ros_rwlock_t        	    lock;
    uint32_t            	    max_num;
    uint16_t            	    pool_id;
    uint16_t                    spare;
};


/* For error indication */
#pragma pack(1)
typedef struct tag_session_fteid_key {
    union {
        uint32_t            ipv4;               /* ipv4 address */
        uint8_t             ipv6[IPV6_ALEN];    /* ipv6 address */
    };
    uint32_t                teid;
}session_fteid_key;
#pragma pack()

struct session_peer_fteid_entry {
    struct rb_node              entry_node;
    ros_rwlock_t                lock;
    uint32_t                    index;
    struct pfcp_session         *sess_cfg;
    session_fteid_key           fteid_key;
    uint8_t                     ip_flag;        /* 1: ipv4, 2: ipv6 */
    uint8_t                     spare[3];
};

struct session_peer_fteid_table {
    struct session_peer_fteid_entry *fteid_entry;
    struct rb_root                  peer_fteid_root; /* For error indication */
    ros_rwlock_t        	        lock;
    uint32_t            	        max_num;
    uint16_t            	        pool_id;
    uint16_t                        spare;
};


int session_gtp_pkt_process(struct filter_key *key);
int64_t session_gtpu_init(uint32_t session_num);
int session_gtpu_end_marker(comm_msg_outh_cr_t *ohc);
int session_gtpu_insert(void *ip, uint8_t ip_ver, uint8_t port, uint32_t node_index);
int session_gtpu_delete(comm_msg_outh_cr_t *ohc);
void session_gtpu_send_error_indication(struct filter_key *key);


int session_peer_fteid_insert(void *ip, uint8_t ip_ver, uint32_t teid, struct pfcp_session *sess_cfg);
int session_peer_fteid_delete(comm_msg_outh_cr_t *ohc);


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _SESSION_TEID_H__ */

