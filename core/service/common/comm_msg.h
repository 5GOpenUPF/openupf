/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef __COMM_MSG_H
#define __COMM_MSG_H

#include "session_struct.h"

/* SERVICE_BUF_SPARE_LEN needs to be greater than (COMM_MSG_HEADER_LEN + ETH_HLEN) */
#define SERVICE_BUF_SPARE_LEN               (64)
#define SERVICE_BUF_MAX_LEN                 (2048)
#define SERVICE_BUF_TOTAL_LEN               (SERVICE_BUF_MAX_LEN + SERVICE_BUF_SPARE_LEN)
#define SERVICE_PROTO                       0x9090
#define SERVICE_N3N6                        0x8199

//#define FAR_DUPL_ENABLE

/* Less than or equal to LB_MAX_LISTEN_NUMBER is required */
#define COMM_MSG_BACKEND_NUMBER             (256)
#define COMM_MSG_BACKEND_START_INDEX        (0)

#define	COMM_SIGNALING_TRACE_FILE_NAME		"/tmp/signaling_trace.pcap"

//#define ENABLE_INST_STAT_COLLECT_IMMD

/* Compatible record fast ID and fast type with Ethernet */
#define RECORD_FAST_INFO_NEW_VER

#ifndef IPV6_ALEN
#define IPV6_ALEN                           (16)
#endif

#ifndef ETH_ALEN
#define ETH_ALEN                            (6)
#endif

/* Support REST API */
#define SUPPORT_REST_API

#define COMM_MSG_PORT                   9000
#define COMM_MSG_MAX_LISTEN_NUM         4
#define COMM_MSG_ETH_NAME_LEN           32
#define COMM_MSG_MAGIC_WORD             0x08675309
#define COMM_MSG_MAX_BUF_SIZE           0x10000
#define COMM_MSG_MAJOR_VERSION          1
#define COMM_MSG_MINOR_VERSION          1
#define COMM_MSG_MAX_NO_RESPONSE_TIMES  5
#define COMM_MSG_BUF_SIZE               0x10000
#define COMM_MSG_INVALID_COMM_ID        0xFFFF
#define COMM_MSG_SLEEP_SECOND           1000000
#define COMM_MSG_MAX_LENGTH             2048
#define COMM_MSG_MAC_LEN                6
#define COMM_MSG_IPV6_LEN               16
#define COMM_MSG_INVALID_INDEX          ((uint32_t)(-1))
#define COMM_MSG_PRE_HEAD_MAX           128

/* 4-byte alignment */
#define MAX_CHECK_VALIDITY_NUMBER       (((uint32_t)(SERVICE_BUF_MAX_LEN - COMM_MSG_HEADER_LEN - \
            COMM_MSG_IE_LEN_COMMON - sizeof(comm_msg_entry_val_config_t)) >> 2) << RES_PART_LEN_BIT)
/* Don't set it too big */
#define ONCE_CHANGE_NUMBER_MAX          (256)

#define COMM_MSG_ORPHAN_NUMBER          (0)

#define COMM_MSG_MAX_DPDK_CORE_NUM      (256)

typedef enum
{
    /* Common command  */
    EN_COMM_MSG_LOC                 = 0x0001,

    /* Common command  */
    EN_COMM_MSG_HEARTBEAT           = 0x005A,

    /* Trains reply ack */
    EN_COMM_MSG_TRANS_REPLY_ACK     = 0x0066,

    /* New flow matching session */
    EN_COMM_MSG_MATCH_SESSION       = 0x1001,       /* SP<-->FP */

    /* SP-->FP */
    /* Add fast table entry, with entry No. */
    EN_COMM_MSG_UPU_ENTR_ADD        = 0x1201,
    /* Delete fast table entry, with entry No. */
    EN_COMM_MSG_UPU_ENTR_DEL        = 0x1202,
    /* Insert fast table entry, alloc entry No. by fast */
    EN_COMM_MSG_UPU_ENTR_INS        = 0x1203,
    /* Remove fast table entry, by five tuple desc */
    EN_COMM_MSG_UPU_ENTR_REM        = 0x1204,
    /* Modify fast table entry, with entry No. */
    EN_COMM_MSG_UPU_ENTR_MOD        = 0x1205,
    /* Get fast table entry */
    EN_COMM_MSG_UPU_ENTR_GET        = 0x1206,
    /* Get effective fast table entry number of fast table */
    EN_COMM_MSG_UPU_ENTR_SUM        = 0x1207,
    /* Clear fast table */
    EN_COMM_MSG_UPU_ENTR_CLR        = 0x1208,

    /* Set the channel work mode between fast and slow plane */
    EN_COMM_MSG_UPU_CHNL_SET_MOD    = 0x1221,
    /* Get the channel between fast plane and slow plane */
    EN_COMM_MSG_UPU_CHNL_GET_MOD    = 0x1222,
    /* Set vxlan between fast plane and slow plane */
    EN_COMM_MSG_UPU_CHNL_SET_VXLAN  = 0x1223,
    /* Get vxlan between fast plane and slow plane */
    EN_COMM_MSG_UPU_CHNL_GET_VXLAN  = 0x1224,

    /* Add Qos entry, with entry No. */
    EN_COMM_MSG_UPU_QER_ADD         = 0x1231,
    /* Delete Qos entry, with entry No. */
    EN_COMM_MSG_UPU_QER_DEL         = 0x1232,
    /* Get Qos entry */
    EN_COMM_MSG_UPU_QER_GET         = 0x1234,
    /* Clear Qos table */
    EN_COMM_MSG_UPU_QER_CLR         = 0x1235,
    /* Get effective table entry number of total table */
    EN_COMM_MSG_UPU_QER_SUM         = 0x1236,
    /* Modify entry */
    EN_COMM_MSG_UPU_QER_MOD         = 0x1237,
    /* Modify entry */
    EN_COMM_MSG_UPU_QER_VAL         = 0x1238,
    /* Get QER packet rate status */
    EN_COMM_MSG_UPU_QER_PRS         = 0x1239,

    /* Add SESSION entry, with entry No. */
    EN_COMM_MSG_UPU_INST_ADD        = 0x1241,
    /* Delete SESSION entry, with entry No. */
    EN_COMM_MSG_UPU_INST_DEL        = 0x1242,
    /* Insert SESSION entry, alloc entry No. by fast plane */
    EN_COMM_MSG_UPU_INST_INS        = 0x1243,
    /* Get SESSION entry */
    EN_COMM_MSG_UPU_INST_GET        = 0x1244,
    /* Get effective SESSION table entry number of total table */
    EN_COMM_MSG_UPU_INST_SUM        = 0x1245,
    /* Clear fast table */
    EN_COMM_MSG_UPU_INST_CLR        = 0x1246,
    /* Modify SESSION entry, with entry No */
    EN_COMM_MSG_UPU_INST_MOD        = 0x1247,
    /* Get SESSION entry validity */
    EN_COMM_MSG_UPU_INST_VALIDITY   = 0x1248,
    /* Update INST light */
    EN_COMM_MSG_UPU_INST_LIGHT      = 0x1249,
    /* Update INST colelct thres */
    EN_COMM_MSG_UPU_INST_THRES      = 0x1250,

    /* Add entry, with entry No. */
    EN_COMM_MSG_UPU_FAR_ADD         = 0x1271,
    /* Delete entry, with entry No. */
    EN_COMM_MSG_UPU_FAR_DEL         = 0x1272,
    /* Get entry */
    EN_COMM_MSG_UPU_FAR_GET         = 0x1274,
    /* Get effective table entry number of total table */
    EN_COMM_MSG_UPU_FAR_SUM         = 0x1275,
    /* Clear table */
    EN_COMM_MSG_UPU_FAR_CLR         = 0x1276,
    /* Modify entry, with entry No */
    EN_COMM_MSG_UPU_FAR_MOD         = 0x1277,
    /* Get entry validity */
    EN_COMM_MSG_UPU_FAR_VAL         = 0x1278,

    /* Add entry, with entry No. */
    EN_COMM_MSG_UPU_BAR_ADD         = 0x1281,
    /* Delete entry, with entry No. */
    EN_COMM_MSG_UPU_BAR_DEL         = 0x1282,
    /* Get entry */
    EN_COMM_MSG_UPU_BAR_GET         = 0x1284,
    /* Get effective table entry number of total table */
    EN_COMM_MSG_UPU_BAR_SUM         = 0x1285,
    /* Clear table */
    EN_COMM_MSG_UPU_BAR_CLR         = 0x1286,
    /* Modify entry, with entry No */
    EN_COMM_MSG_UPU_BAR_MOD         = 0x1287,
    /* Get entry validity */
    EN_COMM_MSG_UPU_BAR_VAL         = 0x1288,

    /* Add or update, with entry No. */
    EN_COMM_MSG_UPU_DNS_ADD         = 0x12a1,
    /* Delete entry, with entry No. */
    EN_COMM_MSG_UPU_DNS_DEL         = 0x12a2,
    /* Get entry */
    EN_COMM_MSG_UPU_DNS_GET         = 0x12a4,
    /* Get effective table entry number of total table */
    EN_COMM_MSG_UPU_DNS_SUM         = 0x12a5,
    /* Clear table */
    EN_COMM_MSG_UPU_DNS_CLR         = 0x12a6,
    /* Get entry validity */
    EN_COMM_MSG_UPU_DNS_VAL         = 0x12a7,


	/* Set user sig trace*/
    EN_COMM_MSG_UPU_SIGTRACE_SET    = 0x12FF,


    /* FP-->SP */
    /* Update URR stat */
    EN_COMM_MSG_UPU_FP_STAT         = 0x2202,


    /* Collect FPU statistics and send it to SPU */
    EN_COMM_MSG_COLLECT_STATUS      = 0x3201,


    /* High-Availbility master <---> standby */
    /* Heartbeat message */
    EN_COMM_MSG_HA_HB               = 0x4001,
    /* Init success, Send sync data request to master */
    EN_COMM_MSG_HA_SYNC_REQUEST     = 0x4002,
    /* Synchronization data block */
    EN_COMM_MSG_HA_SYNC_BLOCK       = 0x4010,
    /* Active/standby switch request */
    EN_COMM_MSG_HA_ASS_REQ          = 0x4020,
    /* Active/standby switch response */
    EN_COMM_MSG_HA_ASS_RESP         = 0x4021,
    /* Get peer working status request */
    EN_COMM_MSG_HA_GET_STAT_REQ     = 0x4030,
    /* Get peer working status response */
    EN_COMM_MSG_HA_GET_STAT_RESP    = 0x4031,
    /* Synchronization backend config */
    EN_COMM_MSG_HA_SYNC_BACKEND     = 0x4032,

    /* smu master(management end) <---> backend */
    /* Backend heartbeat */
    EN_COMM_MSG_BACKEND_HB          = 0x5001,
    /* Send config to Backend */
    EN_COMM_MSG_BACKEND_CONFIG      = 0x5002,
    /* Tell the management-end that the back-end is ready */
    EN_COMM_MSG_BACKEND_ACTIVE      = 0x5003,
    /* Tell the back end to be ready to shut down(used for volume reduction) */
    EN_COMM_MSG_BACKEND_SHUTDOWN    = 0x5004,
    /* Tell backend re register */
    EN_COMM_MSG_BACKEND_RE_REGIS    = 0x5005,
    /* Tell backend change load-balancer MAC */
    EN_COMM_MSG_BACKEND_RESET_LBMAC = 0x5006,
    /* Get backend validity from load-balancer */
    EN_COMM_MSG_BACKEND_VALIDITY    = 0x5007,

    /* Load-balancer master <---> smu(Management end) */
    /* Management end heartbeat */
    EN_COMM_MSG_MB_HB               = 0x5011,
    /* Register backend to load-balancer */
    EN_COMM_MSG_MB_REGISTER         = 0x5012,
    /* Unregister backend to load-balancer */
    EN_COMM_MSG_MB_UNREGISTER       = 0x5013,
    /* Tell backend change load-balancer MAC */
    EN_COMM_MSG_LBMAC_RESET         = 0x5014,


    /* Load-balancer master <---> Load-balancer standby */
    /* Heartbeat message */
    EN_COMM_MSG_LB_HA_HB            = 0x5101,
    /* Init success, Send sync data request to master */
    EN_COMM_MSG_LB_HA_SYNC_REQ      = 0x5102,
    /* Synchronization hash table */
    EN_COMM_MSG_LB_HA_SYNC_HASH     = 0x5110,
    /* Synchronization backend table */
    EN_COMM_MSG_LB_HA_SYNC_BE       = 0x5111,
    /* Active/standby switch request */
    EN_COMM_MSG_LB_HA_ASS_REQ       = 0x5120,
    /* Active/standby switch response */
    EN_COMM_MSG_LB_HA_ASS_RESP      = 0x5121,
    /* Get peer working status request */
    EN_COMM_MSG_LB_HA_GET_STAT_REQ  = 0x5130,
    /* Get peer working status response */
    EN_COMM_MSG_LB_HA_GET_STAT_RESP = 0x5131,

}EN_COMM_MSG_T;

/* COMM errno */
typedef enum tag_EN_COMM_ERRNO
{
    EN_COMM_ERRNO_OK                     = 0,
    EN_COMM_ERRNO_NO_SUCH_ITEM           = 0x81000001,
    EN_COMM_ERRNO_REPEAT_ITEM            = 0x81000002,
    EN_COMM_ERRNO_ITEM_NUM_OVERFLOW      = 0x81000003,
    EN_COMM_ERRNO_SERVICE_INDEX_ERROR    = 0x81000004,
    EN_COMM_ERRNO_DETAIL_INFO_ERROR      = 0x81000005,
    EN_COMM_ERRNO_ITEM_CONFLICT          = 0x81000006,
    EN_COMM_ERRNO_ITEM_CHECK_FAILED      = 0x81000007,
    EN_COMM_ERRNO_PARAM_INVALID          = 0x81000008,
    EN_COMM_ERRNO_RESOURCE_NOT_ENOUGH    = 0x81000009,
    EN_COMM_ERRNO_OTHER_ERROR            = 0x8100000a,
    EN_COMM_ERRNO_UNSUPPORTED            = 0x8100000b,
    EN_COMM_ERRNO_SEND_MSG_ERROR         = 0x8100000c,
    EN_COMM_ERRNO_COMM_CHNL_ERROR        = 0x8100000d,
    EN_COMM_ERRNO_QUERY_MAC_ERROR        = 0x8100000e,
    EN_COMM_ERRNO_BUTT,
}EN_COMM_ERRNO;

#define RETURN_IS_ERROR(code) ((code & 0x81000000) == 0x81000000)

/* COMM outer header creation type */
typedef enum tag_EN_COMM_OUTH_RM_TYPE
{
    COMM_OUTH_RM_GTPU_UDP_IPV4          = 1,
    COMM_OUTH_RM_GTPU_UDP_IPV6          = 2,
    COMM_OUTH_RM_UDP_IPV4               = 3,
    COMM_OUTH_RM_UDP_IPV6               = 4,
    COMM_OUTH_RM_IPV4                   = 5,
    COMM_OUTH_RM_IPV6                   = 6,
    COMM_OUTH_RM_CTAG                   = 7,
    COMM_OUTH_RM_STAG                   = 8,
}EN_COMM_OUTH_RM_TYPE;

/* COMM outer header creation type */
typedef enum tag_EN_COMM_OUTH_CR_TYPE
{
    COMM_OUTH_CR_GTPU_UDP_IPV4          = 0x01,
    COMM_OUTH_CR_GTPU_UDP_IPV6          = 0x02,
    COMM_OUTH_CR_UDP_IPV4               = 0x04,
    COMM_OUTH_CR_UDP_IPV6               = 0x08,
    COMM_OUTH_CR_IPV4                   = 0x10,
    COMM_OUTH_CR_IPV6                   = 0x20,
    COMM_OUTH_CR_CTAG                   = 0x40,
    COMM_OUTH_CR_STAG                   = 0x80,
}EN_COMM_OUTH_CR_TYPE;

/* COMM outer header creation type */
typedef enum tag_EN_COMM_SRC_IF_TYPE
{
    EN_COMM_SRC_IF_ACCESS               = 0,
    EN_COMM_SRC_IF_CORE                 = 1,
    EN_COMM_SRC_IF_SGILAN               = 2,
    EN_COMM_SRC_IF_CP                   = 3,
    EN_COMM_SRC_IF_5GVN                 = 4,
    EN_COMM_SRC_IF_BUTT,
}EN_COMM_SRC_IF_TYPE;
#define COMM_SRC_IF_DN      (EN_COMM_SRC_IF_CORE)

typedef enum tag_EN_COMM_DST_IF_TYPE
{
    EN_COMM_DST_IF_ACCESS               = 0,
    EN_COMM_DST_IF_CORE                 = 1,
    EN_COMM_DST_IF_SGILAN               = 2,
    EN_COMM_DST_IF_CP                   = 3,
    EN_COMM_DST_IF_LI                   = 4,
    EN_COMM_DST_IF_5GVN                 = 5,
    EN_COMM_DST_IF_BUTT,
}EN_COMM_DST_IF_TYPE;

typedef enum tag_EN_PORT_TYPE{
    EN_PORT_N3,
    EN_PORT_N6,
    EN_PORT_N9,
    EN_PORT_N4,
    EN_PORT_BUTT,
}EN_PORT_TYPE;

typedef enum tag_EN_FP_STAT{
    COMM_MSG_FP_STAT_N3_MATCH,
    COMM_MSG_FP_STAT_N3_NOMATCH,
    COMM_MSG_FP_STAT_N3_ECHO,
    COMM_MSG_FP_STAT_N6_MATCH,
    COMM_MSG_FP_STAT_N6_NOMATCH,
    COMM_MSG_FP_STAT_MOD_FAST,
    COMM_MSG_FP_STAT_FROM_SPU,
    COMM_MSG_FP_STAT_REPORT_REQ,
    COMM_MSG_FP_STAT_ARP,
    COMM_MSG_FP_STAT_ICMP,
    COMM_MSG_FP_STAT_ROUTE,
    COMM_MSG_FP_STAT_UP_RECV,
    COMM_MSG_FP_STAT_UP_FWD,
    COMM_MSG_FP_STAT_UP_DROP,
    COMM_MSG_FP_STAT_DOWN_RECV,
    COMM_MSG_FP_STAT_DOWN_FWD,
    COMM_MSG_FP_STAT_DOWN_DROP,
    COMM_MSG_FP_STAT_UNSUPPORT_PKT,
    COMM_MSG_FP_STAT_ERR_PROC,
    COMM_MSG_FP_STAT_BUTT,
}EN_FP_STAT;

typedef enum tag_EN_INST_LIGHT {
    COMM_MSG_LIGHT_GREEN,
    COMM_MSG_LIGHT_YELLOW,
    COMM_MSG_LIGHT_RED,
    COMM_MSG_LIGHT_BUTT,
} EN_INST_LIGHT;

/* Fast table type */
typedef enum tag_EN_COMM_MSG_FAST_TYPE {
    COMM_MSG_FAST_IPV4,
    COMM_MSG_FAST_IPV6,
    COMM_MSG_FAST_MAC,
    COMM_MSG_FAST_BUTT,
} EN_COMM_MSG_FAST_TYPE;

/* General Information Element */
#pragma pack(1)
typedef struct tag_comm_msg_ie_t {
    uint16_t            len;            /* IE length, include len and cmd */
    uint16_t            cmd;            /* command */
    uint32_t            index;          /* index in table */
    uint8_t             data[0];        /* content */
}comm_msg_ie_t;
#pragma pack()
#define COMM_MSG_IE_LEN_COMMON      (8)

/* Delete rules related to node id */
#pragma pack(1)
typedef struct tag_comm_msg_rules_ie_t {
    uint16_t            len;            /* IE length, include len and cmd */
    uint16_t            cmd;            /* command */
    uint32_t            rules_num;      /* total number of index in the rule */
    uint8_t             data[0];        /* content */
}comm_msg_rules_ie_t;
#pragma pack()

/* Trans reply ACK rule ie */
#pragma pack(1)
typedef struct tag_comm_msg_trans_ack_ie_t {
    uint16_t            len;            /* IE length, include len and cmd */
    uint16_t            cmd;            /* command */
    uint32_t            ack_num;        /* total number of ack */
    uint16_t            ack[0];         /* content */
}comm_msg_trans_ack_ie_t;
#pragma pack()

/* General response ie */
#pragma pack(1)
typedef struct tag_comm_msg_sigtrace_ie_t {
    uint16_t            len;            /* IE length, include len and cmd */
    uint16_t            cmd;            /* command */
    uint32_t            index;          /* index in table */
    uint32_t            ueip;            /* sig trace by ueip */
}comm_msg_sigtrace_ie_t;
#pragma pack()
#define COMM_MSG_IE_LEN_SIGTRACE_SET	(sizeof(comm_msg_sigtrace_ie_t))

#pragma pack(1)
typedef struct tag_comm_msg_rules_resp_ie_t {
    uint16_t            len;            /* IE length, include len and cmd */
    uint16_t            cmd;            /* command */
    uint32_t            ret_num;        /* ret number */
	uint8_t             data[0];        /* content */
}comm_msg_rules_resp_ie_t;
#pragma pack()
#define COMM_MSG_IE_LEN_RULES_RESP		(8)

/* Use only when getting entry validity */
#pragma pack(1)
typedef struct tag_comm_msg_entry_val_config_t {
    uint32_t            start;          /* start index */
    uint32_t            entry_num;      /* resources total number */
    uint32_t            data[0];        /* content */
}comm_msg_entry_val_config_t;
#pragma pack()

/* Update light of instance */
typedef struct tag_comm_msg_update_inst_light_t {
    uint32_t            inst_index;     /* instance index */
    uint8_t             light;          /* light */
}comm_msg_update_inst_light_t;

/* Update collect thres of instance */
typedef struct tag_comm_msg_update_inst_thres_t {
    uint32_t            inst_index;     /* instance index */
    uint64_t            collect_thres;  /* collect thres */
}comm_msg_update_inst_thres_t;

typedef uint32_t (*COMM_PROCESS_MSG_CALLBACK)(void *trans, comm_msg_ie_t *ie);
typedef uint32_t (*COMM_PROCESS_MSG_COMMID_ERR)(void *trans, comm_msg_ie_t *ie, uint16_t new_commid);

/* Smart Nic Control Protocol */
/* Main message structure */
#pragma pack(1)
typedef struct tag_comm_msg_header_t {
    uint32_t            magic_word;     /* magic word */
    uint8_t             major_version;  /* major version */
    uint8_t             minor_version;  /* minor version */
    uint16_t            comm_id;        /* communication id */
    uint16_t            index;          /* packet index */
    uint16_t            answer;         /* answer peer index */
    uint32_t            total_len;      /* payload length */
    uint8_t             payload[0];     /* content(IE) */
}comm_msg_header_t;
#pragma pack()

#define COMM_MSG_HEADER_LEN         sizeof(comm_msg_header_t)
#define COMM_MSG_GET_IE(msg)     	((comm_msg_ie_t *)(msg->payload))
#define COMM_MSG_GET_RESP_IE(msg)   ((comm_msg_resp_ie_t *)(msg->payload))
#define COMM_MSG_GET_RULES_IE(msg)	((comm_msg_rules_ie_t *)(msg->payload))
#define COMM_MSG_GET_SIGTRACE_IE(msg)	((comm_msg_sigtrace_ie_t *)(msg->payload))

 /* Location description */
#pragma pack(1)
typedef struct tag_comm_msg_loc_desc_t {
    uint16_t            len;            /* IE length, should be 8 */
    uint16_t            cmd;            /* command, should be 1 */
    uint8_t             service_no;     /* service No. */
    uint8_t             port_no;        /* port No. 0 1 (2 3) */
    uint8_t             user_def1;      /* user define */
    uint8_t             user_def2;      /* user define */
}comm_msg_loc_desc_t;
#define COMM_MSG_IE_LEN_LOC_DESC    (sizeof(comm_msg_loc_desc_t))
#pragma pack()

/* General response ie */
#pragma pack(1)
typedef struct tag_comm_msg_resp_ie_t {
    uint16_t            len;            /* IE length, include len and cmd */
    uint16_t            cmd;            /* command */
    uint32_t            index;          /* index in table */
    uint32_t            ret;            /* ret of ie operation */
    uint64_t            flag_key;
}comm_msg_resp_ie_t;
#pragma pack()
#define COMM_MSG_IE_LEN_RESP          (sizeof(comm_msg_resp_ie_t))

/* local ip address */
#pragma pack(1)
typedef struct tag_comm_msg_ip_address {
    uint8_t         ip_version; /* 1:ipv4 2:ipv6 3:ipv4 and ipv6 */
    uint8_t         resv;       /* spare */
    uint8_t         ipv4_prefix;
    uint8_t         ipv6_prefix;
    uint32_t        ipv4;
    uint8_t         ipv6[IPV6_ALEN];
} comm_msg_ip_address;
#pragma pack()

/* fp configuration */
#pragma pack(1)
typedef struct tag_comm_msg_system_config_t {
    uint32_t            fast_num;       /* fast table size */
    uint32_t            fast_bucket_num;/* fast bucket size */
    uint32_t            session_num;    /* pdr table size */
    uint32_t            block_num;      /* table size */
    uint32_t            block_size;
    uint32_t            cblock_num;
    session_ip_addr     upf_ip[EN_PORT_BUTT];
    uint8_t             upf_mac[EN_PORT_BUTT][ETH_ALEN];
    uint32_t            dns_num;
}comm_msg_system_config_t;
#pragma pack()

/* fp qer packet rate status surplus */
#pragma pack(1)
typedef struct tag_comm_msg_qer_prss_t {
    uint64_t            up_seid;
    uint64_t            cp_seid;
    uint32_t            validity_time;
    uint16_t            ul_pkts;    /* pdr table size */
    uint16_t            dl_pkts;    /* table size */
    uint32_t            seq_num;
    uint8_t             msg_type;   /* Actions to take after receiving a reply */
    uint8_t             node_index;
    struct {
#if BYTE_ORDER == BIG_ENDIAN
            uint8_t                 spare   :6;
            uint8_t                 f_up    :1; /* ul_pkt_max */
            uint8_t                 f_dp    :1; /* dl_pkt_max */
#else
            uint8_t                 f_dp    :1;
            uint8_t                 f_up    :1;
            uint8_t                 spare   :6;
#endif
    } s;
    uint8_t             resv;
}comm_msg_qer_prss_t;
#pragma pack()


/* fast table
    comm_msg_header_t
        |
        |
        v
    comm_msg_ie_t(comm_msg_fast_ie_t)
        |
        |
        v
    comm_msg_fast_cfg_ipv4/ipv6/mac
        |
        |
        v
    struct ipv4_key/ipv6/mac
*/

/* Fast entry ie description */
#pragma pack(1)
typedef struct tag_comm_msg_fast_ie_t {
    uint16_t            len;            /* IE length, include len and cmd */
    uint16_t            cmd;            /* command */
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t            table:4;        /* which table, ipv4(0)/ipv6(1)/mac(2)*/
    uint32_t            index:28;       /* index in table */
#else
    uint32_t            index:28;       /* index in table */
    uint32_t            table:4;        /* which table, ipv4(0)/ipv6(1)/mac(2)*/
#endif
    uint8_t             data[1];        /* user define */
}comm_msg_fast_ie_t;
#pragma pack()

/* Configuration data of fast table */
#pragma pack(1)
typedef struct  tag_comm_msg_fast_cfg {
    uint8_t             dst_mac[6];     /* next hop mac */
    struct {
    #if BYTE_ORDER == BIG_ENDIAN
        uint8_t         temp_flag:  1;   /* 1:fist packet sent to sp, 0:normal */
        uint8_t         tcp_push:   1;   /* 1:check push flag, sent to sp again.  0:normal */
        uint8_t         is_tcp:     1;   /* 1: Is tcp packet, 0: Other */
        uint8_t         resv:       5;
    #else
        uint8_t         resv:       5;
        uint8_t         is_tcp:     1;   /* 1: Is tcp packet, 0: Other */
        uint8_t         tcp_push:   1;   /* 1:check push flag, sent to sp again.  0:normal */
        uint8_t         temp_flag:  1;   /* 1:fist packet sent to sp, 0:normal */
    #endif
    };
    uint8_t             pdr_si;          /* pdr source interface */
    uint32_t            inst_index;      /* relative inst table index */
    uint32_t            far_index;       /* relative far table index */
	uint32_t            head_enrich_flag;/* use for head enrich */
    uint8_t             n6port_index;    /* Route select the target N6 port for up stream. */
    uint8_t             spare;
    ros_atomic16_t      tcp_hs_stat;     /* Statistics of TCP handshake traffic */
}
comm_msg_fast_cfg;
#pragma pack()
#define COMM_MSG_IE_LEN_FAST        sizeof(comm_msg_fast_cfg)

#pragma pack(1)
typedef struct  tag_comm_msg_fast_detail_mac {
    uint8_t             dst_mac[COMM_MSG_MAC_LEN];    /* destination address. */
    uint8_t             src_mac[COMM_MSG_MAC_LEN];    /* source address. */
}comm_msg_fast_detail_mac;
#pragma pack()

#define CACHE_LINE_SIZE   (128)
#define ENTRY_COMMON_LEN  (28)
#define COMM_MSG_FAST_ENTRY_NUM(ie_len) \
    (((ie_len) - COMM_MSG_IE_LEN_COMMON + \
    ENTRY_COMMON_LEN + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE)



/* instance table
    comm_msg_header_t
        |
        |
        v
    comm_msg_ie_t
        |
        |
        v
    comm_msg_inst_config
        |
        |
        |____________________________________________________
        |                |                |                 |
        v                v                v                 v
      far_index        bar_index        urr_index         qer_index
*/

typedef union {
    struct tag_comm_msg_inst_choose_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         flag_rm_header  : 1;   /* remove outer header */
        uint8_t         flag_far1       : 1;   /* include far id */
        uint8_t         flag_far2       : 1;   /* include far id */
        uint8_t         flag_urr        : 1;   /* include urr id  */
        uint8_t         flag_qer        : 1;   /* include qer id */
        uint8_t         flag_bearer_net : 2;   /* 0:IP  1:Ethernet  2:Unstructured */
        uint8_t         flag_ueip_type  : 1;   /* 0:IPv4  1:IPv6 */
#else
        uint8_t         flag_ueip_type  : 1;   /* 0:IPv4  1:IPv6 */
        uint8_t         flag_bearer_net : 2;   /* 0:IP  1:Ethernet  2:Unstructured */
        uint8_t         flag_qer        : 1;   /* include qer id */
        uint8_t         flag_urr        : 1;   /* include urr id  */
        uint8_t         flag_far2       : 1;   /* include far id */
        uint8_t         flag_far1       : 1;   /* include far id */
        uint8_t         flag_rm_header  : 1;   /* remove outer header */
#endif
    }d;
    uint8_t value;
}comm_msg_inst_choose_t;

/* Outer header removal */
#pragma pack(1)
typedef struct tag_comm_msg_outh_rm_t {
    uint8_t             type;           /* Type: 0 GTP-U/UDP/IPv4,
                                             1 GTP-U/UDP/IPv6,
                                             2 UDP/IPv4,
                                             3 UDP/IPv6,
                                             4 IPv4,
                                             5 IPv6,
                                             6 GTP-U/UDP/IP,
                                             7 VLAN S-TAG,
                                             8 S-TAG and C-TAG */
    uint8_t             flag;           /* Extention header deletion flag */
    uint8_t             ohr_flag;       /* outer header removal present */
    uint8_t             resv;
}comm_msg_outh_rm_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_user_info_t {
	session_user_id		user_id;
	session_ue_ip   	ue_ipaddr[MAX_UE_IP_NUM];
	session_apn_dnn 	apn_dnn;
	session_rat_type    rat_type;
    session_user_location_info      user_local_info;
}comm_msg_user_info_t;
#pragma pack()

#pragma pack(1)
typedef struct  tag_comm_msg_inst_config
{
    uint8_t             immediately_act; /* immediately active */
    comm_msg_inst_choose_t choose;
    uint8_t             urr_number;     /* how many item is effective */
    uint8_t             qer_number;     /* how many item is effective */
    comm_msg_outh_rm_t  rm_outh;
    union {
        uint32_t                    ipv4;
        uint8_t                     ipv6[IPV6_ALEN];
    } ueip; /* IP type in the 'choose'  */

    uint32_t            far_index1;     /* far */
    uint32_t            far_index2;     /* far */
    uint32_t            urr_index[MAX_URR_NUM];  /* urr */
    uint32_t            qer_index[MAX_QER_NUM];  /* qer */
    uint32_t            inact; /* inactivity count */
    uint32_t            max_act; /* Maximum activation time */
    comm_msg_user_info_t	user_info; /*use for head enrich user info*/

    uint64_t            collect_thres;  /*how many bytes fpu update state to spu*/
}comm_msg_inst_config;
#pragma pack()

/* far table
    comm_msg_header_t
        |
        |
        v
    comm_msg_ie_t
        |
        |
        v
    comm_msg_far_config
        |
        |
        v
    far_id
    comm_msg_far_action_t
    comm_msg_dest_if_t
    comm_msg_far_choose_t
    comm_msg_outh_cr_t
    comm_msg_redirect_addr_t
    comm_msg_transport_level_t
    comm_msg_header_enrichment_t
    comm_msg_transport_level_t
    comm_msg_outh_cr_t
*/

typedef union {
    struct tag_comm_msg_far_choose_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t    section_forwarding   : 1;   /* Forwarding parameter */
        uint16_t    flag_redirect        : 3;   /* Redirect Information, 1:IPv4 2:IPv6 3:URL 4:SIP URL 5:IPv4&IPv6 */
        uint16_t    flag_transport_level1: 1;   /* Transport Level Marking*/
        uint16_t    flag_forward_policy1 : 1;   /* Forwarding Policy  */
        uint16_t    flag_header_enrich   : 1;   /* header enrichment */
        uint16_t    flag_out_header1     : 1;   /* Outer header creation */
        uint16_t    section_bar          : 1;   /* Include bar */
        uint16_t    section_dupl_num     : 5;   /* Duplicating parameters */
        uint16_t    entry_num            : 2;   /* Entry number,
                                                   0: 1, 1: 2, 2: 4, 3: 8 */
#else
        uint16_t    entry_num            : 2;   /* Entry number,
                                                   0: 1, 1: 2, 2: 4, 3: 8 */
        uint16_t    section_dupl_num     : 5;   /* Duplicating parameters */
        uint16_t    section_bar          : 1;   /* Include bar */
        uint16_t    flag_out_header1     : 1;   /* Outer header creation */
        uint16_t    flag_header_enrich   : 1;   /* header enrichment */
        uint16_t    flag_forward_policy1 : 1;   /* Forwarding Policy  */
        uint16_t    flag_transport_level1: 1;   /* Transport Level Marking*/
        uint16_t    flag_redirect        : 3;   /* Redirect Information, 1:IPv4 2:IPv6 3:URL 4:SIP URL 5:IPv4&IPv6 */
        uint16_t    section_forwarding   : 1;   /* Forwarding parameter */
#endif
    }d;
    uint16_t            value;          /* value in integer */
}comm_msg_far_choose_t;

typedef union {
    struct tag_comm_msg_dupl_choose_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare                : 5;
        uint8_t     flag_out_header      : 1;   /* Outer header creation */
        uint8_t     flag_transport_level : 1;   /* Transport Level Marking*/
        uint8_t     flag_forward_policy  : 1;   /* Forwarding Policy  */
#else

        uint8_t     flag_forward_policy  : 1;   /* Forwarding Policy  */
        uint8_t     flag_transport_level : 1;   /* Transport Level Marking*/
        uint8_t     flag_out_header      : 1;   /* Outer header creation */
        uint8_t     spare                : 5;
#endif
    }d;
    uint8_t            value;          /* value in integer */
}comm_msg_dupl_choose_t;

/* Action */
#pragma pack(1)
typedef union {
    struct tag_comm_msg_far_action_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spar: 3;        /* not define */
        uint8_t         dupl: 1;        /* duplicate */
        uint8_t         nocp: 1;        /* notify */
        uint8_t         buff: 1;        /* buffering */
        uint8_t         forw: 1;        /* forward */
        uint8_t         drop: 1;        /* drop */
#else
        uint8_t         drop: 1;        /* drop */
        uint8_t         forw: 1;        /* forward */
        uint8_t         buff: 1;        /* buffering */
        uint8_t         nocp: 1;        /* notify */
        uint8_t         dupl: 1;        /* duplicate */
        uint8_t         spar: 3;        /* not define */
#endif
    }d;
    uint8_t             value;          /* value in integer */
}comm_msg_far_action_t;
#pragma pack()

/* Redirect address can be configured as IPv4/IPv6/URL/SIP URL/IPv4 and IPv6 */
#pragma pack(1)
typedef union {
    struct tag_comm_msg_vlan_flags_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   : 5;
        uint8_t         pcp     : 1;
        uint8_t         dei     : 1;
        uint8_t         vid     : 1;
#else
        uint8_t         vid     : 1;
        uint8_t         dei     : 1;
        uint8_t         pcp     : 1;
        uint8_t         spare   : 5;
#endif
    }d;
    uint8_t             value;
}comm_msg_vlan_flags_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_vlan_tag_t {
    comm_msg_vlan_flags_t       vlan_flag;
    uint8_t                     spare;
    union vlan_tci              vlan_value;
}comm_msg_vlan_tag_t;

#pragma pack(1)
typedef union {
    struct tag_comm_msg_outh_cr_type_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t            stag        : 1;
        uint16_t            ctag        : 1;
        uint16_t            ipv6        : 1;
        uint16_t            ipv4        : 1;
        uint16_t            udp_ipv6    : 1;
        uint16_t            udp_ipv4    : 1;
        uint16_t            gtp_udp_ipv6: 1;
        uint16_t            gtp_udp_ipv4: 1;
        uint16_t            resv        : 8;
#else
        uint16_t            resv        : 8;
        uint16_t            gtp_udp_ipv4: 1;
        uint16_t            gtp_udp_ipv6: 1;
        uint16_t            udp_ipv4    : 1;
        uint16_t            udp_ipv6    : 1;
        uint16_t            ipv4        : 1;
        uint16_t            ipv6        : 1;
        uint16_t            ctag        : 1;
        uint16_t            stag        : 1;
#endif
    }d;
    uint16_t            value;
}comm_msg_outh_cr_type_t;
#pragma pack()

/* Outerheader */
#pragma pack(1)
typedef struct tag_comm_msg_outh_cr_t {
    /* SP should keep type just one bit set */
    comm_msg_outh_cr_type_t     type;   /* Type: 0x100 GTP-U/UDP/IPv4,
                                                 0x200 GTP-U/UDP/IPv6,
                                                 0x400 UDP/IPv4,
                                                 0x800 UDP/IPv6,
                                                 0x1000 IPv4,
                                                 0x2000 IPv6,
                                                 0x4000 C-TAG,
                                                 0x8000 S-TAG */
    uint16_t            port;           /* Port */
    uint32_t            teid;           /* TEID */
    struct in6_addr     ipv6;           /* IPv6 */
    uint32_t            ipv4;           /* IPv4 */
    comm_msg_vlan_tag_t ctag;           /* C-TAG */
    comm_msg_vlan_tag_t stag;           /* S-TAG */
    uint8_t             resv[4];        /* keep to align 8 bytes */
}comm_msg_outh_cr_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_transport_level_t {
    uint8_t             tos;            /* IPv4 Tos/IPv6 traffic class */
    uint8_t             mask;           /* Mask */
    uint8_t             resv[2];
}comm_msg_transport_level_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_header_enrichment_t {
    uint16_t            name_length;    /* Length of Header Field Name */
    uint16_t            value_length;   /* Length of Header Field Value */
    char                name[256];      /* Header Field Name */
    char                value[256];     /* Header Field Value */
}comm_msg_header_enrichment_t;
#pragma pack()

/* duplicating parameter configuration */
#pragma pack(1)
typedef struct  tag_comm_msg_dupl_config
{
    uint8_t                         dupl_if;    /* duplicate port */
    comm_msg_dupl_choose_t          choose;     /* FAR id */
    comm_msg_transport_level_t      trans;
    comm_msg_outh_cr_t              cr_outh;
}comm_msg_dupl_config;
#pragma pack()

/* far configuration */
#pragma pack(1)
typedef struct  tag_comm_msg_far_config
{
    uint32_t                        far_id;     /* FAR id */
    comm_msg_far_action_t           action;     /* action */
    uint8_t                         forw_if;    /* forward interface */
    comm_msg_far_choose_t           choose;

    comm_msg_outh_cr_t              forw_cr_outh;
    comm_msg_transport_level_t      forw_trans;
    session_redirect_server         forw_redirect;
    comm_msg_header_enrichment_t    forw_enrich;
    uint32_t                        bar_index;  /* include bar cfg */
#ifdef FAR_DUPL_ENABLE
    comm_msg_dupl_config            dupl_cfg[MAX_DUPL_PARAM_NUM];
#endif
}comm_msg_far_config;
#pragma pack()



/* bar table
    comm_msg_header_t
        |
        |
        v
    comm_msg_ie_t
        |
        |
        v
    comm_msg_bar_config
*/

/*
Timer value
Bits 5 to 1 represent the binary coded timer value
Timer unit
Bits 6 to 8 defines the timer value unit as follows:
Bits
8 7 6
0 0 0  value is incremented in multiples of 2 seconds
0 0 1  value is incremented in multiples of 1 minute
0 1 0  value is incremented in multiples of 10 minutes
0 1 1  value is incremented in multiples of 1 hour
1 0 0  value is incremented in multiples of 10 hours
1 1 1  value indicates that the timer is infinite
*/
#pragma pack(1)
typedef union tag_comm_msg_bar_time_t {
	struct {
#if BYTE_ORDER == BIG_ENDIAN
	    uint8_t             unit :3;        /* timer unit */
	    uint8_t             value:5;        /* timer value */
#else
	    uint8_t             value:5;        /* timer value */
	    uint8_t             unit :3;        /* timer unit */
#endif
	} d;
	uint8_t value;
}comm_msg_bar_time_t;
#pragma pack()

/* Buffering configuration */
#pragma pack(1)
typedef struct  tag_comm_msg_bar_config
{
    uint8_t             bar_id;
    uint8_t             notify_delay;   /* Downlink Data Notification Delay */
    uint16_t            pkts_max;       /* max buffer packets */
    uint32_t            time_max;       /* max buffer time */
}comm_msg_bar_config;
#pragma pack()



/* urr table
    comm_msg_header_t
        |
        |
        v
    comm_msg_ie_t
        |
        |
        v
    comm_msg_urr_config
*/

#pragma pack(1)
typedef union {
    struct tag_comm_msg_urr_method_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare:5;        /* spare */
        uint8_t         event:1;        /* measuring events */
        uint8_t         volum:1;        /* measuring traffic volume */
        uint8_t         durat:1;        /* measuring traffic duration */
#else
        uint8_t         durat:1;        /* measuring traffic duration */
        uint8_t         volum:1;        /* measuring traffic volume */
        uint8_t         event:1;        /* measuring events */
        uint8_t         spare:5;        /* spare */
#endif
    }d;
    uint8_t value;
}comm_msg_urr_method_t;
#pragma pack()

#pragma pack(1)
typedef union {
    struct tag_comm_msg_urr_drop_flag_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare:6;        /* spare */
        uint8_t         dlby :1;        /* bytes of downlink data field */
        uint8_t         dlpa :1;        /* downlink packets field */
#else
        uint8_t         dlpa :1;        /* downlink packets field */
        uint8_t         dlby :1;        /* bytes of downlink data field */
        uint8_t         spare:6;        /* spare */
#endif
    }d;
    uint8_t value;
}comm_msg_urr_drop_flag_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_urr_drop_thres_t {
    comm_msg_urr_drop_flag_t        flag;
    uint8_t                         resv[7];
    uint64_t                        packets;    /* in packet */
    uint64_t                        bytes;      /* in bytes */
}comm_msg_urr_drop_thres_t;
#pragma pack()

#pragma pack(1)
typedef union {
    struct tag_comm_msg_urr_vol_flag_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare:5;        /* spare */
        uint8_t         dlvol:1;        /* downlink volume */
        uint8_t         ulvol:1;        /* uplink volume */
        uint8_t         tovol:1;        /* total volume */
#else
        uint8_t         tovol:1;        /* total volume */
        uint8_t         ulvol:1;        /* uplink volume */
        uint8_t         dlvol:1;        /* downlink volume */
        uint8_t         spare:5;        /* spare */
#endif
    }d;
    uint8_t value;
}comm_msg_urr_vol_flag_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_urr_volume_t {
    comm_msg_urr_vol_flag_t         flag;
    uint8_t                         resv[7];
    uint64_t                        total;      /* in byte */
    uint64_t                        uplink;
    uint64_t                        downlink;
}comm_msg_urr_volume_t;
#pragma pack()

#pragma pack(1)
typedef union {
    struct tag_comm_msg_urr_measu_info_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare:4;        /* spare */
        uint8_t         istm:1;         /* Immediate start time metering */
        uint8_t         radi:1;         /* reduced app detection info */
        uint8_t         inam:1;         /* inactive measurement */
        uint8_t         mbqe:1;         /* measure before qos enforcement */
#else
        uint8_t         mbqe:1;         /* measure before qos enforcement */
        uint8_t         inam:1;         /* inactive measurement */
        uint8_t         radi:1;         /* reduced app detection info */
        uint8_t         istm:1;         /* Immediate start time metering */
        uint8_t         spare:4;        /* spare */
#endif
    }d;
    uint8_t value;
}comm_msg_urr_measu_info_t;
#pragma pack()

#pragma pack(1)
typedef union {
    struct tag_comm_msg_urr_usage_info_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare:4;        /* spare */
        uint8_t         ube:1;          /* usage before Qos enforcement */
        uint8_t         uae:1;          /* usage after Qos enforcement */
        uint8_t         aft:1;          /* usage after a monitoring time */
        uint8_t         bef:1;          /* usage before a monitoring time */
#else
        uint8_t         bef:1;          /* usage before a monitoring time */
        uint8_t         aft:1;          /* usage after a monitoring time */
        uint8_t         uae:1;          /* usage after Qos enforcement */
        uint8_t         ube:1;          /* usage before Qos enforcement */
        uint8_t         spare:4;        /* spare */
#endif
    }d;
    uint8_t value;
}comm_msg_urr_usage_info_t;
#pragma pack()

typedef enum {
    COMM_MSG_URR_MAC_TYPE_NEW,
    COMM_MSG_URR_MAC_TYPE_OBS,
}comm_msg_urr_mac_type;

#pragma pack(1)
typedef struct tag_comm_msg_urr_mac_t {
    uint8_t             mac_num;
    uint8_t             type;       /* 0: new, 1: obs. comm_msg_urr_mac_type */
    uint8_t             resv[6];
    uint64_t            mac[1];
}comm_msg_urr_mac_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_urr_app_detect_t {
    uint32_t            stub;
}comm_msg_urr_app_detect_t;
#pragma pack()

#pragma pack(1)
typedef union {
    struct tag_comm_msg_urr_ue_ip_type_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare:4;        /* spare */
        uint8_t         ipv6d:1;        /* ipv6 prefix delegation bits */
        uint8_t         sd:1;           /* source or destination */
        uint8_t         v4:1;           /* ipv4 */
        uint8_t         v6:1;           /* ipv6 */
#else
        uint8_t         v6:1;           /* ipv6 */
        uint8_t         v4:1;           /* ipv4 */
        uint8_t         sd:1;           /* source or destination */
        uint8_t         ipv6d:1;        /* ipv6 prefix delegation bits */
        uint8_t         spare:4;        /* spare */
#endif
    }d;
    uint8_t value;
}comm_msg_urr_ue_ip_type_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_urr_ue_ip_t {
    comm_msg_urr_ue_ip_type_t       type;
    uint8_t                         ipv6_prefix_bits;
    uint8_t                         resv1[2];
    uint32_t                        ipv4;
    struct in6_addr                 ipv6;
}comm_msg_urr_ue_ip_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_urr_aggregate_t {
    uint32_t            agg_urr;        /* aggregated urr id */
    uint32_t            exponent;       /* multiplier */
    uint64_t            value_digits;   /* multiplier */
}comm_msg_urr_aggregate_t;
#pragma pack()

#pragma pack(1)
/* Used for report */
typedef union {
    struct tag_comm_msg_urr_usage_report_trigger_t {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare_b4:8;     /* spare */

        uint32_t        immer:1;        /* immediate report */
        uint32_t        droth:1;        /* dropped dl traffic threshold */
        uint32_t        stopt:1;        /* stop of traffic */
        uint32_t        start:1;        /* start of traffic */
        uint32_t        quhti:1;        /* quota holding time */
        uint32_t        timth:1;        /* time threshold */
        uint32_t        volth:1;        /* volume threshold */
        uint32_t        perio:1;        /* periodic reporting */

        uint32_t        eveth:1;        /* event threshold */
        uint32_t        macar:1;        /* mac address reporting */
        uint32_t        envcl:1;        /* envelope closure */
        uint32_t        monit:1;        /* monitoring time */
        uint32_t        termr:1;        /* termination report */
        uint32_t        liusa:1;        /* linked usage reporting */
        uint32_t        timqu:1;        /* time quota */
        uint32_t        volqu:1;        /* volume quota */

        uint32_t        spare_b1:6;     /* spare */
        uint32_t        tebur:1;        /* Termination By UP function Report */
        uint32_t        evequ:1;        /* event quota */
#else
        uint32_t        evequ:1;        /* event quota */
        uint32_t        tebur:1;        /* Termination By UP function Report */
        uint32_t        spare_b1:6;     /* spare */

        uint32_t        volqu:1;        /* volume quota */
        uint32_t        timqu:1;        /* time quota */
        uint32_t        liusa:1;        /* linked usage reporting */
        uint32_t        termr:1;        /* termination report */
        uint32_t        monit:1;        /* monitoring time */
        uint32_t        envcl:1;        /* envelope closure */
        uint32_t        macar:1;        /* mac address reporting */
        uint32_t        eveth:1;        /* event threshold */

        uint32_t        perio:1;        /* periodic reporting */
        uint32_t        volth:1;        /* volume threshold */
        uint32_t        timth:1;        /* time threshold */
        uint32_t        quhti:1;        /* quota holding time */
        uint32_t        start:1;        /* start of traffic */
        uint32_t        stopt:1;        /* stop of traffic */
        uint32_t        droth:1;        /* dropped dl traffic threshold */
        uint32_t        immer:1;        /* immediate report */

        uint32_t        spare_b4:8;     /* spare */
#endif
    }d;
    uint32_t value;
}comm_msg_urr_usage_report_trigger_t;
#pragma pack()

#pragma pack(1)
/* Used for trigger action to collect info in fp */
typedef union {
    struct tag_comm_msg_urr_reporting_trigger_t
    {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t        liusa:1;        /* linked usage reporting */
        uint16_t        droth:1;        /* dropped dl traffic threshold */
        uint16_t        stopt:1;        /* stop of traffic */
        uint16_t        start:1;        /* start of traffic */
        uint16_t        quhti:1;        /* quota holding time */
        uint16_t        timth:1;        /* time threshold */
        uint16_t        volth:1;        /* time threshold */
        uint16_t        perio:1;        /* periodic reporting */

        uint16_t        spare:2;        /* spare */
        uint16_t        evequ:1;        /* event quota */
        uint16_t        eveth:1;        /* event threshold */
        uint16_t        macar:1;        /* mac address reporting */
        uint16_t        envcl:1;        /* envelope closure */
        uint16_t        timqu:1;        /* time quota */
        uint16_t        volqu:1;        /* volume quota */
#else
        uint16_t        volqu:1;        /* volume quota */
        uint16_t        timqu:1;        /* time quota */
        uint16_t        envcl:1;        /* envelope closure */
        uint16_t        macar:1;        /* mac address reporting */
        uint16_t        eveth:1;        /* event threshold */
        uint16_t        evequ:1;        /* event quota */
        uint16_t        spare:2;        /* spare */

        uint16_t        perio:1;        /* periodic reporting */
        uint16_t        volth:1;        /* time threshold */
        uint16_t        timth:1;        /* time threshold */
        uint16_t        quhti:1;        /* quota holding time */
        uint16_t        start:1;        /* start of traffic */
        uint16_t        stopt:1;        /* stop of traffic */
        uint16_t        droth:1;        /* dropped dl traffic threshold */
        uint16_t        liusa:1;        /* linked usage reporting */
#endif
    }d;
    uint16_t value;
}comm_msg_urr_reporting_trigger_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_urr_mon_time_t {
    uint32_t                        mon_time;       /* UTC time */
    comm_msg_urr_volume_t           sub_vol_thres;  /* multiplier */
    uint32_t                        sub_tim_thres;			/*同时带门限和配额的情况下，每次上报会递增*/
	uint32_t                        sub_tim_thres_fixed;	/*下发的门限*/
    comm_msg_urr_volume_t           sub_vol_quota;
    uint32_t                        sub_tim_quota;
    uint32_t                        sub_eve_thres;
    uint32_t                        sub_eve_quota;
}comm_msg_urr_mon_time_t;
#pragma pack()

#pragma pack(1)
typedef struct  tag_comm_msg_urr_config
{
    uint32_t                        urr_id;
	uint32_t						ur_seqn;
    comm_msg_urr_method_t           method;
    uint8_t                         quota_far_present;  /* quota_far validity */
    comm_msg_urr_reporting_trigger_t trigger;
    uint32_t                        period;     /* in second */
    comm_msg_urr_volume_t           vol_thres;
    comm_msg_urr_volume_t           vol_quota;
    uint32_t                        eve_thres;
    uint32_t                        eve_quota;
    uint32_t                        tim_thres;  /* in second */
    uint32_t                        tim_quota;  /* in second */
    uint32_t                        quota_hold; /* in second */
    comm_msg_urr_drop_thres_t       drop_thres; /* drop DL traffic threshold */
    uint32_t                        mon_time;   /* UTC time,seconds from 1970 */
    comm_msg_urr_volume_t           sub_vol_thres;
    uint32_t                        sub_tim_thres;
    comm_msg_urr_volume_t           sub_vol_quota;
    uint32_t                        sub_tim_quota;
    uint32_t                        sub_eve_thres;
    uint32_t                        sub_eve_quota;
    uint32_t                        inact_detect;
    comm_msg_urr_measu_info_t       measu_info;
    uint32_t                        quota_far;
    uint32_t                        eth_inact_time;
    uint16_t                        linked_urr_number;
    uint16_t                        add_mon_time_number;
    uint32_t                        linked_urr[MAX_URR_NUM];
    comm_msg_urr_mon_time_t         add_mon_time[MAX_ADDED_MONITOR_TIME_NUM];
}comm_msg_urr_config;
#pragma pack()

#pragma pack(1)
/* Usage Report IE within PFCP Session Deletion Response */
typedef struct tag_comm_msg_urr_report_t
{
    uint32_t                        urr_id;
	uint32_t                        urr_index;
    uint32_t                        ur_seqn;
    comm_msg_urr_usage_report_trigger_t trigger;
    uint32_t                        start_time;     /* UTC time */
    uint32_t                        end_time;       /* UTC time */
    comm_msg_urr_volume_t           vol_meas;
    uint32_t                        tim_meas;       /* in second */
	uint32_t						tim_meas_present;
    comm_msg_urr_app_detect_t       app_detect;     /* a stub */
    comm_msg_urr_ue_ip_t            ue_ip;
    uint32_t                        network_instance; /* stub */
    uint32_t                        first_pkt_time; /* UTC time */
    uint32_t                        last_pkt_time;  /* UTC time */
    comm_msg_urr_usage_info_t       usage_info;
    uint32_t                        query_urr_ref;
    uint32_t                        eve_stamp;      /* UTC time */
}comm_msg_urr_report_t;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_urr_stat_t{
    ros_atomic64_t      forw_pkts;      /* packets */
    ros_atomic64_t      forw_bytes;     /* bytes */
    ros_atomic64_t      drop_pkts;      /* packets */
    ros_atomic64_t      drop_bytes;     /* bytes */
    ros_atomic64_t      err_cnt;        /* error count */
}comm_msg_urr_stat_t;
#pragma pack()

/* Send to spu URR status */
typedef struct tag_comm_msg_urr_stat_conf_t{
    comm_msg_urr_stat_t urr_stat;       /* URR status data */
    uint32_t            inst_index;     /* instance entry index */
}comm_msg_urr_stat_conf_t;



/* qer table
    comm_msg_header_t
        |
        |
        v
    comm_msg_ie_t
        |
        |
        v
    comm_msg_qer_config
*/

#pragma pack(1)
/* test case
gtpu_ext_tmp.ext_len                = 8;    // 8 12 16
gtpu_ext_tmp.content.s.ext_header   = 0x85;
gtpu_ext_tmp.content.s.len          = 1;    // 1 2 3
gtpu_ext_tmp.content.s.pdu_type     = 0;
gtpu_ext_tmp.content.s.qmp          = 0;
gtpu_ext_tmp.content.s.ppp          = 0;
gtpu_ext_tmp.content.s.rqi          = 1;
gtpu_ext_tmp.content.s.qfi          = 3;

gtpu_ext_tmp.content.s.ppi          = 0;
gtpu_ext_tmp.content.s.time_stamp   = 0x12345678;
*/

typedef union tag_comm_msg_gtpu_ext_ppi_field {
    uint8_t                     data;
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t                 ppi     :3;
        uint8_t                 spare5  :5;
#else
        uint8_t                 spare5  :5;
        uint8_t                 ppi     :3;
#endif
    }s;
}comm_msg_gtpu_ext_ppi_field;

typedef struct tag_comm_msg_qer_gtpu_ext
{
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t                 ext_len:5; /* extention header length, by bytes */
    uint8_t                 ts_ofs :3; /* Offset of time stamp field in optional[8] */
#else
    uint8_t                 ts_ofs :3;
    uint8_t                 ext_len:5;
#endif

    union {
        uint8_t                     data[15];   /* pure data, need copy to packet */
        struct {
            uint8_t                 resv2[3];   /* Sequence Number:2bytes N-PDU Number:1bytes Default set 0 */
            uint8_t                 ext_header; /* 0x85 */
            uint8_t                 len;        /* after this, 4bytes:1, 8bytes:2 */
#if BYTE_ORDER == BIG_ENDIAN
            uint8_t                 pdu_type:4; /* 0 */
            uint8_t                 qmp     :1; /* if 1, need take time stamp */
            uint8_t                 spare1  :3;
#else
            uint8_t                 spare1  :3;
            uint8_t                 qmp     :1; /* if 1, need take time stamp */
            uint8_t                 pdu_type:4; /* 0 */
#endif

#if BYTE_ORDER == BIG_ENDIAN
            uint8_t                 ppp     :1;
            uint8_t                 rqi     :1;
            uint8_t                 qfi     :6;
#else
            uint8_t                 qfi     :6;
            uint8_t                 rqi     :1;
            uint8_t                 ppp     :1;
#endif

            uint8_t                 optional[8]; /**
                                                  * PPI field: 0 or 1 octets
                                                  * time_stamp: 0 or 4 octets,second number from 0 h 1 January 1900 UTC
                                                  * Padding: 0~3 octets
                                                  **/
        }s;
    }content;
}comm_msg_qer_gtpu_ext;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_meter_trtcm_params
{
    uint64_t cir;       /**< Committed Information Rate (CIR). Measured in bytes per second. */
	uint64_t pir;       /**< Peak Information Rate (PIR). Measured in bytes per second. */
	uint64_t cbs;       /**< Committed Burst Size (CBS). Measured in bytes. */
	uint64_t pbs;       /**< Peak Burst Size (PBS). Measured in bytes. */
} comm_msg_meter_trtcm_params;
#pragma pack()

#pragma pack(1)
typedef struct  tag_comm_msg_qer_config
{
    union {
        uint8_t                     data;       /* pure data, need copy to packet */
        struct {
#if BYTE_ORDER == BIG_ENDIAN
            uint8_t                 f_um    :1; /* ul_mbr */
            uint8_t                 f_ug    :1; /* ul_gbr */
            uint8_t                 f_up    :1; /* ul_pkt_max */
            uint8_t                 spare1  :1;
            uint8_t                 f_dm    :1; /* dl_mbr */
            uint8_t                 f_dg    :1; /* dl_gbr */
            uint8_t                 f_dp    :1; /* dl_pkt_max */
            uint8_t                 spare2  :1;
#else
            uint8_t                 spare2  :1;
            uint8_t                 f_dp    :1;
            uint8_t                 f_dg    :1;
            uint8_t                 f_dm    :1;
            uint8_t                 spare1  :1;
            uint8_t                 f_up    :1;
            uint8_t                 f_ug    :1;
            uint8_t                 f_um    :1;
#endif
        }s;
    }flag;
    uint8_t                         resv1[1];
    uint8_t                         ul_gate;
    uint8_t                         dl_gate;

    uint64_t                        ul_mbr;     /* uplink max bit rate */
    uint64_t                        ul_gbr;     /* uplink guaranteed bit rate */
    uint32_t                        ul_pkt_max; /* uplink maximum allowed rate */

    uint64_t                        dl_mbr;     /* downlink max bit rate */
    uint64_t                        dl_gbr;     /* downlink guaranteed bit rate */
    uint32_t                        dl_pkt_max; /* downlink maximum allowed rate */

    uint32_t                        valid_time; /* from packet rate status, Rate Control Status Validity Time */

    comm_msg_qer_gtpu_ext           gtpu_ext;   /* gtpu extension */

	uint32_t                        qer_id;
	uint8_t                         ul_flag;
    uint8_t                         dl_flag;
	comm_msg_meter_trtcm_params     ul_params;
    comm_msg_meter_trtcm_params     dl_params;
}comm_msg_qer_config;
#pragma pack()

/* dns table
    comm_msg_header_t
        |
        |
        v
    comm_msg_ie_t
        |
        |
        v
    comm_msg_dns_config
*/
#define COMM_MSG_DNS_IP_NUM             (2)
#define COMM_MSG_DNS_NAME_LENG          128

enum EN_COMM_MSG_DNS_IP_VERSION {
    EN_DNS_IPV4     = 1,
    EN_DNS_IPV6     = 2,
};

#pragma pack(1)
typedef struct tag_comm_msg_dns_ip {
    uint8_t                 ip_ver;  /* EN_DNS_IP_VERSION */
    uint8_t                 spare[7];
    union {
        uint32_t            ipv4;
        uint8_t             ipv6[IPV6_ALEN];
    } ip;
} comm_msg_dns_ip;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_dns_config {
    char                name[COMM_MSG_DNS_NAME_LENG];   /* maybe alias */
    //char                cname[COMM_MSG_DNS_NAME_LENG];  /* canonical name */
    uint32_t            expire;                         /* expire time */
    uint16_t            ipaddr_num;
    uint8_t             spare[2]; /* resv */
    comm_msg_dns_ip     ipaddr[COMM_MSG_DNS_IP_NUM];
} comm_msg_dns_config;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_port_mac_cfg {
    uint8_t             src_mac[ETH_ALEN];
    uint8_t             port;
    uint8_t             spare;
} comm_msg_port_mac_cfg;
#pragma pack()

/* Backend/SMU/Load-balancer heartbeat config */
#pragma pack(1)
typedef struct tag_comm_msg_heartbeat_config {
    uint64_t            key; /* Flag key */
    uint8_t             mac[EN_PORT_BUTT][ETH_ALEN]; /* LB/SMU/Backend local port mac */
} comm_msg_heartbeat_config;
#pragma pack()

/* Msg IE data config */
#pragma pack(1)
typedef struct tag_comm_msg_far_ie_data {
    uint32_t                index;
    comm_msg_far_config     cfg;
}comm_msg_far_ie_data;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_qer_ie_data {
    uint32_t                index;
    comm_msg_qer_config     cfg;
}comm_msg_qer_ie_data;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_urr_ie_data {
    uint32_t                index;
    comm_msg_urr_config     cfg;
}comm_msg_urr_ie_data;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_inst_ie_data {
    uint32_t                index;
    comm_msg_inst_config    cfg;
}comm_msg_inst_ie_data;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_bar_ie_data {
    uint32_t                index;
    comm_msg_bar_config     cfg;
}comm_msg_bar_ie_data;
#pragma pack()

#pragma pack(1)
typedef struct tag_comm_msg_dns_ie_data {
    uint32_t                index;
    comm_msg_dns_config     cfg;
}comm_msg_dns_ie_data;
#pragma pack()


typedef struct tag_comm_msg_fpu_stat {
    uint32_t        external_stat[COMM_MSG_FP_STAT_BUTT];
    uint32_t        internal_send_stat;
    uint32_t        internal_recv_stat;
    /* Resource usage status */
    uint32_t        fp_fast_stat;
    uint32_t        fp_inst_stat;
    uint32_t        fp_far_stat;
    uint32_t        fp_qer_stat;
    uint32_t        fp_bar_stat;
    uint32_t        fp_cblk_stat;
    uint32_t        fp_block_stat;
    uint32_t        fp_mac_stat;
}comm_msg_fpu_stat;

struct pcap_file_header {
    uint32_t		magic;
    uint16_t 		version_major;
    uint16_t 		version_minor;
    int		 		thiszone;
    uint32_t 		sigfigs;
    uint32_t 		snaplen;
    uint32_t 		linktype;
};

struct pcap_pkthdr {
    uint32_t 		sec;
	uint32_t 		usec;
    uint32_t 		caplen;
    uint32_t 		len;
};


#ifndef ENABLE_OCTEON_III
/* Received data length */
#define COMM_MSG_CTRL_BUFF_LEN        (8192)

/* Client check interval */
#define COMM_MSG_CHANNEL_CLIENT_CHECK_INTERVAL        (2)

/* Maximum client connect number */
#define COMM_MSG_MAX_LISTEN_NUMBER        (256)

/* Maximum effective number of client connections */
#define COMM_MSG_MAX_CONNECT_CHANNEL        (4)

/* Invalid backend index */
#define COMM_MSG_INVALID_BACKEND_INDEX      (0)

/* Maxium of channel bound cpus number */
#define COMM_MSG_MAX_CHNL_CPUS_NUM          (8)

#pragma pack(1)
typedef struct tag_comm_msg_channel_common {
    pthread_t                   thread_id;      /* Recv thread id */
    ros_rwlock_t                rw_lock;
    int                         fd;             /* Currently valid fd */
    uint8_t                     work_flag;      /* Work flag, normal:1, abnormal:0 */
    uint8_t                     spare[3];       /* It must not be modified or used */
}comm_msg_channel_common;
#pragma pack()

typedef struct tag_comm_msg_channel_server {
    pthread_t                   thread_id;      /* Recv thread id */
    ros_rwlock_t                rw_lock;
    int                         temp_fd;        /* File descriptor of the latest successful connection */
    uint8_t                     work_flag;      /* Work flag, normal:1, abnormal:0 */
    uint8_t                     cpu_num;
    ros_atomic16_t              accept_state;   /* Only when the status is true can the next acceptance be carried out */

    int                         sock;           /* Server sock */
    uint8_t                     cpu_id[COMM_MSG_MAX_CHNL_CPUS_NUM]; /* Bound CPU IDs */
}comm_msg_channel_server;

typedef struct tag_comm_msg_channel_client {
    pthread_t                   thread_id;      /* Recv thread id */
    ros_rwlock_t                rw_lock;
    int                         fd;             /* Currently valid fd */
    uint8_t                     work_flag;      /* Work flag, normal:1, abnormal:0 */
    uint8_t                     spare[3];

    uint8_t                     cpu_num;
    uint8_t                     remote_ips_num;
    uint16_t                    remote_port;
    uint32_t                    remote_ips[COMM_MSG_MAX_CONNECT_CHANNEL];
    uint8_t                     cpu_id[COMM_MSG_MAX_CHNL_CPUS_NUM]; /* Bound CPU IDs */
}comm_msg_channel_client;


static inline void comm_msg_val_bit2index(uint32_t start_bit, uint32_t src,
    uint32_t *dest_arr, uint32_t *dest_num)
{
    uint32_t cnt = 0, tmp_num = *dest_num;

    for (cnt = 0; cnt < RES_PART_LEN; ++cnt) {
        if (((uint32_t)1 << cnt) & src) {
            dest_arr[tmp_num] = start_bit + cnt;
            ++tmp_num;
        }
    }
    *dest_num = tmp_num;
}

int comm_msg_create_channel_server(comm_msg_channel_server *setp, uint16_t port,
    uint8_t *bound_cpu_ids, uint8_t bound_cpu_num);
int comm_msg_create_channel_client(comm_msg_channel_client *setp, uint32_t *remote_ips, uint8_t remote_ips_num,
    uint16_t remote_port, uint8_t *bound_cpu_ids, uint8_t bound_cpu_num);
int32_t comm_msg_channel_client_send(comm_msg_channel_common *chnl, char *buf, uint32_t len);
int32_t comm_msg_channel_reply(int fd, char *buf, uint32_t len);
void comm_msg_channel_server_shutdown(comm_msg_channel_server *server);
void comm_msg_channel_client_shutdown(comm_msg_channel_client *client);
#endif


extern CVMX_SHARED COMM_PROCESS_MSG_CALLBACK comm_msg_cmd_callback;
extern CVMX_SHARED COMM_PROCESS_MSG_COMMID_ERR comm_msg_cmd_commid_err;
int comm_msg_cmd_entry(void *token, char *inbuf, uint32_t inlen);
int comm_msg_parse_ie(void *trans_mng, uint8_t *first_ie, int32_t reminder_len, uint16_t commid);
int comm_msg_parse_ip_addr(comm_msg_ip_address *dst_cfg, char *src);
int write_wireshark_head(const char *file_name);

#endif

