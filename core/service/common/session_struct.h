/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _SESSION_STRUCT_H__
#define _SESSION_STRUCT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "pfcp_def.h"

/* Number of rules for the session */
#define MAX_PDR_NUM                     12
#define MAX_FAR_NUM                     12
#define MAX_QFI_NUM                     8
#define MAX_URR_NUM                     6
#define MAX_QER_NUM                     6
#define MAX_MAR_NUM                     6
#define MAX_BAR_NUM                     1
#define MAX_SRR_NUM                     4
#define MAX_TC_ENDPOINT_NUM             4
#define MAX_FRAMED_ROUTE_NUM            4
#define MAX_MAC_ADDRESS_NUM             16
#define MAX_DUPL_PARAM_NUM              4
#define MAX_ADDED_MONITOR_TIME_NUM      2
#define ACTIVATE_PREDEF_RULE_NUM        6
#define UP_IP_RES_NUM                   16
#define UEIP_POOL_NUM                   16
#define ALTERNATIVE_SMF_IP_NUM          16

#define MAX_UE_IP_NUM                   4
#define MAX_SDF_FILTER_NUM              4
#define MAX_ETH_FILTER_NUM              4

#define MAX_APP_ID_LEN                  32
#define NETWORK_INSTANCE_LEN            64
#define FORWARDING_POLICY_LEN           256
#define HEADER_FIELD_NAME_LEN           64
#define REDIRECT_SERVER_ADDR_LEN        128
#define ACTIVATE_PREDEF_LEN             16
#define DATA_NET_ACCESS_ID_LEN          32
#define PORT_MGMT_INFO_CONT_LEN         32
#define BRIDGE_MGMT_INFO_CONT_LEN       32

#define SESSION_MAX_BCD_BYTES               8
#define SESSION_MAX_NAI_LEN                 256
#define SESSION_MAX_HEADER_FIELD_LEN        256
#define MAX_TRIGGERING_EVENTS_LEN           8
#define MAX_LIST_OF_INTERFACES_LEN          16
#define GEOGRAPHIC_LOCAL_LEN                32

#define APP_DETECTION_ID_LEN                (32)
#define APP_INSTANCE_ID_LEN                 (64)
#define FLOW_DESCRIPTION_STRING_LEN         (128)
#define APN_DNN_LEN                         (64)
#define FQDN_LEN                            (256)
#define CP_PFCP_ENTITY_IP_NUM               (6)
#define UE_IP_ADDRESS_POOL_LEN              (256)
#define REMOTE_GTPU_PEER_NUM                (4)
#define MONITOR_GTPU_PATH_NUM               (4)
#define TSN_TIME_DOMAIN_NUM                 (6)
#define CLOCK_DRIFT_CONTROL_NUM             (4)
#define QOS_INFO_NUM                        (4)
#define GTPU_PATH_QOS_REPORT_NUM            (4)
/* QoS Monitoring per QoS flow Control Information */
#define QOS_MONITOR_NUM                     (4)
#define IP_MUL_SOURCE_IP_NUM                (4)
#define IP_MUL_ADDR_INFO_NUM                (4)
#define JOIN_IP_MUL_INFO_NUM                (4)
#define MAC_ADDRESS_DETECTED_NUM            (4)
#define MAC_ADDRESS_REMOVED_NUM             (4)
#define MAX_S_NSSAI_NUM                     (4)
#define TSC_MGMT_INFO_NUM                   (2)
#define PKT_RATE_STATUS_REPORT_NUM          (2)
#define EXEMPTED_APPLICATION_ID_NUM         (4)
#define EXEMPTED_SDF_FILTER_NUM             (2)
#define OFFENDING_IE_INFO_NUM               (4)
#define PARTIAL_FAILURE_INFO_NUM            (4)
#define UPDATED_PDR_NUM                     (2)

#define MAR_WEIGHT_SUM                      (100)

#ifndef IPV6_ALEN
#define IPV6_ALEN               (16)
#endif

#ifndef ETH_ALEN
#define ETH_ALEN                (6)
#endif

typedef enum {
    SESS_REQUEST_ACCEPTED                           = 1,
    SESS_MORE_USAGE_REPORT_TO_SEND                  = 2,
    SESS_REQUEST_PARTIALLY_ACCEPTED                 = 3,
    SESS_REQUEST_REJECTED                           = 64,
    SESS_SESSION_CONTEXT_NOT_FOUND                  = 65,
    SESS_MANDATORY_IE_MISSING                       = 66,
    SESS_CONDITIONAL_IE_MISSING                     = 67,
    SESS_INVALID_LENGTH                             = 68,
    SESS_MANDATORY_IE_INCORRECT                     = 69,
    SESS_INVALID_FORWARDING_POLICY                  = 70,
    SESS_INVALID_F_TEID_ALLOCATION_OPTION           = 71,
    SESS_NO_ESTABLISHED_PFCP_ASSOCIATION            = 72,
    SESS_RULE_CREATION_MODIFICATION_FAILURE         = 73,
    SESS_PFCP_ENTITY_IN_CONGESTION                  = 74,
    SESS_NO_RESOURCES_AVAILABLE                     = 75,
    SESS_SERVICE_NOT_SUPPORTED                      = 76,
    SESS_SYSTEM_FAILURE                             = 77,
    SESS_REDIRECTION_REQUESTED                      = 78,
    SESS_ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED         = 79,
    SESS_UNKNOWN_PRE_DEFINED_RULE                   = 80,
    SESS_UNKNOWN_APPLICATION_ID                     = 81,

    /* Userdef */
    SESS_CREATE_SYNC_DATA_BLOCK_FAILURE             = 204,
    SESS_SYSTEM_BUSY                                = 205,
}PFCP_CAUSE_TYPE;

typedef enum {
    SESS_HEARTBEAT_REQUEST                          = 1,
    SESS_HEARTBEAT_RESPONSE                         = 2,
    SESS_PFD_MANAGEMENT_REQUEST                     = 3,
    SESS_PFD_MANAGEMENT_RESPONSE                    = 4,
    SESS_ASSOCIATION_SETUP_REQUEST                  = 5,
    SESS_ASSOCIATION_SETUP_RESPONSE                 = 6,
    SESS_ASSOCIATION_UPDATE_REQUEST                 = 7,
    SESS_ASSOCIATION_UPDATE_RESPONSE                = 8,
    SESS_ASSOCIATION_RELEASE_REQUEST                = 9,
    SESS_ASSOCIATION_RELEASE_RESPONSE               = 10,
    SESS_VERSION_NOT_SUPPORTED_RESPONSE             = 11,
    SESS_NODE_REPORT_REQUEST                        = 12,
    SESS_NODE_REPORT_RESPONSE                       = 13,
    SESS_SESSION_SET_DELETION_REQUEST               = 14,
    SESS_SESSION_SET_DELETION_RESPONSE              = 15,

    SESS_SESSION_ESTABLISHMENT_REQUEST              = 50,
    SESS_SESSION_ESTABLISHMENT_RESPONSE             = 51,
    SESS_SESSION_MODIFICATION_REQUEST               = 52,
    SESS_SESSION_MODIFICATION_RESPONSE              = 53,
    SESS_SESSION_DELETION_REQUEST                   = 54,
    SESS_SESSION_DELETION_RESPONSE                  = 55,
    SESS_SESSION_REPORT_REQUEST                     = 56,
    SESS_SESSION_REPORT_RESPONSE                    = 57,

    /* User defined */
    SESS_SESSION_CREATE_ROLLBACK                    = 201,
    SESS_SESSION_MODIFY_ROLLBACK                    = 202,
    SESS_SESSION_REMOVE_ROLLBACK                    = 203,
    SESS_PFD_MANAGEMENT_ROLLBACK                    = 204,
	SESS_LOCAL_PREDEFINE_RULE	                    = 205,
	SESS_SESSION_SIGTRACE_SET	                    = 206,

    SESS_NODE_CREATE                                = 211,
    SESS_NODE_UPDATE                                = 212,
    SESS_NODE_REMOVE                                = 213,

    SESS_SESSION_CHECK                              = 231,

    /* Cannot be greater than 255 */
}SESSION_MSG_TYPE;

typedef enum {
    SESS_FAILED_PDR,
    SESS_FAILED_FAR,
    SESS_FAILED_QER,
    SESS_FAILED_URR,
    SESS_FAILED_BAR,
    SESS_FAILED_MAR,
    SESS_FAILED_SRR,
} SESSION_FAILED_RULE_TYPE;

typedef enum {
    SESSION_IP_V4 = 1,
    SESSION_IP_V6,
    SESSION_IP_V4V6,
} SESSION_IP_TYPE;

typedef enum {
	USER_SIGNALING_TRACE_IMSI	= 1,
	USER_SIGNALING_TRACE_MSISDN,
	USER_SIGNALING_TRACE_BUTT,
}user_Signaing_trace_flag;

typedef struct tag_session_ip_addr {
    uint8_t             version;        /* 1: v4, 2: v6, 3:v4 & v6 */
    uint8_t             spare[3];
    uint32_t            ipv4;
    uint8_t             ipv6[IPV6_ALEN];
} session_ip_addr;

typedef struct tag_session_msg_header {
    uint8_t         msg_type;
    uint8_t         node_id_index;
    uint16_t        spare;
    uint32_t        seq_num;
} session_msg_header;

#pragma pack(1)
typedef union {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :6;     /* spare */
        uint8_t         v4      :1;     /* ipv4 */
        uint8_t         v6      :1;     /* ipv6 */
#else
        uint8_t         v6      :1;     /* ipv6 */
        uint8_t         v4      :1;     /* ipv4 */
        uint8_t         spare   :6;     /* spare */
#endif
    } d;
    uint8_t             value;
} session_f_seid_ip_version;
#pragma pack()

typedef struct tag_session_f_seid {
    session_f_seid_ip_version   ip_version;
    uint8_t                     spare[3];
    uint32_t                    ipv4_addr;
    uint64_t                    seid;
    uint8_t                     ipv6_addr[IPV6_ALEN];
} session_f_seid;

#pragma pack(1)
typedef union tag_session_fully_teid_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t  spare : 4;
        uint8_t  chid  : 1;
        uint8_t  ch    : 1;
        uint8_t  v6    : 1;
        uint8_t  v4    : 1;
#else
        uint8_t  v4    : 1;
        uint8_t  v6    : 1;
        uint8_t  ch    : 1;
        uint8_t  chid  : 1;
        uint8_t  spare : 4;
#endif
    } d;
    uint8_t value;
} session_fully_teid_flag;
#pragma pack()

typedef struct tag_session_f_teid {
    session_fully_teid_flag     f_teid_flag;
    uint8_t                     choose_id;
    uint8_t                     spare[6];
    uint8_t                     ipv6_addr[IPV6_ALEN];
    uint32_t                    teid;
    uint32_t                    ipv4_addr;
} session_f_teid;

#pragma pack(1)
typedef union tag_session_ueip_address_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 1;
        uint8_t     ip6pl   : 1;
        uint8_t     chv6    : 1;
        uint8_t     chv4    : 1;
        uint8_t     ipv6d   : 1;
        uint8_t     s_d     : 1;
        uint8_t     v4      : 1;
        uint8_t     v6      : 1;
#else
        uint8_t     v6      : 1;
        uint8_t     v4      : 1;
        uint8_t     s_d     : 1;
        uint8_t     ipv6d   : 1;
        uint8_t     chv4    : 1;
        uint8_t     chv6    : 1;
        uint8_t     ip6pl   : 1;
        uint8_t     spare   : 1;
#endif
    } d;
    uint8_t value;
} session_ueip_address_flag;
#pragma pack()

typedef struct tag_session_ue_ip {
    session_ueip_address_flag   ueip_flag;
    uint8_t                     ipv6_prefix; /* IPv6 Prefix Delegation Bits */
    uint8_t                     ipv6_prefix_len;
    uint8_t                     spare;
    uint32_t                    ipv4_addr;
    uint8_t                     ipv6_addr[IPV6_ALEN];
} session_ue_ip;

typedef struct tag_session_flow_desc {
    union {
        uint32_t    sipv4;
        uint8_t     sipv6[IPV6_ALEN];
    } sip;
    union {
        uint32_t    sipv4_mask;
        uint8_t     sipv6_mask[IPV6_ALEN];
    } smask;
    union {
        uint32_t    dipv4;
        uint8_t     dipv6[IPV6_ALEN];
    } dip;
    union {
        uint32_t    dipv4_mask;
        uint8_t     dipv6_mask[IPV6_ALEN];
    } dmask;
    uint16_t    sp_min;
    uint16_t    sp_max;
    uint16_t    dp_min;
    uint16_t    dp_max;
    uint8_t     protocol;
    uint8_t     ip_type; /* 1: ipv4  2: ipv6 3: any  SESSION_IP_TYPE */
    uint8_t     no_sp;
    uint8_t     no_dp;
    uint8_t     spare[4];
} session_flow_desc;

#pragma pack(1)
typedef union tag_session_tos_tc {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     tos;
        uint8_t     tos_mask;
#else
        uint8_t     tos_mask;
        uint8_t     tos;
#endif
    } d;
    uint16_t value;
} session_tos_tc;
#pragma pack()

#pragma pack(1)
typedef union tag_session_flow_label {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t  spare          : 12;
        uint32_t  flowlabel_h    : 4;
        uint32_t  flowlabel_l    : 16;
#else
        uint32_t  flowlabel_l    : 16;
        uint32_t  flowlabel_h    : 4;
        uint32_t  spare          : 12;
#endif
    } d;
    uint32_t value;
} session_flow_label;
#pragma pack()

#pragma pack(1)
typedef union tag_session_sdf_filter_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t             spare : 3;
        uint8_t             bid   : 1;
        uint8_t             fl    : 1;
        uint8_t             spi   : 1;
        uint8_t             ttc   : 1;
        uint8_t             fd    : 1;
        uint8_t             spare_u8;
#else
        uint8_t             spare_u8;
        uint8_t             fd    : 1;
        uint8_t             ttc   : 1;
        uint8_t             spi   : 1;
        uint8_t             fl    : 1;
        uint8_t             bid   : 1;
        uint8_t             spare : 3;
#endif
    } d;
    uint16_t value;
} session_sdf_filter_flag;
#pragma pack()

typedef struct tag_session_sdf_filter {
    session_sdf_filter_flag     sdf_flag;
    session_tos_tc              tos_traffic_class;
    uint32_t                    ipsec_spi;
    session_flow_label          label;
    uint32_t                    sdf_id;
    session_flow_desc           desc; /* Flow Description */
} session_sdf_filter;

#pragma pack(1)
typedef union tag_session_mac_addr_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   : 4;
        uint8_t         udes    : 1;
        uint8_t         usou    : 1;
        uint8_t         dest    : 1;
        uint8_t         sour    : 1;
#else
        uint8_t         sour    : 1;
        uint8_t         dest    : 1;
        uint8_t         usou    : 1;
        uint8_t         udes    : 1;
        uint8_t         spare   : 4;
#endif
    } d;
    uint8_t value;
} session_mac_addr_flag;
#pragma pack()

typedef struct tag_session_mac_addr {
    session_mac_addr_flag   mac_flag;
    uint8_t                 src[ETH_ALEN];
    uint8_t                 dst[ETH_ALEN];
    uint8_t                 upper_src[ETH_ALEN];
    uint8_t                 upper_dst[ETH_ALEN];
    uint8_t                 spare[7];
} session_mac_addr;

#pragma pack(1)
typedef union tag_session_vlan_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t        spare   : 5;
        uint8_t        vid     : 1;
        uint8_t        dei     : 1;
        uint8_t        pcp     : 1;
#else
        uint8_t        pcp     : 1;
        uint8_t        dei     : 1;
        uint8_t        vid     : 1;
        uint8_t        spare   : 5;
#endif
    } d;
    uint8_t value;
} session_vlan_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_vlan_value {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t       vid_val : 12;
        uint16_t       dei_flag: 1;
        uint16_t       pcp_val : 3;

#else
        uint16_t       pcp_val : 3;
        uint16_t       dei_flag: 1;
        uint16_t       vid_val : 12;
#endif
    } d;
    uint16_t value;
} session_vlan_value;
#pragma pack()

#pragma pack(1)
typedef struct tag_session_vlan_tag {
    session_vlan_flags      flags;
    uint8_t                 spare;
    session_vlan_value      value;
} session_vlan_tag;
#pragma pack()

#pragma pack(1)
typedef union tag_session_eth_filter_prop {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare_b : 7;
        uint8_t         bide    : 1;
#else
        uint8_t         bide    : 1;
        uint8_t         spare_b : 7;
#endif
    } d;
    uint8_t value;
} session_eth_filter_prop;
#pragma pack()

#pragma pack(1)
typedef union tag_session_eth_filter_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 27;
        uint32_t        s_tag_present               : 1;
        uint32_t        c_tag_present               : 1;
        uint32_t        eth_type_present            : 1;
        uint32_t        eth_filter_prop_present     : 1;
        uint32_t        eth_filter_id_present       : 1;
#else
        uint32_t        eth_filter_id_present       : 1;
        uint32_t        eth_filter_prop_present     : 1;
        uint32_t        eth_type_present            : 1;
        uint32_t        c_tag_present               : 1;
        uint32_t        s_tag_present               : 1;
        uint32_t        spare                       : 27;
#endif
    } d;
    uint32_t value;
} session_eth_filter_member_flags;
#pragma pack()

typedef struct tag_session_eth_filter {
    session_eth_filter_member_flags member_flag;
    uint32_t                        eth_filter_id;
    session_eth_filter_prop         eth_filter_prop;
    uint8_t                         spare[3];
    uint8_t                         mac_addr_num;
    uint8_t                         sdf_arr_num;
    uint16_t                        eth_type;
    session_vlan_tag                c_tag;
    session_vlan_tag                s_tag;
    session_mac_addr                mac_addr[MAX_MAC_ADDRESS_NUM];
    session_sdf_filter              sdf_arr[MAX_SDF_FILTER_NUM];
} session_eth_filter;

typedef struct tag_session_framed_routing {
    uint8_t      type;
    uint8_t      length;
    uint8_t      spare[2];
    uint32_t     value;
} session_framed_routing;

typedef struct tag_session_framed_route {
    uint32_t        dest_ip;
    uint32_t        ip_mask;
    uint32_t        gateway;
    uint32_t        metrics;
} session_framed_route;

typedef struct tag_session_framed_route_ipv6 {
    uint8_t         dest_ip[IPV6_ALEN];
    uint8_t         ip_mask[IPV6_ALEN];
    uint8_t         gateway[IPV6_ALEN];
    uint32_t        metrics;
    uint8_t         spare[4];
} session_framed_route_ipv6;

#pragma pack(1)
typedef union tag_session_pdi_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                           : 24;
        uint32_t        src_if_type_present             : 1;
        uint32_t        framed_routing_present          : 1;
        uint32_t        eth_pdu_ses_info_present        : 1;
        uint32_t        application_id_present          : 1;
        uint32_t        redundant_transmission_present  : 1;
        uint32_t        network_instance_present        : 1;
        uint32_t        local_fteid_present             : 1;
        uint32_t        si_present                      : 1;
#else
        uint32_t        si_present                      : 1;
        uint32_t        local_fteid_present             : 1;
        uint32_t        network_instance_present        : 1;
        uint32_t        redundant_transmission_present  : 1;
        uint32_t        application_id_present          : 1;
        uint32_t        eth_pdu_ses_info_present        : 1;
        uint32_t        framed_routing_present          : 1;
        uint32_t        src_if_type_present             : 1;
        uint32_t        spare                           : 24;
#endif
    } d;
    uint32_t value;
} session_pdi_member_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_3gpp_interface_type {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t        spare                : 2;
        uint8_t        if_type_value        : 6;
        /*
        * S1-U                                              0
        * S5/S8-U                                           1
        * S4-U                                              2
        * S11-U                                             3
        * S12-U                                             4
        * Gn/Gp-U                                           5
        * S2a-U                                             6
        * S2b-U                                             7
        * eNodeB GTP-U interface for DL data forwarding     8
        * eNodeB GTP-U interface for UL data forwarding     9
        * SGW/UPF GTP-U interface for DL data forwarding    10
        * N3 3GPP Access                                    11
        * N3 Trusted Non-3GPP Access                        12
        * N3 Untrusted Non-3GPP Access                      13
        * N3 for data forwarding                            14
        * N9                                                15
        * SGi                                               16
        * N6                                                17
        * N19                                               18
        * S8-U                                              19
        * Gp-U                                              20
        */
#else
        uint8_t        if_type_value        : 6;
        uint8_t        spare                : 2;
#endif
    } d;
    uint8_t value;
} session_3gpp_interface_type;
#pragma pack()

#pragma pack(1)
typedef union tag_session_eth_pdu_sess_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   : 7;
        uint8_t         ethi    : 1;
#else
        uint8_t         ethi    : 1;
        uint8_t         spare   : 7;
#endif
    } d;
    uint8_t value;
} session_eth_pdu_sess_info;
#pragma pack()

#pragma pack(1)
typedef struct tag_session_outer_header_removal {
    uint8_t             type;           /* Type: 0 GTP-U/UDP/IPv4,
                                             1 GTP-U/UDP/IPv6,
                                             2 UDP/IPv4,
                                             3 UDP/IPv6,
                                             4 IPv4,
                                             5 IPv6,
                                             6 GTP-U/UDP/IP,
                                             7 C-TAG,
                                             8 S-TAG */
    uint8_t             gtp_u_exten;    /* Extention header deletion flag */
} session_outer_header_removal;
#pragma pack()

typedef struct tag_session_act_predef_rules {
    char        rules_name[ACTIVATE_PREDEF_LEN];
} session_act_predef_rules;

/* packet replication and detection carry-on information */
#pragma pack(1)
typedef union tag_session_pkt_rd_carry_on_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   : 4;
        uint8_t         DCARONI : 1;
        uint8_t         PRIN6I  : 1;
        uint8_t         PRIN19I : 1;
        uint8_t         PRIUEAI : 1;
#else
        uint8_t         PRIUEAI : 1;
        uint8_t         PRIN19I : 1;
        uint8_t         PRIN6I  : 1;
        uint8_t         DCARONI : 1;
        uint8_t         spare   : 4;
#endif
    } d;
    uint8_t value;
} session_pkt_rd_carry_on_info;
#pragma pack()

#pragma pack(1)
typedef union tag_session_pdr_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 21;
        uint32_t        transport_delay_rep_present : 1;
        uint32_t        mptcp_app_indication_present: 1;
        uint32_t        pkt_rd_carry_on_info_present: 1;
        uint32_t        mar_id_present              : 1;
        uint32_t        deact_time_present          : 1;
        uint32_t        act_time_present            : 1;
        uint32_t        far_id_present              : 1;
        uint32_t        OHR_present                 : 1;
        uint32_t        pdi_content_present         : 1;
        uint32_t        precedence_present          : 1;
        uint32_t        pdr_id_present              : 1;
#else
        uint32_t        pdr_id_present              : 1;
        uint32_t        precedence_present          : 1;
        uint32_t        pdi_content_present         : 1;
        uint32_t        OHR_present                 : 1;
        uint32_t        far_id_present              : 1;
        uint32_t        act_time_present            : 1;
        uint32_t        deact_time_present          : 1;
        uint32_t        mar_id_present              : 1;
        uint32_t        pkt_rd_carry_on_info_present: 1;
        uint32_t        mptcp_app_indication_present: 1;
        uint32_t        transport_delay_rep_present : 1;
        uint32_t        spare                       : 21;
#endif
    } d;
    uint32_t value;
} session_pdr_member_flags;
#pragma pack()

#pragma pack(1)
typedef union {
    struct tag_session_far_action {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t         dfrt: 1;        /* Duplicate for Redundant Transmission */
        uint16_t         ipmd: 1;        /* IP Multicast Deny */
        uint16_t         ipma: 1;        /* IP Multicast Accept */
        uint16_t         dupl: 1;        /* duplicate */
        uint16_t         nocp: 1;        /* notify */
        uint16_t         buff: 1;        /* buffering */
        uint16_t         forw: 1;        /* forward */
        uint16_t         drop: 1;        /* drop */

        uint16_t         spare: 5;       /* not define */
        uint16_t         ddpn: 1;        /* Discarded Downlink Packet Notification */
        uint16_t         bdpn: 1;        /* Buffered Downlink Packet Notification */
        uint16_t         edrt: 1;        /* Eliminate Duplicate Packets for Redundant Transmission */
#else
        uint16_t         edrt: 1;        /* Eliminate Duplicate Packets for Redundant Transmission */
        uint16_t         bdpn: 1;        /* Buffered Downlink Packet Notification */
        uint16_t         ddpn: 1;        /* Discarded Downlink Packet Notification */
        uint16_t         spare: 5;       /* not define */

        uint16_t         drop: 1;        /* drop */
        uint16_t         forw: 1;        /* forward */
        uint16_t         buff: 1;        /* buffering */
        uint16_t         nocp: 1;        /* notify */
        uint16_t         dupl: 1;        /* duplicate */
        uint16_t         ipma: 1;        /* IP Multicast Accept */
        uint16_t         ipmd: 1;        /* IP Multicast Deny */
        uint16_t         dfrt: 1;        /* Duplicate for Redundant Transmission */
#endif
    }d;
    uint16_t             value;          /* value in integer */
}session_far_action;
#pragma pack()

#pragma pack(1)
typedef union tag_session_redirect_server_address {
    uint32_t    ipv4_addr;
    uint8_t     ipv6_addr[IPV6_ALEN];
    char        url[REDIRECT_SERVER_ADDR_LEN];
    char        sip_uri[REDIRECT_SERVER_ADDR_LEN];
    struct {
        uint32_t    ipv4;
        uint8_t     ipv6[IPV6_ALEN];
    } v4_v6;
} session_redirect_server;
#pragma pack()

typedef struct tag_session_redirect_info {
    /* 0:ipv4 1:ipv6 2:URL 3:SIP URI 4:v4 and v6 */
    uint8_t                     addr_type;
    uint8_t                     spare[7];
    session_redirect_server     address;
} session_redirect_info;

#pragma pack(1)
typedef union tag_session_outer_header_create_type {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t            stag         : 1;
        uint8_t            ctag         : 1;
        uint8_t            ipv6         : 1;
        uint8_t            ipv4         : 1;
        uint8_t            udp_ipv6     : 1;
        uint8_t            udp_ipv4     : 1;
        uint8_t            gtp_udp_ipv6 : 1;
        uint8_t            gtp_udp_ipv4 : 1;
        uint8_t            spare        : 6;
        uint8_t            n6_indic     : 1;
        uint8_t            n19_indic    : 1;
#else
        uint8_t            n6_indic     : 1;
        uint8_t            n19_indic    : 1;
        uint8_t            spare        : 6;
        uint8_t            gtp_udp_ipv4 : 1;
        uint8_t            gtp_udp_ipv6 : 1;
        uint8_t            udp_ipv4     : 1;
        uint8_t            udp_ipv6     : 1;
        uint8_t            ipv4         : 1;
        uint8_t            ipv6         : 1;
        uint8_t            ctag         : 1;
        uint8_t            stag         : 1;
#endif
    }d;
    uint16_t            value;
}session_outer_header_create_type;
#pragma pack()

typedef struct tag_session_outer_header_create {
    session_outer_header_create_type    type;   /* Type: 0x100 GTP-U/UDP/IPv4,
                                                 0x200 GTP-U/UDP/IPv6,
                                                 0x400 UDP/IPv4,
                                                 0x800 UDP/IPv6,
                                                 0x1000 IPv4,
                                                 0x2000 IPv6,
                                                 0x4000 C-TAG,
                                                 0x8000 S-TAG,
                                                 0x10000 N19 Indication,
                                                 0x20000 N6 Indication,*/
    uint16_t                port;               /* Port */
    uint32_t                teid;               /* TEID */
    uint32_t                ipv4;               /* IPv4 */
    uint8_t                 ipv6[IPV6_ALEN];    /* IPv6 */
    session_vlan_tag        ctag;               /* C-TAG */
    session_vlan_tag        stag;               /* S-TAG */
} session_outer_header_create;

typedef struct tag_session_header_enrichment {
    uint8_t             header_type;
    uint8_t             name_length;
    uint8_t             value_length;
    uint8_t             spare[5];
    char                name[SESSION_MAX_HEADER_FIELD_LEN];
    char                value[SESSION_MAX_HEADER_FIELD_LEN];
} session_header_enrichment;

typedef struct tag_session_redundant_transmission_detection_param {
    session_f_teid              fteid;
    char                        network_instance[NETWORK_INSTANCE_LEN];
} session_redundant_transmission_detection_param;

typedef struct tag_session_redundant_trans_param_in_far {
    session_outer_header_create ohc;
    char                        network_instance[NETWORK_INSTANCE_LEN];
} session_redundant_trans_param_in_far;

#pragma pack(1)
typedef union {
        struct tag_session_proxying {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t            resv     : 6;
        uint8_t            ins      : 1;
        uint8_t            arp      : 1;
#else
        uint8_t            arp      : 1;
        uint8_t            ins      : 1;
        uint8_t            resv     : 6;
#endif
    }d;
    uint8_t            value;
} session_proxying;
#pragma pack()

#pragma pack(1)
typedef union tag_session_pfcpsm_req_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t            spare    :5;
        uint8_t            qaurr    :1;
        uint8_t            sndem    :1;
        uint8_t            drobu    :1;
#else
        uint8_t            drobu    :1;
        uint8_t            sndem    :1;
        uint8_t            qaurr    :1;
        uint8_t            spare    :5;
#endif
    } d;
    uint8_t value;
} session_pfcpsm_req_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_fwd_param_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 21;
        uint32_t        data_net_access_id_present  : 1;
        uint32_t        dest_if_type_present        : 1;
        uint32_t        proxying_present            : 1;
        uint32_t        traffic_endpoint_id_present : 1;
        uint32_t        header_enrichment_present   : 1;
        uint32_t        forwarding_policy_present   : 1;
        uint32_t        trans_present               : 1;
        uint32_t        ohc_present                 : 1;
        uint32_t        redirect_present            : 1;
        uint32_t        network_instance_present    : 1;
        uint32_t        dest_if_present             : 1;
#else
        uint32_t        dest_if_present             : 1;
        uint32_t        network_instance_present    : 1;
        uint32_t        redirect_present            : 1;
        uint32_t        ohc_present                 : 1;
        uint32_t        trans_present               : 1;
        uint32_t        forwarding_policy_present   : 1;
        uint32_t        header_enrichment_present   : 1;
        uint32_t        traffic_endpoint_id_present : 1;
        uint32_t        proxying_present            : 1;
        uint32_t        dest_if_type_present        : 1;
        uint32_t        data_net_access_id_present  : 1;
        uint32_t        spare                       : 21;
#endif
    } d;
    uint32_t value;
} session_fwd_param_member_flags;
#pragma pack()

typedef struct tag_session_forward_params {
    session_fwd_param_member_flags  member_flag;
    uint8_t                         dest_if;
    uint8_t                         traffic_endpoint_id;
    session_tos_tc                  trans;

    char                            network_instance[NETWORK_INSTANCE_LEN];
    session_redirect_info           redirect_addr;
    session_outer_header_create     outer_header_creation;

    char                            forwarding_policy[FORWARDING_POLICY_LEN];
    session_header_enrichment       header_enrichment;

    session_proxying                proxying;
    session_3gpp_interface_type     dest_if_type;
    uint8_t                         spare[6];
    char                            data_network_access_id[DATA_NET_ACCESS_ID_LEN];
} session_forward_params;

typedef struct tag_session_update_forward_params {
    session_fwd_param_member_flags  member_flag;
    uint8_t                         dest_if;
    uint8_t                         traffic_endpoint_id;
    session_tos_tc                  trans;

    char                            network_instance[NETWORK_INSTANCE_LEN];
    session_redirect_info           redirect_addr;
    session_outer_header_create     outer_header_creation;

    char                            forwarding_policy[FORWARDING_POLICY_LEN];
    session_header_enrichment       header_enrichment;

    session_pfcpsm_req_flags        pfcpsm_req_flag;
    session_3gpp_interface_type     dest_if_type;
    uint8_t                         spare[6];
    char                            data_net_access_id[DATA_NET_ACCESS_ID_LEN];
} session_update_forward_params;

#pragma pack(1)
typedef union tag_session_dupl_param_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 28;
        uint32_t        forwarding_policy_present   : 1;
        uint32_t        trans_present               : 1;
        uint32_t        ohc_present                 : 1;
        uint32_t        dupl_if_present             : 1;
#else
        uint32_t        dupl_if_present             : 1;
        uint32_t        ohc_present                 : 1;
        uint32_t        trans_present               : 1;
        uint32_t        forwarding_policy_present   : 1;
        uint32_t        spare                       : 28;
#endif
    } d;
    uint32_t value;
} session_dupl_param_member_flags;
#pragma pack()

typedef struct tag_session_dupl_params {
    session_dupl_param_member_flags member_flag;
    uint8_t                         dupl_if;    /* duplicate port */
    uint8_t                         spare;
    session_tos_tc                  trans;
    session_outer_header_create     ohc;        /* outher header create */
    char                            forwarding_policy[FORWARDING_POLICY_LEN];
} session_dupl_params;

#pragma pack(1)
typedef union tag_session_far_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                           : 27;
        uint32_t        bar_id_present                  : 1;
        uint32_t        redu_trans_param_present        : 1;
        uint32_t        forw_param_present              : 1;
        uint32_t        action_present                  : 1;
        uint32_t        far_id_present                  : 1;
#else
        uint32_t        far_id_present                  : 1;
        uint32_t        action_present                  : 1;
        uint32_t        forw_param_present              : 1;
        uint32_t        redu_trans_param_present        : 1;
        uint32_t        bar_id_present                  : 1;
        uint32_t        spare                           : 27;
#endif
    } d;
    uint32_t value;
} session_far_member_flags;
#pragma pack()

typedef struct tag_session_far_create {
    uint32_t                                far_id;     /* FAR id */
    session_far_member_flags                member_flag;
    session_far_action                      action;     /* action */
    uint8_t                                 bar_id;
    uint8_t                                 spare;
    uint32_t                                far_index; /* Local alloc index */
    session_forward_params                  forw_param;
    session_redundant_trans_param_in_far    rt_para;
} session_far_create;

typedef struct tag_session_far_update {
    uint32_t                                far_id;     /* FAR id */
    session_far_member_flags                member_flag;
    session_far_action                      action;     /* action */
    uint8_t                                 bar_id;
    uint8_t                                 spare;
    uint32_t                                far_index; /* Local alloc index */
    session_update_forward_params           forw_param;
    session_redundant_trans_param_in_far    redu_trans_param;
} session_far_update;


#pragma pack(1)
typedef union {
    struct {
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
    } d;
    uint8_t value;
} session_urr_method;
#pragma pack()

#pragma pack(1)
typedef union {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare_8:8;      /* spare */

        uint32_t        liusa:1;        /* linked usage reporting */
        uint32_t        droth:1;        /* dropped dl traffic threshold */
        uint32_t        stopt:1;        /* stop of traffic */
        uint32_t        start:1;        /* start of traffic */
        uint32_t        quhti:1;        /* quota holding time */
        uint32_t        timth:1;        /* time threshold */
        uint32_t        volth:1;        /* volume threshold */
        uint32_t        perio:1;        /* periodic reporting */

        uint32_t        quvti:1;        /* Quota Validity Time */
        uint32_t        ipmjl:1;        /* IP Multicast Join/Leave */
        uint32_t        evequ:1;        /* event quota */
        uint32_t        eveth:1;        /* event threshold */
        uint32_t        macar:1;        /* mac address reporting */
        uint32_t        envcl:1;        /* envelope closure */
        uint32_t        timqu:1;        /* time quota */
        uint32_t        volqu:1;        /* volume quota */

        uint32_t        spare_7:7;      /* spare */
        uint32_t        reemr:1;        /* REport the End Marker Reception */
#else
        uint32_t        reemr:1;        /* REport the End Marker Reception */
        uint32_t        spare_7:7;      /* spare */

        uint32_t        volqu:1;        /* volume quota */
        uint32_t        timqu:1;        /* time quota */
        uint32_t        envcl:1;        /* envelope closure */
        uint32_t        macar:1;        /* mac address reporting */
        uint32_t        eveth:1;        /* event threshold */
        uint32_t        evequ:1;        /* event quota */
        uint32_t        ipmjl:1;        /* IP Multicast Join/Leave */
        uint32_t        quvti:1;        /* Quota Validity Time */

        uint32_t        perio:1;        /* periodic reporting */
        uint32_t        volth:1;        /* volume threshold */
        uint32_t        timth:1;        /* time threshold */
        uint32_t        quhti:1;        /* quota holding time */
        uint32_t        start:1;        /* start of traffic */
        uint32_t        stopt:1;        /* stop of traffic */
        uint32_t        droth:1;        /* dropped dl traffic threshold */
        uint32_t        liusa:1;        /* linked usage reporting */

        uint32_t        spare_8:8;      /* spare */
#endif
    }d;
    uint32_t value;
}session_urr_reporting_trigger;
#pragma pack()

#pragma pack(1)
typedef union {
    struct {
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
    } d;
    uint8_t value;
} session_urr_vol_flag;
#pragma pack()

typedef struct tag_session_urr_volume {
    session_urr_vol_flag            flag;
    uint8_t                         spare[7];
    uint64_t                        total;      /* in byte */
    uint64_t                        uplink;
    uint64_t                        downlink;
} session_urr_volume;

#pragma pack(1)
typedef union {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare:2;        /* spare */
        uint8_t         dlnop:1;        /* Downlink Number of Packets */
        uint8_t         ulnop:1;        /* Uplink Number of Packets */
        uint8_t         tonop:1;        /* Total Number of Packets */
        uint8_t         dlvol:1;        /* downlink volume */
        uint8_t         ulvol:1;        /* uplink volume */
        uint8_t         tovol:1;        /* total volume */
#else
        uint8_t         tovol:1;        /* total volume */
        uint8_t         ulvol:1;        /* uplink volume */
        uint8_t         dlvol:1;        /* downlink volume */
        uint8_t         tonop:1;        /* Total Number of Packets */
        uint8_t         ulnop:1;        /* Uplink Number of Packets */
        uint8_t         dlnop:1;        /* Downlink Number of Packets */
        uint8_t         spare:2;        /* spare */
#endif
    } d;
    uint8_t value;
} session_volume_measurement_flag;
#pragma pack()

typedef struct tag_session_volume_measurement {
    session_volume_measurement_flag flag;
    uint8_t                         spare[7];
    uint64_t                        total;      /* in byte */
    uint64_t                        uplink;
    uint64_t                        downlink;
    uint64_t                        to_pkts;
    uint64_t                        ul_pkts;
    uint64_t                        dl_pkts;
} session_volume_measurement;

#pragma pack(1)
typedef union {
    struct {
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
} session_urr_drop_flag;
#pragma pack()

typedef struct tag_session_urr_drop_thres {
    session_urr_drop_flag           flag;
    uint8_t                         spare[7];
    uint64_t                        packets;    /* in packet */
    uint64_t                        bytes;      /* in bytes */
} session_urr_drop_thres;

/* Measurement Information */
#pragma pack(1)
typedef union {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare:1;        /* spare */
        uint8_t         aspoc:1;        /* Applicable for Start of Pause of Charging */
        uint8_t         sspoc:1;        /* Send Start Pause of Charging */
        uint8_t         mnop:1;         /* Measurement of Number of Packets */
        uint8_t         istm:1;         /* Immediate start time metering */
        uint8_t         radi:1;         /* reduced app detection info */
        uint8_t         inam:1;         /* inactive measurement */
        uint8_t         mbqe:1;         /* measure before qos enforcement */
#else
        uint8_t         mbqe:1;         /* measure before qos enforcement */
        uint8_t         inam:1;         /* inactive measurement */
        uint8_t         radi:1;         /* reduced app detection info */
        uint8_t         istm:1;         /* Immediate start time metering */
        uint8_t         mnop:1;         /* Measurement of Number of Packets */
        uint8_t         sspoc:1;        /* Send Start Pause of Charging */
        uint8_t         aspoc:1;        /* Applicable for Start of Pause of Charging */
        uint8_t         spare:1;        /* spare */
#endif
    }d;
    uint8_t value;
} session_urr_measu_info;
#pragma pack()

#pragma pack(1)
typedef union tag_session_add_mon_time_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 25;
        uint32_t        sub_eve_quota_present       : 1;
        uint32_t        sub_eve_thres_present       : 1;
        uint32_t        sub_tim_quota_present       : 1;
        uint32_t        sub_vol_quota_present       : 1;
        uint32_t        sub_tim_thres_present       : 1;
        uint32_t        sub_vol_thres_present       : 1;
        uint32_t        mon_time_present            : 1;
#else
        uint32_t        mon_time_present            : 1;
        uint32_t        sub_vol_thres_present       : 1;
        uint32_t        sub_tim_thres_present       : 1;
        uint32_t        sub_vol_quota_present       : 1;
        uint32_t        sub_tim_quota_present       : 1;
        uint32_t        sub_eve_thres_present       : 1;
        uint32_t        sub_eve_quota_present       : 1;
        uint32_t        spare                       : 25;
#endif
    } d;
    uint32_t value;
} session_add_mon_time_member_flags;
#pragma pack()

typedef struct tag_session_urr_add_mon_time {
    uint32_t                            mon_time;       /* UTC time */
    session_add_mon_time_member_flags   member_flag;
    session_urr_volume                  sub_vol_thres;  /* multiplier */
    session_urr_volume                  sub_vol_quota;
    uint32_t                            sub_tim_thres;
    uint32_t                            sub_tim_quota;
    uint32_t                            sub_eve_thres;
    uint32_t                            sub_eve_quota;
} session_urr_add_mon_time;

#pragma pack(1)
typedef union tag_session_urr_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 7;
        uint32_t        number_of_reports_present   : 1;

        uint32_t        eth_inact_time_present      : 1;
        uint32_t        quota_far_present           : 1;
        uint32_t        measu_info_present          : 1;
        uint32_t        inact_detect_present        : 1;
        uint32_t        sub_eve_quota_present       : 1;
        uint32_t        sub_eve_thres_present       : 1;
        uint32_t        sub_tim_quota_present       : 1;
        uint32_t        sub_vol_quota_present       : 1;

        uint32_t        sub_tim_thres_present       : 1;
        uint32_t        sub_vol_thres_present       : 1;
        uint32_t        mon_time_present            : 1;
        uint32_t        quota_validity_time_present : 1;
        uint32_t        drop_thres_present          : 1;
        uint32_t        quota_hold_present          : 1;
        uint32_t        tim_quota_present           : 1;
        uint32_t        tim_thres_present           : 1;

        uint32_t        eve_quota_present           : 1;
        uint32_t        eve_thres_present           : 1;
        uint32_t        vol_quota_present           : 1;
        uint32_t        vol_thres_present           : 1;
        uint32_t        period_present              : 1;
        uint32_t        trigger_present             : 1;
        uint32_t        method_present              : 1;
        uint32_t        urr_id_present              : 1;
#else
        uint32_t        urr_id_present              : 1;
        uint32_t        method_present              : 1;
        uint32_t        trigger_present             : 1;
        uint32_t        period_present              : 1;
        uint32_t        vol_thres_present           : 1;
        uint32_t        vol_quota_present           : 1;
        uint32_t        eve_thres_present           : 1;
        uint32_t        eve_quota_present           : 1;
        uint32_t        tim_thres_present           : 1;
        uint32_t        tim_quota_present           : 1;
        uint32_t        quota_hold_present          : 1;
        uint32_t        drop_thres_present          : 1;
        uint32_t        quota_validity_time_present : 1;
        uint32_t        mon_time_present            : 1;
        uint32_t        sub_vol_thres_present       : 1;
        uint32_t        sub_tim_thres_present       : 1;
        uint32_t        sub_vol_quota_present       : 1;
        uint32_t        sub_tim_quota_present       : 1;
        uint32_t        sub_eve_thres_present       : 1;
        uint32_t        sub_eve_quota_present       : 1;
        uint32_t        inact_detect_present        : 1;
        uint32_t        measu_info_present          : 1;
        uint32_t        quota_far_present           : 1;
        uint32_t        eth_inact_time_present      : 1;
        uint32_t        number_of_reports_present   : 1;
        uint32_t        spare                       : 7;
#endif
    } d;
    uint32_t value;
} session_urr_member_flags;
#pragma pack()

typedef struct tag_session_usage_report_rule {
    uint32_t                        urr_id;
    session_urr_member_flags        member_flag;

    session_urr_method              method;
    session_urr_measu_info          measu_info;
    uint8_t                         linked_urr_number;
    uint8_t                         add_mon_time_number;
    session_urr_reporting_trigger   trigger;
    uint16_t                        number_of_reports;/* > 0 */
    uint8_t                         exempted_app_id_num;
    uint8_t                         exempted_sdf_filter_num;
    uint8_t                         spare[4];

    session_urr_volume              vol_thres;
    session_urr_volume              vol_quota;
    uint32_t                        period;     /* in second */
    uint32_t                        eve_thres;
    uint32_t                        eve_quota;
    uint32_t                        tim_thres;  /* in second */
    uint32_t                        tim_quota;  /* in second */
    uint32_t                        quota_hold; /* in second */
    session_urr_drop_thres          drop_thres; /* drop DL traffic threshold */
    uint32_t                        quota_validity_time;/* in second */
    uint32_t                        mon_time;   /* UTC time,seconds from 1970 */
    session_urr_volume              sub_vol_thres;
    session_urr_volume              sub_vol_quota;
    uint32_t                        sub_tim_thres;
    uint32_t                        sub_tim_quota;
    uint32_t                        sub_eve_thres;
    uint32_t                        sub_eve_quota;
    uint32_t                        inact_detect;
    uint32_t                        quota_far;

    uint32_t                        eth_inact_time;
    uint32_t                        urr_index; /* Local alloc index */

    uint32_t                        linked_urr[MAX_URR_NUM];
    session_urr_add_mon_time        add_mon_time[MAX_ADDED_MONITOR_TIME_NUM];
    char                            exempted_app_id[EXEMPTED_APPLICATION_ID_NUM][MAX_APP_ID_LEN];
    session_sdf_filter              exempted_sdf_filter[EXEMPTED_SDF_FILTER_NUM];
} session_usage_report_rule;

#pragma pack(1)
typedef union tag_session_qer_gate_status {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 4;
        uint8_t     ul_gate : 2;
        uint8_t     dl_gate : 2;
#else
        uint8_t     dl_gate : 2;
        uint8_t     ul_gate : 2;
        uint8_t     spare   : 4;
#endif
    } d;
    uint8_t value;
} session_qer_gate_status;
#pragma pack()

typedef struct tag_session_mbr {
    uint64_t          ul_mbr;
    uint64_t          dl_mbr;
} session_mbr;

typedef struct tag_session_gbr {
    uint64_t          ul_gbr;
    uint64_t          dl_gbr;
} session_gbr;

#pragma pack(1)
typedef union tag_session_packet_rate_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 5;
        uint8_t     APRC    : 1;
        uint8_t     DLPR    : 1;
        uint8_t     ULPR    : 1;
#else
        uint8_t     ULPR    : 1;
        uint8_t     DLPR    : 1;
        uint8_t     APRC    : 1;
        uint8_t     spare   : 5;
#endif
    } d;
    uint8_t value;
} session_packet_rate_flag;
#pragma pack()

#pragma pack(1)
typedef union tag_session_packet_time_unit {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare       : 5;
        uint8_t     time_unit   : 3;
#else
        uint8_t     time_unit   : 3;
        uint8_t     spare       : 5;
#endif
    } d;
    uint8_t value;
} session_packet_time_unit;
#pragma pack()

typedef struct tag_session_packet_rate {
    session_packet_rate_flag    pr_flag;
    session_packet_time_unit    ul_time_unit;
    session_packet_time_unit    dl_time_unit;
    session_packet_time_unit    add_ul_time_unit;
    session_packet_time_unit    add_dl_time_unit;
    uint8_t                     spare[3];
    uint16_t                    ul_max_pr;
    uint16_t                    dl_max_pr;
    uint16_t                    add_ul_max_pr;
    uint16_t                    add_dl_max_pr;
} session_packet_rate;

#pragma pack(1)
typedef union tag_session_dl_fl_marking_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 6;
        uint8_t     sci     : 1;
        uint8_t     ttc     : 1;
#else
        uint8_t     ttc     : 1;
        uint8_t     sci     : 1;
        uint8_t     spare   : 6;
#endif
    } d;
    uint8_t value;
} session_dl_fl_marking_flags;
#pragma pack()

typedef struct tag_session_dl_fl_marking {
    session_dl_fl_marking_flags         flag;
    uint8_t                             spare[3];
    session_tos_tc                      tos_traffic_class;
    uint16_t                            service_class_indicator;
} session_dl_fl_marking;

#pragma pack(1)
typedef union tag_session_qer_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t        spare                       : 5;
        uint16_t        qer_ctrl_indic_present      : 1;
        uint16_t        averaging_window_present    : 1;
        uint16_t        ppi_present                 : 1;
        uint16_t        ref_qos_present             : 1;
        uint16_t        qfi_present                 : 1;
        uint16_t        packet_rate_status_present  : 1;
        uint16_t        gbr_value_present           : 1;
        uint16_t        mbr_value_present           : 1;
        uint16_t        gate_status_present         : 1;
        uint16_t        qer_corr_id_present         : 1;
        uint16_t        qer_id_present              : 1;
#else
        uint16_t        qer_id_present              : 1;
        uint16_t        qer_corr_id_present         : 1;
        uint16_t        gate_status_present         : 1;
        uint16_t        mbr_value_present           : 1;
        uint16_t        gbr_value_present           : 1;
        uint16_t        packet_rate_status_present  : 1;
        uint16_t        qfi_present                 : 1;
        uint16_t        ref_qos_present             : 1;
        uint16_t        ppi_present                 : 1;
        uint16_t        averaging_window_present    : 1;
        uint16_t        qer_ctrl_indic_present      : 1;
        uint16_t        spare                       : 5;
#endif
    } d;
    uint16_t value;
} session_qer_member_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_packet_rate_status_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 5;
        uint8_t     APR     : 1;
        uint8_t     DL      : 1;
        uint8_t     UL      : 1;
#else
        uint8_t     UL      : 1;
        uint8_t     DL      : 1;
        uint8_t     APR     : 1;
        uint8_t     spare   : 5;
#endif
    } d;
    uint8_t value;
} session_packet_rate_status_flags;
#pragma pack()

typedef struct tag_session_packet_rate_status {
    session_packet_rate_status_flags        flag;
    uint8_t                                 spare[7];
    uint16_t                                remain_ul_packets;
    uint16_t                                addit_remain_ul_packets;
    uint16_t                                remain_dl_packets;
    uint16_t                                addit_remain_dl_packets;
    uint64_t                                rate_ctrl_status_time;/* Rate Control Status Validity Time */
} session_packet_rate_status;

#pragma pack(1)
typedef union tag_session_qer_control_indications {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 7;
        uint8_t     RCSR    : 1;
#else
        uint8_t     RCSR    : 1;
        uint8_t     spare   : 7;
#endif
    } d;
    uint8_t value;
} session_qer_control_indications;
#pragma pack()

typedef struct tag_session_qos_enforcement_rule {
    uint32_t                            qer_id;
    session_qer_member_flags            member_flag;
    session_qer_gate_status             gate_status;
    uint8_t                             qfi;
    uint8_t                             ref_qos;
    uint8_t                             paging_policy_indic;
    session_qer_control_indications     qer_ctrl_indic;
    uint8_t                             spare;
    uint32_t                            qer_corr_id;
    session_mbr                         mbr_value;
    session_gbr                         gbr_value;
    session_packet_rate_status          pkt_rate_status;
    uint32_t                            averaging_window;/* 应在UPF中预先配置一个默认平均值窗口 */
    uint32_t                            qer_index; /* Local alloc index */
} session_qos_enforcement_rule;

#pragma pack(1)
typedef union tag_session_bar_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare                       : 5;
        uint8_t         buffer_pkts_cnt_present     : 1;
        uint8_t         notify_delay_present        : 1;
        uint8_t         bar_id_present              : 1;
#else
        uint8_t         bar_id_present              : 1;
        uint8_t         notify_delay_present        : 1;
        uint8_t         buffer_pkts_cnt_present     : 1;
        uint8_t         spare                       : 5;
#endif
    } d;
    uint8_t value;
} session_bar_member_flags;
#pragma pack()

typedef struct  tag_session_buffer_action_rule {
    session_bar_member_flags    member_flag;
    uint8_t                     bar_id;
    uint8_t                     notify_delay;
    uint8_t                     buffer_pkts_cnt; /* max buffer packets */
    uint32_t                    bar_index; /* Local alloc index */
} session_buffer_action_rule;

#pragma pack(1)
typedef union tag_session_tc_endpoint_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                           : 25;
        uint32_t        source_if_type_present          : 1;
        uint32_t        framed_routing_present          : 1;
        uint32_t        eth_pdu_ses_info_present        : 1;
        uint32_t        redundant_transmission_present  : 1;
        uint32_t        network_instance_present        : 1;
        uint32_t        local_fteid_present             : 1;
        uint32_t        endpoint_id_present             : 1;
#else
        uint32_t        endpoint_id_present             : 1;
        uint32_t        local_fteid_present             : 1;
        uint32_t        network_instance_present        : 1;
        uint32_t        redundant_transmission_present  : 1;
        uint32_t        eth_pdu_ses_info_present        : 1;
        uint32_t        framed_routing_present          : 1;
        uint32_t        source_if_type_present          : 1;
        uint32_t        spare                           : 25;
#endif
    } d;
    uint32_t value;
} session_tc_endpoint_member_flags;
#pragma pack()

typedef struct tag_session_tc_endpoint {
    session_tc_endpoint_member_flags        member_flag;
    uint8_t                                 endpoint_id;
    uint8_t                                 ue_ipaddr_num;
    uint8_t                                 framed_route_num;
    uint8_t                                 framed_ipv6_route_num;

    session_f_teid                          local_fteid;
    char                                    network_instance[NETWORK_INSTANCE_LEN];
    session_redundant_transmission_detection_param      redundant_transmission_param;
    session_ue_ip                           ue_ipaddr[MAX_UE_IP_NUM];
    session_framed_route                    framed_route[MAX_FRAMED_ROUTE_NUM];
    session_framed_route_ipv6               framed_ipv6_route[MAX_FRAMED_ROUTE_NUM];

    uint8_t                                 qfi_array[MAX_QFI_NUM];
    /* 0:None  1:Send routing packets  2:Listen for routing packets  3:Send and Listen */
    uint32_t                                framed_routing;
    session_eth_pdu_sess_info               eth_pdu_ses_info;
    uint8_t                                 qfi_number;
    session_3gpp_interface_type             source_if_type;
    uint8_t                                 spare;
} session_tc_endpoint;

#pragma pack(1)
typedef union tag_session_user_id_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare       : 4;
        uint8_t     naif        : 1;
        uint8_t     msisdnf     : 1;
        uint8_t     imeif       : 1;
        uint8_t     imsif       : 1;
#else
        uint8_t     imsif       : 1;
        uint8_t     imeif       : 1;
        uint8_t     msisdnf     : 1;
        uint8_t     naif        : 1;
        uint8_t     spare       : 4;
#endif
    } d;
    uint8_t value;
} session_user_id_flag;
#pragma pack()

typedef struct tag_session_user_id {
    session_user_id_flag    user_id_flag;
    uint8_t                 imsi_len;
    uint8_t                 imei_len;
    uint8_t                 msisdn_len;
    uint8_t                 nai_len;
    uint8_t                 sig_trace;
    uint8_t                 spare[2];
    uint8_t                 imsi[SESSION_MAX_BCD_BYTES];
    uint8_t                 imei[SESSION_MAX_BCD_BYTES];
    uint8_t                 msisdn[SESSION_MAX_BCD_BYTES];
    char                    nai[SESSION_MAX_NAI_LEN];
} session_user_id;

#pragma pack(1)
typedef union tag_session_trace_reference_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t            spare   :8;
        uint32_t            mnc2    :4;
        uint32_t            mnc1    :4;
        uint32_t            mnc3    :4;
        uint32_t            mcc3    :4;
        uint32_t            mcc2    :4;
        uint32_t            mcc1    :4;
#else
        uint32_t            mcc1    :4;
        uint32_t            mcc2    :4;
        uint32_t            mcc3    :4;
        uint32_t            mnc3    :4;
        uint32_t            mnc1    :4;
        uint32_t            mnc2    :4;
        uint32_t            spare   :8;
#endif
    };
    uint32_t value;
} session_trace_reference_flag;
#pragma pack()

#pragma pack(1)
typedef union tag_session_ip_addr_of_trace {
    uint32_t            addr4;
    uint8_t             addr6[IPV6_ALEN];
} session_ip_addr_of_trace;
#pragma pack()

typedef struct tag_session_trace_info {
  session_trace_reference_flag  trace_ref_flag;
  uint32_t                      trace_id;
  uint8_t                       trigger_events_len;
  uint8_t                       sess_trace_depth;
  uint8_t                       if_list_len;
  uint8_t                       ip_addr_len;
  uint8_t                       spare[4];

  uint8_t                       trigger_events[MAX_TRIGGERING_EVENTS_LEN];
  uint8_t                       if_list[MAX_LIST_OF_INTERFACES_LEN];
  session_ip_addr_of_trace      ip_addr_of_trace;
} session_trace_info;

#pragma pack(1)
typedef union tag_session_access_fwd_action_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 29;
        uint32_t        priority_present            : 1;
        uint32_t        weight_present              : 1;
        uint32_t        far_id_present              : 1;
#else
        uint32_t        far_id_present              : 1;
        uint32_t        weight_present              : 1;
        uint32_t        priority_present            : 1;
        uint32_t        spare                       : 29;
#endif
    } d;
    uint32_t value;
} session_access_fwd_action_member_flags;
#pragma pack()

/* create and update common */
typedef struct tag_session_access_forwarding_action {
    session_access_fwd_action_member_flags  member_flag;
    uint32_t                                far_id;
    uint8_t                                 weight;
    uint8_t                                 priority;   /* 0:active
                                                        * 1:Standby
                                                        * 2:No Standby
                                                        * 3:High
                                                        * 4:Low
                                                        */
    uint8_t                                 spare[5];
    uint8_t                                 urr_num;
    uint32_t                                urr_id_arr[MAX_URR_NUM];
} session_access_forwarding_action;

#pragma pack(1)
typedef union tag_session_mar_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 25;
        uint32_t        afai_2_present              : 1;
        uint32_t        afai_1_present              : 1;
        uint32_t        update_afai_2_present       : 1;
        uint32_t        update_afai_1_present       : 1;
        uint32_t        steer_mod_present           : 1;
        uint32_t        steer_func_present          : 1;
        uint32_t        mar_id_present              : 1;
#else
        uint32_t        mar_id_present              : 1;
        uint32_t        steer_func_present          : 1;
        uint32_t        steer_mod_present           : 1;
        uint32_t        update_afai_1_present       : 1;
        uint32_t        update_afai_2_present       : 1;
        uint32_t        afai_1_present              : 1;
        uint32_t        afai_2_present              : 1;
        uint32_t        spare                       : 25;
#endif
    } d;
    uint32_t value;
} session_mar_member_flags;
#pragma pack()

typedef struct tag_session_mar_create {
    session_mar_member_flags            member_flag;
    uint16_t                            mar_id;
    uint8_t                             steer_func; /* 0:ATSSS-LL 1:MPTCP */
    uint8_t                             steer_mod;  /* 0:Active-Standby
                                                     * 1:Smallest Delay
                                                     * 2:Load Balancing
                                                     * 3:Priority-based
                                                     */
    session_access_forwarding_action    afai_1;
    session_access_forwarding_action    afai_2;
} session_mar_create;

typedef struct tag_session_mar_update {
    session_mar_member_flags            member_flag;
    uint16_t                            mar_id;
    uint8_t                             steer_func; /* 0:ATSSS-LL 1:MPTCP */
    uint8_t                             steer_mod;  /* 0:Active-Standby
                                                     * 1:Smallest Delay
                                                     * 2:Load Balancing
                                                     * 3:Priority-based
                                                     */
    session_access_forwarding_action    update_afai_1;
    session_access_forwarding_action    update_afai_2;
    session_access_forwarding_action    afai_1;
    session_access_forwarding_action    afai_2;
} session_mar_update;

typedef struct tag_session_apn_dnn {
    uint8_t     type;
    uint8_t     len;
    uint8_t     spare[6];
    char        value[APN_DNN_LEN];
} session_apn_dnn;

#pragma pack(1)
typedef union tag_session_pfcpsereq_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare       : 7;
        uint8_t     RESTI       : 1;
#else
        uint8_t     RESTI       : 1;
        uint8_t     spare       : 7;
#endif
    } d;
    uint8_t value;
} session_pfcpsereq_flags;
#pragma pack()

/* Create Bridge Info for TSC within session establishment request */
#pragma pack(1)
typedef union tag_session_create_bg_info_within_req {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare       : 7;
        uint8_t     BII         : 1;
#else
        uint8_t     BII         : 1;
        uint8_t     spare       : 7;
#endif
    } d;
    uint8_t value;
} session_create_bg_info_within_req;
#pragma pack()

#pragma pack(1)
typedef union tag_session_requested_access_avail_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare     : 7;
        uint8_t     RRCA      : 1;
#else
        uint8_t     RRCA      : 1;
        uint8_t     spare     : 7;
#endif
    } d;
    uint8_t value;
} session_requested_access_avail_info;
#pragma pack()

#pragma pack(1)
typedef union tag_session_access_avail_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare           : 4;
        uint8_t     avail_status    : 2;/* 0(Access has become unavailable)  1(Access has become available) */
        uint8_t     access_type     : 2;/* 0(3GPP access type)  1(Non-3GPP access type) */
#else
        uint8_t     access_type     : 2;
        uint8_t     avail_status    : 2;
        uint8_t     spare           : 4;
#endif
    } d;
    uint8_t value;
} session_access_avail_info;
#pragma pack()

#pragma pack(1)
typedef struct tag_session_access_avail_control_info {
    session_requested_access_avail_info requested_access_avail_info;
} session_access_avail_control_info;
#pragma pack()

#pragma pack(1)
typedef union tag_session_requested_qos_monitor {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 4;
        uint8_t     GTPUPM  : 1;
        uint8_t     RP      : 1;
        uint8_t     UL      : 1;
        uint8_t     DL      : 1;
#else
        uint8_t     DL      : 1;
        uint8_t     UL      : 1;
        uint8_t     RP      : 1;
        uint8_t     GTPUPM  : 1;
        uint8_t     spare   : 4;
#endif
    } d;
    uint8_t value;
} session_requested_qos_monitor;
#pragma pack()

#pragma pack(1)
typedef union tag_session_reporting_frequency {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 5;
        uint8_t     SESRL   : 1;
        uint8_t     PERIO   : 1;
        uint8_t     EVETT   : 1;
#else
        uint8_t     EVETT   : 1;
        uint8_t     PERIO   : 1;
        uint8_t     SESRL   : 1;
        uint8_t     spare   : 5;
#endif
    } d;
    uint8_t value;
} session_reporting_frequency;
#pragma pack()

#pragma pack(1)
typedef union tag_session_packet_delay_threshold_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 5;
        uint8_t     RP      : 1;
        uint8_t     UL      : 1;
        uint8_t     DL      : 1;
#else
        uint8_t     DL      : 1;
        uint8_t     UL      : 1;
        uint8_t     RP      : 1;
        uint8_t     spare   : 5;
#endif
    } d;
    uint8_t value;
} session_packet_delay_threshold_flags;
#pragma pack()

typedef struct tag_session_packet_delay_thresholds {
    session_packet_delay_threshold_flags    flag;
    uint8_t                                 spare[3];
    uint32_t                                dl_packet_delay;/* in milliseconds */
    uint32_t                                ul_packet_delay;/* in milliseconds */
    uint32_t                                rt_packet_delay;/* in milliseconds */
} session_packet_delay_thresholds;


/* QoS Monitoring per QoS flow Control Information */
typedef struct tag_session_monitor_per_qf_ctrl_info {
    session_packet_delay_thresholds     packet_delay_thresholds;
    uint32_t                            min_wait_time;/* in seconds */
    uint32_t                            measurement_period;/* in seconds */
    uint8_t                             packet_delay_thresholds_present;
    uint8_t                             min_wait_time_present;
    uint8_t                             measurement_period_present;
    uint8_t                             qfi_num;
    uint8_t                             qfi[MAX_QFI_NUM];
    session_requested_qos_monitor       requested_qos_monitor;
    session_reporting_frequency         reporting_frequency;
    uint8_t                             spare[2];
} session_monitor_per_qf_ctrl_info;

typedef struct tag_session_srr_create {
    uint8_t                                 ssr_id;
    uint8_t                                 monitor_per_qf_ctrl_info_num;
    uint8_t                                 access_avail_control_info_present;
    session_access_avail_control_info       access_avail_control_info;
    uint8_t                                 spare[4];
    session_monitor_per_qf_ctrl_info        monitor_per_qf_ctrl_info[QOS_MONITOR_NUM];
} session_srr_create;

typedef struct tag_session_srr_update {
    uint8_t                                 ssr_id;
    uint8_t                                 monitor_per_qf_ctrl_info_num;
    uint8_t                                 access_avail_control_info_present;
    session_access_avail_control_info       access_avail_control_info;
    uint8_t                                 spare[4];
    session_monitor_per_qf_ctrl_info        monitor_per_qf_ctrl_info[QOS_MONITOR_NUM];
} session_srr_update;

#pragma pack(1)
typedef union tag_session_mptcp_control_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare     : 7;
        uint8_t     TCI       : 1;
#else
        uint8_t     TCI       : 1;
        uint8_t     spare     : 7;
#endif
    } d;
    uint8_t value;
} session_mptcp_control_info;
#pragma pack()

#pragma pack(1)
typedef union tag_session_atsss_ll_control_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare     : 7;
        uint8_t     LLI       : 1;
#else
        uint8_t     LLI       : 1;
        uint8_t     spare     : 7;
#endif
    } d;
    uint8_t value;
} session_atsss_ll_control_info;
#pragma pack()

#pragma pack(1)
typedef union tag_session_pmf_control_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare     : 6;
        uint8_t     DRTTI     : 1;
        uint8_t     PMFI      : 1;
#else
        uint8_t     PMFI      : 1;
        uint8_t     DRTTI     : 1;
        uint8_t     spare     : 6;
#endif
    } d;
    uint8_t value;
} session_pmf_control_info;
#pragma pack()

#pragma pack(1)
typedef struct tag_session_provide_atsss_ctrl_info {
    session_mptcp_control_info              mptcp_control_info;
    session_atsss_ll_control_info           atsss_ll_control_info;
    session_pmf_control_info                pmf_control_info;
} session_provide_atsss_ctrl_info;
#pragma pack()

typedef struct tag_session_mac_address_detected {
    uint8_t             mac_num;
    uint8_t             c_tag_len;
    uint8_t             s_tag_len;
    uint8_t             spare[5];
    session_vlan_tag    c_tag;
    session_vlan_tag    s_tag;
    uint8_t             mac_addr[MAX_MAC_ADDRESS_NUM][ETH_ALEN];
} session_mac_address_detected;

typedef struct tag_session_mac_address_removed {
    uint8_t             mac_num;
    uint8_t             c_tag_len;
    uint8_t             s_tag_len;
    uint8_t             spare[5];
    session_vlan_tag    c_tag;
    session_vlan_tag    s_tag;
    uint8_t             mac_addr[MAX_MAC_ADDRESS_NUM][ETH_ALEN];
} session_mac_address_removed;

/* TSC Management Information */
typedef struct tag_session_tsc_management_info {
    char                            port_mgmt_info_container[PORT_MGMT_INFO_CONT_LEN];
    char                            bridge_mgmt_info_container[BRIDGE_MGMT_INFO_CONT_LEN];
    /* When PMIC IE is present, this IE shall contain the related NW-TT Port Number. */
    uint32_t                        nw_tt_port_number;
    uint8_t                         pmic_present;
    uint8_t                         bmic_present;
    uint8_t                         ntpn_present;
    uint8_t                         spare;
} session_tsc_management_info;

typedef struct tag_session_ethernet_context_information {
    uint8_t                             mac_addr_detected_num;
    uint8_t                             spare[7];
    session_mac_address_detected        mac_addr_detected[MAC_ADDRESS_DETECTED_NUM];
} session_ethernet_context_information;

/* session response */
typedef struct tag_session_created_pdr {
    uint16_t                    pdr_id;
    uint8_t                     ueip_addr_num;
    uint8_t                     local_fteid_present;
    uint8_t                     rt_local_fteid_present;
    uint8_t                     spare[3];
    session_f_teid              local_fteid;
    session_f_teid              rt_local_fteid;/* Local F-TEID for Redundant Transmission */
    session_ue_ip               ueip_addr[MAX_UE_IP_NUM];
} session_created_pdr;

typedef struct tag_session_load_contrl_info {
    uint32_t        sequence_number;
    uint8_t         load_metric;
    uint8_t         spare[3];
} session_load_contrl_info;

#pragma pack(1)
typedef union tag_session_OCI_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare: 7;
        uint8_t     AOCI: 1;
#else
        uint8_t     AOCI: 1;
        uint8_t     spare: 7;
#endif
    } d;
    uint8_t value;
} session_oci_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_timer {
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
} session_timer;
#pragma pack()

typedef struct tag_session_overload_contrl_info {
    uint32_t                    sequence_number;
    uint8_t                     overload_reduc_metric;
    session_timer               timer;
    session_oci_flags           oci_flag;
    uint8_t                     spare;
} session_overload_contrl_info;

#pragma pack(1)
typedef union tag_session_creare_rep_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                           : 22;
        uint32_t        rds_config_info_present         : 1;
        uint32_t        atsss_ctrl_para_present         : 1;
        uint32_t        created_bg_info_present         : 1;
        uint32_t        added_usage_report_present      : 1;
        uint32_t        failed_rule_id_present          : 1;
        uint32_t        overload_ctl_info_present       : 1;
        uint32_t        load_ctl_info_present           : 1;
        uint32_t        local_f_seid_present            : 1;
        uint32_t        offending_ie_present            : 1;

#else
        uint32_t        offending_ie_present            : 1;
        uint32_t        local_f_seid_present            : 1;
        uint32_t        load_ctl_info_present           : 1;
        uint32_t        overload_ctl_info_present       : 1;
        uint32_t        failed_rule_id_present          : 1;
        uint32_t        added_usage_report_present      : 1;
        uint32_t        created_bg_info_present         : 1;
        uint32_t        atsss_ctrl_para_present         : 1;
        uint32_t        rds_config_info_present         : 1;
        uint32_t        spare                           : 22;
#endif
    } d;
    uint32_t value;
} session_creare_rep_member_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_added_usage_report_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t    AURI: 1;
        uint16_t    AUR_value_number: 15;
#else
        uint16_t    AUR_value_number: 15;
        uint16_t    AURI: 1;
#endif
    } d;
    uint16_t     value;
} session_added_usage_report_info;
#pragma pack()

typedef struct tag_session_failed_rule_id {
    uint8_t         rule_type;/* See SESSION_FAILED_RULE_TYPE */
    uint8_t         spare[3];
    uint32_t        rule_id;
} session_failed_rule_id;

typedef struct tag_session_created_tc_endpoint {
    uint8_t             tc_endpoint_id;
    uint8_t             ueip_addr_num;
    uint8_t             local_fteid_present;
    uint8_t             rt_local_fteid_present;
    uint8_t             spare[4];
    session_f_teid      local_fteid;
    session_f_teid      rt_local_fteid;/* Local F-TEID for Redundant Transmission */
    session_ue_ip       ueip_addr[MAX_UE_IP_NUM];
} session_created_tc_endpoint;

#pragma pack(1)
typedef union tag_session_usage_report_trigger {
    struct {
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

        uint32_t        spare_b1:3;     /* spare */
        uint32_t        emrre:1;        /* End Marker Reception REport */
        uint32_t        quvti:1;        /* Quota Validity Time */
        uint32_t        ipmjl:1;        /* IP Multicast Join/Leave */
        uint32_t        tebur:1;        /* Termination By UP function Report */
        uint32_t        evequ:1;        /* event quota */
#else
        uint32_t        evequ:1;        /* event quota */
        uint32_t        tebur:1;        /* Termination By UP function Report */
        uint32_t        ipmjl:1;        /* IP Multicast Join/Leave */
        uint32_t        quvti:1;        /* Quota Validity Time */
        uint32_t        emrre:1;        /* End Marker Reception REport */
        uint32_t        spare_b1:3;     /* spare */

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
} session_usage_report_trigger;
#pragma pack()

#pragma pack(1)
typedef union tag_session_urr_usage_info {
    struct {
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
} session_urr_usage_info;
#pragma pack()

typedef struct tag_session_eth_traffic_info {
    uint8_t                             mac_addr_detect_num;
    uint8_t                             mac_addr_rm_num;
    uint8_t                             spare[6];
    session_mac_address_detected        mac_addr_detect[MAC_ADDRESS_DETECTED_NUM];
    session_mac_address_removed         mac_addr_rm[MAC_ADDRESS_REMOVED_NUM];
} session_eth_traffic_info ;

#pragma pack(1)
typedef union tag_session_md_usage_report_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 23;
        uint32_t        eth_fraffic_present         : 1;
        uint32_t        query_urr_ref_present       : 1;
        uint32_t        usage_info_present          : 1;
        uint32_t        last_pkt_time_present       : 1;
        uint32_t        first_pkt_time_present      : 1;
        uint32_t        duration_present            : 1;
        uint32_t        vol_meas_present            : 1;
        uint32_t        end_time_present            : 1;
        uint32_t        start_time_present          : 1;

#else
        uint32_t        start_time_present          : 1;
        uint32_t        end_time_present            : 1;
        uint32_t        vol_meas_present            : 1;
        uint32_t        duration_present            : 1;
        uint32_t        first_pkt_time_present      : 1;
        uint32_t        last_pkt_time_present       : 1;
        uint32_t        usage_info_present          : 1;
        uint32_t        query_urr_ref_present       : 1;
        uint32_t        eth_fraffic_present         : 1;
        uint32_t        spare                       : 23;
#endif
    } d;
    uint32_t value;
} session_md_usage_report_member_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_tsn_bridge_id_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare:7;
        uint8_t         bid:1;
#else
        uint8_t         bid:1;
        uint8_t         spare:7;
#endif
    }d;
    uint8_t value;
} session_tsn_bridge_id_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_bridge_id_value {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t        priority;
        uint8_t         mac[ETH_ALEN];
#else
        uint8_t         mac[ETH_ALEN];
        uint16_t        priority;
#endif
    }d;
    uint64_t value;
} session_bridge_id_value;
#pragma pack()

typedef struct tag_session_tsn_brige_id {
   session_tsn_bridge_id_flags  flag;
   uint8_t                      spare[7];
   session_bridge_id_value      bridge_id;
} session_tsn_brige_id;

typedef struct tag_session_create_bg_info_within_resp {
   uint32_t                     ds_tt_port_number;
   uint8_t                      ds_tt_port_number_present;
   uint8_t                      tsn_brige_id_present;
   uint8_t                      spare[2];
   session_tsn_brige_id         tsn_brige_id;
} session_created_bg_info_within_resp;

typedef struct tag_session_query_packet_rate_status {
   uint32_t                     qer_id;
} session_query_packet_rate_status;

#pragma pack(1)
typedef union tag_session_rds_config_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :7;
        uint8_t         rds     :1;
#else
        uint8_t         rds     :1;
        uint8_t         spare   :7;
#endif
    }d;
    uint8_t             value;
} session_rds_config_info;
#pragma pack()

#pragma pack(1)
typedef struct tag_session_provide_rds_config_info {
    session_rds_config_info     rds_config_info;
} session_provide_rds_config_info;
#pragma pack()

#pragma pack(1)
typedef union tag_session_mptcp_address_info_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :6;
        uint8_t         V6      :1;
        uint8_t         V4      :1;
#else
        uint8_t         V4      :1;
        uint8_t         V6      :1;
        uint8_t         spare   :6;
#endif
    }d;
    uint8_t value;
} session_mptcp_address_info_flags;
#pragma pack()

typedef struct tag_session_mptcp_address_info {
    session_mptcp_address_info_flags    flag;
    uint8_t                             mptcp_proxy_type;
    uint16_t                            mptcp_proxy_port;
    uint32_t                            mptcp_proxy_ipv4;
    uint8_t                             mptcp_proxy_ipv6[IPV6_ALEN];
} session_mptcp_address_info;

/* UE Link-Specific IP Address */
#pragma pack(1)
typedef union tag_session_ue_link_s_ip_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :4;
        uint8_t         NV6     :1;
        uint8_t         NV4     :1;
        uint8_t         V6      :1;
        uint8_t         V4      :1;
#else
        uint8_t         V4      :1;
        uint8_t         V6      :1;
        uint8_t         NV4     :1;
        uint8_t         NV6     :1;
        uint8_t         spare   :4;
#endif
    }d;
    uint8_t value;
} session_ue_link_s_ip_flags;
#pragma pack()

typedef struct tag_session_ue_link_s_ip_address {
    session_ue_link_s_ip_flags      flag;
    uint8_t                         spare[7];
    uint32_t                        ipv4_3gpp;
    uint32_t                        ipv4_non_3gpp;
    uint8_t                         ipv6_3gpp[IPV6_ALEN];
    uint8_t                         ipv6_non_3gpp[IPV6_ALEN];
} session_ue_link_s_ip_address;

typedef struct tag_session_mptcp_param {
    session_mptcp_address_info      mptcp_address_info;
    session_ue_link_s_ip_address    ue_link_s_ip;
} session_mptcp_param;

#pragma pack(1)
typedef union tag_session_atsss_ll_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare     : 7;
        uint8_t     LLI       : 1;
#else
        uint8_t     LLI       : 1;
        uint8_t     spare     : 7;
#endif
    } d;
    uint8_t value;
} session_atsss_ll_info;
#pragma pack()

#pragma pack(1)
typedef struct tag_session_atsss_ll_param {
    session_atsss_ll_info       atsss_ll_info;
    uint8_t                     spare[7];
} session_atsss_ll_param;
#pragma pack()

#pragma pack(1)
typedef union tag_session_pmf_address_info_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :5;
        uint8_t         MAC     :1;
        uint8_t         V6      :1;
        uint8_t         V4      :1;
#else
        uint8_t         V4      :1;
        uint8_t         V6      :1;
        uint8_t         MAC     :1;
        uint8_t         spare   :5;
#endif
    }d;
    uint8_t value;
} session_pmf_address_info_flags;
#pragma pack()

typedef struct tag_session_pmf_address_info {
    session_pmf_address_info_flags      flag;
    uint8_t                             spare[3];
    uint32_t                            pmf_ipv4;
    uint8_t                             pmf_ipv6[IPV6_ALEN];
    uint16_t                            pmf_port_3gpp;
    uint8_t                             pmf_mac_3gpp[ETH_ALEN];
    uint16_t                            pmf_port_non_3gpp;
    uint8_t                             pmf_mac_non_3gpp[ETH_ALEN];
} session_pmf_address_info;

typedef struct tag_session_pmf_param {
    session_pmf_address_info        pmf_address_info;
} session_pmf_param;

typedef struct tag_session_atsss_control_param {
    session_mptcp_param             mptcp_para;
    session_atsss_ll_param          atsss_ll_para;
    session_pmf_param               pmf_para;
    uint8_t                         mptcp_para_present;
    uint8_t                         atsss_ll_para_present;
    uint8_t                         pmf_para_present;
    uint8_t                         spare[5];
} session_atsss_control_param;

typedef struct tag_session_updated_pdr {
    uint16_t                    pdr_id;
    uint8_t                     rt_local_fteid_present;
    uint8_t                     ueip_addr_num;
    uint8_t                     local_fteid_present;
    uint8_t                     spare[3];
    session_f_teid              rt_local_fteid;/* Local F-TEID for Redundant Transmission */
    session_f_teid              local_fteid;
    session_ue_ip               ueip_addr[UPDATED_PDR_NUM];
} session_updated_pdr;

typedef struct tag_session_packet_rate_status_report {
    uint32_t                            qer_id;
    uint8_t                             spare[4];
    session_packet_rate_status          packet_rate_status;
} session_packet_rate_status_report;

typedef struct tag_session_offending_ie_information {
    void                                *value;
} session_offending_ie_information;

typedef struct tag_session_partial_failure_information {
    session_failed_rule_id              fail_rule_id;
    uint8_t                             cause;
    uint8_t                             spare[6];
    uint8_t                             offending_ie_info_num;
    session_offending_ie_information    offending_ie_info[OFFENDING_IE_INFO_NUM];
} session_partial_failure_information;

#pragma pack(1)
typedef struct tag_session_access_avail_report {
    uint8_t                             access_avail_info_num;
    session_access_avail_info           access_avail_info[2];
} session_access_avail_report;
#pragma pack()

#pragma pack(1)
typedef union tag_session_qos_monitor_measurement_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   : 4;
        uint8_t     PLMF    : 1;
        uint8_t     RP      : 1;
        uint8_t     UL      : 1;
        uint8_t     DL      : 1;
#else
        uint8_t     DL      : 1;
        uint8_t     UL      : 1;
        uint8_t     RP      : 1;
        uint8_t     PLMF    : 1;
        uint8_t     spare   : 4;
#endif
    } d;
    uint8_t value;
} session_qos_monitor_measurement_flags;
#pragma pack()

typedef struct tag_session_qos_monitor_measurement {
    session_qos_monitor_measurement_flags   flag;
    uint8_t                                 spare[3];
    uint32_t                                dl_packet_delay; /* Downlink packet delay */
    uint32_t                                ul_packet_delay; /* Uplink packet delay */
    uint32_t                                rt_packet_delay; /* Round trip packet delay */
} session_qos_monitor_measurement;

typedef struct tag_session_qos_monitor_report {
    uint8_t                             qfi;
    uint8_t                             spare[7];
    session_qos_monitor_measurement     qos_monitor_measurement;
    uint32_t                            time_stamp;
    uint32_t                            start_time;
} session_qos_monitor_report;

typedef struct tag_session_report {
    uint8_t                             srr_id;
    uint8_t                             access_avail_report_present;
    uint8_t                             qos_monitor_report_num;
    session_access_avail_report         access_avail_report;
    uint8_t                             spare[2];
    session_qos_monitor_report          qos_monitor_report[QOS_MONITOR_NUM];
} session_report;

/*
*   usage report within session modify response:
*       urr_id
*       ur_seqn
*       trigger
*       start_time
*       end_time
*       vol_meas
*       duration
*       first_pkt_time
*       last_pkt_time
*       usage_info
*       query_urr_ref
*       eth_fraffic
*   usage report within session delete response:
*       urr_id
*       ur_seqn
*       trigger
*       start_time
*       end_time
*       vol_meas
*       duration
*       first_pkt_time
*       last_pkt_time
*       usage_info
*       eth_fraffic
*/
typedef struct tag_session_md_usage_report {
    uint32_t                                urr_id;
    uint32_t                                ur_seqn;
    session_usage_report_trigger            trigger;
    session_md_usage_report_member_flags    member_flag;
    uint32_t                                start_time;     /* UTC time */
    uint32_t                                end_time;       /* UTC time */
    session_volume_measurement              vol_meas;
    uint32_t                                duration;
    uint32_t                                first_pkt_time; /* UTC time */
    uint32_t                                last_pkt_time;  /* UTC time */
    uint32_t                                query_urr_ref;  /* modify private */
    session_urr_usage_info                  usage_info;
    uint8_t                                 spare[7];
    session_eth_traffic_info                eth_traffic;
} session_md_usage_report;

/*
*   Structure shared by session establishment response,
*   session modification response, and session deletion response
*
*  session establishment apply:
*       Node ID
*       Cause
*       Offending IE
*       UP F-SEID
*       Created PDR
*       Load Control Information
*       Overload Control Information
*       Failed Rule ID
*       Created Traffic Endpoint
*       Created Bridge Info for TSC
*       ATSSS Control Parameters
*       RDS configuration information
*
*   session modification apply:
*       Cause
*       Offending IE
*       Created PDR
*       Load Control Information
*       Overload Control Information
*       Usage Report
*       Failed Rule ID
*       Additional Usage Reports Information
*       Created Traffic Endpoint
*       TSC Management Information
*       ATSSS Control Parameters
*       Updated PDR
*       Packet Rate Status Report
*
*   session delete apply:
*       Cause
*       Offending IE
*       Load Control Information
*       Overload Control Information
*       Usage Report
*       Additional Usage Reports Information
*       Packet Rate Status Report
*       Session Report
*
*/
typedef struct tag_session_emd_response {
    session_msg_header                      msg_header;

    uint64_t                                local_seid;
    uint64_t                                cp_seid;

    session_creare_rep_member_flags         member_flag;
    uint8_t                                 cause;
    uint8_t                                 created_pdr_num;
    uint16_t                                offending_ie;

    uint8_t                                 usage_report_num;
    uint8_t                                 created_tc_endpoint_num;
    session_added_usage_report_info         added_usage_report;
    uint8_t                                 updated_pdr_num;
    uint8_t                                 sess_report_num;
    session_rds_config_info                 rds_config_info;
    uint8_t                                 pkt_rate_status_report_num;

    uint8_t                                 tsc_mgmt_info_num;
    uint8_t                                 partial_failure_info_num;
    uint8_t                                 spare[6];

    session_f_seid                          local_f_seid;
    session_created_pdr                     created_pdr[MAX_PDR_NUM];
    session_load_contrl_info                load_ctl_info;
    session_overload_contrl_info            overload_ctl_info;

    session_md_usage_report                 usage_report[MAX_URR_NUM];
    session_failed_rule_id                  failed_rule_id;
    session_created_tc_endpoint             created_tc_endpoint[MAX_TC_ENDPOINT_NUM];
    session_created_bg_info_within_resp     created_bg_info;
    session_tsc_management_info             tsc_mgmt_info[TSC_MGMT_INFO_NUM];
    session_atsss_control_param             atsss_ctrl_para;
    session_updated_pdr                     updated_pdr[MAX_PDR_NUM];
    session_packet_rate_status_report       pkt_rate_status_report[PKT_RATE_STATUS_REPORT_NUM];
    session_report                          sess_report[MAX_SRR_NUM];
    session_partial_failure_information     partial_failure_info[PARTIAL_FAILURE_INFO_NUM];
} session_emd_response;

typedef struct tag_session_pfd_management_response {
    session_msg_header                      msg_header;

    uint32_t                                index;  /* local entry index */

    uint8_t                                 cause;
    uint8_t                                 offending_ie_present;
    uint16_t                                offending_ie;
} session_pfd_management_response;


/* PFCP session report request */
#pragma pack(1)
typedef union tag_session_report_type {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare:1;
        uint8_t     UISR:1;
        uint8_t     SESR:1;
        uint8_t     TMIR:1;
        uint8_t     UPIR:1;
        uint8_t     ERIR:1;
        uint8_t     USAR:1;
        uint8_t     DLDR:1;
#else
        uint8_t     DLDR:1;
        uint8_t     USAR:1;
        uint8_t     ERIR:1;
        uint8_t     UPIR:1;
        uint8_t     TMIR:1;
        uint8_t     SESR:1;
        uint8_t     UISR:1;
        uint8_t     spare:1;
#endif
    } d;
    uint8_t         value;
} session_report_type;
#pragma pack()

/* PFCP node report request */
#pragma pack(1)
typedef union tag_node_report_type_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare:4;
        uint8_t     GPQR:1;
        uint8_t     CKDR:1;
        uint8_t     UPRR:1;
        uint8_t     UPFR:1;
#else
        uint8_t     UPFR:1;
        uint8_t     UPRR:1;
        uint8_t     CKDR:1;
        uint8_t     GPQR:1;
        uint8_t     spare:4;
#endif
    } d;
    uint8_t         value;
} node_report_type_flags;
#pragma pack()


#pragma pack(1)
typedef union tag_session_dl_data_service_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   :6;
        uint8_t     qfii    :1;
        uint8_t     ppi     :1;
#else
        uint8_t     ppi     :1;
        uint8_t     qfii    :1;
        uint8_t     spare   :6;
#endif
    } d;
    uint8_t         value;
} session_dl_data_service_flags;
#pragma pack()

typedef struct tag_session_dl_data_service {
  session_dl_data_service_flags ddsi_flag;
  uint8_t                       ppi_value;  /* paging Policy Indication value */
  uint8_t                       qfi;        /* Qos Flow Identifer */
  uint8_t                       spare;
} session_dl_data_service_info;

#pragma pack(1)
typedef union tag_session_dl_data_status {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   :6;
        uint8_t     buff    :1;
        uint8_t     drop    :1;
#else
        uint8_t     drop    :1;
        uint8_t     buff    :1;
        uint8_t     spare   :6;
#endif
    } d;
    uint8_t         value;
} session_dl_data_status;
#pragma pack()

typedef struct tag_session_dl_data_report {
    uint8_t                         pdr_id_num;
    uint8_t                         spare[2];
    session_dl_data_status          dl_data_status;
    uint16_t                        pdr_id_arr[MAX_PDR_NUM];
    session_dl_data_service_info    dl_data_service[MAX_PDR_NUM];
} session_dl_data_report;

#pragma pack(1)
typedef union tag_session_remote_gtpu_peer_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare   :4;
        uint8_t     NI      :1;
        uint8_t     DI      :1;
        uint8_t     V4      :1;
        uint8_t     V6      :1;
#else
        uint8_t     V6      :1;
        uint8_t     V4      :1;
        uint8_t     DI      :1;
        uint8_t     NI      :1;
        uint8_t     spare   :4;
#endif
    } d;
    uint8_t         value;
} session_remote_gtpu_peer_flags;
#pragma pack()

typedef struct tag_session_remote_gtpu_peer {
  session_remote_gtpu_peer_flags    regtpr_flag;
  uint8_t                           dest_if;
  uint16_t                          des_if_len;
  uint32_t                          ipv4_addr;
  uint8_t                           ipv6_addr[IPV6_ALEN];
  uint16_t                          net_inst_len;
  uint8_t                           spare[6];
  char                              net_instance[NETWORK_INSTANCE_LEN];
} session_remote_gtpu_peer;

typedef struct tag_session_up_path_failure_report {
    uint8_t                         gtpu_peer_num;
    uint8_t                         spare[7];
    session_remote_gtpu_peer        gtpu_peer_arr[REMOTE_GTPU_PEER_NUM];
} session_up_path_failure_report;


typedef struct tag_session_app_detection_id {
    uint8_t     id_len;
    uint8_t     spare[7];
    uint8_t     value[APP_DETECTION_ID_LEN];
} session_app_detection_id;

typedef struct tag_session_app_instance_id {
    uint8_t     id_len;
    uint8_t     spare[7];
    uint8_t     app_inst_id[APP_INSTANCE_ID_LEN];
} session_app_instance_id;

#pragma pack(1)
typedef union tag_session_flow_direction {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t     spare       : 5;
        uint8_t     flow_direct : 3;
#else
        uint8_t     flow_direct : 3;
        uint8_t     spare       : 5;
#endif
    } d;
    uint8_t value;
} session_flow_direction;
#pragma pack()

typedef struct tag_session_flow_description_str {
    uint8_t     value_len;
    uint8_t     spare[7];
    uint8_t     flow_desc_value[FLOW_DESCRIPTION_STRING_LEN];
} session_flow_description_str;

typedef struct tag_session_flow_infomation {
    session_flow_direction              flow_dire;
    uint8_t                             spare[7];
    session_flow_description_str        flow_desc_str;
} session_flow_infomation;

typedef struct tag_session_app_detection_info {
    session_app_detection_id        app_id;
    uint8_t                         inst_id_present;
    uint8_t                         flow_info_present;
    uint8_t                         spare[3];
    uint8_t                         pdr_id_present;
    uint16_t                        pdr_id;
    session_app_instance_id         inst_id;
    session_flow_infomation         flow_info;
} session_app_detection_info;

/* Source IP Address */
#pragma pack(1)
typedef union tag_session_source_ip_addr_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :5;     /* spare */
        uint8_t         mpl     :1;     /* MPL */
        uint8_t         v4      :1;     /* v4 */
        uint8_t         v6      :1;     /* v6 */
#else
        uint8_t         v6      :1;     /* v6 */
        uint8_t         v4      :1;     /* v4 */
        uint8_t         mpl     :1;     /* MPL */
        uint8_t         spare   :5;     /* spare */
#endif
    }d;
    uint8_t             value;
} session_source_ip_addr_flag;
#pragma pack()

typedef struct tag_session_source_ip_address {
    session_source_ip_addr_flag flag;
    uint8_t                     prefix_len;
    uint8_t                     spare[2];
    uint32_t                    ipv4;
    uint8_t                     ipv6[16];
} session_source_ip_address;

/* SMF set ID */
typedef struct tag_session_smf_set_id {
    uint8_t                     spare;/* 这里是协议上要求保留的并且需要解析 */
    uint8_t                     spare_align[7];
    char                        fqdn[FQDN_LEN];
} session_smf_set_id;

#pragma pack(1)
typedef union tag_session_ip_multicast_address_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   : 4;
        uint8_t         a       : 1;/* any */
        uint8_t         r       : 1;/* range */
        uint8_t         v4      : 1;
        uint8_t         v6      : 1;
#else
        uint8_t         v6      : 1;
        uint8_t         v4      : 1;
        uint8_t         r       : 1;
        uint8_t         a       : 1;
        uint8_t         spare   : 4;
#endif
    } d;
    uint8_t value;
} session_ip_multicast_address_flags;
#pragma pack()

#pragma pack(1)
typedef struct tag_session_ip_multicast_address {
    session_ip_multicast_address_flags      flag;
    uint8_t                                 spare[7];
    union {
        uint32_t    ipv4;
        uint8_t     ipv6[IPV6_ALEN];
    } start_ip;
    union {
        uint32_t    ipv4;
        uint8_t     ipv6[IPV6_ALEN];
    } end_ip;
} session_ip_multicast_address;
#pragma pack()

typedef struct tag_session_ip_multicast_addr_info {
    session_ip_multicast_address    ip_mul_addr;
    uint8_t                         source_ip_num;
    uint8_t                         spare[7];
    session_source_ip_address       source_ip[IP_MUL_SOURCE_IP_NUM];
} session_ip_multicast_addr_info;

typedef struct tag_session_join_ip_multicast_info {
    session_ip_multicast_address        ip_mul_addr;
    uint8_t                             source_ip_addr_num;
    uint8_t                             spare[7];
    session_source_ip_address           source_ip_addr[IP_MUL_SOURCE_IP_NUM];
} session_join_ip_multicast_info;

typedef struct tag_session_leave_ip_multicast_info {
    session_ip_multicast_address        ip_mul_addr;
    uint8_t                             source_ip_addr_num;
    uint8_t                             spare[7];
    session_source_ip_address           source_ip_addr[IP_MUL_SOURCE_IP_NUM];
} session_leave_ip_multicast_info;

#pragma pack(1)
typedef union tag_session_ur_request_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 19;
        uint32_t        eth_fraffic_present         : 1;
        uint32_t        eve_stamp_present           : 1;
        uint32_t        query_urr_ref_present       : 1;
        uint32_t        usage_info_present          : 1;
        uint32_t        last_pkt_time_present       : 1;
        uint32_t        first_pkt_time_present      : 1;
        uint32_t        network_instance_present    : 1;
        uint32_t        ue_ip_present               : 1;
        uint32_t        app_detect_info_present     : 1;
        uint32_t        duration_present            : 1;
        uint32_t        vol_meas_present            : 1;
        uint32_t        end_time_present            : 1;
        uint32_t        start_time_present          : 1;

#else
        uint32_t        start_time_present          : 1;
        uint32_t        end_time_present            : 1;
        uint32_t        vol_meas_present            : 1;
        uint32_t        duration_present            : 1;
        uint32_t        app_detect_info_present     : 1;
        uint32_t        ue_ip_present               : 1;
        uint32_t        network_instance_present    : 1;
        uint32_t        first_pkt_time_present      : 1;
        uint32_t        last_pkt_time_present       : 1;
        uint32_t        usage_info_present          : 1;
        uint32_t        query_urr_ref_present       : 1;
        uint32_t        eve_stamp_present           : 1;
        uint32_t        eth_fraffic_present         : 1;
        uint32_t        spare                       : 19;
#endif
    } d;
    uint32_t value;
} session_ur_request_member_flags;
#pragma pack()

typedef struct tag_session_usage_report_request {
    uint32_t                            urr_id;
    uint32_t                            ur_seqn;
    session_usage_report_trigger        trigger;
    session_ur_request_member_flags     member_flag;
    uint32_t                            start_time;     /* UTC time */
    uint32_t                            end_time;       /* UTC time */
    session_volume_measurement          vol_meas;

    uint8_t                             network_inst_len;
    session_urr_usage_info              usage_info;
    uint8_t                             join_ip_mul_info_num;
    uint8_t                             leave_ip_mul_info_num;
    uint32_t                            duration;

    session_app_detection_info          app_detect_info;
    session_ue_ip                       ue_ip;
    char                                network_instance[NETWORK_INSTANCE_LEN];
    uint32_t                            first_pkt_time; /* UTC time */
    uint32_t                            last_pkt_time;  /* UTC time */
    uint32_t                            query_urr_ref;  /* modify private */
    uint32_t                            eve_stamp;      /* UTC time */
    session_eth_traffic_info            eth_traffic;
    session_join_ip_multicast_info      join_ip_mul_info[JOIN_IP_MUL_INFO_NUM];
    session_leave_ip_multicast_info     leave_ip_mul_info[JOIN_IP_MUL_INFO_NUM];
} session_report_request_ur;

typedef struct tag_session_error_indication_report {
    uint8_t                 f_teid_num;
    uint8_t                 spare[7];
    session_f_teid          remote_f_teid_arr[MAX_PDR_NUM];
} session_error_indication_report;

#pragma pack(1)
typedef union tag_session_pfcpsr_req_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t            spare    :7;
        uint8_t            psdbu    :1;
#else
        uint8_t            psdbu    :1;
        uint8_t            spare    :7;
#endif
    } d;
    uint8_t value;
} session_pfcpsr_req_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_pfcpsr_rsp_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t            spare    :7;
        uint8_t            drobu    :1;
#else
        uint8_t            drobu    :1;
        uint8_t            spare    :7;
#endif
    } d;
    uint8_t value;
} session_pfcpsr_rsp_flags;
#pragma pack()

typedef struct tag_session_up_path_recovery_report {
    uint8_t                         gtpu_peer_num;
    uint8_t                         spare[7];
    session_remote_gtpu_peer        gtpu_peer_arr[REMOTE_GTPU_PEER_NUM];
} session_up_path_recovery_report;

typedef struct tag_session_clock_drift_report {
    uint8_t                                 tsn_time_domain_number;
    uint8_t                                 time_offset_measurement_present;
    uint8_t                                 cumulative_rateratio_measurement_present;
    uint8_t                                 time_tamp_present;
    uint8_t                                 spare[4];
    int64_t                                 time_offset_measurement; /* in nanoseconds */
    uint32_t                                cumulative_rateratio_measurement;
    uint32_t                                time_tamp;
} session_clock_drift_report;


#pragma pack(1)
typedef union tag_session_qos_info_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t spare                       : 5;
        uint8_t dscp_present                : 1;
        uint8_t max_packet_delay_present    : 1;
        uint8_t min_packet_delay_present    : 1;
#else
        uint8_t min_packet_delay_present    : 1;
        uint8_t max_packet_delay_present    : 1;
        uint8_t dscp_present                : 1;
        uint8_t spare                       : 5;
#endif
    } d;
    uint32_t value;
} session_qos_info_member_flags;
#pragma pack()

typedef struct tag_session_qos_information {
    uint32_t                                ave_packet_delay; /* Delay Value in milliseconds */
    uint32_t                                min_packet_delay; /* Delay Value in milliseconds */
    uint32_t                                max_packet_delay; /* Delay Value in milliseconds */
    session_tos_tc                          dscp;
    session_qos_info_member_flags           member_flag;
    uint8_t                                 spare;
} session_qos_information;

#pragma pack(1)
typedef union tag_session_bar_response_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 28;
        uint32_t        buffer_pkts_cnt_present     : 1;
        uint32_t        dl_buff_pkts_cnt_present    : 1;
        uint32_t        dl_buff_duration_present    : 1;
        uint32_t        notify_delay_present        : 1;
#else
        uint32_t        notify_delay_present        : 1;
        uint32_t        dl_buff_duration_present    : 1;
        uint32_t        dl_buff_pkts_cnt_present    : 1;
        uint32_t        buffer_pkts_cnt_present     : 1;
        uint32_t        spare                       : 28;
#endif
    } d;
    uint32_t value;
} session_bar_response_member_flags;
#pragma pack()

typedef struct  tag_session_bar_response_update {
    session_bar_response_member_flags   member_flag;
    uint8_t                             bar_id;
    uint8_t                             notify_delay;
    session_timer                       dl_buff_duration;
    uint8_t                             buffer_pkts_cnt;
    uint16_t                            dl_buff_pkts_cnt;
    uint8_t                             spare[6];
} session_bar_response_update;

#pragma pack(1)
typedef union tag_session_asso_alt_smf_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :6;     /* spare */
        uint8_t         v4      :1;     /* v4 */
        uint8_t         v6      :1;     /* v6 */
#else
        uint8_t         v6      :1;     /* v6 */
        uint8_t         v4      :1;     /* v4 */
        uint8_t         spare   :6;     /* spare */
#endif
    }d;
    uint8_t             value;
} session_asso_alt_smf_flag;
#pragma pack()

typedef struct tag_session_alternative_smf_addr {
    session_asso_alt_smf_flag   flag;
    uint8_t                     spare[3];
    uint32_t                    ipv4;               /* IPv4 */
    uint8_t                     ipv6[IPV6_ALEN];    /* IPv6 */
} session_alternative_smf_addr;

#pragma pack(1)
typedef union tag_session_report_response_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 26;
        uint32_t        alt_smf_addr_present        : 1;
        uint32_t        n4_u_f_teid_present         : 1;
        uint32_t        cp_f_seid_present           : 1;
        uint32_t        pfcpsp_flag_present         : 1;
        uint32_t        update_bar_present          : 1;
        uint32_t        offending_ie_present        : 1;
#else
        uint32_t        offending_ie_present        : 1;
        uint32_t        update_bar_present          : 1;
        uint32_t        pfcpsp_flag_present         : 1;
        uint32_t        cp_f_seid_present           : 1;
        uint32_t        n4_u_f_teid_present         : 1;
        uint32_t        alt_smf_addr_present        : 1;
        uint32_t        spare                       : 26;
#endif
    } d;
    uint32_t value;
} session_report_response_member_flags;
#pragma pack()

typedef struct tag_session_report_response {
    session_msg_header                      msg_header;

    uint64_t                                local_seid;
    uint64_t                                cp_seid;

    session_report_response_member_flags    member_flag;
    uint8_t                                 cause;
    session_pfcpsr_rsp_flags                pfcpsp_flag;
    uint16_t                                offending_ie;
    session_bar_response_update             update_bar;
    session_f_seid                          cp_f_seid;
    session_f_teid                          n4_u_f_teid;
    session_alternative_smf_addr            alt_smf_addr;
} session_report_response;

#pragma pack(1)
typedef union tag_session_up_features {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t            TREU    :1;
        uint8_t            HEEU    :1;
        uint8_t            PFDM    :1;
        uint8_t            FTUP    :1;
        uint8_t            TRST    :1;
        uint8_t            DLBD    :1;
        uint8_t            DDND    :1;
        uint8_t            BUCP    :1;

        uint8_t            EPFAR   :1;
        uint8_t            PFDE    :1;
        uint8_t            FRRT    :1;
        uint8_t            TRACE   :1;
        uint8_t            QUOAC   :1;
        uint8_t            UDBC    :1;
        uint8_t            PDIU    :1;
        uint8_t            EMPU    :1;

        uint8_t            GCOM    :1;
        uint8_t            BUNDL   :1;
        uint8_t            MTE     :1;
        uint8_t            MNOP    :1;
        uint8_t            SSET    :1;
        uint8_t            UEIP    :1;
        uint8_t            ADPDP   :1;
        uint8_t            DPDRA   :1;

        uint8_t            MPTCP   :1;
        uint8_t            TSCU    :1;
        uint8_t            IP6PL   :1;
        uint8_t            IPTV    :1;
        uint8_t            NORP    :1;
        uint8_t            VTIME1  :1;
        uint8_t            RTTL    :1;
        uint8_t            MPAS    :1;

        uint8_t            RDS    :1;
        uint8_t            DDDS    :1;
        uint8_t            ETHAR   :1;
        uint8_t            CIOT    :1;
        uint8_t            MT_EDT  :1;
        uint8_t            GPQM    :1;
        uint8_t            QFQM    :1;
        uint8_t            ATSSS_LL:1;

        uint8_t            spare_6 :5;
        uint8_t            NSPOC   :1;
        uint8_t            QUASF   :1;
        uint8_t            RTTWP   :1;

        uint8_t            spare_7;

        uint8_t            spare_8;
#else
        uint8_t            spare_8;

        uint8_t            spare_7;

        uint8_t            RTTWP   :1;
        uint8_t            QUASF   :1;
        uint8_t            NSPOC   :1;
        uint8_t            spare_6 :5;

        uint8_t            ATSSS_LL:1;
        uint8_t            QFQM    :1;
        uint8_t            GPQM    :1;
        uint8_t            MT_EDT  :1;
        uint8_t            CIOT    :1;
        uint8_t            ETHAR   :1;
        uint8_t            DDDS    :1;
        uint8_t            RDS     :1;

        uint8_t            MPAS    :1;
        uint8_t            RTTL    :1;
        uint8_t            VTIME1  :1;
        uint8_t            NORP    :1;
        uint8_t            IPTV    :1;
        uint8_t            IP6PL   :1;
        uint8_t            TSCU    :1;
        uint8_t            MPTCP   :1;

        uint8_t            DPDRA   :1;
        uint8_t            ADPDP   :1;
        uint8_t            UEIP    :1;
        uint8_t            SSET    :1;
        uint8_t            MNOP    :1;
        uint8_t            MTE     :1;
        uint8_t            BUNDL   :1;
        uint8_t            GCOM    :1;

        uint8_t            EMPU    :1;
        uint8_t            PDIU    :1;
        uint8_t            UDBC    :1;
        uint8_t            QUOAC   :1;
        uint8_t            TRACE   :1;
        uint8_t            FRRT    :1;
        uint8_t            PFDE    :1;
        uint8_t            EPFAR   :1;

        uint8_t            BUCP    :1;
        uint8_t            DDND    :1;
        uint8_t            DLBD    :1;
        uint8_t            TRST    :1;
        uint8_t            FTUP    :1;
        uint8_t            PFDM    :1;
        uint8_t            HEEU    :1;
        uint8_t            TREU    :1;
#endif
    } d;
    uint64_t value;
} session_up_features;
#pragma pack()

#pragma pack(1)
typedef union tag_session_cp_features {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         uiaur   :1;/* CP function supports the UE IP Address Usage Reporting feature */
        uint8_t         ardr    :1;/* CP function supports Additional Usage Reports in the PFCP Session Deletion Response */
        uint8_t         mpas    :1;/* SMF support for multiple PFCP associations from an SMF set to a single UPF */
        uint8_t         bundl   :1;/* PFCP messages bunding is supported by the CP function */
        uint8_t         sset    :1;/* PFCP sessions successively */
        uint8_t         epfar   :1;/* PFCP Association Release feature */
        uint8_t         ovrl    :1;/* overload */
        uint8_t         load    :1;/* load */

        uint8_t         spare   :7;
        uint8_t         psucc   :1;/* CP function supports PFCP session establishment or modification with Partial Success. */
#else
        uint8_t         psucc   :1;/* CP function supports PFCP session establishment or modification with Partial Success. */
        uint8_t         spare   :7;

        uint8_t         load    :1;/* load */
        uint8_t         ovrl    :1;/* overload */
        uint8_t         epfar   :1;/* PFCP Association Release feature */
        uint8_t         sset    :1;/* PFCP sessions successively */
        uint8_t         bundl   :1;/* PFCP messages bunding is supported by the CP function */
        uint8_t         mpas    :1;/* SMF support for multiple PFCP associations from an SMF set to a single UPF */
        uint8_t         ardr    :1;/* CP function supports Additional Usage Reports in the PFCP Session Deletion Response */
        uint8_t         uiaur   :1;/* CP function supports the UE IP Address Usage Reporting feature */
#endif
    }d;
    uint16_t            value;
} session_cp_features;
#pragma pack()

/* user plane ip resource information */
#pragma pack(1)
typedef union tag_session_asso_upiri_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :1;     /* spare */
        uint8_t         assosi  :1;
        uint8_t         assoni  :1;
        uint8_t         teidri  :3;
        uint8_t         v6      :1;
        uint8_t         v4      :1;
#else
        uint8_t         v4      :1;
        uint8_t         v6      :1;
        uint8_t         teidri  :3;
        uint8_t         assoni  :1;
        uint8_t         assosi  :1;
        uint8_t         spare   :1;     /* spare */
#endif
    }d;
    uint8_t             value;
} session_asso_upiri_flag;
#pragma pack()

typedef struct tag_session_asso_upiri_info {
    session_asso_upiri_flag             flag;
    uint8_t                             teid_range;
    uint8_t                             network_inst_len;
    uint8_t                             source_interface;
    uint32_t                            ipv4;
    uint8_t                             ipv6[IPV6_ALEN];
    char                                network_inst[NETWORK_INSTANCE_LEN];
} session_asso_upiri_info;

#pragma pack(1)
typedef union tag_session_asso_release_request {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :6;     /* spare */
        uint8_t         urss    :1;     /* Sent PFCP session usage report */
        uint8_t         sarr    :1;     /* PFCP Association Release Request */
#else
        uint8_t         sarr    :1;     /* PFCP Association Release feature */
        uint8_t         urss    :1;     /* Sent PFCP session usage report */
        uint8_t         spare   :6;     /* spare */
#endif
    }d;
    uint8_t             value;
} session_asso_release_request;
#pragma pack()

/* PFCP Association Update Request message */
#pragma pack(1)
typedef union tag_session_asso_aureq_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :7;     /* spare */
        uint8_t         parps   :1;     /* parps */
#else
        uint8_t         parps   :1;     /* parps */
        uint8_t         spare   :7;     /* spare */
#endif
    }d;
    uint8_t             value;
} session_asso_aureq_flag;
#pragma pack()

#pragma pack(1)
typedef union tag_session_assoc_update_req_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                       : 27;
        uint32_t        pfcpau_req_flag_present     : 1;
        uint32_t        release_period_present      : 1;
        uint32_t        release_request_present     : 1;
        uint32_t        cp_features_present         : 1;
        uint32_t        up_features_present         : 1;
#else
        uint32_t        up_features_present         : 1;
        uint32_t        cp_features_present         : 1;
        uint32_t        release_request_present     : 1;
        uint32_t        release_period_present      : 1;
        uint32_t        pfcpau_req_flag_present     : 1;
        uint32_t        spare                       : 27;
#endif
    } d;
    uint32_t value;
} session_assoc_update_req_member_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_cp_pfcp_entity_ip_addr_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :6;     /* spare */
        uint8_t         v4      :1;     /* v4 */
        uint8_t         v6      :1;     /* v6 */
#else
        uint8_t         v6      :1;     /* v6 */
        uint8_t         v4      :1;     /* v4 */
        uint8_t         spare   :6;     /* spare */
#endif
    }d;
    uint8_t             value;
} session_cp_pfcp_entity_ip_addr_flag;
#pragma pack()

typedef struct tag_session_cp_pfcp_entity_ip_address {
    session_cp_pfcp_entity_ip_addr_flag flag;
    uint8_t                             spare[3];
    uint32_t                            ipv4;
    uint8_t                             ipv6[16];
} session_cp_pfcp_entity_ip_address;

typedef struct tag_session_retention_information {
    uint8_t                             cp_pfcp_entity_ip_num;
    uint8_t                             spare[7];
    session_cp_pfcp_entity_ip_address   cp_pfcp_entity_ip[CP_PFCP_ENTITY_IP_NUM];
} session_retention_information;

typedef struct tag_session_ue_ip_address_pool_identity {
    char                                pool_identity[UE_IP_ADDRESS_POOL_LEN];
} session_ue_ip_address_pool_identity;

#pragma pack(1)
typedef struct tag_session_s_nssai {
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t        sst :8;     /* Slice/Service Type */
    uint32_t        sd  :24;    /* Slice Differentiator */
#else
    uint32_t        sd  :24;    /* Slice Differentiator */
    uint32_t        sst :8;     /* Slice/Service Type */
#endif
} session_s_nssai;
#pragma pack()

typedef struct tag_session_ue_ip_address_pool_info {
    uint8_t                             pool_identity_num;
    uint8_t                             network_instance_present;
    uint8_t                             s_nssai_num;
    uint8_t                             ip_version; /* 1:IPv4 2:IPv6 3:IPv4&IPv6 */
    session_s_nssai                     s_nssai[MAX_S_NSSAI_NUM];
    session_ue_ip_address_pool_identity pool_identity[UEIP_POOL_NUM];
    char                                network_instance[APN_DNN_LEN];
} session_ue_ip_address_pool_info;

#pragma pack(1)
typedef union tag_session_gtpu_path_interface_type {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :6;
        uint8_t         n3      :1;
        uint8_t         n9      :1;
#else
        uint8_t         n9      :1;
        uint8_t         n3      :1;
        uint8_t         spare   :6;
#endif
    }d;
    uint8_t             value;
} session_gtpu_path_interface_type;
#pragma pack()

#pragma pack(1)
typedef union tag_session_qos_report_trigger {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :5;
        uint8_t         ire     :1;
        uint8_t         thr     :1;
        uint8_t         per     :1;
#else
        uint8_t         per     :1; /* 定期上报 */
        uint8_t         thr     :1; /* 超过阈值上报 */
        uint8_t         ire     :1; /* 立即上报 */
        uint8_t         spare   :5;
#endif
    }d;
    uint8_t             value;
} session_qos_report_trigger;
#pragma pack()

/* session_gtp_u_path_qos_control_info member flags */
#pragma pack(1)
typedef union tag_session_gupqci_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t        spare                       :9;
        uint16_t        min_waiting_time_present    :1;
        uint16_t        max_packet_delay_thr_present:1;
        uint16_t        min_packet_delay_thr_present:1;
        uint16_t        ave_packet_delay_thr_present:1;
        uint16_t        measurement_period_present  :1;
        uint16_t        dscp_present                :1;
        uint16_t        gtpu_path_if_type_present   :1;
#else
        uint16_t        gtpu_path_if_type_present   :1;
        uint16_t        dscp_present                :1;
        uint16_t        measurement_period_present  :1;
        uint16_t        ave_packet_delay_thr_present:1;
        uint16_t        min_packet_delay_thr_present:1;
        uint16_t        max_packet_delay_thr_present:1;
        uint16_t        min_waiting_time_present    :1;
        uint16_t        spare                       :9;
#endif
    }d;
    uint16_t            value;
} session_gupqci_member_flags;
#pragma pack()

typedef struct tag_session_gtp_u_path_qos_control_info {
    session_remote_gtpu_peer                remote_gtpu_peer[REMOTE_GTPU_PEER_NUM];
    session_gtpu_path_interface_type        gtpu_path_if_type;
    session_qos_report_trigger              qos_report_trigeer;
    session_tos_tc                          dscp;
    uint32_t                                measurement_period;
    uint32_t                                ave_packet_delay_thr; /* Delay Value in milliseconds */
    uint32_t                                min_packet_delay_thr; /* Delay Value in milliseconds */
    uint32_t                                max_packet_delay_thr; /* Delay Value in milliseconds */
    session_timer                           min_waiting_time;
    uint8_t                                 remote_gtpu_peer_num;
    session_gupqci_member_flags             member_flag;
} session_gtpu_path_qos_control_info;

#pragma pack(1)
typedef union tag_session_requested_clock_drift_info {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :6;
        uint8_t         rrcr    :1;
        uint8_t         rrto    :1;
#else
        uint8_t         rrto    :1;
        uint8_t         rrcr    :1;
        uint8_t         spare   :6;
#endif
    }d;
    uint8_t             value;
} session_requested_clock_drift_info;
#pragma pack()

typedef struct tag_session_clock_drift_control_info {
    session_requested_clock_drift_info      requested_clock_drift_info;
    uint8_t                                 tsn_time_domain_number_num;
    uint8_t                                 cumulative_rateratio_threshold_present;
    uint8_t                                 time_offset_threshold_present;
    uint32_t                                cumulative_rateratio_threshold;
    int64_t                                 time_offset_threshold; /* in nanoseconds */
    uint8_t                                 tsn_time_domain_number[TSN_TIME_DOMAIN_NUM];
    uint8_t                                 spare[2];
} session_clock_drift_control_info;

#pragma pack(1)
typedef union tag_session_pfcpasrsp_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :6;
        uint8_t         uupsi   :1;
        uint8_t         psrei   :1;
#else
        uint8_t         psrei   :1;
        uint8_t         uupsi   :1;
        uint8_t         spare   :6;
#endif
    }d;
    uint8_t             value;
} session_pfcpasrsp_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_mptcp_applicable_indication {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :7;
        uint8_t         mai     :1;
#else
        uint8_t         mai     :1;
        uint8_t         spare   :7;
#endif
    }d;
    uint8_t             value;
} session_mptcp_applicable_indication;
#pragma pack()

#pragma pack(1)
typedef struct tag_session_transport_delay_reporting {
    session_remote_gtpu_peer        preceding_ul_gtpu_peer;
    session_tos_tc                  dscp;
    uint8_t                         dscp_present;
    uint8_t                         spare[5];
} session_transport_delay_reporting;
#pragma pack()

typedef struct tag_session_gtpu_path_qos_report {
    session_remote_gtpu_peer                remote_gtpu_peer;
    uint32_t                                time_stamp;
    uint32_t                                start_time;
    session_qos_information                 qos_info[QOS_INFO_NUM];
    uint8_t                                 qos_info_num;
    session_gtpu_path_interface_type        gtpu_path_if_type;
    session_qos_report_trigger              qos_report_trigger;
    uint8_t                                 gtpu_path_if_type_present;
    uint8_t                                 start_time_present;
    uint8_t                                 spare[3];
} session_gtpu_path_qos_report;

#pragma pack(1)
typedef union tag_session_establish_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                           : 23;
        uint32_t        provide_rds_config_info_present : 1;
        uint32_t        s_nssai_present                 : 1;
        uint32_t        recovery_time_stamp_present     : 1;
        uint32_t        provide_atsss_ctrl_info_present : 1;
        uint32_t        apn_dnn_present                 : 1;
        uint32_t        trace_info_present              : 1;
        uint32_t        user_id_present                 : 1;
        uint32_t        inactivity_timer_present        : 1;
        uint32_t        bar_present                     : 1;
#else
        uint32_t        bar_present                     : 1;
        uint32_t        inactivity_timer_present        : 1;
        uint32_t        user_id_present                 : 1;
        uint32_t        trace_info_present              : 1;
        uint32_t        apn_dnn_present                 : 1;
        uint32_t        provide_atsss_ctrl_info_present : 1;
        uint32_t        recovery_time_stamp_present     : 1;
        uint32_t        s_nssai_present                 : 1;
        uint32_t        provide_rds_config_info_present : 1;
        uint32_t        spare                           : 23;
#endif
    } d;
    uint32_t value;
} session_establish_member_flags;
#pragma pack()

#pragma pack(1)
typedef union tag_session_modification_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        spare                           : 20;
        uint32_t        s_nssai_present                 : 1;
        uint32_t        eth_context_info_present        : 1;
        uint32_t        provide_atsss_ctrl_info_present : 1;
        uint32_t        change_node_present             : 1;
        uint32_t        trace_info_present              : 1;
        uint32_t        query_urr_reference_present     : 1;
        uint32_t        inactivity_timer_present        : 1;
        uint32_t        update_bar_present              : 1;
        uint32_t        create_bar_present              : 1;
        uint32_t        remove_bar_present              : 1;
        uint32_t        update_cp_seid_present          : 1;
#else
        uint32_t        update_cp_seid_present          : 1;
        uint32_t        remove_bar_present              : 1;
        uint32_t        create_bar_present              : 1;
        uint32_t        update_bar_present              : 1;
        uint32_t        inactivity_timer_present        : 1;
        uint32_t        query_urr_reference_present     : 1;
        uint32_t        trace_info_present              : 1;
        uint32_t        change_node_present             : 1;
        uint32_t        provide_atsss_ctrl_info_present : 1;
        uint32_t        eth_context_info_present        : 1;
        uint32_t        s_nssai_present                 : 1;
        uint32_t        spare                           : 20;
#endif
    } d;
    uint32_t value;
} session_modification_member_flags;
#pragma pack()

typedef struct tag_session_packet_detection_info {
    uint8_t                                 si;
    uint8_t                                 ue_ipaddr_num;
    uint8_t                                 traffic_endpoint_num;
    uint8_t                                 sdf_filter_num;
    uint8_t                                 eth_filter_num;
    uint8_t                                 qfi_number;
    uint8_t                                 framed_route_num;
    uint8_t                                 framed_ipv6_route_num;

    uint8_t                                 ip_mul_addr_num;
    session_3gpp_interface_type             src_if_type;
    session_eth_pdu_sess_info               eth_pdu_ses_info;
    uint8_t                                 spare;
    session_pdi_member_flags                member_flag;

    session_f_teid                          local_fteid;
    char                                    network_instance[NETWORK_INSTANCE_LEN];
    session_redundant_transmission_detection_param      redundant_transmission_param;
    session_ue_ip                           ue_ipaddr[MAX_UE_IP_NUM];
    session_sdf_filter                      sdf_filter[MAX_SDF_FILTER_NUM];
    session_eth_filter                      eth_filter[MAX_ETH_FILTER_NUM];
    session_framed_route                    framed_route[MAX_FRAMED_ROUTE_NUM];
    session_framed_route_ipv6               framed_ipv6_route[MAX_FRAMED_ROUTE_NUM];
    session_ip_multicast_addr_info          ip_mul_addr_info[IP_MUL_ADDR_INFO_NUM];
    char                                    application_id[MAX_APP_ID_LEN];

    uint8_t                                 traffic_endpoint_id[MAX_TC_ENDPOINT_NUM];
    uint8_t                                 qfi_array[MAX_QFI_NUM];
    /* 0:None  1:Send routing packets  2:Listen for routing packets  3:Send and Listen */
    uint32_t                                framed_routing;
} session_packet_detection_info;

typedef struct tag_session_pdr_create {
    uint16_t                                pdr_id;
    session_outer_header_removal            outer_header_removal;
    uint32_t                                precedence;

    session_pdr_member_flags                member_flag;
    uint32_t                                far_id;

    uint8_t                                 urr_id_number;
    uint8_t                                 qer_id_number;
    uint8_t                                 act_pre_number;
    uint8_t                                 ip_mul_addr_num;
    uint16_t                                mar_id;
    session_pkt_rd_carry_on_info            pkt_rd_carry_on_info;
    session_transport_delay_reporting       transport_delay_rep;
    uint8_t                                 ueip_addr_pool_identity_num;
    uint8_t                                 spare[2];
    session_mptcp_applicable_indication     mptcp_app_indication;
    uint32_t                                pdr_index; /* Local alloc index */

    uint32_t                                urr_id_array[MAX_URR_NUM];
    uint32_t                                qer_id_array[MAX_QER_NUM];
    session_act_predef_rules                act_pre_arr[ACTIVATE_PREDEF_RULE_NUM];
    uint32_t                                activation_time;
    uint32_t                                deactivation_time;

    session_ip_multicast_addr_info          ip_mul_addr_info[IP_MUL_ADDR_INFO_NUM];
    /* UE IPv4 Address Pool Identity shall be encoded before the UE IPv6 Address Pool Identity. */
    session_ue_ip_address_pool_identity     ueip_addr_pool_identity[2];
    session_packet_detection_info           pdi_content;
} session_pdr_create;

typedef struct tag_session_pdr_update {
    uint16_t                        pdr_id;
    session_outer_header_removal    outer_header_removal;
    uint32_t                        precedence;

    session_pdr_member_flags        member_flag;
    uint32_t                        far_id;

    uint8_t                         urr_id_number;
    uint8_t                         qer_id_number;
    uint8_t                         act_pre_number;
    uint8_t                         deact_pre_number;
    uint8_t                         ip_mul_addr_num;
    uint8_t                         spare[7];
    uint32_t                        pdr_index; /* Local alloc index */

    uint32_t                        urr_id_array[MAX_URR_NUM];
    uint32_t                        qer_id_array[MAX_QER_NUM];
    session_act_predef_rules        act_pre_arr[ACTIVATE_PREDEF_RULE_NUM];
    session_act_predef_rules        deact_pre_arr[ACTIVATE_PREDEF_RULE_NUM];
    uint32_t                        activation_time;
    uint32_t                        deactivation_time;

    session_ip_multicast_addr_info  ip_mul_addr[IP_MUL_ADDR_INFO_NUM];
    session_packet_detection_info   pdi_content;
    session_transport_delay_reporting   transport_delay_rep;
} session_pdr_update;

#pragma pack(1)
typedef union tag_session_pfcpasreq_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :7;
        uint8_t         uupsi   :1;
#else
        uint8_t         uupsi   :1;
        uint8_t         spare   :7;
#endif
    }d;
    uint8_t             value;
} session_pfcpasreq_flags;
#pragma pack()

typedef struct tag_session_ueip_address_usage_info {
    uint32_t                            seq_num;
    uint16_t                            validity_timer;
    uint8_t                             metric;
    uint32_t                            ue_ipv4_num;
    uint32_t                            ue_ipv6_num;
    char                                network_instance[NETWORK_INSTANCE_LEN];
    session_ue_ip_address_pool_identity ueip_pool_id;
} session_ueip_address_usage_info;

#pragma pack(1)
typedef union tag_session_assoc_setup_member_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t        spare                           : 11;
        uint16_t        nf_instance_id_present          : 1;
        uint16_t        retention_information_present   : 1;
        uint16_t        smf_set_id_present              : 1;
        uint16_t        cp_features_present             : 1;
        uint16_t        up_features_present             : 1;
#else
        uint16_t        up_features_present             : 1;
        uint16_t        cp_features_present             : 1;
        uint16_t        smf_set_id_present              : 1;
        uint16_t        retention_information_present   : 1;
        uint16_t        nf_instance_id_present          : 1;
        uint16_t        spare                           : 11;
#endif
    } d;
    uint16_t value;
} session_assoc_setup_member_flags;
#pragma pack()

/* It contains ie that may be used by association setup request/response */
typedef struct tag_session_association_setup {
    session_msg_header                      msg_header;

    uint32_t                                node_id_index;
    uint32_t                                recov_time;
    session_up_features                     up_features;

    pfcp_node_id                            node_id;
    session_cp_features                     cp_features;
    uint8_t                                 smf_ip_num;
    uint8_t                                 ue_ip_pool_num;
    uint8_t                                 gtpu_path_qos_ctrl_num;
    uint8_t                                 clock_drift_ctrl_num;
    session_pfcpasrsp_flags                 pfcpasrsp_flag;
    uint8_t                                 spare[7];
    session_assoc_setup_member_flags        member_flag;

    session_alternative_smf_addr            smf_ip_arr[ALTERNATIVE_SMF_IP_NUM];
    session_smf_set_id                      smf_set_id;
    session_retention_information           retention_information;
    session_ue_ip_address_pool_info         up_ip_pool_info[UEIP_POOL_NUM];
    session_gtpu_path_qos_control_info      gtpu_path_qos_ctrl_info[MONITOR_GTPU_PATH_NUM];
    session_clock_drift_control_info        clock_drift_ctrl_info[CLOCK_DRIFT_CONTROL_NUM];
    //char                                    upf_instance_id[16];
    session_pfcpasreq_flags                 pfcpasreq_flag;
} session_association_setup;

typedef struct tag_session_association_update {
    session_msg_header                      msg_header;

    uint32_t                                node_id_index;
    session_assoc_update_req_member_flags   member_flag;
    session_up_features                     up_features;

    session_cp_features                     cp_features;
    session_asso_release_request            release_request;
    session_timer                           release_period;
    session_asso_aureq_flag                 pfcpau_req_flag;
    uint8_t                                 smf_ip_num;
    uint8_t                                 clock_drift_ctrl_num;
    uint8_t                                 ue_ip_pool_num;
    uint8_t                                 gtpu_path_qos_ctrl_num;
    uint8_t                                 ueip_addrees_usage_info_num;
    uint8_t                                 spare[6];

    session_alternative_smf_addr            smf_ip_arr[ALTERNATIVE_SMF_IP_NUM];
    session_smf_set_id                      smf_set_id;
    session_clock_drift_control_info        clock_drift_ctrl_info[CLOCK_DRIFT_CONTROL_NUM];
    session_ue_ip_address_pool_info         up_ip_pool_info[UEIP_POOL_NUM];
    session_gtpu_path_qos_control_info      gtpu_path_qos_ctrl_info[MONITOR_GTPU_PATH_NUM];
    session_ueip_address_usage_info         ueip_addrees_usage_info[UEIP_POOL_NUM];
} session_association_update;

typedef struct tag_session_association_release_request {
    session_msg_header                      msg_header;

    uint32_t                                node_id_index;
} session_association_release_request;

typedef struct tag_session_association_release_response {
    uint32_t                    node_id_index;
    uint8_t                     cause;
} session_association_release_response;

typedef struct tag_session_content_create {
    session_msg_header              msg_header;

    uint32_t                        node_index;
    uint8_t                         pdr_num;
    uint8_t                         far_num;
    uint8_t                         urr_num;
    uint8_t                         qer_num;
    uint64_t                        local_seid;
    session_f_seid                  cp_f_seid;

    session_pdr_create              pdr_arr[MAX_PDR_NUM];
    session_far_create              far_arr[MAX_FAR_NUM];
    session_usage_report_rule       urr_arr[MAX_URR_NUM];
    session_qos_enforcement_rule    qer_arr[MAX_QER_NUM];

    uint8_t                         tc_endpoint_num;
    uint8_t                         pdn_type;
    uint8_t                         mar_num;
    session_pfcpsereq_flags         pfcpserq_flags;
    session_create_bg_info_within_req  create_bridge;
    session_provide_atsss_ctrl_info provide_atsss_ctrl_info;

    uint8_t                         srr_num;
    session_provide_rds_config_info provide_rds_config_info;
    uint8_t                         spare;
    uint8_t                         rat_type;
    session_establish_member_flags  member_flag;

    uint32_t                        recovery_time_stamp;
    uint32_t                        inactivity_timer;

    session_buffer_action_rule      bar;
    session_tc_endpoint             tc_endpoint_arr[MAX_TC_ENDPOINT_NUM];
    session_user_id                 user_id;
    session_trace_info              trace_info;
    session_apn_dnn                 apn_dnn;
    session_mar_create              mar_arr[MAX_MAR_NUM];
    session_srr_create              srr_arr[MAX_SRR_NUM];
    session_s_nssai                 s_nssai;
} session_content_create;

typedef struct tag_session_content_modify {
    session_msg_header                      msg_header;

    uint32_t                                node_index;
    uint64_t                                local_seid;
    uint64_t                                cp_seid;

    session_modification_member_flags       member_flag;
    uint32_t                                change_node_index;
    session_f_seid                          update_cp_fseid;

    uint8_t                                 remove_pdr_num;
    uint8_t                                 remove_far_num;
    uint8_t                                 remove_urr_num;
    uint8_t                                 remove_qer_num;
    uint8_t                                 remove_bar;
    uint8_t                                 remove_tc_endpoint_num;
    uint8_t                                 remove_mar_num;
    uint8_t                                 remove_srr_num;

    uint8_t                                 create_pdr_num;
    uint8_t                                 create_far_num;
    uint8_t                                 create_urr_num;
    uint8_t                                 create_qer_num;
    uint8_t                                 create_tc_endpoint_num;
    uint8_t                                 create_mar_num;
    uint8_t                                 create_srr_num;
    session_pfcpsm_req_flags                pfcpsm_flag;

    uint8_t                                 update_pdr_num;
    uint8_t                                 update_far_num;
    uint8_t                                 update_urr_num;
    uint8_t                                 update_qer_num;
    uint8_t                                 update_tc_endpoint_num;
    uint8_t                                 update_mar_num;
    uint8_t                                 update_srr_num;
    uint8_t                                 query_urr_num;

    /* session remove */
    uint16_t                                remove_pdr_arr[MAX_PDR_NUM];
    uint32_t                                remove_pdr_index_arr[MAX_PDR_NUM]; /* Local alloc index */
    uint16_t                                remove_mar_arr[MAX_MAR_NUM];
    uint32_t                                remove_far_arr[MAX_FAR_NUM];
    uint32_t                                remove_far_index_arr[MAX_FAR_NUM]; /* Local alloc index */
    uint32_t                                remove_urr_arr[MAX_URR_NUM];
    uint32_t                                remove_urr_index_arr[MAX_URR_NUM]; /* Local alloc index */
    uint32_t                                remove_qer_arr[MAX_QER_NUM];
    uint32_t                                remove_qer_index_arr[MAX_QER_NUM]; /* Local alloc index */

    uint8_t                                 remove_tc_endpoint_arr[MAX_TC_ENDPOINT_NUM];
    uint8_t                                 remove_srr_arr[MAX_SRR_NUM];
    session_provide_atsss_ctrl_info         provide_atsss_ctrl_info;
    uint8_t                                 access_avail_info_num;
    session_access_avail_info               access_avail_info[2];
    uint8_t                                 tsc_mgmt_info_num;
    uint8_t                                 query_pkt_rate_status_num;
    uint32_t                                remove_bar_index;
    uint32_t                                remove_pdr_index_num;

    uint8_t                                 rat_type;
    uint8_t                                 spare[3];
    session_s_nssai                         s_nssai;

    /* session create */
    session_pdr_create                      create_pdr_arr[MAX_PDR_NUM];
    session_far_create                      create_far_arr[MAX_FAR_NUM];
    session_usage_report_rule               create_urr_arr[MAX_URR_NUM];
    session_qos_enforcement_rule            create_qer_arr[MAX_QER_NUM];
    session_buffer_action_rule              create_bar;
    session_tc_endpoint                     create_tc_endpoint_arr[MAX_TC_ENDPOINT_NUM];
    session_mar_create                      create_mar_arr[MAX_MAR_NUM];
    session_srr_create                      create_srr_arr[MAX_SRR_NUM];
    /* session update */
    session_pdr_update                      update_pdr_arr[MAX_PDR_NUM];
    session_far_update                      update_far_arr[MAX_FAR_NUM];
    session_usage_report_rule               update_urr_arr[MAX_URR_NUM];
    session_qos_enforcement_rule            update_qer_arr[MAX_QER_NUM];
    session_buffer_action_rule              update_bar;
    session_tc_endpoint                     update_tc_endpoint_arr[MAX_TC_ENDPOINT_NUM];
    session_mar_update                      update_mar_arr[MAX_MAR_NUM];
    session_srr_update                      update_srr_arr[MAX_SRR_NUM];

    uint32_t                                query_urr_arr[MAX_URR_NUM];
    uint32_t                                inactivity_timer;
    uint32_t                                query_urr_reference;
    session_trace_info                      trace_info;
    session_tsc_management_info             tsc_mgmt_info[TSC_MGMT_INFO_NUM];
    session_ethernet_context_information    eth_context_info;
    session_query_packet_rate_status        query_pkt_rate_status[MAX_QER_NUM];
} session_content_modify;

typedef struct tag_session_content_delete {
    session_msg_header          msg_header;

    uint32_t                    node_index;
    uint8_t                     spare[4];
    uint64_t                    local_seid;
    uint64_t                    cp_seid;
} session_content_delete;

typedef struct tag_session_report_request {
    session_msg_header                      msg_header;

    uint64_t                                local_seid;
    uint64_t                                cp_seid;

    session_report_type                     report_type;
    uint8_t                                 usage_report_num;
    uint8_t                                 load_ctrl_present;
    uint8_t                                 overload_ctrl_present;
    session_added_usage_report_info         added_usage_report_info;
    session_pfcpsr_req_flags                pfcpsr_flag;
    uint8_t                                 old_cp_fseid_present;
    uint8_t                                 packet_rate_status_report_present;

    uint8_t                                 tsc_mgmt_info_num;
    uint8_t                                 sess_report_num;
    uint8_t                                 spare[6];

    session_dl_data_report                  dl_data_report;
    session_report_request_ur               usage_report_arr[MAX_URR_NUM];
    session_error_indication_report         err_indic_report;
    session_load_contrl_info                load_ctrl_info;
    session_overload_contrl_info            overload_ctrl_info;
    session_f_seid                          old_cp_fseid;
    session_packet_rate_status_report       packet_rate_status_report;
    session_tsc_management_info             tsc_mgmt_info[TSC_MGMT_INFO_NUM];
    session_report                          sess_report[MAX_SRR_NUM];
} session_report_request;

typedef struct tag_session_node_report_request {
    session_msg_header                      msg_header;

    node_report_type_flags                  node_report_type;
    uint8_t                                 path_fail_report_present;
    uint8_t                                 up_path_recovery_report_present;
    uint8_t                                 clock_drift_report_num;
    uint8_t                                 gtpu_path_qos_report_num;
    uint8_t                                 spare[7];
    session_up_path_failure_report          path_fail_report;
    session_up_path_recovery_report         up_path_recovery_report;
    session_clock_drift_report              clock_drift_report[CLOCK_DRIFT_CONTROL_NUM];
    session_gtpu_path_qos_report            gtpu_path_qos_report[GTPU_PATH_QOS_REPORT_NUM];
} session_node_report_request;

#pragma pack(1)
typedef union tag_session_pfd_content_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         ADNP    :1;
        uint8_t         AURL    :1;
        uint8_t         AFD     :1;
        uint8_t         DNP     :1;
        uint8_t         CP      :1;
        uint8_t         DN      :1;
        uint8_t         URL     :1;
        uint8_t         FD      :1;

        uint8_t         spare;
#else
        uint8_t         spare;

        uint8_t         FD      :1;
        uint8_t         URL     :1;
        uint8_t         DN      :1;
        uint8_t         CP      :1;
        uint8_t         DNP     :1;
        uint8_t         AFD     :1;
        uint8_t         AURL    :1;
        uint8_t         ADNP    :1;
#endif
    }d;
    uint16_t             value;
} session_pfd_content_flags;
#pragma pack()

typedef struct tag_session_pfd_flow_desc {
    union {
        uint32_t    ipv4;
        uint8_t     ipv6[IPV6_ALEN];
    } ip;
    union {
        uint32_t    ipv4_mask;
        uint8_t     ipv6_mask[IPV6_ALEN];
    } mask;
    uint16_t    port_min;
    uint16_t    port_max;
    uint8_t     protocol;
    uint8_t     ip_type; /* 1: ipv4  2: ipv6 3: any  SESSION_IP_TYPE */
    uint8_t     action; /* 0:permit  1:deny */
    uint8_t     dir; /* 0:in  1:out */
    uint8_t     ip_not; /* 0:default  1:not */
    uint8_t     no_port; /* 0:port valied  1:port invalied */
    uint8_t     spare[6];
} session_pfd_flow_desc;

#define MAX_PFD_FD_NUM              (4)
#define MAX_PFD_URL_NUM             (4)
#define MAX_PFD_URL_LEN             (256)
#define MAX_PFD_CUSTOM_PFD_LEN      (8)
#define MAX_PFD_DN_NUM              (4)
#define MAX_PFD_DNP_LEN             (16)
#define MAX_PFD_NUM_IN_APP          (4)
#define MAX_PFD_APP_IDS_NUM         (4)

typedef struct tag_session_pfd_contents {
    session_pfd_content_flags               flag;
    uint8_t                                 fd_num;
    uint8_t                                 url_num;
    uint8_t                                 domain_names_num;
    uint8_t                                 domain_name_pro_num;
    uint8_t                                 spare[2];
    session_pfd_flow_desc                   fd[MAX_PFD_FD_NUM];
    char                                    url[MAX_PFD_URL_NUM][MAX_PFD_URL_LEN];
    char                                    custom_pfd[MAX_PFD_CUSTOM_PFD_LEN];
    char                                    domain_names[MAX_PFD_DN_NUM][FQDN_LEN];
    char                                    domain_name_pro[MAX_PFD_DN_NUM][MAX_PFD_DNP_LEN];/* see 29.251 */
} session_pfd_contents;

typedef struct tag_session_pfd_context {
    uint8_t                                 pfd_contents_num;
    uint8_t                                 spare[7];
    session_pfd_contents                    pfd_contents[MAX_PFD_NUM_IN_APP];
} session_pfd_context;

typedef struct tag_session_application_ids_pfds {
    char                                    application_id[MAX_APP_ID_LEN];
    uint8_t                                 pfd_context_num;
    uint8_t                                 spare[7];
    session_pfd_context                     pfd_context[MAX_PFD_NUM_IN_APP];
} session_application_ids_pfds;

typedef struct tag_session_pfd_mgmt_request {
    session_msg_header                      msg_header;

    uint32_t                                entry_index; /* private */
    uint8_t                                 spare[3];
    uint8_t                                 app_ids_pfds_num;
    session_application_ids_pfds            app_ids_pfds[MAX_PFD_APP_IDS_NUM];
} session_pfd_mgmt_request;

/*****************user defined*******************/

#pragma pack(1)
typedef union tag_session_globally_unique_id {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t            time_low;
        uint16_t            time_mid;
        uint16_t            time_high_and_ver;
        uint64_t            clock_seq_and_res   :8;
        uint64_t            clock_seq_low       :8;
        uint64_t            node                :48;
#else
        uint64_t            node                :48;
        uint64_t            clock_seq_low       :8;
        uint64_t            clock_seq_and_res   :8;
        uint16_t            time_high_and_ver;
        uint16_t            time_mid;
        uint32_t            time_low;
#endif
    } d;
    uint8_t value[16];
} session_globally_unique_id;
#pragma pack()

/* Session rollback */
typedef struct tag_session_content_rollback {
    session_msg_header              msg_header;

    uint64_t                        local_seid;
    uint64_t                        cp_seid;
} session_content_rollback;

typedef struct tag_session_sig_trace {
    session_msg_header              msg_header;

	uint64_t                        local_seid;
    uint64_t                        cp_seid;

    uint32_t                        sigtrace_flag;	/*0: close, 1: open*/
} session_sig_trace;


/* Session seid pair */
typedef struct tag_session_seid_pair {
    uint64_t    up_seid;
    uint64_t    cp_seid;
} session_seid_pair;

/* PFD management rollback */
typedef struct tag_session_pfd_management_rollback {
    session_msg_header              msg_header;

    uint8_t                         app_ids_num;
    char                            app_ids[MAX_PFD_APP_IDS_NUM][MAX_APP_ID_LEN];
} session_pfd_management_rollback;

/* Session check */
typedef struct tag_session_content_check {
    session_msg_header              msg_header;

    uint64_t                        local_seid;
    uint64_t                        cp_seid;
    uint32_t                        ret; /* 0:success  1:fail */
} session_content_check;

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _SESSION_STRUCT_H__ */
