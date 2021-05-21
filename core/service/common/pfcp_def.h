/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _PFCP_DEF_H__
#define _PFCP_DEF_H__

#ifdef __cplusplus
extern "C" {
#endif

#define PFCP_MAJOR_VERSION                  1
#define PFCP_MAX_NODE_ID_LEN                127

#define PFCP_MOVE_FORWORD(buf_pos, move_len)         \
{                                           \
    buf_pos  += move_len;                   \
}

typedef enum
{
    UPF_RESERVED                                        = 0,
    UPF_CREATE_PDR                                      = 1,
    UPF_PDI                                             = 2,
    UPF_CREATE_FAR                                      = 3,
    UPF_FORWARDING_PARAMETERS                           = 4,
    UPF_DUPLICATING_PARAMETERS                          = 5,
    UPF_CREATE_URR                                      = 6,
    UPF_CREATE_QER                                      = 7,
    UPF_CREATED_PDR                                     = 8,
    UPF_UPDATE_PDR                                      = 9,
    UPF_UPDATE_FAR                                      = 10,
    UPF_UPDATE_FORWARDING_PARAMETERS                    = 11,
    UPF_UPDATE_BAR_PFCP_SESSION_REPORT_RESPONSE         = 12,
    UPF_UPDATE_URR                                      = 13,
    UPF_UPDATE_QER                                      = 14,
    UPF_REMOVE_PDR                                      = 15,
    UPF_REMOVE_FAR                                      = 16,
    UPF_REMOVE_URR                                      = 17,
    UPF_REMOVE_QER                                      = 18,
    UPF_CAUSE                                           = 19,
    UPF_SOURCE_INTERFACE                                = 20,
    UPF_F_TEID                                          = 21,
    UPF_NETWORK_INSTANCE                                = 22,
    UPF_SDF_FILTER                                      = 23,
    UPF_APPLICATION_ID                                  = 24,
    UPF_GATE_STATUS                                     = 25,
    UPF_MBR                                             = 26,
    UPF_GBR                                             = 27,
    UPF_QER_CORRELATION_ID                              = 28,
    UPF_PRECEDENCE                                      = 29,
    UPF_TRANSPORT_LEVEL_MARKING                         = 30,
    UPF_VOLUME_THRESHOLD                                = 31,
    UPF_TIME_THRESHOLD                                  = 32,
    UPF_MONITORING_TIME                                 = 33,
    UPF_SUBSEQUENT_VOLUME_THRESHOLD                     = 34,
    UPF_SUBSEQUENT_TIME_THRESHOLD                       = 35,
    UPF_INACTIVITY_DETECTION_TIME                       = 36,
    UPF_REPORTING_TRIGGERS                              = 37,
    UPF_REDIRECT_INFORMATION                            = 38,
    UPF_REPORT_TYPE                                     = 39,
    UPF_OFFENDING_IE                                    = 40,
    UPF_FORWARDING_POLICY                               = 41,
    UPF_DESTINATION_INTERFACE                           = 42,
    UPF_UP_FUNCTION_FEATURES                            = 43,
    UPF_APPLY_ACTION                                    = 44,
    UPF_DOWNLINK_DATA_SERVICE_INFORMATION               = 45,
    UPF_DOWNLINK_DATA_NOTIFICATION_DELAY                = 46,
    UPF_DL_BUFFERING_DURATION                           = 47,
    UPF_DL_BUFFERING_SUGGESTED_PACKET_COUNT             = 48,
    UPF_PFCPSMREQ_FLAGS                                 = 49,
    UPF_PFCPSRRSP_FLAGS                                 = 50,
    UPF_LOAD_CONTROL_INFORMATION                        = 51,
    UPF_SEQUENCE_NUMBER                                 = 52,
    UPF_METRIC                                          = 53,
    UPF_OVERLOAD_CONTROL_INFORMATION                    = 54,
    UPF_TIMER                                           = 55,
    UPF_PDR_ID                                          = 56,
    UPF_F_SEID                                          = 57,
    UPF_APPLICATION_IDS_PFDS                            = 58,
    UPF_PFD_CONTEXT                                     = 59,
    UPF_NODE_ID                                         = 60,
    UPF_PFD_CONTENTS                                    = 61,
    UPF_MEASUREMENT_METHOD                              = 62,
    UPF_USAGE_REPORT_TRIGGER                            = 63,
    UPF_MEASUREMENT_PERIOD                              = 64,
    UPF_FQ_CSID                                         = 65,
    UPF_VOLUME_MEASUREMENT                              = 66,
    UPF_DURATION_MEASUREMENT                            = 67,
    UPF_APPLICATION_DETECTION_INFORMATION               = 68,
    UPF_TIME_OF_FIRST_PACKET                            = 69,
    UPF_TIME_OF_LAST_PACKET                             = 70,
    UPF_QUOTA_HOLDING_TIME                              = 71,
    UPF_DROPPED_DL_TRAFFIC_THRESHOLD                    = 72,
    UPF_VOLUME_QUOTA                                    = 73,
    UPF_TIME_QUOTA                                      = 74,
    UPF_START_TIME                                      = 75,
    UPF_END_TIME                                        = 76,
    UPF_QUERY_URR                                       = 77,
    UPF_USAGE_REPORT_SESSION_MODIFICATION_RESPONSE      = 78,
    UPF_USAGE_REPORT_SESSION_DELETION_RESPONSE          = 79,
    UPF_USAGE_REPORT_SESSION_REPORT_REQUEST             = 80,
    UPF_URR_ID                                          = 81,
    UPF_LINKED_URR_ID                                   = 82,
    UPF_DOWNLINK_DATA_REPORT                            = 83,
    UPF_OUTER_HEADER_CREATION                           = 84,
    UPF_CREATE_BAR                                      = 85,
    UPF_UPDATE_BAR_SESSION_MODIFICATION_REQUEST         = 86,
    UPF_REMOVE_BAR                                      = 87,
    UPF_BAR_ID                                          = 88,
    UPF_CP_FUNCTION_FEATURES                            = 89,
    UPF_USAGE_INFORMATION                               = 90,
    UPF_APPLICATION_INSTANCE_ID                         = 91,
    UPF_FLOW_INFORMATION                                = 92,
    UPF_UE_IP_ADDRESS                                   = 93,
    UPF_PACKET_RATE                                     = 94,
    UPF_OUTER_HEADER_REMOVAL                            = 95,
    UPF_RECOVERY_TIME_STAMP                             = 96,
    UPF_DL_FLOW_LEVEL_MARKING                           = 97,
    UPF_HEADER_ENRICHMENT                               = 98,
    UPF_ERROR_INDICATION_REPORT                         = 99,
    UPF_MEASUREMENT_INFORMATION                         = 100,
    UPF_NODE_REPORT_TYPE                                = 101,
    UPF_USER_PLANE_PATH_FAILURE_REPORT                  = 102,
    UPF_REMOTE_GTP_U_PEER                               = 103,
    UPF_UR_SEQN                                         = 104,
    UPF_UPDATE_DUPLICATING_PARAMETERS                   = 105,
    UPF_ACTIVATE_PREDEFINED_RULES_                      = 106,
    UPF_DEACTIVATE_PREDEFINED_RULES_                    = 107,
    UPF_FAR_ID                                          = 108,
    UPF_QER_ID                                          = 109,
    UPF_OCI_FLAGS                                       = 110,
    UPF_PFCP_ASSOCIATION_RELEASE_REQUEST                = 111,
    UPF_GRACEFUL_RELEASE_PERIOD                         = 112,
    UPF_PDN_TYPE                                        = 113,
    UPF_FAILED_RULE_ID                                  = 114,
    UPF_TIME_QUOTA_MECHANISM                            = 115,
    UPF_RESERVED_116                                    = 116,
    UPF_USER_PLANE_INACTIVITY_TIMER                     = 117,
    UPF_AGGREGATED_URRS                                 = 118,
    UPF_MULTIPLIER                                      = 119,
    UPF_AGGREGATED_URR_ID                               = 120,
    UPF_SUBSEQUENT_VOLUME_QUOTA                         = 121,
    UPF_SUBSEQUENT_TIME_QUOTA                           = 122,
    UPF_RQI                                             = 123,
    UPF_QFI                                             = 124,
    UPF_QUERY_URR_REFERENCE                             = 125,
    UPF_ADDITIONAL_USAGE_REPORTS_INFORMATION            = 126,
    UPF_CREATE_TRAFFIC_ENDPOINT                         = 127,
    UPF_CREATED_TRAFFIC_ENDPOINT                        = 128,
    UPF_UPDATE_TRAFFIC_ENDPOINT                         = 129,
    UPF_REMOVE_TRAFFIC_ENDPOINT                         = 130,
    UPF_TRAFFIC_ENDPOINT_ID                             = 131,
    UPF_ETHERNET_PACKET_FILTER                          = 132,
    UPF_MAC_ADDRESS                                     = 133,
    UPF_C_TAG                                           = 134,
    UPF_S_TAG                                           = 135,
    UPF_ETHERTYPE                                       = 136,
    UPF_PROXYING                                        = 137,
    UPF_ETHERNET_FILTER_ID                              = 138,
    UPF_ETHERNET_FILTER_PROPERTIES                      = 139,
    UPF_SUGGESTED_BUFFERING_PACKETS_COUNT               = 140,
    UPF_USER_ID                                         = 141,
    UPF_ETHERNET_PDU_SESSION_INFORMATION                = 142,
    UPF_ETHERNET_TRAFFIC_INFORMATION                    = 143,
    UPF_MAC_ADDRESSES_DETECTED                          = 144,
    UPF_MAC_ADDRESSES_REMOVED                           = 145,
    UPF_ETHERNET_INACTIVITY_TIMER                       = 146,
    UPF_ADDITIONAL_MONITORING_TIME                      = 147,
    UPF_EVENT_QUOTA                                     = 148,
    UPF_EVENT_THRESHOLD                                 = 149,
    UPF_SUBSEQUENT_EVENT_QUOTA                          = 150,
    UPF_SUBSEQUENT_EVENT_THRESHOLD                      = 151,
    UPF_TRACE_INFORMATION                               = 152,
    UPF_FRAMED_ROUTE                                    = 153,
    UPF_FRAMED_ROUTING                                  = 154,
    UPF_FRAMED_IPV6_ROUTE                               = 155,
    UPF_TIME_STAMP                                      = 156,
    UPF_AVERAGING_WINDOW                                = 157,
    UPF_PAGING_POLICY_INDICATOR                         = 158,
    UPF_APN_DNN                                         = 159,
    UPF_3GPP_INTERFACE_TYPE                             = 160,
    UPF_PFCPSRREQ_FLAGS                                 = 161,
    UPF_PFCPAUREQ_FLAGS                                 = 162,
    UPF_ACTIVATION_TIME                                 = 163,
    UPF_DEACTIVATION_TIME                               = 164,
    UPF_CREATE_MAR                                      = 165,
    UPF_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION       = 166,
    UPF_NON_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION   = 167,
    UPF_REMOVE_MAR                                      = 168,
    UPF_UPDATE_MAR                                      = 169,
    UPF_MAR_ID                                          = 170,
    UPF_STEERING_FUNCTIONALITY                          = 171,
    UPF_STEERING_MODE                                   = 172,
    UPF_WEIGHT                                          = 173,
    UPF_PRIORITY                                        = 174,
    UPF_UPDATE_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION = 175,
    UPF_UPDATE_NON_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION = 176,
    UPF_UE_IP_ADDRESS_POOL_IDENTITY                     = 177,
    UPF_ALTERNATIVE_SMF_IP_ADDRESS                      = 178,

    UPF_PACKET_REPLICATION_AND_DETECTION_CARRY_ON_INFORMATION = 179,
    UPF_SMF_SET_ID                                          = 180,
    UPF_QUOTA_VALIDITY_TIME                                 = 181,
    UPF_NUMBER_OF_REPORTS                                   = 182,
    UPF_PFCP_SESSION_RETENTION_INFORMATION                  = 183,
    UPF_PFCPASRSP_FLAGS                                     = 184,
    UPF_CP_PFCP_ENTITY_IP_ADDRESS                           = 185,
    UPF_PFCPSEREQ_FLAGS                                     = 186,
    UPF_USER_PLANE_PATH_RECOVERY_REPORT                     = 187,
    UPF_IP_MULTICAST_ADDRESSING_INFO_WITHIN_PFCP_SESSION_ESTABLISHMENT_REQUEST = 188,
    UPF_JOIN_IP_MULTICAST_INFORMATION_IE_WITHIN_USAGE_REPORT = 189,
    UPF_LEAVE_IP_MULTICAST_INFORMATION_IE_WITHIN_USAGE_REPORT = 190,
    UPF_IP_MULTICAST_ADDRESS                                = 191,
    UPF_SOURCE_IP_ADDRESS                                   = 192,
    UPF_PACKET_RATE_STATUS                                  = 193,
    UPF_CREATE_BRIDGE_INFO_FOR_TSC                          = 194,
    UPF_CREATED_BRIDGE_INFO_FOR_TSC                         = 195,
    UPF_DS_TT_PORT_NUMBER                                   = 196,
    UPF_NW_TT_PORT_NUMBER                                   = 197,
    UPF_TSN_BRIDGE_ID                                       = 198,
    UPF_TSC_MGMT_INFO_IE_WITHIN_PFCP_SESSION_MODIFICATION_REQUEST = 199,
    UPF_TSC_MGMT_INFO_IE_WITHIN_PFCP_SESSION_MODIFICATION_RESPONSE = 200,
    UPF_TSC_MGMT_INFO_IE_WITHIN_PFCP_SESSION_REPORT_REQUEST = 201,
    UPF_PORT_MANAGEMENT_INFORMATION_CONTAINER               = 202,
    UPF_CLOCK_DRIFT_CONTROL_INFORMATION                     = 203,
    UPF_REQUESTED_CLOCK_DRIFT_INFORMATION                   = 204,
    UPF_CLOCK_DRIFT_REPORT                                  = 205,
    UPF_TSN_TIME_DOMAIN_NUMBER                              = 206,
    UPF_TIME_OFFSET_THRESHOLD                               = 207,
    UPF_CUMULATIVE_RATERATIO_THRESHOLD                      = 208,
    UPF_TIME_OFFSET_MEASUREMENT                             = 209,
    UPF_CUMULATIVE_RATERATIO_MEASUREMENT                    = 210,
    UPF_REMOVE_SRR                                          = 211,
    UPF_CREATE_SRR                                          = 212,
    UPF_UPDATE_SRR                                          = 213,
    UPF_SESSION_REPORT                                      = 214,
    UPF_SRR_ID                                              = 215,
    UPF_ACCESS_AVAILABILITY_CONTROL_INFORMATION             = 216,
    UPF_REQUESTED_ACCESS_AVAILABILITY_INFORMATION           = 217,
    UPF_ACCESS_AVAILABILITY_REPORT                          = 218,
    UPF_ACCESS_AVAILABILITY_INFORMATION                     = 219,
    UPF_PROVIDE_ATSSS_CONTROL_INFORMATION                   = 220,
    UPF_ATSSS_CONTROL_PARAMETERS                            = 221,
    UPF_MPTCP_CONTROL_INFORMATION                           = 222,
    UPF_ATSSS_LL_CONTROL_INFORMATION                        = 223,
    UPF_PMF_CONTROL_INFORMATION                             = 224,
    UPF_MPTCP_PARAMETERS                                    = 225,
    UPF_ATSSS_LL_PARAMETERS                                 = 226,
    UPF_PMF_PARAMETERS                                      = 227,
    UPF_MPTCP_ADDRESS_INFORMATION                           = 228,
    UPF_UE_LINK_SPECIFIC_IP_ADDRESS                         = 229,
    UPF_PMF_ADDRESS_INFORMATION                             = 230,
    UPF_ATSSS_LL_INFORMATION                                = 231,
    UPF_DATA_NETWORK_ACCESS_IDENTIFIER                      = 232,
    UPF_UE_IP_ADDRESS_POOL_INFORMATION                      = 233,
    UPF_AVERAGE_PACKET_DELAY                                = 234,
    UPF_MINIMUM_PACKET_DELAY                                = 235,
    UPF_MAXIMUM_PACKET_DELAY                                = 236,
    UPF_QOS_REPORT_TRIGGER                                  = 237,
    UPF_GTP_U_PATH_QOS_CONTROL_INFORMATION                  = 238,
    UPF_GTP_U_PATH_QOS_REPORT                               = 239,
    UPF_QOS_INFORMATION_IN_GTP_U_PATH_QOS_REPORT            = 240,
    UPF_GTP_U_PATH_INTERFACE_TYPE                           = 241,
    UPF_QOS_MONITORING_PER_QOS_FLOW_CONTROL_INFORMATION     = 242,
    UPF_REQUESTED_QOS_MONITORING                            = 243,
    UPF_REPORTING_FREQUENCY                                 = 244,
    UPF_PACKET_DELAY_THRESHOLDS                             = 245,
    UPF_MINIMUM_WAIT_TIME                                   = 246,
    UPF_QOS_MONITORING_REPORT                               = 247,
    UPF_QOS_MONITORING_MEASUREMENT                          = 248,
    UPF_MT_EDT_CONTROL_INFORMATION                          = 249,
    UPF_DL_DATA_PACKETS_SIZE                                = 250,
    UPF_QER_CONTROL_INDICATIONS                             = 251,
    UPF_PACKET_RATE_STATUS_REPORT                           = 252,
    UPF_NF_INSTANCE_ID                                      = 253,
    UPF_ETHERNET_CONTEXT_INFORMATION                        = 254,
    UPF_REDUNDANT_TRANSMISSION_PARAMETERS                   = 255,
    UPF_UPDATED_PDR                                         = 256,
    UPF_S_NSSAI                                             = 257,
    UPF_IP_VERSION                                          = 258,
    UPF_PFCPASREQ_FLAGS                                     = 259,
    UPF_DATA_STATUS                                         = 260,
    UPF_PROVIDE_RDS_CONFIGURATION_INFORMATION               = 261,
    UPF_RDS_CONFIGURATION_INFORMATION                       = 262,
    UPF_QUERY_PACKET_RATE_STATUS_IE_WITHIN_PFCP_SESSION_MODIFICATION_REQUEST = 263,
    UPF_PACKET_RATE_STATUS_REPORT_IE_WITHIN_PFCP_SESSION_MODIFICATION_RESPONSE = 264,
    UPF_MPTCP_APPLICABLE_INDICATION                         = 265,
    UPF_BRIDGE_MANAGEMENT_INFORMATION_CONTAINER             = 266,
    UPF_UE_IP_ADDRESS_USAGE_INFORMATION                     = 267,
    UPF_NUMBER_OF_UE_IP_ADDRESSES                           = 268,
    UPF_VALIDITY_TIMER                                      = 269,
    UPF_REDUNDANT_TRANSMISSION_FORWARDING_PARAMETERS        = 270,
    UPF_TRANSPORT_DELAY_REPORTING                           = 271,
    UPF_PARTIAL_FAILURE_INFORMATION_FOR_SESS_EST_RESP       = 272,
    UPF_PARTIAL_FAILURE_INFORMATION_FOR_SESS_MOD_RESP       = 273,
    UPF_OFFENDING_IE_INFORMATION                            = 274,
    UPF_RAT_TYPE                                            = 275,


    /* 276 to 32767 spare. For future use.
    *  32768 to 65535 Reserved for vendor specific IEs
    */
    UPF_VENDOR_RAT_TYPE                                     = 36001,
    UPF_USER_LOCATION_INFO                                  = 36006,

}EN_PFCP_OBJ_TYPE;

typedef enum {
    UPF_NODE_TYPE_IPV4,
    UPF_NODE_TYPE_IPV6,
    UPF_NODE_TYPE_FQDN,
    UPF_NODE_TYPE_BUTT,
}EN_UPF_NODE_TYPE;

#pragma pack(1)
typedef struct  tag_pfcp_msg_header
{
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t             version :3;     /* Version */
    uint8_t             spare   :2;     /* Spare */
    uint8_t             fo      :1;     /* Follow On flag */
    uint8_t             mp      :1;     /* Message Priority flag */
    uint8_t             s       :1;     /* SEID flag */
#else
    uint8_t             s       :1;     /* SEID flag */
    uint8_t             mp      :1;     /* Message Priority flag */
    uint8_t             fo      :1;     /* Follow On flag */
    uint8_t             spare   :2;     /* Spare */
    uint8_t             version :3;     /* Version */
#endif
    uint8_t             msg_type;
    uint16_t            msg_len;
}pfcp_msg_header;
#pragma pack()
#define PFCP_HEADER_LEN         4       /* Before length site */

typedef union {
    struct tag_pfcp_node_id_type{
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t         spare   :4;     /* spare */
        uint8_t         type    :4;     /* node id type */
#else
        uint8_t         type    :4;     /* node id type */
        uint8_t         spare   :4;     /* spare */
#endif
    }d;
    uint8_t value;
}pfcp_node_id_type;

#pragma pack(1)
typedef struct  tag_pfcp_node_id
{
    pfcp_node_id_type   type;
    uint8_t             node_id[PFCP_MAX_NODE_ID_LEN];
}pfcp_node_id;
#pragma pack()


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _PFCP_DEF_H__ */

