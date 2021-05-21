/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _UPC_SESSION_H__
#define _UPC_SESSION_H__

#ifdef __cplusplus
extern "C" {
#endif


#define UPC_PRINT(fmt, arg...) \
    do { \
    } while(0);
//printf("smu # %s(%d) "fmt"\r\n", __FUNCTION__, __LINE__, ##arg);

typedef enum {
    PUBLISH_COMM = 0,
    PUBLISH_EST,
    PUBLISH_MOD,
    PUBLISH_DEL,
    PUBLISH_PFD,
} PUBLISH_TYPE;

/* Session establishment request declear supported mandatory option */
typedef enum {
    UPC_F_SEID,
    UPC_NODE_ID,
    UPC_PDN_TYPE,
    UPC_M_OPT_BUTT,
}EN_UPC_ESTABLISHMENT_OPT;

#pragma pack(1)
typedef union tag_upc_establish_m_opt {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t             spare       :4;     /* spare */
    uint8_t             create_far  :1;     /* create far or activate predefined rules flag */
    uint8_t             create_pdr  :1;     /* create pdr flag */
    uint8_t             f_seid      :1;     /* f-seid flag */
    uint8_t             node_id     :1;     /* node id flag */
#else
    uint8_t             node_id     :1;     /* node id flag */
    uint8_t             f_seid      :1;     /* f-seid flag */
    uint8_t             create_pdr  :1;     /* create pdr flag */
    uint8_t             create_far  :1;     /* create far or activate predefined rules flag */
    uint8_t             spare       :4;     /* spare */
#endif
    } d;
    uint8_t             value;
} upc_establish_m_opt;
#pragma pack()
#define UPC_ESTABLISH_M_OPT_NUMBER  (4)
#define UPC_ESTABLISH_M_OPT_MASK  ((1 << UPC_ESTABLISH_M_OPT_NUMBER) - 1)

#pragma pack(1)
typedef union tag_upc_create_pdr_m_opt {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t             spare       :5;     /* spare */
    uint8_t             pdi         :1;
    uint8_t             precedence  :1;
    uint8_t             pdr_id      :1;
#else
    uint8_t             pdr_id      :1;
    uint8_t             precedence  :1;
    uint8_t             pdi         :1;
    uint8_t             spare       :5;     /* spare */
#endif
    } d;
    uint8_t             value;
} upc_create_pdr_m_opt;
#pragma pack()
#define UPC_CREATE_PDR_M_OPT_NUMBER  (3)
#define UPC_CREATE_PDR_M_OPT_MASK  ((1 << UPC_CREATE_PDR_M_OPT_NUMBER) - 1)

#pragma pack(1)
typedef union tag_upc_create_far_m_opt {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t             spare       :6;     /* spare */
    uint8_t             action      :1;
    uint8_t             far_id      :1;
#else
    uint8_t             far_id      :1;
    uint8_t             action      :1;
    uint8_t             spare       :6;     /* spare */
#endif
    } d;
    uint8_t             value;
} upc_create_far_m_opt;
#pragma pack()
#define UPC_CREATE_FAR_M_OPT_NUMBER  (2)
#define UPC_CREATE_FAR_M_OPT_MASK  ((1 << UPC_CREATE_FAR_M_OPT_NUMBER) - 1)

#pragma pack(1)
typedef union tag_upc_create_urr_m_opt {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t             spare       :5;     /* spare */
    uint8_t             triggers    :1;
    uint8_t             method      :1;
    uint8_t             urr_id      :1;
#else
    uint8_t             urr_id      :1;
    uint8_t             method      :1;
    uint8_t             triggers    :1;
    uint8_t             spare       :5;     /* spare */
#endif
    } d;
    uint8_t             value;
} upc_create_urr_m_opt;
#pragma pack()
#define UPC_CREATE_URR_M_OPT_NUMBER  (3)
#define UPC_CREATE_URR_M_OPT_MASK  ((1 << UPC_CREATE_URR_M_OPT_NUMBER) - 1)

#pragma pack(1)
typedef union tag_upc_create_qer_m_opt {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t             spare       :6;     /* spare */
    uint8_t             gate_status :1;
    uint8_t             qer_id      :1;
#else
    uint8_t             qer_id      :1;
    uint8_t             gate_status :1;
    uint8_t             spare       :6;     /* spare */
#endif
    } d;
    uint8_t             value;
} upc_create_qer_m_opt;
#pragma pack()
#define UPC_CREATE_QER_M_OPT_NUMBER  (2)
#define UPC_CREATE_QER_M_OPT_MASK  ((1 << UPC_CREATE_QER_M_OPT_NUMBER) - 1)

#pragma pack(1)
typedef union tag_upc_create_mar_m_opt {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t             spare       :4;     /* spare */
    uint8_t             afai1       :1;
    uint8_t             mode        :1;
    uint8_t             func        :1;
    uint8_t             mar_id      :1;
#else
    uint8_t             mar_id      :1;
    uint8_t             func        :1;
    uint8_t             mode        :1;
    uint8_t             afai1       :1;
    uint8_t             spare       :4;     /* spare */
#endif
    } d;
    uint8_t             value;
} upc_create_mar_m_opt;
#pragma pack()
#define UPC_CREATE_MAR_M_OPT_NUMBER  (4)
#define UPC_CREATE_MAR_M_OPT_MASK  ((1 << UPC_CREATE_MAR_M_OPT_NUMBER) - 1)


int upc_ueip_add_target(session_pdr_create *pdr);

PFCP_CAUSE_TYPE upc_parse_source_ip_address(session_source_ip_address *source_ip,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len);

void upc_parse_session_establishment_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa);
void upc_parse_session_modification_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, uint64_t up_seid, struct sockaddr *sa);
void upc_parse_session_deletion_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, uint64_t up_seid, struct sockaddr *sa);
void upc_parse_session_report_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, uint64_t up_seid, struct sockaddr *sa);

int upc_free_resources_from_deletion(session_content_create *sess);

void upc_est_fill_created_pdr(session_content_create *sess, session_emd_response *sess_rep);
void upc_mdf_fill_created_pdr(session_content_modify *sess, session_emd_response *sess_rep);
void upc_est_fill_created_traffic_endpoint(session_content_create *sess, session_emd_response *sess_rep);
void upc_mdf_fill_created_traffic_endpoint(session_content_modify *sess, session_emd_response *sess_rep);

void upc_parse_node_report_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, struct sockaddr *sa);
int upc_publish_sess_sig_trace(uint8_t msg_type, uint64_t up_seid, uint64_t cp_seid, uint32_t flag);
int upc_write_wireshark(char *buf, int len, uint32_t remote_ip, int flag);

int upc_build_source_ip_address(session_source_ip_address *src_ip_addr,
    uint8_t *resp_buffer, uint16_t *resp_pos);

int upc_local_session_establishment(session_content_create *sess_content);
void upc_build_session_establishment_response(
    session_emd_response *sess_rep, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq, uint64_t cp_seid, int trace_flag, uint8_t node_type);
int upc_local_session_modification(session_content_modify *sess_content);
void upc_build_session_modification_response(
    session_emd_response *sess_rep, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq, uint64_t cp_seid, int trace_flag);
int upc_local_session_deletion(session_content_delete *sess_content);
void upc_build_session_deletion_response(
    session_emd_response *sess_rep, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq, uint64_t cp_seid, int trace_flag);

void upc_report_proc(void *report, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _UPC_SESSION_H__ */
