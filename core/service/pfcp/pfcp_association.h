/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _PFCP_ASSOCIATION_H__
#define _PFCP_ASSOCIATION_H__

#ifdef __cplusplus
extern "C" {
#endif

void pfcp_encode_node_id(uint8_t* resp_buffer, uint16_t *buf_pos, uint8_t type);

int pfcp_local_association_setup(session_association_setup *assoc_setup);
int pfcp_local_association_update(session_association_update *assoc_update);
int pfcp_local_association_release(session_association_release_request *assoc_rels);

void pfcp_parse_association_setup_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa);
void pfcp_parse_association_setup_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max);
void pfcp_parse_association_update_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa);
void pfcp_parse_association_update_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max);
void pfcp_parse_association_release_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa);
void pfcp_build_association_release_request(upc_node_cb *node);
void pfcp_parse_association_release_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max);

void pfcp_build_association_setup_request(upc_node_cb *node);
void pfcp_build_association_setup_response(uint8_t* resp_buffer,
    uint16_t *buf_pos, uint8_t res_cause, uint32_t pkt_seq, uint8_t node_type);
void pfcp_build_association_update_request(upc_node_cb *node, uint8_t rel_flag,
    uint8_t gra_flag, uint8_t aur_flag);
void pfcp_build_association_update_response(uint8_t* resp_buffer,
    uint16_t *buf_pos, uint8_t res_cause, uint32_t pkt_seq, uint8_t node_type);
void pfcp_build_association_release_response(uint8_t* resp_buffer,
    uint16_t *buf_pos, uint8_t res_cause, uint32_t pkt_seq, uint8_t node_type);


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _PFCP_ASSOCIATION_H__ */


