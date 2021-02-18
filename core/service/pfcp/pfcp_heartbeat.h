/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _PFCP_HEARTBEAT_H__
#define _PFCP_HEARTBEAT_H__

#ifdef __cplusplus
extern "C" {
#endif

void pfcp_parse_heartbeat_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa);
int pfcp_build_heartbeat_request(upc_node_cb *node_cb);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _PFCP_HEARTBEAT_H__ */



