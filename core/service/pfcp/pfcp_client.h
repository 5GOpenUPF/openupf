/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _PFCP_CLIENT_H__
#define _PFCP_CLIENT_H__

#ifdef __cplusplus
extern "C" {
#endif

int  pfcp_client_entry(char *buf, int len, void *arg);
void pfcp_client_encode_header(uint8_t *buffer, uint16_t *buf_pos,
    uint8_t seid_flag, uint64_t seid, uint16_t msg_type, uint16_t msg_len,
    uint32_t seq);
void pfcp_client_set_header_length(uint8_t *buffer, uint16_t msg_hdr_pos,
    uint16_t total_len);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _PFCP_CLIENT_H__ */

