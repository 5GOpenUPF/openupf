/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _PFCP_PFD_MGMT_H__
#define _PFCP_PFD_MGMT_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tag_pfcp_pfd_entry {
    struct rb_node                  node;
    ros_rwlock_t                    lock;
    uint32_t                        index;
} pfcp_pfd_entry;

typedef struct tag_pfcp_pfd_table_header {
    pfcp_pfd_entry              *entry;
    uint32_t                    max_num;
    ros_rwlock_t                lock;
    uint16_t                    pool_id;
} pfcp_pfd_table_header;

pfcp_pfd_table_header *pfcp_pfd_get_table_header_public(void);

int64_t pfcp_pfd_table_init(uint32_t pfd_num);
int pfcp_local_pfd_request_proc(session_pfd_mgmt_request *pfd_mgmt_req);
void pfcp_parse_pfd_mgmt_request(uint8_t* buffer, uint16_t buf_pos1, int buf_max,
    uint32_t pkt_seq, struct sockaddr *sa);
void pfcp_build_pfd_management_response(session_pfd_management_response *pfd_rep, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _PFCP_PFD_MGMT_H__ */


