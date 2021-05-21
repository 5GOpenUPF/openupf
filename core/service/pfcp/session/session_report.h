/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_REPORT_H_
#define __SESSION_REPORT_H_

#ifdef __cplusplus
extern "C" {
#endif


void session_report_nocp(void *tim, uint64_t para);
int session_start_nocp_timer(struct session_t *session, struct pdr_table *pdr_tbl, uint32_t far_index);
int session_report_local_urr(comm_msg_urr_report_t *config, uint8_t usage_report_num, uint32_t trigger);
int session_report_teid_err(struct session_peer_fteid_entry *fteid_entry);
int session_node_report_publish(session_node_report_request *node_req);
int session_node_report_gtpu_err(struct session_gtpu_entry *gtpu_entry);
int session_report_inactivity(struct session_t *sess);
void session_report_urr_content_copy(session_report_request_ur *urr_dst, comm_msg_urr_report_t *urr_src);


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  __SESSION_REPORT_H_ */


