/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "pfcp_def.h"
#include "upc_node.h"
#include "pfcp_client.h"
#include "pfcp_association.h"
#include "pfcp_heartbeat.h"
#include "upc_session.h"
#include "pfcp_pfd_mgmt.h"

int pfcp_client_entry(char *buf, int len, void *arg)
{
    pfcp_msg_header *msg_header;
    uint16_t buf_pos = 0, msg_len, msg_buf_pos = 0;
    uint64_t pkt_seid = 0;
    uint32_t pkt_seq;
    uint8_t  *buffer;

    LOG(UPC, RUNNING, "get new packet, pkt len %d", len);

    /* Parse header */
    do {
        buffer = (uint8_t *)buf + msg_buf_pos;
        msg_header = (pfcp_msg_header *)buffer;

        /* Check length */
        msg_len = htons(msg_header->msg_len);
        if (msg_len > (len - msg_buf_pos - PFCP_HEADER_LEN)) {
            LOG(UPC, ERR, "msg length(%d) over packet left length(%d).\r\n",
                msg_len, len - msg_buf_pos - PFCP_HEADER_LEN);
            return SESS_INVALID_LENGTH;
        }
        buf_pos = PFCP_HEADER_LEN;
        msg_len += PFCP_HEADER_LEN;
        msg_buf_pos += msg_len;
        LOG(UPC, RUNNING, "get msg len %d(include msg header 4 bytes)", msg_len);

        /* Get seid */
        if (msg_header->s) {
            pkt_seid = tlv_decode_uint64_t(buffer, &buf_pos);
            LOG(UPC, RUNNING, "get seid 0x%lx", pkt_seid);
        }

        /* Get sequence */
        pkt_seq = tlv_decode_int_3b(buffer, &buf_pos);
        LOG(UPC, RUNNING, "msg sequence %d", pkt_seq);

        /* skip spare byte */
        buf_pos++;

        LOG(UPC, RUNNING, "msg type %d", msg_header->msg_type);

        if (likely(msg_header->version == PFCP_MAJOR_VERSION)) {
            /* Parse msg by type */
            switch(msg_header->msg_type) {
                case SESS_HEARTBEAT_REQUEST:
                    /* Parse heartbeat */
                    pfcp_parse_heartbeat_request(buffer, buf_pos, msg_len, pkt_seq, (struct sockaddr *)arg);
                    break;

                case SESS_HEARTBEAT_RESPONSE:
                    {
                        upc_node_cb *node_cb = upc_get_node_by_sa(arg);
                        if (likely(NULL != node_cb)) {
                            ros_atomic16_init(&node_cb->hb_timeout_cnt);
                        } else {
                            /* No association, do nothing */
                            LOG(UPC, ERR, "Process heartbeat response fail, no such node.");
                        }
                    }
                    break;

                case SESS_PFD_MANAGEMENT_REQUEST:
                    /* Parse request */
                    upc_pkt_status_add(UPC_PKT_SESS_EST_RECV4SMF);
                    pfcp_parse_pfd_mgmt_request(buffer, buf_pos,
                        msg_len, pkt_seq, (struct sockaddr *)arg);
                    upc_pkt_status_add(UPC_PKT_SESS_EST_SEND2SMF);
                    break;

                case SESS_PFD_MANAGEMENT_RESPONSE:
                    break;

                case SESS_ASSOCIATION_SETUP_REQUEST:
                    /* Parse request */
                    upc_pkt_status_add(UPC_PKT_NODE_CREATE_RECV4SMF);
                    pfcp_parse_association_setup_request(buffer, buf_pos,
                        msg_len, pkt_seq, (struct sockaddr *)arg);
                    upc_pkt_status_add(UPC_PKT_NODE_CREATE_SEND2SMF);
                    break;
                case SESS_ASSOCIATION_SETUP_RESPONSE:
                    /* Parse response */
                    pfcp_parse_association_setup_response(buffer, buf_pos, msg_len);
                    continue;

                case SESS_ASSOCIATION_UPDATE_REQUEST:
                    /* Parse request */
                    upc_pkt_status_add(UPC_PKT_NODE_UPDATE_RECV4SMF);
                    pfcp_parse_association_update_request(buffer, buf_pos,
                        msg_len, pkt_seq, (struct sockaddr *)arg);
                    upc_pkt_status_add(UPC_PKT_NODE_UPDATE_SEND2SMF);
                    break;
                case SESS_ASSOCIATION_UPDATE_RESPONSE:
                    /* Parse response */
                    pfcp_parse_association_update_response(buffer, buf_pos, msg_len);
                    continue;

                case SESS_ASSOCIATION_RELEASE_REQUEST:
                    /* Parse request */
                    upc_pkt_status_add(UPC_PKT_NODE_REMOVE_RECV4SMF);
                    pfcp_parse_association_release_request(buffer, buf_pos,
                        msg_len, pkt_seq, (struct sockaddr *)arg);
                    upc_pkt_status_add(UPC_PKT_NODE_REMOVE_SEND2SMF);
                    break;
                case SESS_ASSOCIATION_RELEASE_RESPONSE:
                    pfcp_parse_association_release_response(buffer, buf_pos, msg_len);
                    continue;
                case SESS_VERSION_NOT_SUPPORTED_RESPONSE:
                    continue;

                case SESS_NODE_REPORT_RESPONSE:
                    /* Parse node report response */
                    upc_pkt_status_add(UPC_PKT_NODE_REPORT_RECV4SMF);
                    upc_parse_node_report_response(buffer, buf_pos, msg_len, (struct sockaddr *)arg);
                    continue;

                case SESS_SESSION_SET_DELETION_REQUEST:
                    continue;

                case SESS_SESSION_SET_DELETION_RESPONSE:
                    continue;

                case SESS_SESSION_ESTABLISHMENT_REQUEST:
                    /* Parse request */
                    upc_pkt_status_add(UPC_PKT_SESS_EST_RECV4SMF);
                    upc_parse_session_establishment_request(buffer, buf_pos,
                        msg_len, pkt_seq, (struct sockaddr *)arg);
                    upc_pkt_status_add(UPC_PKT_SESS_EST_SEND2SMF);
                    break;

                case SESS_SESSION_MODIFICATION_REQUEST:
                    /* Parse request */
                    upc_pkt_status_add(UPC_PKT_SESS_MDF_RECV4SMF);
                    upc_parse_session_modification_request(buffer, buf_pos,
                        msg_len, pkt_seq, pkt_seid, (struct sockaddr *)arg);
                    upc_pkt_status_add(UPC_PKT_SESS_MDF_SEND2SMF);
                    break;

                case SESS_SESSION_DELETION_REQUEST:
                    /* Parse request */
                    upc_pkt_status_add(UPC_PKT_SESS_DEL_RECV4SMF);
                    upc_parse_session_deletion_request(buffer, buf_pos,
                        msg_len, pkt_seq, pkt_seid, (struct sockaddr *)arg);
                    upc_pkt_status_add(UPC_PKT_SESS_DEL_SEND2SMF);
                    break;

                case SESS_SESSION_REPORT_RESPONSE:
                    /* Parse report response */
                    upc_pkt_status_add(UPC_PKT_SESS_REPORT_RECV4SMF);
                    upc_parse_session_report_response(buffer, buf_pos,
                        msg_len, pkt_seq, pkt_seid, (struct sockaddr *)arg);
                    continue;

                default:
                    continue;
            }
        } else {
            uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
            uint16_t resp_pos = 0, msg_hdr_pos;

            upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, (struct sockaddr *)arg);

            msg_hdr_pos = resp_pos;
            pfcp_client_encode_header(resp_buffer, &resp_pos, 0, 0,
    			SESS_VERSION_NOT_SUPPORTED_RESPONSE, 0, pkt_seq);

            pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, resp_pos);
            upc_buff_send2smf(resp_buffer, resp_pos, (struct sockaddr *)arg);
        }
    } while (msg_header->fo);

    return OK;
}

void pfcp_client_encode_header(uint8_t *buffer, uint16_t *buf_pos,
    uint8_t seid_flag, uint64_t seid, uint16_t msg_type, uint16_t msg_len,
    uint32_t seq)
{
    pfcp_msg_header *msg_header = NULL;
    uint16_t cur_pos = 0;

    /* Check buffer */
    if (!buffer || !buf_pos) {
        LOG(UPC, ERR, "abnormal parameter, buffer(%p), buf_pos(%p).",
            buffer, buf_pos);
        *buf_pos = 0;
        return;
    }

    cur_pos = *buf_pos;
    msg_header = (pfcp_msg_header *)(buffer + cur_pos);

    /* Set content */
    msg_header->version 	= PFCP_MAJOR_VERSION;
    msg_header->spare   	= 0;
    msg_header->fo			= 0;
    msg_header->mp      	= 0;
    msg_header->s       	= (seid_flag != 0);
    msg_header->msg_type 	= msg_type;
    cur_pos += TLV_TYPE_LEN;

    tlv_encode_length(buffer, &cur_pos, msg_len);

    if (seid_flag != 0) {
        tlv_encode_uint64_t(buffer, &cur_pos, seid);
    }

    tlv_encode_int_3b(buffer, &cur_pos, seq);
    tlv_encode_uint8_t(buffer, &cur_pos, 0);

    *buf_pos = cur_pos;
}

void pfcp_client_set_header_length(uint8_t *buffer, uint16_t msg_hdr_pos,
    uint16_t total_len)
{
    uint16_t msg_len_pos = msg_hdr_pos + TLV_TYPE_LEN;
    uint16_t msg_len = total_len - msg_hdr_pos - PFCP_HEADER_LEN;

    /* Check buffer */
    if (unlikely(NULL == buffer)) {
        LOG(UPC, ERR, "abnormal parameter, buffer(%p).", buffer);
        return;
    }

    tlv_encode_length(buffer, &msg_len_pos, msg_len);

    LOG(UPC, RUNNING, "modify output msg length to %d", msg_len);
}

