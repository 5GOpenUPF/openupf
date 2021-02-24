/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "pfcp_def.h"
#include "upc_node.h"
#include "pfcp_heartbeat.h"
#include "pfcp_client.h"

void pfcp_parse_heartbeat_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t resp_pos = 0, msg_hdr_pos;
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint8_t  m_recover_time = G_FALSE;
    uint16_t obj_type, obj_len;
    uint32_t peer_stamp;
    upc_node_cb *node_cb;

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    node_cb = upc_get_node_by_sa(sa);
    if (NULL == node_cb) {
        /* No association, do nothing */
        LOG(UPC, ERR, "Process heartbeat request fail, no such node.");
        return;
    }

    /* Parse packet */
    while (buf_pos < buf_max) {
        obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
        obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);
        (void)obj_len;

        switch (obj_type) {
            case UPF_RECOVERY_TIME_STAMP:
                /* Declear supported mandatory option */
                m_recover_time = G_TRUE;

                peer_stamp = tlv_decode_uint32_t(buffer, &buf_pos);

                LOG(UPC, RUNNING,
                    "decode recover time stamp, value %x", htonl(peer_stamp));
                break;
            default:
                LOG(UPC, RUNNING,
                    "type %d, not support.", obj_type);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        LOG(UPC, RUNNING,
            "decode pos from %d to %d, %02x %02x ...",
            last_pos, buf_pos, buffer[last_pos], buffer[last_pos + 1]);
        if (last_pos == buf_pos) {
            LOG(UPC, ERR, "empty ie.");
            break;
        }
        else {
            last_pos = buf_pos;
        }
    }

    /* Check mandaytory option */
    if (m_recover_time == G_FALSE) {
        LOG(UPC, ERR, "no mandatory option recover_time_stamp(%d).",
            m_recover_time);
        return;
    }

    /* Check time stamp */
    if (peer_stamp > node_cb->assoc_config.recov_time) {
        LOG(UPC, RUNNING,
            "recover time stamp(%x) is different with local save(%x).",
            htonl(peer_stamp), htonl(node_cb->assoc_config.recov_time));
        node_cb->assoc_config.recov_time =  peer_stamp;
        return;
    }

    upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, sa);

    msg_hdr_pos = resp_pos;
    pfcp_client_encode_header(resp_buffer, &resp_pos, 0, 0, SESS_HEARTBEAT_RESPONSE, 0, pkt_seq);

    /* Encode recover time stamp */
    tlv_encode_type(resp_buffer, &resp_pos, UPF_RECOVERY_TIME_STAMP);
    tlv_encode_length(resp_buffer, &resp_pos, sizeof(uint32_t));
    tlv_encode_uint32_t(resp_buffer, &resp_pos, upc_node_get_local_time_stamp());
    LOG(UPC, RUNNING, "encode local recover time stamp.");

    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, resp_pos);
    if (0 > upc_buff_send2smf(resp_buffer, resp_pos, sa)) {
        LOG(UPC, ERR, "Send packet to SMF failed.");
    }
}

int pfcp_build_heartbeat_request(upc_node_cb *node_cb)
{
    uint16_t            buf_pos = 0, msg_hdr_pos;
    uint8_t             buffer[COMM_MSG_CTRL_BUFF_LEN];

    LOG(UPC, RUNNING, "send heartbeat request.");

    upc_fill_ip_udp_hdr(buffer, &buf_pos, &node_cb->peer_sa);

    /* Prepare response header */
    msg_hdr_pos = buf_pos;
    pfcp_client_encode_header(buffer, &buf_pos, 0, 0,
        SESS_HEARTBEAT_REQUEST, 0, ros_atomic32_add_return(&node_cb->local_seq, 1));

    /* Encode recover time stamp */
    tlv_encode_type(buffer, &buf_pos, UPF_RECOVERY_TIME_STAMP);
    tlv_encode_length(buffer, &buf_pos, sizeof(uint32_t));
    tlv_encode_uint32_t(buffer, &buf_pos, upc_node_get_local_time_stamp());

    /* Set payload length */
    pfcp_client_set_header_length(buffer, msg_hdr_pos, buf_pos);

    upc_buff_send2smf(buffer, buf_pos, &node_cb->peer_sa);

    return 0;
}

