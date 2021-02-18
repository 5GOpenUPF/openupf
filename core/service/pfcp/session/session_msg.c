/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "pdr_mgmt.h"
#include "far_mgmt.h"
#include "qer_mgmt.h"
#include "bar_mgmt.h"
#include "session_instance.h"
#include "session_teid.h"
#include "session_report.h"
#include "session_msg.h"
#include "sp_dns_cache.h"
#include "sp_backend_mgmt.h"

extern uint16_t comm_msg_comm_id;

void session_msg_set_comm_id(void)
{
    uint64_t cur_tsc = ros_rdtsc();

    comm_msg_comm_id = cur_tsc & 0xFFFF;
    comm_msg_comm_id ^= htonll(cur_tsc) & 0xFFFF0000;
    LOG(SESSION, RUNNING, "comm id: %d.", comm_msg_comm_id);
}

int session_msg_send_to_fp(char *buf, uint32_t buf_len, int fd)
{
    if (MB_SEND2BE_BROADCAST_FD == fd) {
        upc_backend_mgmt *be_mgmt = upc_get_backend_mgmt_public();
        upc_backend_config *be_cfg;
        int32_t cur_index = COMM_MSG_BACKEND_START_INDEX - 1;

        cur_index = Res_GetAvailableInBand(be_mgmt->pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER);
        while (-1 != cur_index) {
            be_cfg = upc_get_backend_config_public(cur_index);
            if (EN_BACKEND_SYNC > ros_atomic32_read(&be_cfg->be_state)) {
                cur_index = Res_GetAvailableInBand(be_mgmt->pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER);
                continue;
            }

            if (0 > comm_msg_channel_reply(be_cfg->fd, buf, buf_len)) {
                LOG(SESSION, ERR, "session send buffer to fpu failed.");
                return -1;
            }

            cur_index = Res_GetAvailableInBand(be_mgmt->pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER);
        }
    } else {
        if (0 > comm_msg_channel_reply(fd, buf, buf_len)) {
            LOG(SESSION, ERR, "session send buffer to fpu failed.");
            return -1;
        }
    }

    return 0;
}

