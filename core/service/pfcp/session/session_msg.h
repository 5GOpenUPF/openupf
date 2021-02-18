/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_MSG_H
#define __SESSION_MSG_H

void session_msg_set_comm_id(void);

int session_msg_send_to_fp(char *buf, uint32_t buf_len, int fd);

#endif
