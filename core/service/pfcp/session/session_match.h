/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_MATCH_H
#define __SESSION_MATCH_H


void session_match(struct filter_key *key, uint32_t fast_tid, uint8_t fast_type, int fd);
int session_remove_orphan_fast(struct sp_fast_entry *fast_entry, uint8_t pkt_type);

#endif
