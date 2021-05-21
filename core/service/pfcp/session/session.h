/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_H
#define __SESSION_H

#include "fsm.h"


#define _1_SECONDS_TIME  (ROS_TIMER_TICKS_PER_SEC)

#define MAX_AUDIT_TIMES   (3)

/* Fd of Management-end to back-end broadcast */
#define MB_SEND2BE_BROADCAST_FD     (-23)

struct session_key {
    uint64_t        local_seid;
    uint64_t        cp_seid;
};

/* release node */
enum SESSION_RULES_TYPE {
	EN_RULE_INST,
	EN_RULE_FAR,
	EN_RULE_QER,
	EN_RULE_BAR,
	EN_RULE_BUTT,
};

union rules_overflow_flag {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t		spare       : 3;
        uint8_t		rule_bar    : 1;
        uint8_t		rule_qer    : 1;
        uint8_t		rule_far    : 1;
        uint8_t		rule_inst   : 1;
#else
        uint8_t		rule_inst   : 1;
        uint8_t		rule_far    : 1;
        uint8_t		rule_qer    : 1;
        uint8_t		rule_bar    : 1;
        uint8_t		spare       : 3;
#endif
    } d;
    uint8_t	value;
};


/* SESSION_RULE_INDEX_MAX - SESSION_RULE_INDEX_LIMIT > rules max of session */
#define SESSION_RULE_SIZE_MAX       (max(max(MAX_PDR_NUM, MAX_URR_NUM), max(MAX_FAR_NUM, MAX_QER_NUM)))
#define SESSION_RULE_INDEX_MAX		(2048)
#define SESSION_RULE_INDEX_LIMIT	(SESSION_RULE_INDEX_MAX - (SESSION_RULE_SIZE_MAX << 1))
struct session_rules_index {
	union rules_overflow_flag	overflow;	/* rules overflow flags */
	uint32_t					index_num[EN_RULE_BUTT];
	uint32_t					index_arr[EN_RULE_BUTT][SESSION_RULE_INDEX_MAX];
};

enum SESSION_PKT_STATUS_UNIT {
    SESSION_PKT_RECV_FORM_FPU,
    SESSION_PKT_MDF_FAST,       /* modify fast to fpu */
    SESSION_PKT_STATUS_BUTT,
};


static inline int session_val_ntoh(comm_msg_entry_val_config_t *val_cfg)
{
    uint32_t cnt = 0, fld_num = 0;

    val_cfg->start = ntohl(val_cfg->start);
    val_cfg->entry_num = ntohl(val_cfg->entry_num);
    if (val_cfg->entry_num > MAX_CHECK_VALIDITY_NUMBER) {
        return -1;
    }

    fld_num = val_cfg->entry_num >> RES_PART_LEN_BIT;
    //LOG(SESSION, RUNNING, "start: %u, entry_num: %u.", val_cfg->start, val_cfg->entry_num);
    for (cnt = 0; cnt < fld_num; ++cnt) {
        val_cfg->data[cnt] = ntohl(val_cfg->data[cnt]);
    }

    if (val_cfg->entry_num & RES_PART_LEN_MASK) {
        val_cfg->data[cnt] = ntohl(val_cfg->data[cnt]);
    }

    return 0;
}

void session_pkt_status_add(int unit);
int64_t session_pkt_status_read(int unit);
void session_pkt_status_init(void);

int rules_fp_del(uint32_t *index_arr, uint32_t index_num, uint16_t cmd, int fd);
uint32_t session_send_simple_cmd_to_fp(uint16_t cmd, int fd);
uint32_t session_send_prs_cmd_to_fp(uint32_t qer_index, uint64_t up_seid, uint64_t cp_seid,
    uint32_t seq_num, uint8_t node_index, uint8_t msg_type);

int session_pkt_match_process(char *buf, int len, int fd);

void session_collect_fp_status(char *stat_str, comm_msg_fpu_stat *stat_data);
void session_update_fpu_status(comm_msg_fpu_stat *fpu_stat);
int session_init(upc_config_info *upc_conf);
void session_deinit(void);
int session_proc_qer_prss(comm_msg_ie_t *ie);
int session_sig_trace_proc(session_sig_trace *sess_st);


#endif
