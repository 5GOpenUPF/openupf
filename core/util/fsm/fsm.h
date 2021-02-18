/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __FSM_H__
#define __FSM_H__


struct FSM_t {
    void                *fsm_table; /* struct FSM_table */
    int                 cur_state;
    unsigned int        fsm_table_num;
    void                *priv_data;
};
typedef void (*FSM_ACTION)(struct FSM_t *fsm);

struct FSM_table {
    int                 cur_status;
    int                 trigger_event;
    FSM_ACTION          action; /* FSM_ACTION */
    int                 next_status;
};


int FSM_init(struct FSM_t *fsm, int start_state,
    const struct FSM_table *fsm_tables, int fsm_table_num, void *priv_data);
int FSM_event_handle(struct FSM_t *fsm, int event);

/* 重新设置当前的状态 */
static inline void FSM_reset_cur_state(struct FSM_t *fsm, int state)
{
    fsm->cur_state = state;
}

#endif
