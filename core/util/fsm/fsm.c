/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include <stdio.h>
#include "fsm.h"

#ifdef __GNUC__
#  define likely(x)   __builtin_expect(!!(x), 1)
#  define unlikely(x) __builtin_expect(!!(x), 0)
#else
#  define likely(x)   !!(x)
#  define unlikely(x) !!(x)
#endif

/* fsm init */
int FSM_init(struct FSM_t *fsm, int start_state,
    const struct FSM_table *fsm_tables, int fsm_table_num, void *priv_data)
{
    if ((NULL == fsm) || (NULL == fsm_tables) || (0 == fsm_table_num)) {
        printf("%s(%d) FSM init failed, fsm addr: %p,"
            " fsm_tables addr: %p, fsm_table_num: %d.\r\n",
            __FUNCTION__, __LINE__, fsm, fsm_tables, fsm_table_num);
        return -1;
    }

    fsm->fsm_table_num = fsm_table_num;
    fsm->cur_state = start_state;
    fsm->fsm_table = (void *)fsm_tables;
    fsm->priv_data = priv_data;

    return 0;
}

/* status transfer */
inline void FSM_state_transfer(struct FSM_t* fsm, int state)
{
    if (unlikely(NULL == fsm)) {
        return;
    }

    fsm->cur_state = state;
}

int FSM_event_handle(struct FSM_t *fsm, int event)
{
    struct FSM_table* fst_tables = NULL;
    FSM_ACTION action = NULL;
    int next_state = 0;
    int cur_state = 0;
    int fsm_table_num = 0;
    int cnt = 0;

    if (unlikely(NULL == fsm)) {
        return -1;
    }

    cur_state = fsm->cur_state;
    fst_tables = (struct FSM_table *)fsm->fsm_table;
    fsm_table_num = fsm->fsm_table_num;

    /* get action */
    for (cnt = 0; cnt < fsm_table_num; ++cnt) {
        if ((event == fst_tables[cnt].trigger_event) &&
            (cur_state == fst_tables[cnt].cur_status)) {
            action = fst_tables[cnt].action;
            next_state = fst_tables[cnt].next_status;
            break;
        }
    }

    if ((cnt < fsm_table_num) && (action)) {
        /* State transfer needs to be done before the action */
        FSM_state_transfer(fsm, next_state);
        action(fsm);
    } else {
        /* ERROR */
        /*printf("%s(%d) event, status or action abnormal, event: %d,"
            " status: %d, action: %p, cnt: %d.\r\n",
            __FUNCTION__, __LINE__, event, cur_state, action, cnt);*/
        return -1;
    }

    return 0;
}

