/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_AUDOT_H__
#define __SESSION_AUDOT_H__

#include "fsm.h"


/* unit is 10ms, default 10s = 1000 * 10ms */
#define _10_SECONDS_TIME  (ROS_TIMER_TICKS_PER_SEC * 10)

/* unit is 10ms, default 1s = 100 * 10ms */
#ifndef _1_SECONDS_TIME
#define _1_SECONDS_TIME  (ROS_TIMER_TICKS_PER_SEC)
#endif

/* 86400 seconds in one day */
#define TIMES_OF_DAY	(86400)

/* timer time of normal state */
#define NORMAL_TIMER_TIME       _10_SECONDS_TIME

/* timer time of abnormal state */
#define ABNORMAL_TIMER_TIME     _1_SECONDS_TIME * 3

/* FSM events */
enum EVENTS {
	SUM_AUDIT_SUCCESS,
	SUM_AUDIT_FAILED,
	VALIDITY_AUDIT_SUCCESS,
	VALIDITY_AUDIT_FAILED,
};
/* FSM status */
enum STATUS {
	NORMAL = 1,
    ABNORMAL,
};

/* audit */
struct fsm_audit {
    uint32_t            audit_rule; /* enum AUDIT_RULES */
    uint32_t            last_sum_num; /* 用来确定审计期间是否有数据变动,如果存在数据变动这次就不执行审计 */
    struct ros_timer    *audit_timer_id;
};


void set_audit_time(uint32_t audit_time);
void set_audit_switch(uint32_t enabled);
uint32_t get_audit_switch(void);
uint64_t get_timer_time(void);
int audit_4am_init(struct fsm_audit *audit_4am, uint32_t rule);
int audit_simple_init(struct fsm_audit *audit_simple, uint32_t rule);

#endif