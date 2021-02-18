/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "far_mgmt.h"
#include "bar_mgmt.h"
#include "qer_mgmt.h"
#include "session_instance.h"
#include "sp_dns_cache.h"
#include "sp_backend_mgmt.h"
#include "session_audit.h"

static uint32_t audit_time_second = 0;
static uint32_t audit_switch = 1;

static void audit_normal_action(struct FSM_t *fsm);
static void audit_abnormal_action(struct FSM_t *fsm);
static void audit_sum_audit(void *tim, uint64_t para);
static void audit_period_audit(void *tim, uint64_t para);

const struct FSM_table g_audit_fsm_table[] = {
	{NORMAL, SUM_AUDIT_SUCCESS, audit_normal_action, NORMAL},
	{NORMAL, SUM_AUDIT_FAILED, audit_abnormal_action, ABNORMAL},
    {ABNORMAL, VALIDITY_AUDIT_SUCCESS, audit_normal_action, NORMAL},
    {ABNORMAL, VALIDITY_AUDIT_FAILED, audit_normal_action, NORMAL},
};

void set_audit_time(uint32_t audit_time)
{
    audit_time_second = audit_time * 3600;
}

void set_audit_switch(uint32_t enabled)
{
    audit_switch = enabled;
}

uint32_t get_audit_switch(void)
{
    return audit_switch;
}

inline uint64_t get_time_zone(void)
{
	time_t tm = 0;
	struct tm *local_time = NULL;

	local_time = localtime(&tm);

	return local_time->tm_hour * 3600;
}

uint64_t get_timer_time(void)
{
    time_t tm = 0;

    tm = (time(NULL) + get_time_zone()) % TIMES_OF_DAY;
    tm = ((audit_time_second + TIMES_OF_DAY) - tm) % TIMES_OF_DAY;
    if (0 == tm) {
        tm = TIMES_OF_DAY;
    }

    return tm;
}

int audit_4am_init(struct fsm_audit *audit_4am, uint32_t rule)
{
    uint64_t tm = 0;

    if (rule >= EN_AUDIT_BUTT) {
        LOG(SESSION, ERR, "Abnormal parameter, rule:%u should be less then %u.", rule, EN_AUDIT_BUTT);
        return -1;
    }

    if (audit_switch) {
        /* init 4am audit */
        tm = get_timer_time();
        LOG(SESSION, RUNNING, "4am timer reset time: %lu ==> hour: %lu"
            " min: %lu sec: %lu.", tm, tm / 3600, (tm % 3600) / 60, tm % 60);

        audit_4am->audit_rule = rule;
        audit_4am->audit_timer_id = ros_timer_create(
            ROS_TIMER_MODE_ONCE, tm * _1_SECONDS_TIME, (uint64_t)audit_4am, audit_period_audit);
        if (NULL == audit_4am->audit_timer_id) {
            LOG(SESSION, ERR, "timer create failed, timer time: %u.", audit_time_second);
            return -1;
        }
    }

    return 0;
}

int audit_simple_init(struct fsm_audit *audit_simple, uint32_t rule)
{
    if (rule >= EN_AUDIT_BUTT) {
        LOG(SESSION, ERR, "Abnormal parameter, rule:%u should be less then %u.", rule, EN_AUDIT_BUTT);
        return -1;
    }

    /* init sample FSM */
    if (0 > upc_backend_init_audit_fsm(g_audit_fsm_table,
        sizeof(g_audit_fsm_table) / sizeof(struct FSM_table), rule)) {
        LOG(SESSION, ERR, "Failed to initialize the state machine of the backend.");
        return -1;
    }

    if (audit_switch) {
        /* init simple audit */
        audit_simple->last_sum_num  = 0;
        audit_simple->audit_rule    = rule;
        audit_simple->audit_timer_id = ros_timer_create(
            ROS_TIMER_MODE_ONCE, NORMAL_TIMER_TIME, (uint64_t)audit_simple, audit_sum_audit);
        if (NULL == audit_simple->audit_timer_id) {
            LOG(SESSION, ERR, "timer create failed, timer time: %u.", NORMAL_TIMER_TIME);
            return -1;
        }
    }

    return 0;
}

static void audit_normal_action(struct FSM_t *fsm)
{
    /* Nothing to do */
}

static void audit_abnormal_action(struct FSM_t *fsm)
{
    uint16_t cmd;
    uint32_t rule;
    upc_backend_config *be_cfg = (upc_backend_config *)fsm->priv_data;

    if (unlikely(NULL == be_cfg)) {
        LOG(SESSION, ERR, "Should not be to here, maybe coding error.");
        if (0 > FSM_event_handle(fsm, VALIDITY_AUDIT_FAILED)) {
            LOG(SESSION, ERR, "FSM_event_handle process failed.");
            LOG(SESSION, ERR, "cur state: %d, event: %d.",
                fsm->cur_state, VALIDITY_AUDIT_FAILED);
        }
        return;
    }

    rule = ((char *)fsm - (char *)&be_cfg->fsm[0]) / sizeof(struct FSM_t);
    switch (rule) {
        case EN_FAR_AUDIT:
            cmd = EN_COMM_MSG_UPU_FAR_VAL;
            break;

        case EN_BAR_AUDIT:
            cmd = EN_COMM_MSG_UPU_BAR_VAL;
            break;

        case EN_QER_AUDIT:
            cmd = EN_COMM_MSG_UPU_QER_VAL;
            break;

        case EN_INST_AUDIT:
            cmd = EN_COMM_MSG_UPU_INST_VALIDITY;
            break;

        case EN_DNS_AUDIT:
            cmd = EN_COMM_MSG_UPU_DNS_VAL;
            break;

        default:
            LOG(SESSION, ERR, "Should not be to here, maybe coding error.");
            if (0 > FSM_event_handle(fsm, VALIDITY_AUDIT_FAILED)) {
                LOG(SESSION, ERR, "FSM_event_handle process failed.");
                LOG(SESSION, ERR, "cur state: %d, event: %d.",
                    fsm->cur_state, VALIDITY_AUDIT_FAILED);
            }
            return;
    }

    if (EN_COMM_ERRNO_OK != session_send_simple_cmd_to_fp(cmd, be_cfg->fd)) {
        LOG(SESSION, ERR, "Send msg to fpu failed.");
    }

    /* 到这里如果还存在sp和fp的sum值不一致，那原因可能出在sum的统计存在问题 */
    if (0 > FSM_event_handle(fsm, VALIDITY_AUDIT_SUCCESS)) {
        LOG(SESSION, ERR, "FSM_event_handle process failed.");
        LOG(SESSION, ERR, "cur state: %d, event: %d.",
            fsm->cur_state, VALIDITY_AUDIT_SUCCESS);
    }
    LOG(SESSION, RUNNING, "validity action end.");
}

static void audit_sum_audit(void *tim, uint64_t para)
{
    struct fsm_audit *sum_audit = (struct fsm_audit *)para;
    uint16_t cmd;

    switch (sum_audit->audit_rule) {
        case EN_FAR_AUDIT:
            sum_audit->last_sum_num = far_sum();
            cmd = EN_COMM_MSG_UPU_FAR_SUM;
            break;

        case EN_BAR_AUDIT:
            sum_audit->last_sum_num = bar_sum();
            cmd = EN_COMM_MSG_UPU_BAR_SUM;
            break;

        case EN_QER_AUDIT:
            sum_audit->last_sum_num = qer_sum();
            cmd = EN_COMM_MSG_UPU_QER_SUM;
            break;

        case EN_INST_AUDIT:
            sum_audit->last_sum_num = session_instance_sum();
            cmd = EN_COMM_MSG_UPU_INST_SUM;
            break;

        case EN_DNS_AUDIT:
            sum_audit->last_sum_num = sdc_sum();
            cmd = EN_COMM_MSG_UPU_DNS_SUM;
            break;

        default:
            LOG(SESSION, ERR, "Should not be to here, maybe coding error.");
            return;
    }

    session_send_simple_cmd_to_fp(cmd, MB_SEND2BE_BROADCAST_FD);
    ros_timer_start(sum_audit->audit_timer_id);
}

static void audit_period_audit(void *tim, uint64_t para)
{
    time_t tm = 0;
    struct fsm_audit *_4am_audit = (struct fsm_audit *)para;
    uint16_t cmd;

    LOG(SESSION, RUNNING, "period audit start.");

    switch (_4am_audit->audit_rule) {
        case EN_FAR_AUDIT:
            cmd = EN_COMM_MSG_UPU_FAR_GET;
            break;

        case EN_BAR_AUDIT:
            cmd = EN_COMM_MSG_UPU_BAR_GET;
            break;

        case EN_QER_AUDIT:
            cmd = EN_COMM_MSG_UPU_QER_GET;
            break;

        case EN_INST_AUDIT:
            cmd = EN_COMM_MSG_UPU_INST_GET;
            break;

        case EN_DNS_AUDIT:
            cmd = EN_COMM_MSG_UPU_DNS_GET;
            break;

        default:
            LOG(SESSION, ERR, "Should not be to here, maybe coding error.");
            return;
    }

    if (EN_COMM_ERRNO_OK != session_send_simple_cmd_to_fp(cmd, MB_SEND2BE_BROADCAST_FD)) {
        LOG(SESSION, ERR, "Send msg to fpu failed.");
    }

    tm = get_timer_time();
    LOG(SESSION, RUNNING, "4am timer reset time: %lu ==> hour: %lu"
        " min: %lu sec: %lu.", tm, tm / 3600, (tm % 3600) / 60, tm % 60);

    ros_timer_reset_time(_4am_audit->audit_timer_id, tm * _1_SECONDS_TIME);
}

