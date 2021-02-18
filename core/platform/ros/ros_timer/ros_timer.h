/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _ROS_TIMER_H__
#define _ROS_TIMER_H__

#ifdef __cplusplus
extern "C" {
#endif

#define ROS_TIMER_MAX_CORE               1
#define ROS_TIMER_PROCESS_AFFAIR_CORE    0
#define ROS_TIMER_ACCURACY               10  /* The unit is milliseconds */
#define ROS_TIMER_TICKS_PER_SEC          100 /* 100 ticks per second */

/* The maximum number of timers created per core run */
#define ROS_TIMER_EACH_CORE_MAX_NUM     1500000

typedef void (*ros_timer_cb_t)(void *tim, uint64_t para);

enum ros_timer_mode
{
    /* 一次性定时器, 到期后自动停止, 需要手动删除控制块 */
    ROS_TIMER_MODE_ONCE = 0,
    /* 周期性定时器, 到期后重新开启定时器，需要手动停止删除控制块 */
    ROS_TIMER_MODE_PERIOD = 1,

    ROS_TIMER_MODE_BUTT
};

enum ros_timer_status
{
    ROS_TIMER_STATUS_NULL = 0,
    ROS_TIMER_STATUS_CREATE,
    ROS_TIMER_STATUS_START,

    ROS_TIMER_STATUS_BUTT
};

struct ros_timer_cb {
    /* Ordered linked list, only one */
    LIST orderlist;

    /* Disordered list, one for each core */
    LIST disorderlist;

    /* Timer control block resource list, one for each core */
    LIST ftnoderm;

    ros_spinlock_t lock;
}__attribute__ ((aligned (128)));

struct ros_timer {
    NODE node;

    enum ros_timer_mode mode;
    ros_timer_cb_t fct;
    LIST          *list;
    /*
     * para can be a value or a pointer, if it is a pointer,
     * you need to make sure the memory is shared
     */
    uint64_t para;
    /* timer out tick, base ros_rdtsc */
    uint64_t tick;
    uint64_t ms;

    uint64_t core_num;
    uint16_t status;
    uint8_t resv[6];
};

extern uint64_t ros_timer_init(uint8_t first_core);
extern uint64_t ros_timer_exit(void);
extern struct ros_timer *ros_timer_create(enum ros_timer_mode mode,
                                        uint64_t time,
                                        uint64_t para,
                                        ros_timer_cb_t fct);
extern struct ros_timer *ros_timer_create_by_core(enum ros_timer_mode mode,
                                        uint64_t time,
                                        uint64_t para,
                                        uint64_t core_num,
                                        ros_timer_cb_t fct);
extern uint64_t ros_timer_start(struct ros_timer *tim);
extern uint64_t ros_timer_stop(struct ros_timer *tim);
extern uint64_t ros_timer_del(struct ros_timer *tim);
extern uint64_t ros_timer_reset_time(struct ros_timer *tim,
                                    uint64_t time);
extern void* ros_timer_process(void *arg);
extern uint64_t ros_timer_reset(struct ros_timer *tim,
                            uint64_t time,
                            enum ros_timer_mode mode,
                            uint64_t para,
                            ros_timer_cb_t fct);
int ros_timer_resource_status(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _ROS_TIMER_H__ */
