/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "ros_timer.h"

struct ros_timer_cb ros_timer_cb[ROS_TIMER_MAX_CORE];
static BOOL ros_timer_work = G_FALSE;
struct ros_timer *ros_timer_head[ROS_TIMER_MAX_CORE];

#define ROS_TIMER_LOCK_INIT ros_spinlock_init
#define ROS_TIMER_LOCK      ros_spinlock_lock
#define ROS_TIMER_UNLOCK    ros_spinlock_unlock

uint64_t ros_timer_init(uint8_t first_core)
{
    uint64_t core_num;
    uint64_t ft_num;
    struct ros_timer *tim;
    int ret;
    pthread_t thread_id;
    cpu_set_t cpuset;
    pthread_attr_t attr1;

    ros_memset((void *)&ros_timer_cb, 0, sizeof(ros_timer_cb));

    for (core_num = 0; core_num < ROS_TIMER_MAX_CORE; core_num ++) {
        lstInit(&ros_timer_cb[core_num].orderlist);
        lstInit(&ros_timer_cb[core_num].disorderlist);
        lstInit(&ros_timer_cb[core_num].ftnoderm);
        ROS_TIMER_LOCK_INIT(&ros_timer_cb[core_num].lock);

        ros_timer_head[core_num] = ros_calloc(sizeof(struct ros_timer),
                    ROS_TIMER_EACH_CORE_MAX_NUM);
        if (ros_timer_head[core_num] == NULL) {
    		LOG(ROS_TIMER, ERR, "ros_calloc fail!");
            return G_FAILURE;
        }
    }

    for (core_num = 0; core_num < ROS_TIMER_MAX_CORE; core_num ++) {
        for (ft_num = 0; ft_num < ROS_TIMER_EACH_CORE_MAX_NUM; ft_num ++) {
            tim = &ros_timer_head[core_num][ft_num];
            tim->status = ROS_TIMER_STATUS_NULL;
            lstAdd(&ros_timer_cb[core_num].ftnoderm, &tim->node);
            tim->list = &ros_timer_cb[core_num].ftnoderm;
        }
    }

    ros_timer_work = G_TRUE;

    pthread_attr_init(&attr1);

    CPU_ZERO(&cpuset);
    CPU_SET(first_core, &cpuset);
    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(ROS_TIMER, ERR, "pthread_attr_setaffinity_np fail on core(%d)", first_core);
        return G_FAILURE;
    }

    ret = pthread_create(&thread_id, &attr1, ros_timer_process, NULL);
    if (ret != 0) {
        LOG(ROS_TIMER, ERR, "pthread_create fail!");
        return G_FAILURE;
    }
    pthread_attr_destroy(&attr1);

    return G_SUCCESS;
}

uint64_t ros_timer_exit(void)
{
    uint64_t core_num;

    ros_timer_work = G_FALSE;

    for (core_num = 0; core_num < ROS_TIMER_MAX_CORE; core_num ++) {
        if (ros_timer_head[core_num]) {
    		ros_free(ros_timer_head[core_num]);
            ros_timer_head[core_num] = NULL;
        }
    }
    return G_SUCCESS;
}

struct ros_timer *ros_timer_create(enum ros_timer_mode mode,
                                        uint64_t time,
                                        uint64_t para,
                                        ros_timer_cb_t fct)
{
    struct ros_timer *tim = NULL;

    if (unlikely(fct == NULL)) {
		LOG(ROS_TIMER, ERR, "Incorrect input parameters!");
        return NULL;
    }

    ROS_TIMER_LOCK(&ros_timer_cb[0].lock);
    if (lstCount(&ros_timer_cb[0].ftnoderm) <= 0) {
        ROS_TIMER_UNLOCK(&ros_timer_cb[0].lock);
        printf("timer klist is empty, ftnoderm count: %d!\r\n", lstCount(&ros_timer_cb[0].ftnoderm));
        printf("timer klist is empty, orderlist count: %d!\r\n", lstCount(&ros_timer_cb[0].orderlist));
        printf("timer klist is empty, disorderlist count: %d!\r\n", lstCount(&ros_timer_cb[0].disorderlist));
		LOG(ROS_TIMER, ERR, "klist is empty!");
        return NULL;
    }

    tim = (struct ros_timer *)lstGet(&ros_timer_cb[0].ftnoderm);
    tim->core_num = 0;
    tim->mode = mode;
    tim->fct = fct;
    tim->para = para;
    tim->ms = time*ROS_TIMER_ACCURACY;

    //LOG(ROS_TIMER, DEBUG, "tim:%p, tim->fct:%p", tim, tim->fct);

    tim->status = ROS_TIMER_STATUS_CREATE;
    tim->list = NULL;

    ROS_TIMER_UNLOCK(&ros_timer_cb[0].lock);
    return tim;
}

struct ros_timer *ros_timer_create_by_core(enum ros_timer_mode mode,
                                        uint64_t time,
                                        uint64_t para,
                                        uint64_t core_num,
                                        ros_timer_cb_t fct)
{
    struct ros_timer *tim;

    if (unlikely((fct == NULL) || (core_num >= ROS_TIMER_MAX_CORE))) {
		LOG(ROS_TIMER, ERR, "Incorrect input parameters!");
        return NULL;
    }

    if (lstCount(&ros_timer_cb[core_num].ftnoderm) <= 0) {
		LOG(ROS_TIMER, ERR, "klist is empty!");
        return NULL;
    }

    ROS_TIMER_LOCK(&ros_timer_cb[core_num].lock);
    tim = (struct ros_timer *)lstGet(&ros_timer_cb[core_num].ftnoderm);
    tim->core_num = core_num;
    tim->mode = mode;
    tim->fct = fct;
    tim->para = para;
    tim->ms = time*ROS_TIMER_ACCURACY;

    tim->status = ROS_TIMER_STATUS_CREATE;
    tim->list = NULL;

    ROS_TIMER_UNLOCK(&ros_timer_cb[core_num].lock);
    return tim;
}

uint64_t ros_timer_start(struct ros_timer *tim)
{
    if (unlikely(tim == NULL)) {
		LOG(ROS_TIMER, ERR, "Incorrect input parameters!");
        return G_FAILURE;
    }
    if (unlikely(tim->status < ROS_TIMER_STATUS_CREATE)) {
		LOG(ROS_TIMER, ERR, "The timer status(%hu) is incorrect.",
                            tim->status);
        return G_FAILURE;
    }

    tim->tick = ros_get_futurn_tsc(tim->ms);

    ROS_TIMER_LOCK(&ros_timer_cb[tim->core_num].lock);

    tim->status = ROS_TIMER_STATUS_START;
    if (tim->list) {
        lstDelete(tim->list, &tim->node);
        tim->list = NULL;
    }
    lstAdd(&ros_timer_cb[tim->core_num].disorderlist, &tim->node);
    tim->list = &ros_timer_cb[tim->core_num].disorderlist;

    ROS_TIMER_UNLOCK(&ros_timer_cb[tim->core_num].lock);
    return G_SUCCESS;
}

uint64_t ros_timer_stop(struct ros_timer *tim)
{
    if (unlikely(tim == NULL)) {
		LOG(ROS_TIMER, ERR, "Incorrect input parameters!");
        return G_FAILURE;
    }
    if (unlikely(tim->status < ROS_TIMER_STATUS_CREATE)) {
		LOG(ROS_TIMER, ERR, "The timer status(%hu) is incorrect.",
                            tim->status);
        return G_FAILURE;
    }

    ROS_TIMER_LOCK(&ros_timer_cb[tim->core_num].lock);

    tim->status = ROS_TIMER_STATUS_CREATE;
    if (tim->list) {
        lstDelete(tim->list, &tim->node);
        tim->list = NULL;
    }

    ROS_TIMER_UNLOCK(&ros_timer_cb[tim->core_num].lock);
    return G_SUCCESS;
}

uint64_t ros_timer_reset(struct ros_timer *tim,
                            uint64_t time,
                            enum ros_timer_mode mode,
                            uint64_t para,
                            ros_timer_cb_t fct)
{
    if (unlikely(tim == NULL)) {
		LOG(ROS_TIMER, ERR, "Incorrect input parameters!");
        return G_FAILURE;
    }

    tim->fct  = fct;
    tim->para = para;
    tim->mode = mode;
    tim->ms   = time*ROS_TIMER_ACCURACY;

    tim->tick = ros_get_futurn_tsc(tim->ms);
    ROS_TIMER_LOCK(&ros_timer_cb[tim->core_num].lock);

    tim->status = ROS_TIMER_STATUS_START;
    if (tim->list) {
        lstDelete(tim->list, &tim->node);
        tim->list = NULL;
    }
    lstAdd(&ros_timer_cb[tim->core_num].disorderlist, &tim->node);
    tim->list = &ros_timer_cb[tim->core_num].disorderlist;

    ROS_TIMER_UNLOCK(&ros_timer_cb[tim->core_num].lock);
    return G_SUCCESS;
}

uint64_t ros_timer_del(struct ros_timer *tim)
{
    if (likely(tim != NULL)) {
        if (unlikely(tim->status < ROS_TIMER_STATUS_CREATE)) {
    		LOG(ROS_TIMER, ERR, "The timer status(%hu) is incorrect.",
                                tim->status);
            return G_FAILURE;
        }
        ROS_TIMER_LOCK(&ros_timer_cb[tim->core_num].lock);

        tim->status = ROS_TIMER_STATUS_NULL;
        if (tim->list) {
            lstDelete(tim->list, &tim->node);
            tim->list = NULL;
        }
        lstAdd(&ros_timer_cb[tim->core_num].ftnoderm, &tim->node);
        tim->list = &ros_timer_cb[tim->core_num].ftnoderm;

        ROS_TIMER_UNLOCK(&ros_timer_cb[tim->core_num].lock);
        return G_SUCCESS;
    }

    return G_FAILURE;
}

uint64_t ros_timer_reset_time(struct ros_timer *tim, uint64_t time)
{
    if (unlikely(tim == NULL)) {
		LOG(ROS_TIMER, ERR, "Incorrect input parameters!");
        return G_FAILURE;
    }

    ROS_TIMER_LOCK(&ros_timer_cb[tim->core_num].lock);

    tim->ms   = time*ROS_TIMER_ACCURACY;
    switch (tim->status) {
        case ROS_TIMER_STATUS_START:
            tim->tick = ros_get_futurn_tsc(tim->ms);

            if (tim->list) {
                lstDelete(tim->list, &tim->node);
                tim->list = NULL;
            }
            lstAdd(&ros_timer_cb[tim->core_num].disorderlist, &tim->node);
            tim->list = &ros_timer_cb[tim->core_num].disorderlist;
            break;

        default:
            break;
    }
    ROS_TIMER_UNLOCK(&ros_timer_cb[tim->core_num].lock);

    return G_SUCCESS;
}

void* ros_timer_process(__mb_unused void *arg)
{
    uint64_t core_num;
    struct ros_timer *dis_tim;
    struct ros_timer *ord_tim;
    struct ros_timer *child;
    struct ros_timer *prvchild;
    struct ros_timer_cb *timer_cb;
    uint8_t flag;

	LOG(ROS_TIMER, DEBUG, "ros_timer_work:%d", ros_timer_work);

    while (ros_timer_work == G_TRUE) {
        for (core_num = 0; core_num < ROS_TIMER_MAX_CORE; core_num ++) {
            timer_cb = &ros_timer_cb[core_num];

            ROS_TIMER_LOCK(&timer_cb->lock);

            if (lstCount(&timer_cb->disorderlist) <= 0) {
                ROS_TIMER_UNLOCK(&timer_cb->lock);
                continue;
            }

            dis_tim = (struct ros_timer *)lstGet(&timer_cb->disorderlist);
            while (dis_tim != NULL) {
                dis_tim->list = NULL;

//                PanathLog(ROS_TIMER, DEBUG, "dis_tim:%p, tick:%ld, orderlist count:%d",
//                    dis_tim, dis_tim->tick, lstCount(&timer_cb->orderlist));
                if (lstCount(&timer_cb->orderlist) <= 0) {
                    lstInit(&timer_cb->orderlist);
                    lstAdd(&timer_cb->orderlist, &dis_tim->node);
                    dis_tim->list = &timer_cb->orderlist;
                    dis_tim = (struct ros_timer *)lstGet(&timer_cb->disorderlist);
//                    PanathLog(ROS_TIMER, DEBUG, "dis_tim:%p", dis_tim);
                    continue;
                }

                flag = G_FALSE;
                child = (struct ros_timer *)lstFirst(&timer_cb->orderlist);
                while (child != NULL) {
                    if (child->tick >= dis_tim->tick) {
                        prvchild = (struct ros_timer *)lstPrevious(&child->node);
                        if (prvchild)
                            lstInsert(&timer_cb->orderlist, &prvchild->node, &dis_tim->node);
                        else
                            lstInsert(&timer_cb->orderlist, NULL, &dis_tim->node);
                        dis_tim->list = &timer_cb->orderlist;
                        flag = G_TRUE;
                        break;
                    }

                    child = (struct ros_timer *)lstNext(&child->node);
                }

                if (G_FALSE == flag) {
                    lstAdd(&timer_cb->orderlist, &dis_tim->node);
                    dis_tim->list = &timer_cb->orderlist;
                }

                dis_tim = (struct ros_timer *)lstGet(&timer_cb->disorderlist);
            }

//            PanathLog(ROS_TIMER, DEBUG, " ");
            ROS_TIMER_UNLOCK(&timer_cb->lock);
        }

        for (core_num = 0; core_num < ROS_TIMER_MAX_CORE; core_num ++) {
            timer_cb = &ros_timer_cb[core_num];

            ROS_TIMER_LOCK(&timer_cb->lock);

            if (lstCount(&timer_cb->orderlist) <= 0) {
                ROS_TIMER_UNLOCK(&timer_cb->lock);
                continue;
            }

            child = (struct ros_timer *)lstFirst(&timer_cb->orderlist);
            while (child != NULL) {
                ord_tim = child;
                if (ord_tim->tick > ros_rdtsc()) {
                    break;
                }
                child = (struct ros_timer *)lstNext(&child->node);
                if (ord_tim->list) {
                    lstDelete(ord_tim->list, &ord_tim->node);
                    ord_tim->list = NULL;
                }

                ROS_TIMER_UNLOCK(&timer_cb->lock);

                ord_tim->fct(ord_tim, ord_tim->para);

                ROS_TIMER_LOCK(&timer_cb->lock);

                if (ord_tim->status == ROS_TIMER_STATUS_START) {
                    if (ord_tim->tick < ros_rdtsc()) {
                        if (ord_tim->mode == ROS_TIMER_MODE_PERIOD) {
                            ord_tim->tick = ros_get_futurn_tsc(ord_tim->ms);

                            if (ord_tim->list) {
                                lstDelete(ord_tim->list, &ord_tim->node);
                                ord_tim->list = NULL;
                            }
                            lstAdd(&ros_timer_cb[ord_tim->core_num].disorderlist, &ord_tim->node);
                            ord_tim->list = &ros_timer_cb[ord_tim->core_num].disorderlist;
                        } else {
                            ord_tim->status = ROS_TIMER_STATUS_CREATE;
                            if (ord_tim->list) {
                                lstDelete(ord_tim->list, &ord_tim->node);
                                ord_tim->list = NULL;
                            }

                            /* create对应delete,start对应stop.在stop或者timeout的时候不做delete */
                            ord_tim->list = NULL;
                        }
                    }
                }

            }

            ROS_TIMER_UNLOCK(&timer_cb->lock);
        }

        usleep((ROS_TIMER_ACCURACY/10)*1000);
    }

    return NULL;
}

int ros_timer_resource_status(int argc, char **argv)
{
    uint32_t i;

        printf("      Maximum number      Ordered    Disordered    Free   \r\n");
    for (i = 0; i < ROS_TIMER_MAX_CORE; ++i) {
        printf("Timer[%-2u]:   %-8u       %-8u    %-8u   %-8u\r\n", i, ROS_TIMER_EACH_CORE_MAX_NUM,
            lstCount(&ros_timer_cb[i].orderlist),
            lstCount(&ros_timer_cb[i].disorderlist),
            lstCount(&ros_timer_cb[i].ftnoderm));
    }

    return 0;
}

