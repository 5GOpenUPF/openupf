/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "ros_lock.h"

uint64_t ros_mutex_create(
                __mb_unused char *semName,
                ROS_MUTEX_ID *semId,
                __mb_unused const char *fileName,
                __mb_unused uint64_t line)
{
    int ret;
    ROS_MUTEXATTR_ID  semAttr;

    if (unlikely(NULL == semId)) {
        return G_FAILURE;
    }

    ret = pthread_mutexattr_init(&semAttr);
    if (unlikely(ret != 0)) {
        return G_FAILURE;
    }

    pthread_mutexattr_settype(&semAttr, PTHREAD_MUTEX_RECURSIVE);
    ret = pthread_mutex_init(semId, &semAttr);
    if (unlikely(ret != 0)) {
        return G_FAILURE;
    }

    return G_SUCCESS;
}

uint64_t ros_mutex_delete(ROS_MUTEX_ID *semId,
                __mb_unused const char *fileName,
                __mb_unused uint64_t line)
{
    if (unlikely(NULL == semId)) {
        return G_FAILURE;
    }

    pthread_mutex_destroy(semId);
    return G_SUCCESS;
}

uint64_t ros_mutex_lock(ROS_MUTEX_ID *semId,
                __mb_unused const char *fileName,
                __mb_unused uint64_t line)
{
    if (unlikely(NULL == semId)) {
        return G_FAILURE;
    }

    pthread_mutex_lock(semId);
    return G_SUCCESS;
}

uint64_t ros_mutex_unlock(ROS_MUTEX_ID *semId,
                __mb_unused const char *fileName,
                __mb_unused uint64_t line)
{
    if (unlikely(NULL == semId)) {
        return G_FAILURE;
    }

    pthread_mutex_unlock(semId);
    return G_SUCCESS;
}

