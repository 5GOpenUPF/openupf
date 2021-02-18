/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _ROS_TASK_H__
#define _ROS_TASK_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef pthread_mutex_t                 ROS_MUTEX_ID;
typedef pthread_mutexattr_t             ROS_MUTEXATTR_ID;

uint64_t ros_mutex_create(char *semName, ROS_MUTEX_ID *semId, 
                const char *fileName, uint64_t line);
uint64_t ros_mutex_delete(ROS_MUTEX_ID *semId, 
                const char *fileName, uint64_t line);
uint64_t ros_mutex_lock(ROS_MUTEX_ID *semId, 
                const char *fileName, uint64_t line);
uint64_t ros_mutex_unlock(ROS_MUTEX_ID *semId, 
                const char *fileName, uint64_t line);

#define ROS_MutexCreate(semName, semId) \
        ros_mutex_create(semName, semId, __FILE__, __LINE__)
        
#define ROS_MutexDelete(semId) \
        ros_mutex_delete(semId, __FILE__, __LINE__)

#define ROS_MutexLock(semId) \
        ros_mutex_lock(semId, __FILE__, __LINE__)

#define ROS_MutexUnLock(semId) \
        ros_mutex_unlock(semId, __FILE__, __LINE__)
        
#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _ROS_TASK_H__ */
