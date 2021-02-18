/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _ROS_RWLOCK_H_
#define _ROS_RWLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <emmintrin.h>

/**
 * The ros_rwlock_t type.
 *
 * cnt is -1 when write lock is held, and > 0 when read locks are held.
 */
typedef struct {
	volatile int32_t cnt; /**< -1 when W lock held, > 0 when R locks held. */
} ros_rwlock_t;

/**
 * A static rwlock initializer.
 */
#define ROS_RWLOCK_INITIALIZER { 0 }

/**
 * Initialize the rwlock to an unlocked state.
 *
 * @param rwl
 *   A pointer to the rwlock structure.
 */
static inline void
ros_rwlock_init(ros_rwlock_t *rwl)
{
	rwl->cnt = 0;
}

/**
 * Take a read lock. Loop until the lock is held.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static inline void
ros_rwlock_read_lock(ros_rwlock_t *rwl)
{
	int32_t x;
	int success = 0;

	while (success == 0) {
		x = rwl->cnt;
		/* write lock is held */
		if (x < 0) {
			_mm_pause();
			continue;
		}
		success = ros_atomic32_cmpset((volatile uint32_t *)&rwl->cnt,
					      (uint32_t)x, (uint32_t)(x + 1));
	}
}

/**
 * Release a read lock.
 *
 * @param rwl
 *   A pointer to the rwlock structure.
 */
static inline void
ros_rwlock_read_unlock(ros_rwlock_t *rwl)
{
	ros_atomic32_dec((ros_atomic32_t *)(intptr_t)&rwl->cnt);
}

/**
 * Take a write lock. Loop until the lock is held.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static inline void
ros_rwlock_write_lock(ros_rwlock_t *rwl)
{
	int32_t x;
	int success = 0;

	while (success == 0) {
		x = rwl->cnt;
		/* a lock is held */
		if (x != 0) {
			_mm_pause();
			continue;
		}
		success = ros_atomic32_cmpset((volatile uint32_t *)&rwl->cnt,
					      0, (uint32_t)-1);
	}
}

static inline void
ros_rwlock_write_unlock(ros_rwlock_t *rwl)
{
	ros_atomic32_inc((ros_atomic32_t *)(intptr_t)&rwl->cnt);
}

#ifdef __cplusplus
}
#endif

#endif /* _ROS_RWLOCK_H_ */

