/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _ROS_CYCLES_H__
#define _ROS_CYCLES_H__

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t
ros_rdtsc(void)
{
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	asm volatile("rdtsc" :
		     "=a" (tsc.lo_32),
		     "=d" (tsc.hi_32));
	return tsc.tsc_64;
}

uint64_t ros_get_tsc_hz(void);
void ros_set_tsc_freq(void);
uint64_t ros_get_futurn_tsc(uint64_t ms);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _ROS_CYCLES_H__ */
