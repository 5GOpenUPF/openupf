/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef _FP_RECYCLE_H__
#define _FP_RECYCLE_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 600s/10minutes as a period */
#define FP_RECYCLE_PERIOD               600

/* default level, recycle entries that no access over 60 minutes */
#define FP_RECYCLE_LEVEL_1              6

/* used rate over 70%, recycle entries that no access over 20 minutes */
#define FP_RECYCLE_LEVEL_2              2
#define FP_RECYCLE_THRESHOLD_2          70

/* used rate over 90%, recycle entries that no access over 10 minutes */
#define FP_RECYCLE_LEVEL_3              1
#define FP_RECYCLE_THRESHOLD_3          90

void fp_recycle_init(uint32_t fast_num);
void fp_recycle_entry(void);

#ifdef __cplusplus
}
#endif

#endif /* _FP_RECYCLE_H__ */

