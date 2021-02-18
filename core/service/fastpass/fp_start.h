/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef _FP_START_H__
#define _FP_START_H__

#ifdef __cplusplus
extern "C" {
#endif

#define FP_START_BUF_SIZE           256

typedef enum
{
    FP_START_STATUS_INIT    = 0x00,     /* Keep this value is 0 */
    FP_START_STATUS_READY   = 0x01,
    FP_START_STATUS_RUN     = 0x02,
    FP_START_STATUS_BUTT,
}fp_start_status_type_t;


inline int fp_start_get_status(void);
inline int fp_start_is_init(void);
inline int fp_start_is_run(void);
void fp_start_set_status(fp_start_status_type_t new_status);
int fp_start_config(comm_msg_system_config_t *cfg);
int fp_start_proc_reset(void);
int fp_start_proc_config(comm_msg_ie_t *ie);
int fp_start_proc_start(void);


#ifdef __cplusplus
}
#endif

#endif /* _FP_START_H__ */


