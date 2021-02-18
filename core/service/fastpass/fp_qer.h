/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef _FP_QER_H_
#define _FP_QER_H_

#define ENABLE_FP_QER

#define FP_QER_KBR_TO_BYTE              125                         /* mbr unit is kbps, means 125 bytes */
#define FP_QER_BURST_TIMES              2                           /* butst times */

#define FP_QER_UPDATE_TIME_LEN          (fp_get_freq())           /* update token per second */
#define FP_QER_BURST_TIME_LEN           (FP_QER_BURST_TIMES * fp_get_freq())

typedef int (*FP_QER_HANDLE)(int, int, fp_qer_entry *, uint32_t);

void fp_qer_launch(fp_qer_entry *qer_entry);
void fp_qer_update_token(ros_atomic64_t *last_cycle, ros_atomic64_t *token_num, uint64_t token_grow, ros_atomic64_t *debt);
void fp_qer_update_cp_token(ros_atomic64_t *last_cycle, ros_atomic64_t *tokenc_num, uint64_t tokenc_grow,
	ros_atomic64_t *tokenp_num, uint64_t tokenp_grow, ros_atomic64_t *debt);
int  fp_qer_handle_ul(int pkt_len, int pkt_num, fp_qer_entry *qer_entry, uint32_t input_color);
int  fp_qer_handle_dl(int pkt_len, int pkt_num, fp_qer_entry *qer_entry, uint32_t input_color);
int  fp_qos_config(fp_qer_entry *qer_entry);

enum policer_action {
        FP_GREEN    = 0,
        FP_YELLOW   = 1,
        FP_RED      = 2,
        FP_DROP     = 3,
};


#endif /* _FP_QER_H_ */

