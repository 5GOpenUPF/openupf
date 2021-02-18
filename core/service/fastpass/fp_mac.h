/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef _FP_URR_MAC_H__
#define _FP_URR_MAC_H__

#ifdef __cplusplus
extern "C" {
#endif

#define FP_URR_MAC_MAX          255

#ifdef ENABLE_FP_URR
char *fp_urr_mac_copy(char *buff, comm_msg_urr_mac_t *mac_list);
void fp_urr_mac_chk(fp_urr_entry *urr_entry, uint64_t input_mac);
void fp_urr_mac_proc_timer(void *timer, uint64_t para);
void fp_urr_mac_create_bucket(fp_urr_entry *urr_entry);
void fp_urr_mac_destroy_bucket(fp_urr_entry *urr_entry);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FP_URR_MAC_H__ */



