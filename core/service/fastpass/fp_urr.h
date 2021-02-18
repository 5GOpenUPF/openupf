/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef _FP_URR_H__
#define _FP_URR_H__

#ifdef __cplusplus
extern "C" {
#endif

#undef ENABLE_FP_URR

typedef enum
{
    FP_URR_STATUS_INVALID   = 0x00,
    FP_URR_STATUS_NORMAL    = 0x01,
    FP_URR_STATUS_OVERFLOW  = 0x02,
    FP_URR_STATUS_REPORTED  = 0x04,
    FP_URR_STATUS_STOPED    = 0x08,
}fp_urr_status_type_t;

typedef enum
{
    FP_URR_TRIGGER_IMMER,        /* immediate report */
    FP_URR_TRIGGER_DROTH,        /* dropped dl traffic threshold */
    FP_URR_TRIGGER_STOPT,        /* stop of traffic */
    FP_URR_TRIGGER_START,        /* start of traffic */
    FP_URR_TRIGGER_QUHTI,        /* quota holding time */
    FP_URR_TRIGGER_TIMTH,        /* time threshold */
    FP_URR_TRIGGER_VOLTH,        /* volume threshold */
    FP_URR_TRIGGER_PERIO,        /* periodic reporting */
    FP_URR_TRIGGER_EVETH,        /* event threshold */
    FP_URR_TRIGGER_MACAR,        /* mac address reporting */
    FP_URR_TRIGGER_ENVCL,        /* envelope closure */
    FP_URR_TRIGGER_MONIT,        /* monitoring time */
    FP_URR_TRIGGER_TERMR,        /* termination report */
    FP_URR_TRIGGER_LIUSA,        /* linked usage reporting */
    FP_URR_TRIGGER_TIMQU,        /* time quota */
    FP_URR_TRIGGER_VOLQU,        /* volume quota */
    FP_URR_TRIGGER_EVEQU,        /* event quota */
}fp_urr_report_trigger;

uint32_t fp_urr_container_init(uint32_t urr_index);
uint32_t fp_urr_container_destroy(uint32_t urr_index);
uint32_t fp_urr_proc_recv(uint32_t urr_index, uint32_t pkt_len, uint8_t dlflag);
uint32_t fp_urr_proc_drop(uint32_t urr_index, uint32_t pkt_len);
void fp_urr_send_report(fp_urr_entry *urr_entry, uint16_t trigger);
void fp_urr_select_monitor(fp_urr_entry *urr_entry);
int  fp_urr_get_status(uint32_t urr_index);
void fp_urr_fill_value(fp_urr_entry *urr_entry, comm_msg_urr_report_t *report);


#ifdef __cplusplus
}
#endif

#endif /* _FP_URR_H__ */


