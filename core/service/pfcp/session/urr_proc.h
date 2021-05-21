/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef _URR_PROC_H__
#define _URR_PROC_H__

#ifdef __cplusplus
extern "C" {
#endif

#define URR_MAC_MAX          255
#define URR_STOP_TIME		 10

typedef enum
{
    URR_STATUS_INVALID   = 0x00,
    URR_STATUS_NORMAL    = 0x01,
    URR_STATUS_OVERFLOW  = 0x02,
    URR_STATUS_REPORTED  = 0x04,
    URR_STATUS_STOPED    = 0x08,
}urr_status_type_t;


typedef enum
{
    URR_TRIGGER_IMMER,        /* immediate report */
    URR_TRIGGER_DROTH,        /* dropped dl traffic threshold */
    URR_TRIGGER_STOPT,        /* stop of traffic */
    URR_TRIGGER_START,        /* start of traffic */
    URR_TRIGGER_QUHTI,        /* quota holding time */
    URR_TRIGGER_TIMTH,        /* time threshold */
    URR_TRIGGER_VOLTH,        /* volume threshold */
    URR_TRIGGER_PERIO,        /* periodic reporting */
    URR_TRIGGER_EVETH,        /* event threshold */
    URR_TRIGGER_MACAR,        /* mac address reporting */
    URR_TRIGGER_ENVCL,        /* envelope closure */
    URR_TRIGGER_MONIT,        /* monitoring time */
    URR_TRIGGER_TERMR,        /* termination report */
    URR_TRIGGER_LIUSA,        /* linked usage reporting */
    URR_TRIGGER_TIMQU,        /* time quota */
    URR_TRIGGER_VOLQU,        /* volume quota */
    URR_TRIGGER_EVEQU,        /* event quota */
}urr_report_trigger;

uint32_t urr_container_init(uint32_t urr_index);
uint32_t urr_container_destroy(uint32_t urr_index);
uint32_t urr_proc_recv(uint32_t urr_index, int64_t pkt_len, uint8_t dlflag);
uint32_t urr_proc_drop(uint32_t urr_index, int64_t pkt_len, int64_t pkt_num);
void urr_send_report(struct urr_table *urr_entry, uint32_t trigger);
void urr_select_monitor(struct urr_table *urr_entry);
int  urr_get_status(uint32_t urr_index);
void urr_fill_value(struct urr_table *urr_entry, comm_msg_urr_report_t *report);
int urr_count_proc(uint32_t stat_num, comm_msg_urr_stat_conf_t *stat_arr);
int urr_get_link_report(comm_msg_urr_report_t *report, struct urr_table *urr_entry, uint32_t start_num);




#ifdef __cplusplus
}
#endif

#endif /* _URR_PROC_H__ */



