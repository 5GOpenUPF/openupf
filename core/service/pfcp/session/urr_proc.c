/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "urr_mgmt.h"
#include "session_mgmt.h"
#include "session_instance.h"
#include "pdr_mgmt.h"
#include "far_mgmt.h"
#include "bar_mgmt.h"
#include "urr_mgmt.h"
#include "session_teid.h"
#include "session_report.h"
#include "session_msg.h"
#include "urr_proc.h"

static inline void urr_proc_timer_idt(void *timer, uint64_t para);
static inline void urr_proc_timer_qht(void *timer, uint64_t para);
static int urr_update_light_to_fpu(comm_msg_update_inst_light_t *light_arr, uint32_t index_num);
static int urr_update_thres_to_fpu(comm_msg_update_inst_thres_t *thres_arr, uint32_t index_num);
static inline int urr_change_inst_light(struct urr_table *entry, uint8_t light);
static inline int urr_change_inst_thres(struct urr_table *entry);

int urr_get_link_report(comm_msg_urr_report_t *report, struct urr_table *urr_entry, uint32_t start_num)
{
    urr_container           *cont = NULL;
    struct pfcp_session     *sess = NULL;
    struct urr_table        *urr_tbl = NULL;
    uint32_t cnt, urr_link_num, report_num = start_num;

    if(start_num > MAX_URR_NUM) {
        LOG(SESSION, ERR, "parameters error , start_num %d out of range.", start_num);
        return -1;
    }

    if(NULL == report) {
        LOG(SESSION, ERR, "parameters error , report NULL.");
        return -1;
    }

    if(NULL == urr_entry) {
        LOG(SESSION, ERR, "parameters error , urr_entry NULL.");
        return -1;
    }

    sess = &urr_entry->sess->session;
    urr_tbl = (struct urr_table *)rbtree_first(&sess->urr_root);

    while (NULL != urr_tbl) {
        urr_link_num = urr_tbl->urr.linked_urr_number;
        cont = &urr_tbl->container;
        if((0 != urr_link_num)) {

            if(!urr_tbl->urr.trigger.d.liusa) {
                LOG(SESSION, ERR, "urr %d, linked_urr_number is %d, but liusa is not set.",
                    urr_tbl->urr.urr_id, urr_link_num);

                urr_tbl = (struct urr_table *)rbtree_next(&urr_tbl->urr_node);
                continue;
            }
            for(cnt=0; cnt<urr_link_num; cnt++) {
                if(urr_tbl->urr.linked_urr[cnt] == urr_entry->urr.urr_id) {
                    break;
                }
            }

            if(cnt < urr_link_num) {
                /*避免重复上报*/
                for(cnt=0; cnt<report_num; cnt++) {
                    if (report[cnt].urr_id == urr_tbl->urr.urr_id) {
                        break;
                    }
                }
                if(cnt >= report_num) {
                    report[report_num].start_time      = cont->start_time.cnt;
                    report[report_num].end_time        = ros_getime();
                    report[report_num].first_pkt_time  = cont->first_pkt.cnt;
                    report[report_num].last_pkt_time   = ros_getime();
                    if (urr_tbl->urr.method.d.durat) {
                        report[report_num].last_pkt_time = (uint32_t)ros_atomic32_read(&cont->last_pkt);
                    }
                    report[report_num].urr_id          = urr_tbl->urr.urr_id;
                    report[report_num].urr_index       = urr_tbl->index;
                    //简单处理下，为了跑移动的测试用例能带上收包时间和末包时间
                    if (!report[report_num].start_time) {
                        report[report_num].start_time = report[0].start_time;
                    }
                    if (!report[report_num].first_pkt_time) {
                        report[report_num].first_pkt_time = report[0].first_pkt_time;
                    }
                    if (!report[report_num].last_pkt_time) {
                        report[report_num].last_pkt_time = report[0].last_pkt_time;
                    }

                    report[report_num].trigger.d.liusa = G_TRUE;
                    urr_fill_value(urr_tbl, &report[report_num]);
                    report[report_num].ur_seqn = urr_tbl->urr.ur_seqn++;

                    report_num++;
                    if(report_num >= MAX_URR_NUM) {
                        LOG(SESSION, ERR, "report_num(%d) MAX.", report_num);
                        break;
                    }
                }
            }
        }
        urr_tbl = (struct urr_table *)rbtree_next(&urr_tbl->urr_node);
    }

    return report_num;
}

void urr_send_report(struct urr_table *urr_entry, uint32_t trigger)
{
    comm_msg_urr_report_t   report[MAX_URR_NUM];
    urr_container           *cont = NULL;          /* resource container */
    uint32_t                report_num;
    /*char *mac_buf = NULL;*/

    //带了门限或配额但是触发条件没有带的话，不上报
    if (URR_TRIGGER_VOLTH == trigger || URR_TRIGGER_VOLQU == trigger) {
        if (!urr_entry->urr.trigger.d.volth && !urr_entry->urr.trigger.d.volqu) {
            LOG(SESSION, RUNNING,
                "not send report, trigger(%u), but report trigger not set!", trigger);
            return;
        }
    }
    else if (URR_TRIGGER_TIMTH == trigger || URR_TRIGGER_TIMQU == trigger) {
        if (!urr_entry->urr.trigger.d.timth && !urr_entry->urr.trigger.d.timqu) {
            LOG(SESSION, RUNNING,
                "not send report, trigger(%u), but report trigger not set!", trigger);
            return;
        }
    }

    memset(report, 0, sizeof(report));
    cont = &urr_entry->container;

    report[0].urr_index  = urr_entry->index;
    report[0].ur_seqn = urr_entry->urr.ur_seqn++;

    /*针对fp第一次给sp上报urr统计信息就触发上报导致缺少
    Time of First Packet和Time of Last Packet两个IE的情况，作特殊处理*/
    if (0 == ros_atomic32_read(&cont->last_pkt)) {
        cont->last_pkt.cnt = cont->first_pkt.cnt;
    }

    switch (trigger) {
        case URR_TRIGGER_IMMER:
        case URR_TRIGGER_PERIO:
        case URR_TRIGGER_MONIT:
        case URR_TRIGGER_TERMR:
        case URR_TRIGGER_ENVCL:
        case URR_TRIGGER_DROTH:
        case URR_TRIGGER_STOPT:
        case URR_TRIGGER_QUHTI:
        case URR_TRIGGER_TIMTH:
        case URR_TRIGGER_TIMQU:
        case URR_TRIGGER_VOLTH:
        case URR_TRIGGER_VOLQU:
        case URR_TRIGGER_EVETH:
        case URR_TRIGGER_EVEQU:
        case URR_TRIGGER_MACAR:
            report[0].start_time      = (uint32_t)ros_atomic32_read(&cont->start_time);
            report[0].end_time        = ros_getime();
            report[0].first_pkt_time  = (uint32_t)ros_atomic32_read(&cont->first_pkt);
            report[0].last_pkt_time   = (uint32_t)ros_atomic32_read(&cont->last_pkt);
            break;

        default:
            break;
    }

    switch (trigger) {
        case URR_TRIGGER_IMMER:
        case URR_TRIGGER_PERIO:
        case URR_TRIGGER_MONIT:
        case URR_TRIGGER_TERMR:
        case URR_TRIGGER_ENVCL:
            if (trigger == URR_TRIGGER_IMMER) {
                report[0].trigger.d.immer = G_TRUE;
            }
            else if (trigger == URR_TRIGGER_PERIO) {
                report[0].trigger.d.perio = G_TRUE;
            }
            else if (trigger == URR_TRIGGER_TERMR) {
                report[0].trigger.d.termr = G_TRUE;
            }
            else if (trigger == URR_TRIGGER_ENVCL){
                report[0].trigger.d.envcl = G_TRUE;
            }
            else {
                report[0].trigger.d.monit = G_TRUE;
            }

            urr_fill_value(urr_entry, &report[0]);
            break;
        case URR_TRIGGER_DROTH:
            report[0].trigger.d.droth = G_TRUE;
            break;
        case URR_TRIGGER_STOPT:
            report[0].trigger.d.stopt = G_TRUE;

            urr_fill_value(urr_entry, &report[0]);
            break;
        case URR_TRIGGER_START:
            report[0].trigger.d.start = G_TRUE;
            break;
        case URR_TRIGGER_QUHTI:
            report[0].trigger.d.quhti = G_TRUE;
            break;
        case URR_TRIGGER_TIMTH:
        case URR_TRIGGER_TIMQU:
            if (trigger == URR_TRIGGER_TIMTH) {
                report[0].trigger.d.timth = G_TRUE;
            }
            else {
                report[0].trigger.d.timqu = G_TRUE;
            }

            /* Get time */
            urr_fill_value(urr_entry, &report[0]);
            break;
        case URR_TRIGGER_VOLTH:
        case URR_TRIGGER_VOLQU:
            if (trigger == URR_TRIGGER_VOLTH) {
                report[0].trigger.d.volth = G_TRUE;
            }
            else {
                report[0].trigger.d.volqu = G_TRUE;
            }

            /* Get volume */
            urr_fill_value(urr_entry, &report[0]);
            break;
        case URR_TRIGGER_EVETH:
        case URR_TRIGGER_EVEQU:
            if (trigger == URR_TRIGGER_EVETH) {
                report[0].trigger.d.eveth = G_TRUE;
            }
            else {
                report[0].trigger.d.evequ = G_TRUE;
            }

            /* Get events */
            report[0].eve_stamp = ros_getime();
            break;
        case URR_TRIGGER_MACAR:
            report[0].trigger.d.macar = G_TRUE;

            /* Copy mac list from buffer */
            /*mac_buf = (char *)(report + 1);
            mac_buf = urr_mac_copy(mac_buf, urr_entry->mac_bucket.new_mac);
            mac_buf = urr_mac_copy(mac_buf, urr_entry->mac_bucket.obs_mac);*/
            break;
        case URR_TRIGGER_LIUSA:
            break;
        default:
            LOG(SESSION, RUNNING,
                "unknown trigger type(%u)!", trigger);
            break;
    }

    report_num = urr_get_link_report(&report[0], urr_entry, 1);
    if(-1 == report_num) {
        LOG(SESSION, ERR, "urr_get_link_report error.");
        return;
    }

    if (0 > session_report_local_urr(&report[0], report_num, trigger)) {
        LOG(SESSION, ERR, "Report URR failed.");
    }

    LOG(SESSION, RUNNING, "send report, trigger %u", trigger);
}

void urr_fill_value(struct urr_table *urr_entry, comm_msg_urr_report_t *report)
{
    urr_container        *cont;          /* resource container */
    comm_msg_urr_mon_time_t *monitor;

    cont = &urr_entry->container;
    monitor = &urr_entry->container.mon_cfg;

    ros_atomic32_set(&cont->first_pkt, ros_getime());
    ros_atomic32_set(&cont->last_pkt, ros_getime());
    ros_atomic32_set(&cont->start_time, ros_getime());

    if (urr_entry->urr.method.d.volum) {
        report->vol_meas.flag.value = urr_entry->container.flag.value;

        report->vol_meas.uplink = cont->vol_ulink.cnt;
        report->vol_meas.downlink = cont->vol_dlink.cnt;
        report->vol_meas.total = cont->vol_total.cnt;

        ros_atomic64_init(&cont->vol_dlink);
        ros_atomic64_init(&cont->vol_ulink);
        ros_atomic64_init(&cont->vol_total);
    }

    if (urr_entry->urr.method.d.durat) {
        report->tim_meas_present = 1;
        if (urr_entry->container.tim_status & URR_STATUS_NORMAL) {
            if (monitor->sub_tim_thres) {
                report->tim_meas = (monitor->sub_tim_thres_fixed - cont->time.cnt);
            }
            else {
                report->tim_meas = (monitor->sub_tim_quota - cont->time.cnt);
            }
        }
        else {
            if (!monitor->sub_tim_quota) {
                report->tim_meas = monitor->sub_tim_thres;
            }
            else {
                report->tim_meas = (monitor->sub_tim_quota - cont->time.cnt);
            }
        }

        //只收到一次用量统计导致链接上去的时间为0
        if (report->trigger.d.liusa ) {
            if (!urr_entry->urr.measu_info.d.inam) {
                report->tim_meas = ros_getime() - report->start_time;
            }
        }
    }

    if (urr_entry->urr.mon_time) {
        if (cont->mon_timer == NULL) {
            report->usage_info.d.aft = 1;
        } else {
            report->usage_info.d.bef = 1;
        }
    }

    if (urr_entry->urr.measu_info.d.mbqe) {
        report->usage_info.d.ube = 1;
    } else {
        report->usage_info.d.uae = 1;
    }
}

static inline void
urr_sub_volume(ros_atomic64_t *volume, uint32_t pkt_len,
    uint64_t vol_thres, uint64_t vol_quota, uint8_t *vol_status)
{
    uint32_t                new_vol;

    LOG(SESSION, RUNNING,
        "volume %ld, packet len %u.",
        ros_atomic64_read(volume), pkt_len);

    if (likely(ros_atomic64_read(volume) > pkt_len)) {
        /* Volume is enough, no action */
        ros_atomic64_sub(volume, pkt_len);
        return;
    }

    /* Volume exhaust, need handle */
    switch (*vol_status)
    {
        case URR_STATUS_NORMAL:
            /* If not configure threshold */
            if (!vol_thres) {
                /* Stop to forward more packets */
                *vol_status = (URR_STATUS_STOPED|URR_STATUS_OVERFLOW);
                ros_atomic64_set(volume, 0);
            }
            else {
                /* Keep the remainder bytes in pool */
                if (vol_quota) {
                    if (vol_quota > vol_thres) {
                        new_vol = vol_quota - vol_thres + ros_atomic64_read(volume);

                        /* Before sub pkt len, need judge */
                        if (new_vol > pkt_len) {
                            /* Reset volume */
                            *vol_status = (URR_STATUS_REPORTED|URR_STATUS_OVERFLOW);
                            ros_atomic64_set(volume, new_vol - pkt_len);
                        }
                        else {
                            /* Stop to forward more packets */
                            *vol_status = (URR_STATUS_REPORTED|URR_STATUS_STOPED|URR_STATUS_OVERFLOW);
                            ros_atomic64_set(volume, 0);
                        }
                    }
                    else {
                        /* Stop to forward more packets */
                        *vol_status = (URR_STATUS_REPORTED|URR_STATUS_STOPED|URR_STATUS_OVERFLOW);
                        ros_atomic64_set(volume, 0);
                    }
                }
                else {
                    /* No quota is set, unlimited by default */
                    *vol_status = (URR_STATUS_REPORTED|URR_STATUS_OVERFLOW);
                    ros_atomic64_set(volume, 0);
                }
            }
            break;

        case URR_STATUS_REPORTED:
            /* Keep forward */
#if 0
            /* Stop to forward more packets */
            *vol_status = FP_URR_STATUS_STOPED;

            /* Have reported, no action here */
            ros_atomic64_set(volume, 0);
#endif
            if (vol_quota) {
                /* Stop to forward more packets, don't report */
                *vol_status = URR_STATUS_STOPED;
                ros_atomic64_set(volume, 0);
            }
            break;

        case URR_STATUS_STOPED:
            /* No volume resource, drop this packet */
            break;
    }

    return;
}

static inline void
urr_add_volume(ros_atomic64_t *volume, ros_atomic64_t *vol_total, int64_t pkt_len,
    uint64_t vol_thres, uint64_t vol_quota, uint8_t *vol_status)
{
    int64_t tmp_value, total_value;
    ros_atomic64_add(volume, pkt_len);
    ros_atomic64_add(vol_total, pkt_len);
    tmp_value = ros_atomic64_read(volume);
    total_value = ros_atomic64_read(vol_total);

    LOG(SESSION, RUNNING,
        "volume %ld, vol_total %ld, packet len %ld.",
        ros_atomic64_read(volume), ros_atomic64_read(vol_total), pkt_len);

    /* Volume exhaust, need handle */
    switch (*vol_status)
    {
        case URR_STATUS_NORMAL:
            /* If not configure threshold */
            if (!vol_thres) {
                /* Stop to forward more packets */
                if (total_value >= vol_quota) {
                    *vol_status = (URR_STATUS_STOPED|URR_STATUS_REPORTED);
                }
            }
            else {
                /* Keep the remainder bytes in pool */
                if (vol_quota) {
                    if (total_value >= vol_quota) {
                        *vol_status = URR_STATUS_STOPED;
                    }
                    if (tmp_value >= vol_thres) {
                        *vol_status |= URR_STATUS_REPORTED;
                    }
                }
                else {
                    /* No quota is set, unlimited by default */
                    if (tmp_value >= vol_thres) {
                        *vol_status = URR_STATUS_REPORTED;
                    }
                }
            }
            break;

        case URR_STATUS_STOPED:
            /* No volume resource, drop this packet */
            break;
    }

    return;
}


static inline void
urr_chk_volume(struct urr_table *urr_entry, int64_t pkt_len, uint8_t dlflag)
{
    urr_container *cont;

    cont = &urr_entry->container;

    LOG(SESSION, RUNNING,
        "urr(%d): check %s volume, flag %x.", urr_entry->index,
        (dlflag == 0)?"uplink":"downlink", cont->flag.value);

    /* Downlink */
    if (dlflag) {
        if (cont->flag.d.dlvol) {
            urr_add_volume(&cont->vol_dlink, &cont->vol_all_dlink, pkt_len,
                cont->mon_cfg.sub_vol_thres.downlink, cont->mon_cfg.sub_vol_quota.downlink,
                &cont->vol_dl_status);
            LOG(SESSION, RUNNING,
                "urr(%d): dl status %x.", urr_entry->index, cont->vol_dl_status);
        }
        if (cont->flag.d.tovol) {
            urr_add_volume(&cont->vol_total, &cont->vol_all_total, pkt_len,
                cont->mon_cfg.sub_vol_thres.total, cont->mon_cfg.sub_vol_quota.total,
                &cont->vol_tot_status);
            LOG(SESSION, RUNNING,
                "urr(%d): tot status %x.", urr_entry->index, cont->vol_tot_status);
        }

        /* The threshold report uses the method of circular report, and the statistics are repeated after each report */
        if (cont->vol_dl_status & URR_STATUS_REPORTED) {
            /* Send report */
            if (cont->vol_dl_status & URR_STATUS_STOPED) {
                urr_send_report(urr_entry, URR_TRIGGER_VOLQU);
                cont->vol_dl_status = URR_STATUS_STOPED;
            }
            else {
                /* Send report */
                urr_send_report(urr_entry, URR_TRIGGER_VOLTH);
                cont->vol_dl_status = URR_STATUS_NORMAL;

                if (cont->flag.d.tovol) {
                    cont->vol_tot_status = URR_STATUS_NORMAL;
                }
            }
        }
        else if (cont->vol_tot_status & URR_STATUS_REPORTED) {
            /* Send report */
            if (cont->vol_tot_status & URR_STATUS_STOPED) {
                urr_send_report(urr_entry, URR_TRIGGER_VOLQU);
                cont->vol_tot_status = URR_STATUS_STOPED;
            }
            else {
                /* Send report */
                urr_send_report(urr_entry, URR_TRIGGER_VOLTH);
                cont->vol_tot_status = URR_STATUS_NORMAL;
            }
        }
    }
    else {
        if (cont->flag.d.ulvol) {
            urr_add_volume(&cont->vol_ulink, &cont->vol_all_ulink, pkt_len,
                cont->mon_cfg.sub_vol_thres.uplink, cont->mon_cfg.sub_vol_quota.uplink,
                &cont->vol_ul_status);
            LOG(SESSION, RUNNING,
                "urr(%d): ul status %x.", urr_entry->index, cont->vol_ul_status);
        }
        if (cont->flag.d.tovol) {
            urr_add_volume(&cont->vol_total, &cont->vol_all_total, pkt_len,
                cont->mon_cfg.sub_vol_thres.total, cont->mon_cfg.sub_vol_quota.total,
                &cont->vol_tot_status);
            LOG(SESSION, RUNNING,
                "urr(%d): tot status %x.", urr_entry->index, cont->vol_tot_status);
        }

        //门限上报使用循环上报的方法，每次上报完重新统计
        if (cont->vol_ul_status & URR_STATUS_REPORTED) {
            /* Send report */
            if (cont->vol_ul_status & URR_STATUS_STOPED) {
                urr_send_report(urr_entry, URR_TRIGGER_VOLQU);
                cont->vol_ul_status = URR_STATUS_STOPED;
            }
            else {
                /* Send report */
                urr_send_report(urr_entry, URR_TRIGGER_VOLTH);
                cont->vol_ul_status = URR_STATUS_NORMAL;

                if (cont->flag.d.tovol) {
                    cont->vol_tot_status = URR_STATUS_NORMAL;
                }
            }
        }
        else if (cont->vol_tot_status & URR_STATUS_REPORTED) {
            /* Send report */
            if (cont->vol_tot_status & URR_STATUS_STOPED) {
                urr_send_report(urr_entry, URR_TRIGGER_VOLQU);
                cont->vol_tot_status = URR_STATUS_STOPED;
            }
            else {
                /* Send report */
                urr_send_report(urr_entry, URR_TRIGGER_VOLTH);
                cont->vol_tot_status = URR_STATUS_NORMAL;
            }
        }
    }

    return;
}

static inline void
urr_chk_droppkts(struct urr_table *urr_entry, int64_t pkt_len, int64_t pkt_num)
{
    urr_container *cont;

    cont = &urr_entry->container;

    if (likely(ros_atomic32_read(&cont->droppkts))) {
        /* If zero */
        if (0 >= ros_atomic32_sub_return(&cont->droppkts, pkt_num)) {

            /* Send report */
            urr_send_report(urr_entry, URR_TRIGGER_DROTH);
        }
        else {
            /* Do nothing */
        }
    }
    else {
        /* Do nothing */
    }

    if (likely(ros_atomic32_read(&cont->dropbyte))) {
        if (ros_atomic32_read(&cont->dropbyte) > pkt_len) {
            ros_atomic32_sub(&cont->dropbyte, pkt_len);
        }
        else {
            /* Reach zero */
            ros_atomic32_set(&cont->dropbyte, 0);

            /* Send report */
            urr_send_report(urr_entry, URR_TRIGGER_DROTH);
        }
    }
    else {
        /* Do nothing */
    }

    return;
}

static void urr_chk_time(struct urr_table *urr_entry)
{
    urr_container        *cont;
    uint32_t                new_gap, new_time;
    uint8_t                 *tim_status;
    comm_msg_urr_config     *conf = &urr_entry->urr;

    cont = &urr_entry->container;

    if (unlikely(0 == ros_atomic32_read(&cont->last_pkt))) {
        /* First packet, don't record */
        LOG(SESSION, RUNNING, "Last packet time is 0.");
        /*停止检测流量收到第一个包时，如果剩余时间小于不活跃检测时间，
        将定时时长设为剩余时长*/
        if(ros_atomic32_read(&cont->time) <= conf->inact_detect) {
            ros_timer_reset(cont->idt_timer, ros_atomic32_read(&cont->time) * ROS_TIMER_TICKS_PER_SEC,
                ROS_TIMER_MODE_ONCE, (uint64_t)urr_entry, urr_proc_timer_idt);

            LOG(SESSION, RUNNING, "ros_atomic32_read(&cont->time) %d!", ros_atomic32_read(&cont->time));
        }
        return;
    }

    new_gap = ros_getime() - ros_atomic32_read(&cont->last_pkt);
    LOG(SESSION, RUNNING, "urr(%d), new_gap %d, ros_atomic32_read(&cont->time) %d.", urr_entry->index,new_gap, ros_atomic32_read(&cont->time));
    if (likely(!new_gap)) {
        /* Toooo frequently, don't record */
        return;
    }
    else if (new_gap < ros_atomic32_read(&cont->time)) {
        /* Minus gap second */
        ros_atomic32_sub(&cont->time, new_gap);
        return;
    }

    /* Time exhaust, need handle */
    tim_status = &cont->tim_status;
    switch (*tim_status)
    {
        case URR_STATUS_NORMAL:
            /* If not configure threshold */
            if (!cont->mon_cfg.sub_tim_thres) {
                /* Stop to forward more packets */
                *tim_status = URR_STATUS_STOPED;
                ros_atomic32_set(&cont->time, 0);
                LOG(SESSION, RUNNING,
                    "cont->mon_cfg.sub_tim_thres(%d)!", cont->mon_cfg.sub_tim_thres);
                /* Send report */
                urr_send_report(urr_entry, URR_TRIGGER_TIMQU);
            }
            else {
                if (cont->mon_cfg.sub_tim_quota) {
                    if (cont->mon_cfg.sub_tim_quota >= cont->mon_cfg.sub_tim_thres) {
                        /* Keep the remainder bytes in pool */
                        new_time = cont->mon_cfg.sub_tim_quota - cont->mon_cfg.sub_tim_thres
                            + ros_atomic32_read(&cont->time);

                        LOG(SESSION, RUNNING,
                            "new_time(%u), new_gap(%u)!", new_time, new_gap);

                        ros_atomic32_set(&cont->time, new_time - new_gap);
                        /* Before sub pkt len, need judge */
                        if (new_time > new_gap) {
                            /* Reset volume */
                            if (ros_atomic32_read(&cont->time) >= cont->mon_cfg.sub_tim_thres_fixed) {
                                ros_atomic32_set(&cont->time, 0);
                                *tim_status = URR_STATUS_NORMAL;
                                cont->mon_cfg.sub_tim_thres +=  cont->mon_cfg.sub_tim_thres_fixed;
                                /* Send report */
                                urr_send_report(urr_entry, URR_TRIGGER_TIMTH);
                                ros_atomic32_set(&cont->time, cont->mon_cfg.sub_tim_thres_fixed);
                            }
                            else {
                                *tim_status = URR_STATUS_REPORTED;
                                /* Send report */
                                urr_send_report(urr_entry, URR_TRIGGER_TIMTH);
                            }

                        }
                        else {
                            ros_atomic32_set(&cont->time, 0);
                            /* Send report */
                            urr_send_report(urr_entry, URR_TRIGGER_TIMTH);

                             /* Stop to forward more packets */
                            *tim_status = URR_STATUS_STOPED;
                        }
                    }
                    else {
                        /* Stop to forward more packets */
                        *tim_status = URR_STATUS_STOPED;
                        ros_atomic32_set(&cont->time, 0);

                        /* Send report */
                        urr_send_report(urr_entry, URR_TRIGGER_TIMTH);
                    }
                }
                else {
                    /* No quota is set, unlimited by default */
                    /* Threshold cycle Report */
                    *tim_status = URR_STATUS_NORMAL;
                    ros_atomic32_set(&cont->time, 0);

                    urr_send_report(urr_entry, URR_TRIGGER_TIMTH);
                    LOG(SESSION, RUNNING,
                            "reset timer %u, &cont->time %d!", cont->mon_cfg.sub_tim_thres, ros_atomic32_read(&cont->time));
                    ros_atomic32_set(&cont->time, cont->mon_cfg.sub_tim_thres);
                }
            }
            break;

        case URR_STATUS_REPORTED:
            if (cont->mon_cfg.sub_tim_quota) {
                /* Stop to forward more packets */
                *tim_status = URR_STATUS_STOPED;
                ros_atomic32_set(&cont->time, 0);
            }
            break;

        case URR_STATUS_STOPED:
            /* No volume resource, drop this packet */
            break;
    }

    return;
}

int urr_get_status(uint32_t urr_index)
{
    struct urr_table *urr_entry;
    int new_status;

    urr_entry = urr_get_table(urr_index);

    if (urr_entry->container.vol_ul_status > urr_entry->container.vol_dl_status) {
        new_status = urr_entry->container.vol_ul_status;
    }
    else {
        new_status = urr_entry->container.vol_dl_status;
    }


    if (new_status < urr_entry->container.vol_tot_status) {
        new_status = urr_entry->container.vol_tot_status;
    }

    if (new_status < urr_entry->container.tim_status) {
        new_status = urr_entry->container.tim_status;
    }

    if (new_status < urr_entry->container.eve_status) {
        new_status = urr_entry->container.eve_status;
    }

    switch (new_status) {
        case URR_STATUS_REPORTED:
            return COMM_MSG_LIGHT_YELLOW;
        case URR_STATUS_STOPED:
            return COMM_MSG_LIGHT_RED;
        default:
            return COMM_MSG_LIGHT_GREEN;
    }
    return COMM_MSG_LIGHT_GREEN;
}

static inline uint32_t
urr_inact_detect(struct urr_table *urr_entry)
{
    return 0;
}

static void *urr_proc_timer_idt_pthr_cb(void *arg)
{
    struct urr_table *urr_entry = (struct urr_table *)arg;
    uint32_t new_gap, new_time_len;
    comm_msg_urr_config *conf = &urr_entry->urr;
    urr_container *cont = &urr_entry->container;

    if(NULL == urr_entry){
        LOG(SESSION, ERR, "urr_entry is NULL!");
    }

    LOG(SESSION, RUNNING,
        "urr(%d): IDT timer expired! cont->time %d, new_gap %d",
        urr_entry->index, ros_atomic32_read(&cont->time), ros_getime() - cont->last_pkt.cnt);

    /* 需要上报的场景:
    1. 达到门限
    2. 达到配额，并且没有配置门限*/
    if(likely(urr_entry->urr.inact_detect > 0)) {
        if (0 == ros_atomic32_read(&cont->last_pkt)) {
            new_time_len = conf->inact_detect;
        } else {
            new_gap = ros_getime() - cont->last_pkt.cnt;

            /* The remaining time in the pool is greater than the IDT time */
            if (ros_atomic32_read(&cont->time) <= conf->inact_detect) {
                if (new_gap >= ros_atomic32_read(&cont->time)) {
                    ros_rwlock_write_lock(&urr_entry->lock); /* lock */
                    urr_chk_time(urr_entry);
                    ros_rwlock_write_unlock(&urr_entry->lock); /* unlock */
                    new_time_len = conf->inact_detect;
                }
                else
                    new_time_len = ros_atomic32_read(&cont->time) - new_gap;
            } else {
                if (new_gap >= conf->inact_detect) {
                    ros_atomic32_sub(&cont->time, conf->inact_detect);
                    ros_atomic32_set(&cont->last_pkt, 0);
                    new_time_len = conf->inact_detect;
                }
                else
                    new_time_len = conf->inact_detect - new_gap;
            }
        }

        if (cont->tim_status != URR_STATUS_STOPED) {
            /* Reset timer, set the gap as timer length */
            ros_timer_reset(cont->idt_timer, new_time_len * ROS_TIMER_TICKS_PER_SEC,
                ROS_TIMER_MODE_ONCE, (uint64_t)urr_entry, urr_proc_timer_idt);
        }
    }else{
        ros_rwlock_write_lock(&urr_entry->lock); /* lock */
        urr_chk_time(urr_entry);
        ros_rwlock_write_unlock(&urr_entry->lock); /* unlock */

        if(cont->tim_status != URR_STATUS_STOPED) {
            if (cont->mon_cfg.sub_tim_quota >= cont->mon_cfg.sub_tim_thres) {
                new_time_len = cont->mon_cfg.sub_tim_thres_fixed;
            }
            else if (cont->mon_cfg.sub_tim_quota > cont->mon_cfg.sub_tim_thres_fixed) {
                new_time_len = cont->mon_cfg.sub_tim_quota - cont->mon_cfg.sub_tim_thres;
            }
            else {
                new_time_len = cont->mon_cfg.sub_tim_thres_fixed;
            }
            LOG(SESSION, RUNNING, "ros_timer_reset idt new_time_len: %d", new_time_len);
            ros_timer_reset(cont->idt_timer, new_time_len * ROS_TIMER_TICKS_PER_SEC,
                ROS_TIMER_MODE_ONCE, (uint64_t)urr_entry, urr_proc_timer_idt);
        }
    }

    if (URR_STATUS_STOPED == cont->tim_status)
    {
        urr_change_inst_light(urr_entry, COMM_MSG_LIGHT_RED);
        LOG(SESSION, RUNNING, "Stop forward");
    }

    return NULL;
}

static void urr_proc_timer_idt(void *timer, uint64_t para)
{
    urr_proc_timer_idt_pthr_cb((void *)para);
}

static void *urr_proc_timer_mon_pthr_cb(void *arg)
{
    struct urr_table *urr_entry = (struct urr_table *)arg;

    LOG(SESSION, RUNNING,
        "urr(%d): monitoring timer expired!", urr_entry->index);

    /* Send report before apply new threshold and quota */
    urr_send_report(urr_entry, URR_TRIGGER_MONIT);

    /* Select a monitor that is closest in time */
    urr_select_monitor(urr_entry);

    /* Init urr container by new parameter */
    urr_container_init(urr_entry->index);

    return NULL;
}

static inline void urr_proc_timer_mon(void *timer, uint64_t para)
{
    urr_proc_timer_mon_pthr_cb((void *)para);
}

static void *urr_proc_timer_qht_pthr_cb(void *arg)
{
    struct urr_table *urr_entry = (struct urr_table *)arg;
    uint32_t new_gap, new_time_len;

    LOG(SESSION, RUNNING,
        "urr(%d): quota holding timer expired!", urr_entry->index);

    new_gap = ros_getime() - ros_atomic32_read(&urr_entry->container.last_pkt);
    /* Handle Quota Holding Timer */
    if (new_gap >= urr_entry->urr.quota_hold) {

        urr_entry->container.tim_status = URR_STATUS_STOPED;
        /* No packet received from last timer start */
        urr_send_report(urr_entry, URR_TRIGGER_QUHTI);
    } else {
        /* Create a new timer, set the gap as timer length */
        new_time_len = urr_entry->urr.quota_hold - new_gap;
        urr_entry->container.qht_timer = ros_timer_create(ROS_TIMER_MODE_ONCE,
            new_time_len * ROS_TIMER_TICKS_PER_SEC, (uint64_t)urr_entry,
            urr_proc_timer_qht);

        /* Start it */
        ros_timer_start(urr_entry->container.qht_timer);
    }

    return NULL;
}

static inline void urr_proc_timer_qht(void *timer, uint64_t para)
{
    urr_proc_timer_qht_pthr_cb((void *)para);
}

static inline void urr_proc_timer_per(void *timer, uint64_t para)
{
    struct urr_table *urr_entry = (struct urr_table *)para;

    LOG(SESSION, RUNNING,
        "urr(%d): period timer expired!", urr_entry->index);

    /* No packet received from last timer start */
    urr_send_report(urr_entry, URR_TRIGGER_PERIO);
}

static inline void urr_proc_timer_stp(void *timer, uint64_t para)
{
    struct urr_table *urr_entry = (struct urr_table *)para;

    LOG(SESSION, RUNNING,
        "urr(%d): traffic stop detection timer expired!", urr_entry->index);

    /* the stop of traffic is detected*/
    urr_send_report(urr_entry, URR_TRIGGER_STOPT);

    ros_timer_del(urr_entry->container.stp_timer);
    urr_entry->container.stp_timer = NULL;
}

static inline int urr_change_inst_light(struct urr_table *entry, uint8_t light)
{
    struct pfcp_session *sess = NULL;
    struct pdr_table *pdr = NULL;
    uint32_t cnt, urr_id, urr_num;
    comm_msg_update_inst_light_t mdf_light_arr[MAX_PDR_NUM];
    uint32_t mdf_light_num = 0;

    /* Search for PDRs using this URR */
    urr_id = entry->urr.urr_id;

    if (unlikely(NULL == entry->sess)) {
        LOG(SESSION, ERR, "URR entry data error, entry->sess(%p).", entry->sess);
        return -1;
    }
    sess = &entry->sess->session;

    pdr = (struct pdr_table *)rbtree_first(&sess->pdr_root);
    while (pdr) {
        urr_num = pdr->pdr.urr_list_number;
        for (cnt = 0; cnt < urr_num; ++cnt) {
            if (urr_id == pdr->pdr.urr_id_array[cnt]) {
                mdf_light_arr[mdf_light_num].inst_index = pdr->index;
                mdf_light_arr[mdf_light_num].light = light;
                ++mdf_light_num;
            }
        }

        pdr = (struct pdr_table *)rbtree_next(&pdr->pdr_node);
    }

    if (0 > urr_update_light_to_fpu(mdf_light_arr, mdf_light_num)) {
        LOG(SESSION, ERR, "Update inst light to fpu failed.\n");
        return -1;
    }

    return 0;
}

static inline int urr_change_inst_thres(struct urr_table *entry)
{
    struct pfcp_session *sess = NULL;
    struct pdr_table *pdr = NULL;
    struct urr_table *urr_tbl = NULL;
    uint32_t cnt, cnt2, urr_id, urr_num;
    comm_msg_update_inst_thres_t mdf_thres_arr[MAX_PDR_NUM];
    uint32_t mdf_thres_num = 0;
    uint64_t min_thres = -1;

    /* Search for PDRs using this URR */
    urr_id = entry->urr.urr_id;

    if (unlikely(NULL == entry->sess)) {
        LOG(SESSION, ERR, "URR entry data error, entry->sess(%p).", entry->sess);
        return -1;
    }
    sess = &entry->sess->session;

    pdr = (struct pdr_table *)rbtree_first(&sess->pdr_root);
    while (pdr) {
        urr_num = pdr->pdr.urr_list_number;
        for (cnt = 0; cnt < urr_num; ++cnt) {
            if (urr_id == pdr->pdr.urr_id_array[cnt]) {

                for (cnt2 = 0; cnt2 < urr_num; ++cnt2)
                {
                    urr_tbl = urr_table_search(entry->sess, pdr->pdr.urr_id_array[cnt2]);
                    /* Take the minimum threshold of all URRS */
                    if (urr_tbl->urr.vol_thres.flag.d.dlvol) {
                        if (min_thres > urr_tbl->urr.vol_thres.downlink)
                            min_thres = urr_tbl->urr.vol_thres.downlink;
                    }
                    if (urr_tbl->urr.vol_thres.flag.d.ulvol) {
                        if (min_thres > urr_tbl->urr.vol_thres.uplink)
                            min_thres = urr_tbl->urr.vol_thres.uplink;
                    }
                    if (urr_tbl->urr.vol_thres.flag.d.tovol) {
                        if (min_thres > urr_tbl->urr.vol_thres.total)
                            min_thres = urr_tbl->urr.vol_thres.total;
                    }
                }

                mdf_thres_arr[mdf_thres_num].inst_index = pdr->index;
                mdf_thres_arr[mdf_thres_num].collect_thres = min_thres/2;
                ++mdf_thres_num;
            }
        }

        pdr = (struct pdr_table *)rbtree_next(&pdr->pdr_node);
    }

    if (0 > urr_update_thres_to_fpu(mdf_thres_arr, mdf_thres_num)) {
        LOG(SESSION, ERR, "Update inst light to fpu failed.\n");
        return -1;
    }

    return 0;
}

void urr_select_monitor(struct urr_table *urr_entry)
{
    comm_msg_urr_mon_time_t *add_mon;
    comm_msg_urr_config     *config;
    urr_container        *container;      /* resource container */
    uint32_t                nearest, loop, index;

    LOG(SESSION, RUNNING,
        "urr(%d): monitoring timer expired!", urr_entry->index);

    /* Get configuration */
    config    = &urr_entry->urr;
    container = &urr_entry->container;

    /* If too many monitor, reserve first 16 */
    if (config->add_mon_time_number >= MAX_ADDED_MONITOR_TIME_NUM) {
        config->add_mon_time_number = MAX_ADDED_MONITOR_TIME_NUM;
    }

    /* Choose next applied configuration */
    index   = MAX_ADDED_MONITOR_TIME_NUM;
    nearest = 0;
    for (loop = 0; loop < config->add_mon_time_number; loop++) {

        add_mon = &(config->add_mon_time[loop]);

        /* If Monitoring Time is not in future, don't care */
        /*if (((nearest)&&(add_mon->mon_time < nearest))
          &&(add_mon->mon_time > ros_getime()))
        {
            nearest = add_mon->mon_time;
            index   = loop;
        }*/
        if (add_mon->mon_time > ros_getime())
        {
            nearest = add_mon->mon_time;
            index   = loop;
        }
    }

    /* If direct configuration can work, use it */
    if (config->mon_time >= ros_getime()) {

        /* Copy sub configuration */
        container->mon_cfg.mon_time = config->mon_time;
        ros_memcpy(&container->mon_cfg.sub_vol_thres,
            &config->sub_vol_thres, sizeof(comm_msg_urr_volume_t));
        ros_memcpy(&container->mon_cfg.sub_vol_quota,
            &config->sub_vol_quota, sizeof(comm_msg_urr_volume_t));
        container->mon_cfg.sub_tim_thres = config->sub_tim_thres;
        container->mon_cfg.sub_tim_quota = config->sub_tim_quota;
        container->mon_cfg.sub_eve_thres = config->sub_eve_thres;
        container->mon_cfg.sub_eve_quota = config->sub_eve_quota;

        LOG(SESSION, RUNNING,
            "Apply configured sub monitoring time configuration!");
    }
    else if ((nearest)&&(config->mon_time <= nearest)) {
        if (index >= MAX_ADDED_MONITOR_TIME_NUM) {
            LOG(SESSION, ERR,
                "No avaliable next monitoring time configuration!");
            return;
        }
        add_mon = &(config->add_mon_time[index]);

        /* Copy additional configuration */
        container->mon_cfg.mon_time = add_mon->mon_time;
        ros_memcpy(&container->mon_cfg.sub_vol_thres,
            &add_mon->sub_vol_thres, sizeof(comm_msg_urr_volume_t));
        ros_memcpy(&container->mon_cfg.sub_vol_quota,
            &add_mon->sub_vol_quota, sizeof(comm_msg_urr_volume_t));
        container->mon_cfg.sub_tim_thres = add_mon->sub_tim_thres;
        container->mon_cfg.sub_tim_quota = add_mon->sub_tim_quota;
        container->mon_cfg.sub_eve_thres = add_mon->sub_eve_thres;
        container->mon_cfg.sub_eve_quota = add_mon->sub_eve_quota;

        LOG(SESSION, RUNNING,
            "Apply additional %d monitoring time configuration!", index);
    }

    return;
}

//act: 0 insert, 1 update
uint32_t urr_container_init(uint32_t urr_index)
{
    struct urr_table        *urr_entry;
    urr_container           *cont;
    comm_msg_urr_config     *conf;
    comm_msg_urr_method_t   *method;
    comm_msg_urr_mon_time_t *monitor;

    /* Get entry */
    urr_entry = urr_get_table(urr_index);
    if (!urr_entry) {
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    conf    = &urr_entry->urr;
    cont    = &urr_entry->container;
    monitor = &urr_entry->container.mon_cfg;
    method  = &urr_entry->urr.method;

    /* Init parameters */
    cont->vol_ul_status = 0;
    cont->vol_dl_status = 0;
    cont->vol_tot_status = 0;
    cont->tim_status    = 0;
    cont->eve_status    = 0;
    cont->flag.value    = 0;
    ros_atomic64_init(&cont->vol_total);
    ros_atomic64_init(&cont->vol_dlink);
    ros_atomic64_init(&cont->vol_ulink);
    ros_atomic64_init(&cont->vol_all_total);
    ros_atomic64_init(&cont->vol_all_dlink);
    ros_atomic64_init(&cont->vol_all_ulink);
    ros_atomic32_init(&cont->event);
    ros_atomic32_init(&cont->droppkts);
    ros_atomic32_init(&cont->dropbyte);
    ros_atomic32_init(&cont->time);
    ros_atomic32_init(&cont->first_pkt);
    ros_atomic32_init(&cont->last_pkt);
    ros_atomic32_init(&cont->start_hold);
    ros_atomic32_init(&cont->start_time);

    if (cont->idt_timer) {
        /* If idt_timer timer is running, stop it */
        ros_timer_del(cont->idt_timer);
        cont->idt_timer = NULL;
    }

    if (cont->stp_timer) {
        /* If stp_timer timer is running, stop it */
        ros_timer_del(cont->stp_timer);
        cont->stp_timer = NULL;
    }

    if (cont->mon_timer) {
        /* If mon_timer timer is running, stop it */
        ros_timer_del(cont->mon_timer);
        cont->mon_timer = NULL;
    }

    if (cont->qht_timer) {
        /* If qht_timer timer is running, stop it */
        ros_timer_del(cont->qht_timer);
        cont->qht_timer = NULL;
    }

    if (cont->per_timer) {
        /* If per_timer timer is running, stop it */
        ros_timer_del(cont->per_timer);
        cont->per_timer = NULL;
    }

    if (cont->eit_timer) {
        /* If eit_timer timer is running, stop it */
        ros_timer_del(cont->eit_timer);
        cont->eit_timer = NULL;
    }

    /* If Inactive Measurement Flag is true, stop measuring */
    if (conf->measu_info.d.inam) {

        LOG(SESSION, RUNNING,
            "Inactive Measurement Flag is true, don't measure!");

        return EN_COMM_ERRNO_OK;
    }

    if (method->d.volum) {
        /* Check total */
        if (monitor->sub_vol_thres.flag.d.tovol) {
            cont->flag.d.tovol = G_TRUE;
        }
        else if (monitor->sub_vol_quota.flag.d.tovol) {
            cont->flag.d.tovol = G_TRUE;
        }
        else {
            cont->flag.d.tovol = G_FALSE;
        }

        /* Check downlink */
        if (monitor->sub_vol_thres.flag.d.dlvol) {
            cont->flag.d.dlvol = G_TRUE;
        }
        else if (monitor->sub_vol_quota.flag.d.dlvol) {
            cont->flag.d.dlvol = G_TRUE;
        }
        else {
            cont->flag.d.dlvol = G_FALSE;
        }

        /* Check uplink */
        if (monitor->sub_vol_thres.flag.d.ulvol) {
            cont->flag.d.ulvol = G_TRUE;
        }
        else if (monitor->sub_vol_quota.flag.d.ulvol) {
            cont->flag.d.ulvol = G_TRUE;
        }
        else {
            cont->flag.d.ulvol = G_FALSE;
        }

        /* Set dropped pkts threshold */
        if (conf->drop_thres.flag.d.dlby) {
            ros_atomic32_set(&cont->dropbyte, conf->drop_thres.bytes);
        }
        if (conf->drop_thres.flag.d.dlpa) {
            ros_atomic32_set(&cont->droppkts, conf->drop_thres.packets);
        }

        cont->vol_ul_status  = URR_STATUS_NORMAL;
        cont->vol_dl_status  = URR_STATUS_NORMAL;
        cont->vol_tot_status = URR_STATUS_NORMAL;

        LOG(SESSION, RUNNING,
            "urr(%d): start volume charging!", urr_entry->index);
    }
    else {
        /* Set init status */
        cont->vol_ul_status  = URR_STATUS_INVALID;
        cont->vol_dl_status  = URR_STATUS_INVALID;
        cont->vol_tot_status = URR_STATUS_INVALID;
    }

    if (method->d.durat) {
        if (monitor->sub_tim_thres) {
            /* If threshold is not zero, set it to volume */
            ros_atomic32_set(&cont->time, monitor->sub_tim_thres);
        }
        else {
            /* If no threshold, directly use quota, don't care what it is */
            ros_atomic32_set(&cont->time, monitor->sub_tim_quota);
        }

        /* If Inactivity Detection Timer IE is set */
        if (conf->inact_detect) {
            /* Create IDT timer */
            cont->idt_timer = ros_timer_create(ROS_TIMER_MODE_ONCE,
                conf->inact_detect * ROS_TIMER_TICKS_PER_SEC, (uint64_t)urr_entry,
                urr_proc_timer_idt);
            LOG(SESSION, RUNNING, "Inactivity Detection Time is valid.");
        } else {
            /* 不带IDT时，达到门限或达到配额上报 */
            if(monitor->sub_tim_thres){
                cont->idt_timer = ros_timer_create(ROS_TIMER_MODE_ONCE,
                    monitor->sub_tim_thres * ROS_TIMER_TICKS_PER_SEC, (uint64_t)urr_entry,
                    urr_proc_timer_idt);
            }else{
                cont->idt_timer = ros_timer_create(ROS_TIMER_MODE_ONCE,
                    monitor->sub_tim_quota * ROS_TIMER_TICKS_PER_SEC, (uint64_t)urr_entry,
                    urr_proc_timer_idt);
            }
        }

        /* Set init status */
        cont->tim_status = URR_STATUS_NORMAL;

        LOG(SESSION, RUNNING,
            "urr(%d): start time charging!", urr_entry->index);
    }
    else {
        /* Set init status */
        cont->tim_status = URR_STATUS_INVALID;
    }

    if (method->d.event) {
        if (monitor->sub_eve_thres) {
            /* If threshold is not zero, set it to volume */
            ros_atomic32_set(&cont->event, monitor->sub_eve_thres);
        }
        else {
            /* If no threshold, directly use quota, don't care what it is */
            ros_atomic32_set(&cont->event, monitor->sub_eve_quota);
        }

        /* Set init status */
        cont->eve_status = URR_STATUS_NORMAL;

        LOG(SESSION, RUNNING,
            "urr(%d): start event charging!", urr_entry->index);
    }
    else {
        /* Set init status */
        cont->eve_status = URR_STATUS_INVALID;
    }

    if (monitor->mon_time > ros_getime()) {
        uint32_t time_diff;

        /* Monitoring Time is UTC time, so set timer length as time diff */
        time_diff = monitor->mon_time - ros_getime();
        cont->mon_timer = ros_timer_create(ROS_TIMER_MODE_ONCE,
            time_diff * ROS_TIMER_TICKS_PER_SEC, (uint64_t)urr_entry,
            urr_proc_timer_mon);
        ros_timer_start(cont->mon_timer);

        LOG(SESSION, RUNNING,
            "urr(%d): start monitoring timer(time len: %d)!",
            urr_entry->index, time_diff);
    }

    if (conf->trigger.d.macar && conf->eth_inact_time) {
        /*urr_mac_create_bucket(urr_entry);
        cont->eit_timer = ros_timer_create(ROS_TIMER_MODE_ONCE,
            conf->eth_inact_time * ROS_TIMER_TICKS_PER_SEC, (uint64_t)urr_entry,
            urr_mac_proc_timer);
        ros_timer_start(cont->eit_timer);*/

        LOG(SESSION, RUNNING,
            "urr(%d): start mac detecting timer(time len: %d)!",
            urr_entry->index, conf->eth_inact_time);
    }

    if (conf->trigger.d.perio && conf->period) {
        cont->per_timer = ros_timer_create(ROS_TIMER_MODE_PERIOD,
            conf->period * ROS_TIMER_TICKS_PER_SEC, (uint64_t)urr_entry,
            urr_proc_timer_per);
        ros_timer_start(cont->per_timer);

        LOG(SESSION, RUNNING,
            "urr(%d): start period report timer(time len: %d)!",
            urr_entry->index, conf->period);
    }
    else {
        /* Set to zero to indicate QHT stopped */
        cont->per_timer = NULL;
    }


    if (conf->trigger.d.stopt) {
        cont->stp_timer = ros_timer_create(ROS_TIMER_MODE_ONCE,
            URR_STOP_TIME * ROS_TIMER_TICKS_PER_SEC, (uint64_t)urr_entry,
            urr_proc_timer_stp);

        LOG(SESSION, RUNNING,
            "traffic stop detection timer is valid!");
    }
    else {
        /* Set to zero to indicate QHT stopped */
        cont->stp_timer = NULL;
    }

    /* If provisioned QHT, create timer but not start */
    if (conf->trigger.d.quhti && conf->quota_hold) {
        cont->qht_timer = ros_timer_create(ROS_TIMER_MODE_ONCE,
            conf->quota_hold * ROS_TIMER_TICKS_PER_SEC, (uint64_t)urr_entry,
            urr_proc_timer_qht);
        LOG(SESSION, RUNNING, "Quota Hold Time is valid.");
    }

    /* If Immediate Start Time Metering Flag is true, start timer now */
    /* Or start timer when receive first packet */
    if (urr_entry->urr.measu_info.d.istm) {
        LOG(SESSION, RUNNING,
            "Immediate Start Time Metering Flag is true, "
            "start measure timer now!");

        ros_atomic32_set(&cont->last_pkt, ros_getime());
        ros_atomic32_set(&cont->start_time, ros_getime());

        if (cont->idt_timer) {
            ros_timer_start(cont->idt_timer);
        }

        /* If provisioned quota holing timer, start it */
        if (cont->qht_timer) {
            ros_timer_start(cont->qht_timer);
            ros_atomic32_set(&cont->start_hold, ros_getime());
        }
    }

    urr_change_inst_light(urr_entry, COMM_MSG_LIGHT_GREEN);
    urr_change_inst_thres(urr_entry);

    return 0;
}

uint32_t urr_container_destroy(uint32_t urr_index)
{
    struct urr_table *urr_entry;
    urr_container *cont;

    /* Get entry */
    urr_entry = urr_get_table(urr_index);
    if (!urr_entry) {
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    cont = &urr_entry->container;

    if (cont->idt_timer) {
        /* If idt_timer timer is running, stop it */
        ros_timer_del(cont->idt_timer);
        cont->idt_timer = NULL;

        LOG(SESSION, RUNNING,
            "urr(%d): del idt timer.", urr_entry->index);
    }

    if (cont->mon_timer) {
        /* If mon_timer timer is running, stop it */
        ros_timer_del(cont->mon_timer);
        cont->mon_timer = NULL;

        LOG(SESSION, RUNNING,
            "urr(%d): del mon timer.", urr_entry->index);
    }

    if (cont->qht_timer) {
        /* If qht_timer timer is running, stop it */
        ros_timer_del(cont->qht_timer);
        cont->qht_timer = NULL;

        LOG(SESSION, RUNNING,
            "urr(%d): del qht timer.", urr_entry->index);
    }

    if (cont->eit_timer) {
        /* If eit_timer timer is running, stop it */
        ros_timer_del(cont->eit_timer);
        cont->eit_timer = NULL;

        LOG(SESSION, RUNNING,
            "urr(%d): del eit timer.", urr_entry->index);
    }

    if (cont->per_timer) {
        /* If per_timer timer is running, stop it */
        ros_timer_del(cont->per_timer);
        cont->per_timer = NULL;

        LOG(SESSION, RUNNING,
            "urr(%d): del per timer.", urr_entry->index);
    }

    if (urr_entry->urr.trigger.d.macar) {
        /* Destroy mac bucket */
        /*urr_mac_destroy_bucket(urr_entry);*/

        LOG(SESSION, RUNNING,
            "urr(%d): destroy mac bucket!", urr_entry->index);
    }

    /* Init parameters */
    ros_memset(cont, 0, sizeof(urr_container));

    LOG(SESSION, RUNNING,
        "urr(%d): urr destroyed!", urr_entry->index);

    return 0;
}

uint32_t urr_proc_recv(uint32_t urr_index, int64_t pkt_len, uint8_t dlflag)
{
    struct urr_table *urr_entry;
    comm_msg_urr_method_t *method;

    LOG(SESSION, RUNNING, "start to handle urr(%d), packet len %ld, %s.",
        urr_index, pkt_len, (dlflag==0) ? "uplink" : "downlink");

    /* Get entry */
    urr_entry = urr_get_table(urr_index);
    if (!urr_entry) {
        LOG(SESSION, RUNNING,
            "Invalid urr index(%d)!", urr_index);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }
    method = &urr_entry->urr.method;

    /* An action performed only when there is traffic */
    if (pkt_len) {
        if (unlikely(0 == ros_atomic32_read(&urr_entry->container.first_pkt))) {
            if(urr_entry->urr.trigger.d.start) {
                urr_send_report(urr_entry, URR_TRIGGER_START);
            }
            /* First packet time */
            ros_atomic32_set(&urr_entry->container.first_pkt, ros_getime());
        }

        /* Record packet time */
        ros_atomic32_set(&urr_entry->container.last_pkt, ros_getime());

        /* If Inactive Measurement Flag is true, stop measuring */
        if (urr_entry->urr.measu_info.d.inam) {
            LOG(SESSION, RUNNING, "Inactive Measurement Flag is true, don't measure!");
            return EN_COMM_ERRNO_OK;
        }

        /* If it is first packet in this cycle, record time */
        if (unlikely(0 == ros_atomic32_read(&urr_entry->container.start_time))) {

            /* If not NULL, start it */
            if (urr_entry->container.idt_timer) {
                /* Start timer */
                ros_timer_start(urr_entry->container.idt_timer);
            }

            if (urr_entry->container.qht_timer) {
                /* Start timer */
                ros_timer_start(urr_entry->container.qht_timer);
            }

            /* Record current time */
            ros_atomic32_set(&urr_entry->container.start_time, ros_getime());
            ros_atomic32_set(&urr_entry->container.start_hold, ros_getime());
        }

        if (urr_entry->container.stp_timer) {
            /* Start timer */
            ros_timer_start(urr_entry->container.stp_timer);
        }

        /* Handle volume */
        if (method->d.volum) {
            urr_chk_volume(urr_entry, pkt_len, dlflag);
        }
    }

    /* Handle time, Even if there is no flow, it needs to be detected regularly */
    if (method->d.durat) {
        ros_rwlock_write_lock(&urr_entry->lock); /* lock */
        urr_chk_time(urr_entry); /* The external lock may be removed */
        ros_rwlock_write_unlock(&urr_entry->lock); /* unlock */
    }

    return 0;
}

uint32_t urr_proc_drop(uint32_t urr_index, int64_t pkt_len, int64_t pkt_num)
{
    struct urr_table            *urr_entry;
    comm_msg_urr_method_t   *method;

    /* Get entry */
    urr_entry = urr_get_table(urr_index);
    if (!urr_entry) {
        LOG(SESSION, RUNNING,"urr_entry is NULL ");
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    method = &urr_entry->urr.method;

    /* Handle volume */
    if (method->d.volum) {
        urr_chk_droppkts(urr_entry, pkt_len, pkt_num);
    }

    return 0;
}

int urr_change_quota_far(uint32_t urr_index)
{
    struct urr_table *entry = NULL;
    struct pfcp_session *sess = NULL;
    struct pdr_table *pdr = NULL;
    uint32_t cnt, urr_id;

    /* Search for PDRs using this URR */
    entry = urr_get_table(urr_index);
    if (NULL == entry) {
        LOG(SESSION, ERR, "Get URR entry failed, index: %u.", urr_index);
        return -1;
    }
    urr_id = entry->urr.urr_id;

    if (NULL == entry->sess) {
        LOG(SESSION, ERR, "URR entry data error, entry->sess(%p).", entry->sess);
        return -1;
    }
    sess = &entry->sess->session;

    pdr = (struct pdr_table *)rbtree_first(&sess->pdr_root);
    while (pdr) {
        for (cnt = 0; cnt < pdr->pdr.urr_list_number; ++cnt) {
            if (urr_id == pdr->pdr.urr_id_array[cnt]) {
                if (0 > session_instance_modify_far(pdr->index, entry->urr.quota_far, 1)) {
                    LOG(SESSION, ERR, "Failed to change the FAR index of instance entry, instance index: %u.",
                        pdr->index);
                }

                break;
            }
        }

        pdr = (struct pdr_table *)rbtree_next(&pdr->pdr_node);
    }

    return 0;
}

static int urr_update_light_to_fpu(comm_msg_update_inst_light_t *light_arr, uint32_t index_num)
{
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len = 0;
    comm_msg_header_t           *msg;
    comm_msg_rules_ie_t         *ie = NULL;
    uint32_t                    cnt = 0, data_cnt = 0;
    comm_msg_update_inst_light_t *ie_data = NULL;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_update_inst_light_t);

    if (0 == index_num) {
        return 0;
    }

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd     = htons(EN_COMM_MSG_UPU_INST_LIGHT);
    ie_data     = (comm_msg_update_inst_light_t *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        ie_data[data_cnt].inst_index = htonl(light_arr[data_cnt].inst_index);
        ie_data[data_cnt].light = light_arr[data_cnt].light;
        ++data_cnt;

        if (data_cnt >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_update_inst_light_t) * data_cnt;
            ie->rules_num = htonl(data_cnt);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > session_msg_send_to_fp((char *)buf, buf_len, MB_SEND2BE_BROADCAST_FD)) {
                LOG(UPC, ERR, "Send buffer to backend failed.");
                return -1;
            }
            data_cnt = 0;
        }
    }

    if (data_cnt > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_update_inst_light_t) * data_cnt;
        ie->rules_num = htonl(data_cnt);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > session_msg_send_to_fp((char *)buf, buf_len, MB_SEND2BE_BROADCAST_FD)) {
            LOG(UPC, ERR, "Send buffer to backend failed.");
            return -1;
        }
        data_cnt = 0;
    }

    return 0;
}

static int urr_update_thres_to_fpu(comm_msg_update_inst_thres_t *thres_arr, uint32_t index_num)
{
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len = 0;
    comm_msg_header_t           *msg;
    comm_msg_rules_ie_t         *ie = NULL;
    uint32_t                    cnt = 0, data_cnt = 0;
    comm_msg_update_inst_thres_t *ie_data = NULL;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_update_inst_thres_t);

    if (0 == index_num) {
        return 0;
    }

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd = htons(EN_COMM_MSG_UPU_INST_THRES);
    ie_data = (comm_msg_update_inst_thres_t *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        ie_data[data_cnt].inst_index = htonl(thres_arr[data_cnt].inst_index);
        ie_data[data_cnt].collect_thres = htonll(thres_arr[data_cnt].collect_thres);
        ++data_cnt;

        if (data_cnt >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_update_inst_thres_t) * data_cnt;
            ie->rules_num = htonl(data_cnt);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > session_msg_send_to_fp((char *)buf, buf_len, MB_SEND2BE_BROADCAST_FD)) {
                LOG(UPC, ERR, "Send buffer to backend failed.");
                return -1;
            }
            data_cnt = 0;
        }
    }

    if (data_cnt > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_update_inst_thres_t) * data_cnt;
        ie->rules_num = htonl(data_cnt);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > session_msg_send_to_fp((char *)buf, buf_len, MB_SEND2BE_BROADCAST_FD)) {
            LOG(UPC, ERR, "Send buffer to backend failed.");
            return -1;
        }
        data_cnt = 0;
    }

    return 0;
}

int urr_count_proc(uint32_t stat_num, comm_msg_urr_stat_conf_t *stat_arr)
{
    uint8_t index, pdr_si;
    struct session_inst_entry *entry = NULL;
    struct session_t *sess_tbl = NULL;
    struct pdr_table *pdr_tbl = NULL;
    uint32_t new_status, max_status = COMM_MSG_LIGHT_GREEN;
    uint32_t cnt, light_cnt = 0;
    comm_msg_update_inst_light_t mdf_light[stat_num];

    LOG(SESSION, RUNNING, "Process URR status, stat_num: %u.", stat_num);
    for (cnt = 0; cnt < stat_num; ++cnt) {
        stat_arr[cnt].inst_index = ntohl(stat_arr[cnt].inst_index);
        stat_arr[cnt].urr_stat.forw_pkts    = ntohll(stat_arr[cnt].urr_stat.forw_pkts);
        stat_arr[cnt].urr_stat.forw_bytes   = ntohll(stat_arr[cnt].urr_stat.forw_bytes);
        stat_arr[cnt].urr_stat.drop_pkts    = ntohll(stat_arr[cnt].urr_stat.drop_pkts);
        stat_arr[cnt].urr_stat.drop_bytes   = ntohll(stat_arr[cnt].urr_stat.drop_bytes);
        stat_arr[cnt].urr_stat.err_cnt      = ntohll(stat_arr[cnt].urr_stat.err_cnt);

        if (COMM_MSG_ORPHAN_NUMBER == stat_arr[cnt].inst_index) {
            continue;
        }
        entry = session_instance_get_entry(stat_arr[cnt].inst_index);
        if (NULL == entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", stat_arr[cnt].inst_index);
            continue;
        }

        if (G_FALSE == entry->valid) {
            LOG(SESSION, ERR, "Entry is invalid, index: %u, maybe deleted.", stat_arr[cnt].inst_index);
            continue;
        }

        pdr_tbl = pdr_get_table_public(stat_arr[cnt].inst_index);
        if (NULL == pdr_tbl) {
            LOG(SESSION, ERR, "PDR index error, index: %u.", stat_arr[cnt].inst_index);
            continue;
        }
        pdr_si = pdr_tbl->pdr.pdi_content.si;

        sess_tbl = pdr_tbl->session_link;
        if (unlikely(NULL == sess_tbl)) {
            LOG(SESSION, ERR, "pdr linked session is NULL, pdr id: %d.\n",
                pdr_tbl->pdr.pdr_id);
            continue;
        }
        if (sess_tbl->inactivity_timer_id){
            /* If not NULL, restart it */
            ros_timer_start(sess_tbl->inactivity_timer_id);
        }

        LOG(SESSION, RUNNING, "PDR %u, Forward bytes: %ld, forward packets: %ld, dorp bytes: %ld, dorp packets: %ld",
            pdr_tbl->pdr.pdr_id,
            stat_arr[cnt].urr_stat.forw_bytes,
            stat_arr[cnt].urr_stat.forw_pkts,
            stat_arr[cnt].urr_stat.drop_bytes,
            stat_arr[cnt].urr_stat.drop_pkts);

        for (index = 0; index < entry->control.urr_bnum; ++index) {
            urr_proc_recv(entry->control.urr_bqos[index],
                stat_arr[cnt].urr_stat.forw_bytes - entry->stat.forw_bytes,
                (pdr_si != EN_COMM_SRC_IF_ACCESS));

            /* Update instance status */
            new_status = urr_get_status(entry->control.urr_bqos[index]);
            if (new_status > max_status) {
                max_status = new_status;
            }
        }

        /* Apply the rules after qos enforcement */
        for (index = 0; index < entry->control.urr_anum; ++index) {
            urr_proc_recv(entry->control.urr_aqos[index], stat_arr[cnt].urr_stat.forw_bytes - entry->stat.forw_bytes,
                (pdr_si != EN_COMM_SRC_IF_ACCESS));

            /* Update instance status */
            new_status = urr_get_status(entry->control.urr_aqos[index]);
            if (new_status > max_status) {
                max_status = new_status;
            }
        }
        entry->control.light = max_status;

        /* Apply urr drop rules */
        for (index = 0; index < entry->control.urr_dnum; ++index) {
            urr_proc_drop(entry->control.urr_drop[index], stat_arr[cnt].urr_stat.drop_bytes - entry->stat.drop_bytes,
                stat_arr[cnt].urr_stat.drop_pkts - entry->stat.drop_pkts);
        }

        /* Update local statistics */
        ros_memcpy(&entry->stat, &stat_arr[cnt].urr_stat, sizeof(comm_msg_urr_stat_t));

        mdf_light[light_cnt].inst_index = stat_arr[cnt].inst_index;
        mdf_light[light_cnt].light = entry->control.light;
        ++light_cnt;

        LOG(SESSION, RUNNING, "URR light is %d.\r\n", entry->control.light);
    }

    if (0 > urr_update_light_to_fpu(mdf_light, light_cnt)) {
        LOG(SESSION, ERR, "Update inst light to fpu failed.\n");
        return -1;
    }

    return 0;
}

