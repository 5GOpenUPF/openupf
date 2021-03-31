/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "pdr_mgmt.h"
#include "far_mgmt.h"
#include "qer_mgmt.h"
#include "urr_mgmt.h"
#include "bar_mgmt.h"
#include "mar_mgmt.h"
#include "traffic_endpoint_mgmt.h"
#include "session_check.h"

#include "local_parse.h"


static int session_pdr_cmp(session_pdr_create *exp, struct pdr_table *act)
{
    int ret = 0;

    if (exp->pdr_id != act->pdr.pdr_id) {
        ++ret;
        LOG(SESSION, ERR, "pdr_id compare failed.");
    }

    if (exp->precedence != act->pdr.precedence) {
        ++ret;
        LOG(SESSION, ERR, "precedence compare failed.");
    }

    if (exp->pdi_content.si != act->pdr.pdi_content.si) {
        ++ret;
        LOG(SESSION, ERR, "si compare failed.");
    }

    if (exp->pdi_content.member_flag.d.local_fteid_present) {
        if (memcmp(&exp->pdi_content.local_fteid,
            &act->pdr.pdi_content.local_fteid[0].local_fteid, sizeof(session_f_teid))) {
            ++ret;
            LOG(SESSION, ERR, "local_fteid compare failed.");
        }
    }

    if (exp->pdi_content.member_flag.d.network_instance_present) {
        if (strcmp(exp->pdi_content.network_instance,
            act->pdr.pdi_content.network_instance)) {
            ++ret;
            LOG(SESSION, ERR, "network_instance compare failed.");
        }
    }

    if (exp->pdi_content.ue_ipaddr_num) {
        uint8_t cnt;

        for (cnt = 0; cnt < exp->pdi_content.ue_ipaddr_num; ++cnt) {
            if (memcmp(&exp->pdi_content.ue_ipaddr[cnt],
                &act->pdr.pdi_content.ue_ipaddr[cnt].ueip, sizeof(session_ue_ip))) {
                ++ret;
                LOG(SESSION, ERR, "ue_ipaddr compare failed.");
            }
        }
    }

    if (exp->pdi_content.traffic_endpoint_num) {
        if (memcmp(exp->pdi_content.traffic_endpoint_id,
            act->pdr.pdi_content.traffic_endpoint_id, exp->pdi_content.traffic_endpoint_num)) {
            ++ret;
            LOG(SESSION, ERR, "traffic_endpoint_id compare failed.");
        }
    }

    /* lost SDF filter compare */

    if (exp->pdi_content.member_flag.d.application_id_present) {
        if (strcmp(exp->pdi_content.application_id,
            act->pdr.pdi_content.application_id)) {
            ++ret;
            LOG(SESSION, ERR, "application_id compare failed.");
        }
    }

    if (exp->pdi_content.member_flag.d.eth_pdu_ses_info_present) {
        if (memcmp(&exp->pdi_content.eth_pdu_ses_info,
            &act->pdr.pdi_content.eth_pdu_ses_info,
            sizeof(session_eth_pdu_sess_info))) {
            ++ret;
            LOG(SESSION, ERR, "eth_pdu_ses_info compare failed.");
        }
    }

    /* lost ETH filter compare */

    if (exp->pdi_content.qfi_number !=
        act->pdr.pdi_content.qfi_number) {
        ++ret;
        LOG(SESSION, ERR, "qfi_number compare failed.");
    }
    if (exp->pdi_content.qfi_number) {
        if (memcmp(&exp->pdi_content.qfi_array,
            &act->pdr.pdi_content.qfi_array,
            sizeof(exp->pdi_content.qfi_array) * exp->pdi_content.qfi_number)) {
            ++ret;
            LOG(SESSION, ERR, "qfi_array compare failed.");
        }
    }

    if (exp->pdi_content.framed_route_num !=
        act->pdr.pdi_content.framed_ipv4_route_num) {
        ++ret;
        LOG(SESSION, ERR, "framed_route_num compare failed.");
    }
    if (exp->pdi_content.framed_route_num) {
        uint8_t cnt_l2 = 0;
        for (; cnt_l2 < exp->pdi_content.framed_route_num; ++cnt_l2) {
            if (memcmp(&exp->pdi_content.framed_route[cnt_l2],
                &act->pdr.pdi_content.framed_ipv4_route[cnt_l2].route,
                sizeof(session_framed_route))) {
                ++ret;
                LOG(SESSION, ERR, "framed_route compare failed.");
            }
        }
    }

    if (exp->pdi_content.member_flag.d.framed_routing_present) {
        if (exp->pdi_content.framed_routing !=
            act->pdr.pdi_content.framed_routing) {
            ++ret;
            LOG(SESSION, ERR, "framed_routing compare failed.");
        }
    }

    if (exp->pdi_content.framed_ipv6_route_num !=
        act->pdr.pdi_content.framed_ipv6_route_num) {
        ++ret;
        LOG(SESSION, ERR, "framed_ipv6_route_num compare failed.");
    }
    if (exp->pdi_content.framed_ipv6_route_num) {
        uint8_t cnt_l2 = 0;
        for (; cnt_l2 < exp->pdi_content.framed_ipv6_route_num; ++cnt_l2) {
            if (memcmp(&exp->pdi_content.framed_ipv6_route[cnt_l2],
                &act->pdr.pdi_content.framed_ipv6_route[cnt_l2].route,
                sizeof(session_framed_route_ipv6))) {
                ++ret;
                LOG(SESSION, ERR, "framed_ipv6_route compare failed.");
            }
        }
    }

    if (exp->pdi_content.member_flag.d.src_if_type_present) {
        if (exp->pdi_content.src_if_type.value !=
            act->pdr.pdi_content.src_if_type.value) {
            ++ret;
            LOG(SESSION, ERR, "src_if_type compare failed.");
        }
    }

    if (exp->member_flag.d.OHR_present) {
        if (exp->outer_header_removal.type !=
            act->pdr.outer_header_removal.type) {
            ++ret;
            LOG(SESSION, ERR, "type compare failed.");
        }

        if (exp->outer_header_removal.gtp_u_exten !=
            act->pdr.outer_header_removal.flag) {
            ++ret;
            LOG(SESSION, ERR, "gtp_u_exten compare failed.");
        }
    }

    if (exp->member_flag.d.far_id_present) {
        if (exp->far_id != act->pdr.far_id || !act->pdr.far_present) {
            ++ret;
            LOG(SESSION, ERR, "far_id compare failed.");
        }
    }

    if (exp->urr_id_number != act->pdr.urr_list_number) {
        ++ret;
        LOG(SESSION, ERR, "urr_id_number compare failed.");
    }
    if (exp->urr_id_number) {
        if (memcmp(exp->urr_id_array, act->pdr.urr_id_array,
            sizeof(exp->urr_id_array[0]) * exp->urr_id_number)) {
            ++ret;
            LOG(SESSION, ERR, "urr_id_array compare failed.");
        }
    }

    if (exp->qer_id_number != act->pdr.qer_list_number) {
        ++ret;
        LOG(SESSION, ERR, "qer_id_number compare failed.");
    }
    if (exp->qer_id_number) {
        if (memcmp(exp->qer_id_array, act->pdr.qer_id_array,
            sizeof(exp->qer_id_array[0]) * exp->qer_id_number)) {
            ++ret;
            LOG(SESSION, ERR, "qer_id_array compare failed.");
        }
    }

    if (exp->act_pre_number != act->pdr.act_pre_number) {
        ++ret;
        LOG(SESSION, ERR, "act_pre_number compare failed.");
    }
    if (exp->act_pre_number) {
        if (memcmp(exp->act_pre_arr, act->pdr.act_pre_arr,
            sizeof(exp->act_pre_arr[0]) * exp->act_pre_number)) {
            ++ret;
            LOG(SESSION, ERR, "act_pre_arr compare failed.");
        }
    }

    if (exp->member_flag.d.act_time_present) {
        if (exp->activation_time != act->pdr.activation_time) {
            ++ret;
            LOG(SESSION, ERR, "activation_time compare failed.");
        }
    }

    if (exp->member_flag.d.deact_time_present) {
        if (exp->deactivation_time != act->pdr.deactivation_time) {
            ++ret;
            LOG(SESSION, ERR, "deactivation_time compare failed.");
        }
    }

    if (exp->member_flag.d.mar_id_present) {
        if (exp->mar_id != act->pdr.mar_id || !act->pdr.mar_present) {
            ++ret;
            LOG(SESSION, ERR, "mar_id compare failed.");
        }
    }

    return ret;
}

static int session_far_cmp(session_far_create *exp, struct far_table *act)
{
    int ret = 0;

    if (exp->far_id != act->far_cfg.far_id) {
        ++ret;
        LOG(SESSION, ERR, "far_id compare failed.");
    }

    if (exp->action.value != act->far_cfg.action.value) {
        ++ret;
        LOG(SESSION, ERR, "action compare failed.");
    }

    if (exp->member_flag.d.forw_param_present !=
        act->far_cfg.choose.d.section_forwarding) {
        ++ret;
        LOG(SESSION, ERR, "forw_param_present compare failed.");
    }
    if (exp->member_flag.d.forw_param_present) {
        if (exp->forw_param.dest_if != act->far_cfg.forw_if) {
            ++ret;
            LOG(SESSION, ERR, "dest_if compare failed.");
        }

        if (exp->forw_param.member_flag.d.network_instance_present) {
            if (strcmp(exp->forw_param.network_instance,
                act->far_priv.network_instance)) {
                ++ret;
                LOG(SESSION, ERR, "network_instance compare failed.");
            }
        }

        if ((exp->forw_param.member_flag.d.redirect_present ? 1 : 0) ^
            (act->far_cfg.choose.d.flag_redirect ? 1: 0)) {
            ++ret;
            LOG(SESSION, ERR, "redirect_present compare failed.");
        }

        if (exp->forw_param.member_flag.d.redirect_present) {
            if ((exp->forw_param.redirect_addr.addr_type + 1) != act->far_cfg.choose.d.flag_redirect) {
                ++ret;
                LOG(SESSION, ERR, "redirect_addr type compare failed.");
            }

            if (memcmp(&exp->forw_param.redirect_addr.address,
                &act->far_cfg.forw_redirect, sizeof(session_redirect_server))) {
                ++ret;
                LOG(SESSION, ERR, "redirect_addr compare failed.");
            }
        }

        if (exp->forw_param.member_flag.d.ohc_present !=
            act->far_cfg.choose.d.flag_out_header1) {
            ++ret;
            LOG(SESSION, ERR, "ohc_present compare failed.");
        }
        if (exp->forw_param.member_flag.d.ohc_present) {
            if (exp->forw_param.outer_header_creation.type.value !=
                act->far_cfg.forw_cr_outh.type.value) {
                ++ret;
                LOG(SESSION, ERR, "type compare failed.");
            }

            if (exp->forw_param.outer_header_creation.type.value & 0x300) {
                if (exp->forw_param.outer_header_creation.teid !=
                    act->far_cfg.forw_cr_outh.teid) {
                    ++ret;
                    LOG(SESSION, ERR, "teid compare failed.");
                }
            }

            if (exp->forw_param.outer_header_creation.type.value & 0x1500) {
                if (exp->forw_param.outer_header_creation.ipv4 !=
                    act->far_cfg.forw_cr_outh.ipv4) {
                    ++ret;
                    LOG(SESSION, ERR, "ipv4 compare failed.");
                }
            }

            if (exp->forw_param.outer_header_creation.type.value & 0x2A00) {
                if (memcmp(exp->forw_param.outer_header_creation.ipv6,
                    &act->far_cfg.forw_cr_outh.ipv6, IPV6_ALEN)) {
                    ++ret;
                    LOG(SESSION, ERR, "ipv6 compare failed.");
                }
            }

            if (exp->forw_param.outer_header_creation.type.value & 0x0C00) {
                if (exp->forw_param.outer_header_creation.port !=
                    act->far_cfg.forw_cr_outh.port) {
                    ++ret;
                    LOG(SESSION, ERR, "port compare failed.");
                }
            }

            if (exp->forw_param.outer_header_creation.type.d.ctag) {
                if (exp->forw_param.outer_header_creation.ctag.flags.value !=
                    act->far_cfg.forw_cr_outh.ctag.vlan_flag.value) {
                    ++ret;
                    LOG(SESSION, ERR, "ctag flags compare failed.");
                }
                if (exp->forw_param.outer_header_creation.ctag.value.value !=
                    act->far_cfg.forw_cr_outh.ctag.vlan_value.data) {
                    ++ret;
                    LOG(SESSION, ERR, "ctag value compare failed.");
                }
            }

            if (exp->forw_param.outer_header_creation.type.d.stag) {
                if (exp->forw_param.outer_header_creation.stag.flags.value !=
                    act->far_cfg.forw_cr_outh.stag.vlan_flag.value) {
                    ++ret;
                    LOG(SESSION, ERR, "stag falgs compare failed.");
                }
                if (exp->forw_param.outer_header_creation.stag.value.value !=
                    act->far_cfg.forw_cr_outh.stag.vlan_value.data) {
                    ++ret;
                    LOG(SESSION, ERR, "stag value compare failed.");
                }
            }
        }

        if (exp->forw_param.member_flag.d.trans_present !=
            act->far_cfg.choose.d.flag_transport_level1) {
            ++ret;
            LOG(SESSION, ERR, "trans_present compare failed.");
        }
        if (exp->forw_param.member_flag.d.trans_present) {
            if (exp->forw_param.trans.d.tos != act->far_cfg.forw_trans.tos) {
                ++ret;
                LOG(SESSION, ERR, "tos compare failed.");
            }

            if (exp->forw_param.trans.d.tos_mask !=
                act->far_cfg.forw_trans.mask) {
                ++ret;
                LOG(SESSION, ERR, "tos_mask compare failed.");
            }
        }

        if (exp->forw_param.member_flag.d.forwarding_policy_present !=
            act->far_cfg.choose.d.flag_forward_policy1) {
            ++ret;
            LOG(SESSION, ERR, "forwarding_policy_present compare failed.");
        }
        if (exp->forw_param.member_flag.d.forwarding_policy_present) {
            if (strcmp(exp->forw_param.forwarding_policy,
                act->far_priv.forwarding_policy)) {
                ++ret;
                LOG(SESSION, ERR, "forwarding_policy compare failed.");
            }
        }

        if (exp->forw_param.member_flag.d.header_enrichment_present !=
            act->far_cfg.choose.d.flag_header_enrich) {
            ++ret;
            LOG(SESSION, ERR, "header_enrichment_present compare failed.");
        }
        if (exp->forw_param.member_flag.d.header_enrichment_present) {
            if (exp->forw_param.header_enrichment.name_length !=
                act->far_cfg.forw_enrich.name_length) {
                ++ret;
                LOG(SESSION, ERR, "name_length compare failed.");
            }
            if (strcmp(exp->forw_param.header_enrichment.name,
                act->far_cfg.forw_enrich.name)) {
                ++ret;
                LOG(SESSION, ERR, "name compare failed.");
            }
            if (exp->forw_param.header_enrichment.value_length !=
                act->far_cfg.forw_enrich.value_length) {
                ++ret;
                LOG(SESSION, ERR, "value_length compare failed.");
            }
            if (strcmp(exp->forw_param.header_enrichment.value,
                act->far_cfg.forw_enrich.value)) {
                ++ret;
                LOG(SESSION, ERR, "value compare failed.");
            }
        }

        if (exp->forw_param.member_flag.d.traffic_endpoint_id_present !=
            act->far_priv.traffic_endpoint_id_present) {
            ++ret;
            LOG(SESSION, ERR, "traffic_endpoint_id_present compare failed.");
        }
        if (exp->forw_param.member_flag.d.traffic_endpoint_id_present) {
            if (exp->forw_param.traffic_endpoint_id !=
                act->far_priv.traffic_endpoint_id) {
                ++ret;
                LOG(SESSION, ERR, "traffic_endpoint_id compare failed.");
            }
        }

        if (exp->forw_param.member_flag.d.proxying_present) {
            if (exp->forw_param.proxying.value !=
                act->far_priv.proxying.value) {
                ++ret;
                LOG(SESSION, ERR, "proxying compare failed.");
            }
        }

        if (exp->forw_param.member_flag.d.dest_if_type_present) {
            if (exp->forw_param.dest_if_type.value !=
                act->far_priv.dest_if_type.value) {
                ++ret;
                LOG(SESSION, ERR, "dest_if_type compare failed.");
            }
        }
    }

    if (exp->member_flag.d.bar_id_present != act->far_priv.bar_id_present ||
        act->far_priv.bar_id_present != act->far_cfg.choose.d.section_bar) {
        ++ret;
        LOG(SESSION, ERR, "bar_id_present compare failed.");
    }
    if (exp->member_flag.d.bar_id_present) {
        if (exp->bar_id != act->far_priv.bar_id) {
            ++ret;
            LOG(SESSION, ERR, "bar_id compare failed.");
        }
    }

    return ret;
}

static int session_qer_cmp(session_qos_enforcement_rule *exp, struct qer_table *act)
{
    int ret = 0;

    if (exp->qer_id != act->qer_priv.qer_id) {
        ++ret;
        LOG(SESSION, ERR, "qer_id compare failed.");
    }

    if (exp->member_flag.d.qer_corr_id_present) {
        if (exp->qer_corr_id != act->qer_priv.qer_corr_id) {
            ++ret;
            LOG(SESSION, ERR, "qer_corr_id compare failed.");
        }
    }

    if (exp->gate_status.d.dl_gate != act->qer.dl_gate) {
        ++ret;
        LOG(SESSION, ERR, "dl_gate compare failed.");
    }

    if (exp->gate_status.d.ul_gate != act->qer.ul_gate) {
        ++ret;
        LOG(SESSION, ERR, "ul_gate compare failed.");
    }

    if (exp->member_flag.d.mbr_value_present) {
        if (memcmp(&exp->mbr_value, &act->qer_priv.mbr_value,
            sizeof(session_mbr))) {
            ++ret;
            LOG(SESSION, ERR, "mbr_value compare failed.");
        }

        if (exp->mbr_value.ul_mbr != act->qer.ul_mbr) {
            ++ret;
            LOG(SESSION, ERR, "ul_mbr compare failed.");
        }
        if (exp->mbr_value.dl_mbr != act->qer.dl_mbr) {
            ++ret;
            LOG(SESSION, ERR, "dl_mbr compare failed.");
        }
    }

    if (exp->member_flag.d.gbr_value_present) {
        if (memcmp(&exp->gbr_value, &act->qer_priv.gbr_value,
            sizeof(session_gbr))) {
            ++ret;
            LOG(SESSION, ERR, "gbr_value compare failed.");
        }

        if (exp->gbr_value.ul_gbr != act->qer.ul_gbr) {
            ++ret;
            LOG(SESSION, ERR, "ul_gbr compare failed.");
        }
        if (exp->gbr_value.dl_gbr != act->qer.dl_gbr) {
            ++ret;
            LOG(SESSION, ERR, "dl_gbr compare failed.");
        }
    }

    if (exp->member_flag.d.qfi_present) {
        if (exp->qfi != act->qer_priv.qfi) {
            ++ret;
            LOG(SESSION, ERR, "qfi compare failed.");
        }
    }

    if (exp->member_flag.d.ref_qos_present) {
        if (exp->ref_qos != act->qer_priv.ref_qos) {
            ++ret;
            LOG(SESSION, ERR, "ref_qos compare failed.");
        }
    }

    if (exp->member_flag.d.ppi_present) {
        if (exp->paging_policy_indic != act->qer_priv.paging_policy_indic) {
            ++ret;
            LOG(SESSION, ERR, "paging_policy_indic compare failed.");
        }
    }

    if (exp->member_flag.d.averaging_window_present) {
        if (exp->averaging_window != act->qer_priv.averaging_window) {
            ++ret;
            LOG(SESSION, ERR, "averaging_window compare failed.");
        }
    }

    return ret;
}

static int session_urr_cmp(session_usage_report_rule *exp, struct urr_table *act)
{
    int ret = 0;

    if (exp->urr_id != act->urr.urr_id) {
        ++ret;
        LOG(SESSION, ERR, "urr_id compare failed.");
    }

    if (exp->method.value != act->urr.method.value) {
        ++ret;
        LOG(SESSION, ERR, "method compare failed.");
    }

    if (exp->trigger.value != act->urr.trigger.value) {
        ++ret;
        LOG(SESSION, ERR, "trigger compare failed.");
    }

    if (exp->member_flag.d.period_present) {
        if (exp->period != act->urr.period) {
            ++ret;
            LOG(SESSION, ERR, "period compare failed.");
        }
    }

    if (exp->member_flag.d.vol_thres_present) {
        if (exp->vol_thres.flag.value != act->urr.vol_thres.flag.value) {
            ++ret;
            LOG(SESSION, ERR, "flag compare failed.");
        }

        if (exp->vol_thres.total != act->urr.vol_thres.total) {
            ++ret;
            LOG(SESSION, ERR, "total compare failed.");
        }

        if (exp->vol_thres.uplink != act->urr.vol_thres.uplink) {
            ++ret;
            LOG(SESSION, ERR, "uplink compare failed.");
        }

        if (exp->vol_thres.downlink != act->urr.vol_thres.downlink) {
            ++ret;
            LOG(SESSION, ERR, "downlink compare failed.");
        }
    }

    if (exp->member_flag.d.vol_quota_present) {
        if (exp->vol_quota.flag.value != act->urr.vol_quota.flag.value) {
            ++ret;
            LOG(SESSION, ERR, "flag compare failed.");
        }

        if (exp->vol_quota.total != act->urr.vol_quota.total) {
            ++ret;
            LOG(SESSION, ERR, "total compare failed.");
        }

        if (exp->vol_quota.uplink != act->urr.vol_quota.uplink) {
            ++ret;
            LOG(SESSION, ERR, "uplink compare failed.");
        }

        if (exp->vol_quota.downlink != act->urr.vol_quota.downlink) {
            ++ret;
            LOG(SESSION, ERR, "downlink compare failed.");
        }
    }

    if (exp->member_flag.d.eve_thres_present) {
        if (exp->eve_thres != act->urr.eve_thres) {
            ++ret;
            LOG(SESSION, ERR, "eve_thres compare failed.");
        }
    }

    if (exp->member_flag.d.eve_quota_present) {
        if (exp->eve_quota != act->urr.eve_quota) {
            ++ret;
            LOG(SESSION, ERR, "eve_quota compare failed.");
        }
    }

    if (exp->member_flag.d.tim_thres_present) {
        if (exp->tim_thres != act->urr.tim_thres) {
            ++ret;
            LOG(SESSION, ERR, "tim_thres compare failed.");
        }
    }

    if (exp->member_flag.d.tim_quota_present) {
        if (exp->tim_quota != act->urr.tim_quota) {
            ++ret;
            LOG(SESSION, ERR, "tim_quota compare failed.");
        }
    }

    if (exp->member_flag.d.quota_hold_present) {
        if (exp->quota_hold != act->urr.quota_hold) {
            ++ret;
            LOG(SESSION, ERR, "tim_thres compare failed.");
        }
    }

    if (exp->member_flag.d.drop_thres_present) {
        if (exp->drop_thres.flag.value != act->urr.drop_thres.flag.value) {
            ++ret;
            LOG(SESSION, ERR, "flag compare failed.");
        }

        if (exp->drop_thres.packets != act->urr.drop_thres.packets) {
            ++ret;
            LOG(SESSION, ERR, "packets compare failed.");
        }

        if (exp->drop_thres.bytes != act->urr.drop_thres.bytes) {
            ++ret;
            LOG(SESSION, ERR, "bytes compare failed.");
        }
    }

    if (exp->member_flag.d.mon_time_present) {
        if (exp->mon_time != act->urr.mon_time) {
            ++ret;
            LOG(SESSION, ERR, "mon_time compare failed.");
        }
    }

    if (exp->member_flag.d.sub_vol_thres_present) {
        if (exp->sub_vol_thres.flag.value !=
            act->urr.sub_vol_thres.flag.value) {
            ++ret;
            LOG(SESSION, ERR, "flag compare failed.");
        }

        if (exp->sub_vol_thres.total != act->urr.sub_vol_thres.total) {
            ++ret;
            LOG(SESSION, ERR, "total compare failed.");
        }

        if (exp->sub_vol_thres.uplink != act->urr.sub_vol_thres.uplink) {
            ++ret;
            LOG(SESSION, ERR, "uplink compare failed.");
        }

        if (exp->sub_vol_thres.downlink != act->urr.sub_vol_thres.downlink) {
            ++ret;
            LOG(SESSION, ERR, "downlink compare failed.");
        }
    }

    if (exp->member_flag.d.sub_tim_thres_present) {
        if (exp->sub_tim_thres != act->urr.sub_tim_thres) {
            ++ret;
            LOG(SESSION, ERR, "sub_tim_thres compare failed.");
        }
    }

    if (exp->member_flag.d.sub_vol_quota_present) {
        if (exp->sub_vol_quota.flag.value !=
            act->urr.sub_vol_quota.flag.value) {
            ++ret;
            LOG(SESSION, ERR, "flag compare failed.");
        }

        if (exp->sub_vol_quota.total != act->urr.sub_vol_quota.total) {
            ++ret;
            LOG(SESSION, ERR, "total compare failed.");
        }

        if (exp->sub_vol_quota.uplink != act->urr.sub_vol_quota.uplink) {
            ++ret;
            LOG(SESSION, ERR, "uplink compare failed.");
        }

        if (exp->sub_vol_quota.downlink != act->urr.sub_vol_quota.downlink) {
            ++ret;
            LOG(SESSION, ERR, "downlink compare failed.");
        }
    }

    if (exp->member_flag.d.sub_tim_quota_present) {
        if (exp->sub_tim_quota != act->urr.sub_tim_quota) {
            ++ret;
            LOG(SESSION, ERR, "sub_tim_quota compare failed.");
        }
    }

    if (exp->member_flag.d.sub_eve_thres_present) {
        if (exp->sub_eve_thres != act->urr.sub_eve_thres) {
            ++ret;
            LOG(SESSION, ERR, "sub_eve_thres compare failed.");
        }
    }

    if (exp->member_flag.d.sub_eve_quota_present) {
        if (exp->sub_eve_quota != act->urr.sub_eve_quota) {
            ++ret;
            LOG(SESSION, ERR, "sub_eve_quota compare failed.");
        }
    }

    if (exp->member_flag.d.inact_detect_present) {
        if (exp->inact_detect != act->urr.inact_detect) {
            ++ret;
            LOG(SESSION, ERR, "sub_tim_quota compare failed.");
        }
    }

    if (exp->member_flag.d.measu_info_present) {
        if (exp->measu_info.value != act->urr.measu_info.value) {
            ++ret;
            LOG(SESSION, ERR, "measu_info compare failed.");
        }
    }

    if (exp->member_flag.d.quota_far_present != act->urr.quota_far_present) {
        ++ret;
        LOG(SESSION, ERR, "quota_far_present compare failed.");
    }
    if (exp->member_flag.d.quota_far_present) {
        if (exp->quota_far != act->urr.quota_far) {
            ++ret;
            LOG(SESSION, ERR, "quota_far compare failed.");
        }
    }

    if (exp->member_flag.d.eth_inact_time_present) {
        if (exp->eth_inact_time != act->urr.eth_inact_time) {
            ++ret;
            LOG(SESSION, ERR, "eth_inact_time compare failed.");
        }
    }

    if (exp->linked_urr_number != act->urr.linked_urr_number) {
        ++ret;
        LOG(SESSION, ERR, "linked_urr_number compare failed.");
    }
    if (exp->linked_urr_number) {
        if (memcmp(exp->linked_urr, act->urr.linked_urr,
            sizeof(exp->linked_urr) * exp->linked_urr_number)) {
            ++ret;
            LOG(SESSION, ERR, "linked_urr compare failed.");
        }
    }

    if (exp->add_mon_time_number != act->urr.add_mon_time_number) {
        ++ret;
        LOG(SESSION, ERR, "add_mon_time_number compare failed.");
    }
    if (exp->add_mon_time_number) {
        uint8_t cnt = 0;
        session_urr_add_mon_time *exp_amt = NULL;
        comm_msg_urr_mon_time_t *act_amt = NULL;

        for (cnt = 0; cnt < exp->add_mon_time_number; ++cnt) {
            exp_amt = &exp->add_mon_time[cnt];
            act_amt = &act->urr.add_mon_time[cnt];

            if (exp_amt->mon_time != act_amt->mon_time) {
                ++ret;
                LOG(SESSION, ERR, "mon_time compare failed.");
            }

            if (exp_amt->member_flag.d.sub_vol_thres_present) {
                if (exp_amt->sub_vol_thres.flag.value !=
                    act_amt->sub_vol_thres.flag.value) {
                    ++ret;
                    LOG(SESSION, ERR, "flag compare failed.");
                }

                if (exp_amt->sub_vol_thres.total !=
                    act_amt->sub_vol_thres.total) {
                    ++ret;
                    LOG(SESSION, ERR, "total compare failed.");
                }

                if (exp_amt->sub_vol_thres.uplink !=
                    act_amt->sub_vol_thres.uplink) {
                    ++ret;
                    LOG(SESSION, ERR, "uplink compare failed.");
                }

                if (exp_amt->sub_vol_thres.downlink !=
                    act_amt->sub_vol_thres.downlink) {
                    ++ret;
                    LOG(SESSION, ERR, "downlink compare failed.");
                }
            }

            if (exp_amt->member_flag.d.sub_tim_thres_present) {
                if (exp_amt->sub_tim_thres != act_amt->sub_tim_thres) {
                    ++ret;
                    LOG(SESSION, ERR, "sub_tim_thres compare failed.");
                }
            }

            if (exp_amt->member_flag.d.sub_vol_quota_present) {
                if (exp_amt->sub_vol_quota.flag.value !=
                    act_amt->sub_vol_quota.flag.value) {
                    ++ret;
                    LOG(SESSION, ERR, "flag compare failed.");
                }

                if (exp_amt->sub_vol_quota.total !=
                    act_amt->sub_vol_quota.total) {
                    ++ret;
                    LOG(SESSION, ERR, "total compare failed.");
                }

                if (exp_amt->sub_vol_quota.uplink !=
                    act_amt->sub_vol_quota.uplink) {
                    ++ret;
                    LOG(SESSION, ERR, "uplink compare failed.");
                }

                if (exp_amt->sub_vol_quota.downlink !=
                    act_amt->sub_vol_quota.downlink) {
                    ++ret;
                    LOG(SESSION, ERR, "downlink compare failed.");
                }
            }

            if (exp_amt->member_flag.d.sub_tim_quota_present) {
                if (exp_amt->sub_tim_quota != act_amt->sub_tim_quota) {
                    ++ret;
                    LOG(SESSION, ERR, "sub_tim_quota compare failed.");
                }
            }

            if (exp_amt->member_flag.d.sub_eve_thres_present) {
                if (exp_amt->sub_eve_thres != act_amt->sub_eve_thres) {
                    ++ret;
                    LOG(SESSION, ERR, "sub_eve_thres compare failed.");
                }
            }

            if (exp_amt->member_flag.d.sub_eve_quota_present) {
                if (exp_amt->sub_eve_quota != act_amt->sub_eve_quota) {
                    ++ret;
                    LOG(SESSION, ERR, "sub_eve_quota compare failed.");
                }
            }
        }
    }

    return ret;
}

static int session_bar_cmp(session_buffer_action_rule *exp, struct bar_table *act)
{
    int ret = 0;

    if (exp->bar_id != act->bar.bar_id) {
        ++ret;
        LOG(SESSION, ERR, "bar_id compare failed.");
    }

    if (exp->member_flag.d.notify_delay_present) {
        if (exp->notify_delay != act->bar.notify_delay) {
            ++ret;
            LOG(SESSION, ERR, "notify_delay compare failed.");
        }
    }

    if (exp->member_flag.d.buffer_pkts_cnt_present) {
        if (exp->buffer_pkts_cnt != act->bar.pkts_max) {
            ++ret;
            LOG(SESSION, ERR, "buffer_pkts_cnt compare failed.");
        }
    }

    return ret;
}

int session_mar_cmp(session_mar_create *exp, struct mar_table *act)
{
    int ret = 0;

    if (exp->mar_id != act->mar.mar_id) {
        ++ret;
        LOG(SESSION, ERR, "mar_id compare failed.");
    }

    if (exp->steer_func != act->mar.steer_func) {
        ++ret;
        LOG(SESSION, ERR, "steer_func compare failed.");
    }

    if (exp->steer_mod != act->mar.steer_mod) {
        ++ret;
        LOG(SESSION, ERR, "steer_mod compare failed.");
    }

    if (exp->member_flag.d.afai_1_present != act->mar.afai_1_validity) {
        ++ret;
        LOG(SESSION, ERR, "afai_1_present compare failed.");
    }
    if (exp->member_flag.d.afai_1_present) {
        if (exp->afai_1.far_id != act->mar.afai_1.far_id) {
            ++ret;
            LOG(SESSION, ERR, "far_id compare failed.");
        }

        if(exp->afai_1.member_flag.d.weight_present !=
            act->mar.afai_1.member_flag.d.weight_present) {
            ++ret;
            LOG(SESSION, ERR, "weight_present compare failed.");
        }
        if (exp->afai_1.member_flag.d.weight_present) {
            if (exp->afai_1.weight != act->mar.afai_1.weight) {
                ++ret;
                LOG(SESSION, ERR, "far_id compare failed.");
            }
        }

        if(exp->afai_1.member_flag.d.priority_present !=
            act->mar.afai_1.member_flag.d.priority_present) {
            ++ret;
            LOG(SESSION, ERR, "priority_present compare failed.");
        }
        if (exp->afai_1.member_flag.d.priority_present) {
            if (exp->afai_1.priority != act->mar.afai_1.priority) {
                ++ret;
                LOG(SESSION, ERR, "priority compare failed.");
            }
        }

        if(exp->afai_1.urr_num != act->mar.afai_1.urr_num) {
            ++ret;
            LOG(SESSION, ERR, "urr_num compare failed.");
        }
        if (exp->afai_1.urr_num) {
            if (memcmp(exp->afai_1.urr_id_arr, act->mar.afai_1.urr_id_arr,
                sizeof(exp->afai_1.urr_id_arr) * exp->afai_1.urr_num)) {
                ++ret;
                LOG(SESSION, ERR, "urr_id_arr compare failed.");
            }
        }
    }

    if (exp->member_flag.d.afai_2_present != act->mar.afai_2_validity) {
        ++ret;
        LOG(SESSION, ERR, "afai_2_present compare failed.");
    }
    if (exp->member_flag.d.afai_2_present) {
        if (exp->afai_2.far_id != act->mar.afai_2.far_id) {
            ++ret;
            LOG(SESSION, ERR, "far_id compare failed.");
        }

        if(exp->afai_2.member_flag.d.weight_present !=
            act->mar.afai_2.member_flag.d.weight_present) {
            ++ret;
            LOG(SESSION, ERR, "weight_present compare failed.");
        }
        if (exp->afai_2.member_flag.d.weight_present) {
            if (exp->afai_2.weight != act->mar.afai_2.weight) {
                ++ret;
                LOG(SESSION, ERR, "far_id compare failed.");
            }
        }

        if(exp->afai_2.member_flag.d.priority_present !=
            act->mar.afai_2.member_flag.d.priority_present) {
            ++ret;
            LOG(SESSION, ERR, "priority_present compare failed.");
        }
        if (exp->afai_2.member_flag.d.priority_present) {
            if (exp->afai_2.priority != act->mar.afai_2.priority) {
                ++ret;
                LOG(SESSION, ERR, "priority compare failed.");
            }
        }

        if(exp->afai_2.urr_num != act->mar.afai_2.urr_num) {
            ++ret;
            LOG(SESSION, ERR, "urr_num compare failed.");
        }
        if (exp->afai_2.urr_num) {
            if (memcmp(exp->afai_2.urr_id_arr, act->mar.afai_2.urr_id_arr,
                sizeof(exp->afai_2.urr_id_arr) * exp->afai_2.urr_num)) {
                ++ret;
                LOG(SESSION, ERR, "urr_id_arr compare failed.");
            }
        }
    }

    return ret;
}

static int session_traffic_endpoint_cmp(session_tc_endpoint *exp, struct traffic_endpoint_table *act)
{
    int ret = 0;

    if (exp->endpoint_id != act->te.endpoint_id) {
        ++ret;
        LOG(SESSION, ERR, "endpoint_id compare failed.");
    }

    if (exp->member_flag.d.local_fteid_present) {
        if (memcmp(&exp->local_fteid, &act->te.local_fteid, sizeof(session_f_teid))) {
            ++ret;
            LOG(SESSION, ERR, "local_fteid compare failed.");
        }
    }

    if (exp->member_flag.d.network_instance_present) {
        if (strcmp(exp->network_instance, act->te.network_instance)) {
            ++ret;
            LOG(SESSION, ERR, "network_instance compare failed.");
        }
    }

    if (exp->member_flag.d.redundant_transmission_present) {
        if (memcmp(&exp->redundant_transmission_param, &act->te.redundant_transmission_param,
            sizeof(session_redundant_trans_param_in_pdi))) {
            ++ret;
            LOG(SESSION, ERR, "redundant_transmission_param compare failed.");
        }
    }

    if (exp->ue_ipaddr_num != act->te.ue_ipaddr_num) {
        ++ret;
        LOG(SESSION, ERR, "ue_ipaddr_num compare failed.");
    }
    if (exp->ue_ipaddr_num) {
        uint8_t cnt;

        for (cnt = 0; cnt < exp->ue_ipaddr_num; ++cnt) {
            if (memcmp(&exp->ue_ipaddr[cnt],
                &act->te.ue_ipaddr[cnt], sizeof(session_ue_ip))) {
                ++ret;
                LOG(SESSION, ERR, "ue_ipaddr compare failed.");
            }
        }
    }

    if (exp->member_flag.d.eth_pdu_ses_info_present) {
        if (exp->eth_pdu_ses_info.value != act->te.eth_pdu_ses_info.value) {
            ++ret;
            LOG(SESSION, ERR, "eth_pdu_ses_info compare failed.");
        }
    }

    if (exp->framed_route_num != act->te.framed_route_num) {
        ++ret;
        LOG(SESSION, ERR, "framed_route_num compare failed.");
    }
    if (exp->framed_route_num) {
        uint8_t cnt_l2 = 0;
        for (; cnt_l2 < exp->framed_route_num; ++cnt_l2) {
            if (memcmp(&exp->framed_route[cnt_l2], &act->te.framed_route[cnt_l2],
                sizeof(session_framed_route))) {
                ++ret;
                LOG(SESSION, ERR, "framed_route compare failed.");
            }
        }
    }

    if (exp->member_flag.d.framed_routing_present) {
        if (exp->framed_routing != act->te.framed_routing) {
            ++ret;
            LOG(SESSION, ERR, "framed_routing compare failed.");
        }
    }

    if (exp->framed_ipv6_route_num != act->te.framed_ipv6_route_num) {
        ++ret;
        LOG(SESSION, ERR, "framed_ipv6_route_num compare failed.");
    }
    if (exp->framed_ipv6_route_num) {
        uint8_t cnt_l2 = 0;
        for (; cnt_l2 < exp->framed_ipv6_route_num; ++cnt_l2) {
            if (memcmp(&exp->framed_ipv6_route[cnt_l2],
                &act->te.framed_ipv6_route[cnt_l2],
                sizeof(session_framed_route_ipv6))) {
                ++ret;
                LOG(SESSION, ERR, "framed_ipv6_route compare failed.");
            }
        }
    }

    if (exp->qfi_number != act->te.qfi_number) {
        ++ret;
        LOG(SESSION, ERR, "qfi_number compare failed.");
    }
    if (exp->qfi_number) {
        if (memcmp(&exp->qfi_array, &act->te.qfi_array,
            sizeof(exp->qfi_array) * exp->qfi_number)) {
            ++ret;
            LOG(SESSION, ERR, "qfi_array compare failed.");
        }
    }

    return ret;
}

int session_table_cmp(session_content_create *exp, struct session_t *act)
{
    struct pdr_table *pdr_tbl = NULL;
    struct far_table *far_tbl = NULL;
    struct urr_table *urr_tbl = NULL;
    struct qer_table *qer_tbl = NULL;
    struct bar_table *bar_tbl = NULL;
    struct mar_table *mar_tbl = NULL;
    struct traffic_endpoint_table *te_tbl = NULL;
    uint8_t cnt = 0;
    int ret = 0;

    LOG(SESSION, DEBUG, "seid pair: 0x%lx:0x%lx.",
        act->session.local_seid, act->session.cp_seid);

    /* pdr */
    for (cnt = 0; cnt < exp->pdr_num; ++cnt) {
        pdr_tbl = pdr_table_search(act, exp->pdr_arr[cnt].pdr_id);
        if (NULL == pdr_tbl) {
            ++ret;
            LOG(SESSION, ERR, "pdr(%d) search failure in SPU.",
                exp->pdr_arr[cnt].pdr_id);
        } else {
            if (session_pdr_cmp(&exp->pdr_arr[cnt], pdr_tbl)) {
                ++ret;
                LOG(SESSION, ERR, "pdr(%d) compare failed.",
                    exp->pdr_arr[cnt].pdr_id);
            }
        }
    }

    /* far */
    for (cnt = 0; cnt < exp->far_num; ++cnt) {
        far_tbl = far_table_search(act, exp->far_arr[cnt].far_id);
        if (NULL == far_tbl) {
            ++ret;
            LOG(SESSION, ERR, "far(%d) search failure in SPU.",
                exp->far_arr[cnt].far_id);
        } else {
            if (session_far_cmp(&exp->far_arr[cnt], far_tbl)) {
                ++ret;
                LOG(SESSION, ERR, "far(%d) compare failed.",
                    exp->far_arr[cnt].far_id);
            }
        }
    }

    /* urr */
    for (cnt = 0; cnt < exp->urr_num; ++cnt) {
        urr_tbl = urr_table_search(act, exp->urr_arr[cnt].urr_id);
        if (NULL == urr_tbl) {
            ++ret;
            LOG(SESSION, ERR, "urr(%d) search failure in SPU.",
                exp->urr_arr[cnt].urr_id);
        } else {
            if (session_urr_cmp(&exp->urr_arr[cnt], urr_tbl)) {
                ++ret;
                LOG(SESSION, ERR, "urr(%d) compare failed.",
                    exp->urr_arr[cnt].urr_id);
            }
        }
    }

    /* qer */
    for (cnt = 0; cnt < exp->qer_num; ++cnt) {
        qer_tbl = qer_table_search(act, exp->qer_arr[cnt].qer_id);
        if (NULL == qer_tbl) {
            ++ret;
            LOG(SESSION, ERR, "qer(%d) search failure in SPU.",
                exp->qer_arr[cnt].qer_id);
        } else {
            if (session_qer_cmp(&exp->qer_arr[cnt], qer_tbl)) {
                ++ret;
                LOG(SESSION, ERR, "qer(%d) compare failed.",
                    exp->qer_arr[cnt].qer_id);
            }
        }
    }

    /* bar */
    if (exp->member_flag.d.bar_present) {
        bar_tbl = bar_table_search(act, exp->bar.bar_id);
        if (NULL == bar_tbl) {
            ++ret;
            LOG(SESSION, ERR, "bar(%d) search failure in SPU.",
                exp->bar.bar_id);
        } else {
            if (session_bar_cmp(&exp->bar, bar_tbl)) {
                ++ret;
                LOG(SESSION, ERR, "bar(%d) compare failed.", exp->bar.bar_id);
            }
        }
    }

    /* mar */
    for (cnt = 0; cnt < exp->mar_num; ++cnt) {
        mar_tbl = mar_table_search(act, exp->mar_arr[cnt].mar_id);
        if (NULL == mar_tbl) {
            ++ret;
            LOG(SESSION, ERR, "mar(%d) search failure in SPU.",
                exp->mar_arr[cnt].mar_id);
        } else {
            if (session_mar_cmp(&exp->mar_arr[cnt], mar_tbl)) {
                ++ret;
                LOG(SESSION, ERR, "mar(%d) compare failed.",
                    exp->mar_arr[cnt].mar_id);
            }
        }
    }

    /* traffic endpoint */
    for (cnt = 0; cnt < exp->tc_endpoint_num; ++cnt) {
        te_tbl = traffic_endpoint_table_search(act, exp->tc_endpoint_arr[cnt].endpoint_id);
        if (NULL == te_tbl) {
            ++ret;
            LOG(SESSION, ERR, "traffic endpoint(%d) search failure in SPU.",
                exp->tc_endpoint_arr[cnt].endpoint_id);
        } else {
            if (session_traffic_endpoint_cmp(&exp->tc_endpoint_arr[cnt], te_tbl)) {
                ++ret;
                LOG(SESSION, ERR, "traffic endpoint(%d) compare failed.",
                    exp->tc_endpoint_arr[cnt].endpoint_id);
            }
        }
    }

    LOG(SESSION, RUNNING, "Compare session date finish.\n");

    return ret;
}

int session_check_equ(session_seid_pair *seid_pair)
{

    LOG(SESSION, RUNNING, "session table compare, seid: 0x%lx:0x%lx.",
            seid_pair->up_seid, seid_pair->cp_seid);

    return 0;
}


