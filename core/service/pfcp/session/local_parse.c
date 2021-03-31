/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "bar_mgmt.h"
#include "far_mgmt.h"
#include "qer_mgmt.h"
#include "urr_mgmt.h"
#include "pdr_mgmt.h"
#include "session_teid.h"
#include "session_report.h"
#include "mar_mgmt.h"
#include "session_check.h"
#include "traffic_endpoint_mgmt.h"
#include "pfd_mgmt.h"
#include "predefine_rule_mgmt.h"
#include "upc_node.h"
#include "session_msg.h"
#include "urr_proc.h"
#include "session_instance.h"
#include "sp_backend_mgmt.h"
#include "sp_dns_cache.h"
#include "session_audit.h"

#include "local_parse.h"

struct bar_table *bar_add_predefined(session_buffer_action_rule *parse_bar)
{
    struct bar_table *bar_tbl = NULL;

    bar_tbl = bar_table_create_local(parse_bar->bar_id);
    if (NULL == bar_tbl) {
        LOG(SESSION, ERR, "bar table create failed, bar_id %u.",
            parse_bar->bar_id);
        return NULL;
    }

    ros_rwlock_write_lock(&bar_tbl->lock);// lock
    bar_tbl->bar.notify_delay = parse_bar->notify_delay;
    bar_tbl->bar.pkts_max = parse_bar->buffer_pkts_cnt;
    ros_rwlock_write_unlock(&bar_tbl->lock);// unlock

    return bar_tbl;
}

static int far_create_content_copy(struct far_table *local_far,
    session_far_create *parse_far, uint32_t node_index)
{
    comm_msg_far_config     *local_far_cfg = &local_far->far_cfg;
    struct far_sp_private   *local_far_priv = &local_far->far_priv;

    /* far_id */
    local_far_cfg->far_id = parse_far->far_id;
    /* action */
    if (parse_far->member_flag.d.action_present) {
        local_far_cfg->action.value = parse_far->action.value;
    }
    /* forw_param */
    if (parse_far->member_flag.d.forw_param_present) {
        local_far_cfg->choose.d.section_forwarding = 1;

        if (parse_far->forw_param.member_flag.d.dest_if_present) {
            local_far_cfg->forw_if = parse_far->forw_param.dest_if;
        }
        if (parse_far->forw_param.member_flag.d.network_instance_present) {
            ros_memcpy(local_far_priv->network_instance,
                parse_far->forw_param.network_instance, NETWORK_INSTANCE_LEN);
        }
        if (parse_far->forw_param.member_flag.d.redirect_present) {
            if (G_FALSE == upc_node_features_validity_query(UF_TREU)) {
                LOG(SESSION, ERR, "TREU feature not support,"
                    " Redirection Information invalid.");
                return -1;
            } else {
                ros_memcpy(&local_far_cfg->forw_redirect, &parse_far->forw_param.redirect_addr.address,
                    sizeof(session_redirect_server));
                local_far_cfg->choose.d.flag_redirect = parse_far->forw_param.redirect_addr.addr_type + 1;
            }
        }
        if (parse_far->forw_param.member_flag.d.ohc_present) {
            local_far_cfg->choose.d.flag_out_header1 = 1;
            local_far_cfg->forw_cr_outh.type.value =
                parse_far->forw_param.outer_header_creation.type.value;
            local_far_cfg->forw_cr_outh.port =
                parse_far->forw_param.outer_header_creation.port;
            local_far_cfg->forw_cr_outh.teid =
                parse_far->forw_param.outer_header_creation.teid;
            local_far_cfg->forw_cr_outh.ipv4 =
                parse_far->forw_param.outer_header_creation.ipv4;
            ros_memcpy(&local_far_cfg->forw_cr_outh.ipv6,
                parse_far->forw_param.outer_header_creation.ipv6, IPV6_ALEN);

            local_far_cfg->forw_cr_outh.ctag.vlan_flag.value =
                parse_far->forw_param.outer_header_creation.ctag.flags.value;
            local_far_cfg->forw_cr_outh.ctag.vlan_value.data =
                parse_far->forw_param.outer_header_creation.ctag.value.value;
            local_far_cfg->forw_cr_outh.stag.vlan_flag.value =
                parse_far->forw_param.outer_header_creation.stag.flags.value;
            local_far_cfg->forw_cr_outh.stag.vlan_value.data =
                parse_far->forw_param.outer_header_creation.stag.value.value;
        }
        if (parse_far->forw_param.member_flag.d.trans_present) {
            local_far_cfg->choose.d.flag_transport_level1 = 1;
            local_far_cfg->forw_trans.tos = parse_far->forw_param.trans.d.tos;
            local_far_cfg->forw_trans.mask =
                parse_far->forw_param.trans.d.tos_mask;
        }
        if (parse_far->forw_param.member_flag.d.forwarding_policy_present) {
            local_far_cfg->choose.d.flag_forward_policy1 = 1;
            ros_memcpy(local_far_priv->forwarding_policy,
                parse_far->forw_param.forwarding_policy,
                FORWARDING_POLICY_LEN);
        }
        if (parse_far->forw_param.member_flag.d.header_enrichment_present) {
            if (G_FALSE == upc_node_features_validity_query(UF_HEEU)) {
                LOG(SESSION, ERR, "HEEU feature not support,"
                    " header enrichment invalid.");
                return -1;
            } else {
                local_far_cfg->choose.d.flag_header_enrich = 1;
                local_far_cfg->forw_enrich.name_length =
                    parse_far->forw_param.header_enrichment.name_length;
                ros_memcpy(local_far_cfg->forw_enrich.name,
                    parse_far->forw_param.header_enrichment.name,
                    local_far_cfg->forw_enrich.name_length);

                local_far_cfg->forw_enrich.value_length =
                    parse_far->forw_param.header_enrichment.value_length;
                ros_memcpy(local_far_cfg->forw_enrich.value,
                    parse_far->forw_param.header_enrichment.value,
                    local_far_cfg->forw_enrich.value_length);
            }
        }
        if (parse_far->forw_param.member_flag.d.traffic_endpoint_id_present) {
            local_far_priv->traffic_endpoint_id_present = 1;
            local_far_priv->traffic_endpoint_id =
                parse_far->forw_param.traffic_endpoint_id;
        }
        if (parse_far->forw_param.member_flag.d.proxying_present) {
            local_far_priv->proxying.value =
                parse_far->forw_param.proxying.value;
        }
        if (parse_far->forw_param.member_flag.d.dest_if_type_present) {
            local_far_priv->dest_if_type.value =
                parse_far->forw_param.dest_if_type.value;
        }
    }
    /* bar_id */
    if (parse_far->member_flag.d.bar_id_present) {
        local_far_priv->bar_id_present = 1;
        local_far_priv->bar_id = parse_far->bar_id;
    }

    return 0;
}

static int far_update_content_copy(struct far_table *local_far,
    session_far_update *parse_far, uint32_t node_index)
{
    comm_msg_far_config     *local_far_cfg = &local_far->far_cfg;
    struct far_sp_private   *local_far_priv = &local_far->far_priv;

    /* far_id */
    local_far_cfg->far_id = parse_far->far_id;
    /* action */
    if (parse_far->member_flag.d.action_present) {
        local_far_cfg->action.value = parse_far->action.value;
    }
    /* forw_param */
    if (parse_far->member_flag.d.forw_param_present) {
        local_far_cfg->choose.d.section_forwarding = 1;

        if (parse_far->forw_param.member_flag.d.dest_if_present) {
            local_far_cfg->forw_if = parse_far->forw_param.dest_if;
        }
        if (parse_far->forw_param.member_flag.d.network_instance_present) {
            ros_memcpy(local_far_priv->network_instance,
                parse_far->forw_param.network_instance, NETWORK_INSTANCE_LEN);
        }
        if (parse_far->forw_param.member_flag.d.redirect_present) {
            if (G_FALSE ==
                upc_node_features_validity_query(UF_TREU)) {
                LOG(SESSION, ERR, "TREU feature not support,"
                    " Redirection Information invalid.");
                return -1;
            } else {
                ros_memcpy(&local_far_cfg->forw_redirect, &parse_far->forw_param.redirect_addr.address,
                    sizeof(session_redirect_server));
                local_far_cfg->choose.d.flag_redirect = parse_far->forw_param.redirect_addr.addr_type + 1;
            }
        }
        if (parse_far->forw_param.member_flag.d.ohc_present) {
            local_far_cfg->choose.d.flag_out_header1 = 1;
            local_far_cfg->forw_cr_outh.type.value =
                parse_far->forw_param.outer_header_creation.type.value;
            local_far_cfg->forw_cr_outh.port =
                parse_far->forw_param.outer_header_creation.port;
            local_far_cfg->forw_cr_outh.teid =
                parse_far->forw_param.outer_header_creation.teid;
            local_far_cfg->forw_cr_outh.ipv4 =
                parse_far->forw_param.outer_header_creation.ipv4;
            ros_memcpy(&local_far_cfg->forw_cr_outh.ipv6,
                parse_far->forw_param.outer_header_creation.ipv6, IPV6_ALEN);

            local_far_cfg->forw_cr_outh.ctag.vlan_flag.value =
                parse_far->forw_param.outer_header_creation.ctag.flags.value;
            local_far_cfg->forw_cr_outh.ctag.vlan_value.data =
                parse_far->forw_param.outer_header_creation.ctag.value.value;
            local_far_cfg->forw_cr_outh.stag.vlan_flag.value =
                parse_far->forw_param.outer_header_creation.stag.flags.value;
            local_far_cfg->forw_cr_outh.stag.vlan_value.data =
                parse_far->forw_param.outer_header_creation.stag.value.value;
        }
        if (parse_far->forw_param.member_flag.d.trans_present) {
            local_far_cfg->choose.d.flag_transport_level1 = 1;
            local_far_cfg->forw_trans.tos = parse_far->forw_param.trans.d.tos;
            local_far_cfg->forw_trans.mask =
                parse_far->forw_param.trans.d.tos_mask;
        }
        if (parse_far->forw_param.member_flag.d.forwarding_policy_present) {
            local_far_cfg->choose.d.flag_forward_policy1 = 1;
            ros_memcpy(local_far_priv->forwarding_policy,
                parse_far->forw_param.forwarding_policy,
                FORWARDING_POLICY_LEN);
        }
        if (parse_far->forw_param.member_flag.d.header_enrichment_present) {
            if (G_FALSE ==
                upc_node_features_validity_query(UF_HEEU)) {
                LOG(SESSION, ERR, "HEEU feature not support,"
                    " header enrichment invalid.");
                return -1;
            } else {
                local_far_cfg->choose.d.flag_header_enrich = 1;
                local_far_cfg->forw_enrich.name_length =
                    parse_far->forw_param.header_enrichment.name_length;
                ros_memcpy(local_far_cfg->forw_enrich.name,
                    parse_far->forw_param.header_enrichment.name,
                    local_far_cfg->forw_enrich.name_length);

                local_far_cfg->forw_enrich.value_length =
                    parse_far->forw_param.header_enrichment.value_length;
                ros_memcpy(local_far_cfg->forw_enrich.value,
                    parse_far->forw_param.header_enrichment.value,
                    local_far_cfg->forw_enrich.value_length);
            }
        }
        if (parse_far->forw_param.member_flag.d.traffic_endpoint_id_present) {
            local_far_priv->traffic_endpoint_id_present = 1;
            local_far_priv->traffic_endpoint_id =
                parse_far->forw_param.traffic_endpoint_id;
        }
        if (parse_far->forw_param.member_flag.d.dest_if_type_present) {
            local_far_priv->dest_if_type.value =
                parse_far->forw_param.dest_if_type.value;
        }
    }
    /* bar_id */
    if (parse_far->member_flag.d.bar_id_present) {
        local_far_priv->bar_id_present = 1;
        local_far_priv->bar_id = parse_far->bar_id;
    }

    return 0;
}

struct far_table *far_add(struct session_t *sess,
    session_far_create *parse_far_arr, uint32_t index, uint32_t *fail_id)
{
    struct far_table *far_tbl = NULL;
    session_far_create *parse_far = &parse_far_arr[index];

    /* create far table */
    far_tbl = far_table_create(sess, parse_far->far_id);
    if (NULL == far_tbl) {
        LOG(SESSION, ERR,
        	"far table create failed, far_id %u.", parse_far->far_id);
        *fail_id = parse_far->far_id;
        return NULL;
    }

    ros_rwlock_write_lock(&far_tbl->lock);  /* lock */

	if (0 > far_create_content_copy(far_tbl, parse_far,
        sess->session.node_index)) {
        ros_rwlock_write_unlock(&far_tbl->lock);  /* unlock */
        uint32_t rm_id = parse_far->far_id;

        LOG(SESSION, ERR, "far create content copy failed.");
        far_remove(sess, &rm_id, 1, NULL);
        *fail_id = rm_id;
        return NULL;
    }

    if (far_tbl->far_cfg.choose.d.flag_out_header1) {
        if (0 > far_gtpu_tunnel_add(&sess->session, far_tbl)) {
            LOG(SESSION, ERR, "far add gtpu tunnel failed.");
            /* Not return */
        }
    }

    if (far_tbl->far_cfg.choose.d.flag_header_enrich &&
        EN_COMM_SRC_IF_ACCESS == far_tbl->far_cfg.forw_if) {
        LOG(SESSION, ERR, "HEEU feature valid,"
            " But forward interface is ACCESS.");
    }
    ros_rwlock_write_unlock(&far_tbl->lock);  /* unlock */

    parse_far->far_index = far_tbl->index;

    return far_tbl;
}

struct far_table *far_add_predefined(session_far_create *parse_far_arr,uint32_t *fail_id)
{
    struct far_table *far_tbl = NULL;
    session_far_create *parse_far = parse_far_arr;
	comm_msg_far_config     *local_far_cfg = NULL;

    /* create far table */
    far_tbl = far_table_create_local(parse_far->far_id);
    if (NULL == far_tbl) {
        LOG(SESSION, ERR,
        	"far table create failed, far_id %u.", parse_far->far_id);
        *fail_id = parse_far->far_id;
        return NULL;
    }

    ros_rwlock_write_lock(&far_tbl->lock);  /* lock */

	if (0 > far_create_content_copy(far_tbl, parse_far,
        0xffffffff)) {
        ros_rwlock_write_unlock(&far_tbl->lock);  /* unlock */
        uint32_t rm_id = parse_far->far_id;

        LOG(SESSION, ERR, "far create content copy failed.");
        *fail_id = rm_id;
        return NULL;
    }

	if (parse_far->forw_param.member_flag.d.redirect_present) {
		local_far_cfg = &far_tbl->far_cfg;

        ros_memcpy(&local_far_cfg->forw_redirect, &parse_far->forw_param.redirect_addr.address,
            sizeof(session_redirect_server));
        local_far_cfg->choose.d.flag_redirect = parse_far->forw_param.redirect_addr.addr_type + 1;
    }

    if (far_tbl->far_cfg.choose.d.flag_header_enrich &&
        EN_COMM_SRC_IF_ACCESS == far_tbl->far_cfg.forw_if) {
        LOG(SESSION, ERR, "HEEU feature valid,"
            " But forward interface is ACCESS.");
    }
    ros_rwlock_write_unlock(&far_tbl->lock);  /* unlock */

    return far_tbl;
}

struct far_table *far_update(struct session_t *sess,
    session_far_update *parse_far_arr, uint32_t index, uint32_t *fail_id)
{
    struct far_table *far_tbl = NULL;
    session_far_update *parse_far = &parse_far_arr[index];
    uint8_t update_gtpu = 0;

    /* search far table */
    far_tbl = far_table_search(sess, parse_far->far_id);
    if (NULL == far_tbl) {
        LOG(SESSION, ERR,
        	"far table search failed, far_id %u.", parse_far->far_id);
        *fail_id = parse_far->far_id;
        return NULL;
    }

    ros_rwlock_write_lock(&far_tbl->lock); /* lock */
    /* OHC change */
    /* 从无到有需要添加 */
    if (far_tbl->far_cfg.choose.d.flag_out_header1 == 0 &&
        parse_far->forw_param.member_flag.d.ohc_present) {
        update_gtpu = 1;
    }
    /* 从有到有需要添加先删后加 */
    if (far_tbl->far_cfg.choose.d.flag_out_header1 &&
        parse_far->forw_param.member_flag.d.ohc_present) {
        update_gtpu = 1;

        if (-1 == far_gtpu_em_and_del(sess->session.node_index,
            &far_tbl->far_cfg.forw_cr_outh,
            parse_far->forw_param.pfcpsm_req_flag.d.sndem)) {
            LOG(SESSION, ERR, "far send endMarker failed.");
            /* don't be return */
        }
    }

	if (0 > far_update_content_copy(far_tbl, parse_far,
        sess->session.node_index)) {
        ros_rwlock_write_unlock(&far_tbl->lock);  /* unlock */
        LOG(SESSION, ERR, "far update content copy failed.");
        *fail_id = far_tbl->far_cfg.far_id;

        return NULL;
    }

    if (far_tbl->far_cfg.choose.d.flag_header_enrich &&
        EN_COMM_SRC_IF_ACCESS == far_tbl->far_cfg.forw_if) {
        LOG(SESSION, ERR, "HEEU feature valid,"
            " But forward interface is ACCESS.");
    }

    if (far_tbl->far_priv.bar_id_present) {
        struct bar_table *bar_tbl =
            bar_table_search(sess, far_tbl->far_priv.bar_id);
        if (NULL == bar_tbl) {
            ros_rwlock_write_unlock(&far_tbl->lock);  /* unlock */

            LOG(SESSION, ERR, "search bar table failed, bar id: %d.",
                far_tbl->far_priv.bar_id);
            *fail_id = far_tbl->far_cfg.far_id;

            return NULL;
        }
        far_tbl->far_cfg.choose.d.section_bar = 1;
        far_tbl->far_cfg.bar_index = bar_tbl->index;
    }
    ros_rwlock_write_unlock(&far_tbl->lock); /* unlock */

    /* if OHC changed */
    if (update_gtpu) {
        if (0 > far_gtpu_tunnel_add(&sess->session, far_tbl)) {
            LOG(SESSION, ERR, "far add gtpu tunnel failed.");
            /* Not return */
        }
    }

    parse_far->far_index = far_tbl->index;

    return far_tbl;
}


static void qer_content_copy(struct qer_table *qer_tbl,
    session_qos_enforcement_rule *parse_qer)
{
    comm_msg_qer_config     *local_qer_cfg = &qer_tbl->qer;
	struct qer_private		*local_qer_priv = &qer_tbl->qer_priv;

    /* default averaging window */
    local_qer_priv->averaging_window = 2000;

    /* qer id */
    local_qer_priv->qer_id = parse_qer->qer_id;
    /* qer_corr_id */
    if (parse_qer->member_flag.d.qer_corr_id_present) {
        local_qer_priv->qer_corr_id = parse_qer->qer_corr_id;
    }
    /* gate_status */
    if (parse_qer->member_flag.d.gate_status_present) {
        //local_qer_priv->gate_status.value = parse_qer->gate_status.value;
        local_qer_cfg->dl_gate = parse_qer->gate_status.d.dl_gate;
        local_qer_cfg->ul_gate = parse_qer->gate_status.d.ul_gate;

		if (local_qer_cfg->dl_gate == 0) {
            local_qer_cfg->dl_flag = 1;
        }

        if (local_qer_cfg->ul_gate == 0) {
            local_qer_cfg->ul_flag = 1;
        }
    }
    /* mbr_value */
    if (parse_qer->member_flag.d.mbr_value_present) {
        local_qer_priv->mbr_value.ul_mbr = parse_qer->mbr_value.ul_mbr;
        local_qer_priv->mbr_value.dl_mbr = parse_qer->mbr_value.dl_mbr;

        local_qer_cfg->flag.s.f_um = 1;
        local_qer_cfg->flag.s.f_dm = 1;
        local_qer_cfg->ul_mbr = parse_qer->mbr_value.ul_mbr;
        local_qer_cfg->dl_mbr = parse_qer->mbr_value.dl_mbr;
    }
    /* gbr_value */
    if (parse_qer->member_flag.d.gbr_value_present) {
        local_qer_priv->gbr_value.ul_gbr = parse_qer->gbr_value.ul_gbr;
        local_qer_priv->gbr_value.dl_gbr = parse_qer->gbr_value.dl_gbr;

        local_qer_cfg->flag.s.f_ug = 1;
        local_qer_cfg->flag.s.f_dg = 1;
        local_qer_cfg->ul_gbr = parse_qer->gbr_value.ul_gbr;
        local_qer_cfg->dl_gbr = parse_qer->gbr_value.dl_gbr;
    }
    /* qfi */
    if (parse_qer->member_flag.d.qfi_present) {
        local_qer_priv->qfi = parse_qer->qfi;
    }
    /* ref_qos */
    if (parse_qer->member_flag.d.ref_qos_present) {
        local_qer_priv->ref_qos = parse_qer->ref_qos;
    }
    /* ppi */
    if (parse_qer->member_flag.d.ppi_present) {
        local_qer_priv->paging_policy_indic = parse_qer->paging_policy_indic;
    }
    /* averaging_window */
    if (parse_qer->member_flag.d.averaging_window_present) {
        local_qer_priv->averaging_window = parse_qer->averaging_window;
    }
    /* qer_ctrl_indic */
    if (parse_qer->qer_ctrl_indic.value) {
        local_qer_priv->qer_ctrl_indic.value = parse_qer->qer_ctrl_indic.value;
    }
    /* pkt_rate_status */
    if (parse_qer->member_flag.d.packet_rate_status_present) {
        ros_memcpy(&local_qer_priv->pkt_rate_status, &parse_qer->pkt_rate_status,
            sizeof(session_packet_rate_status));

        local_qer_cfg->flag.s.f_up = local_qer_priv->pkt_rate_status.flag.d.UL;
        local_qer_cfg->flag.s.f_dp = local_qer_priv->pkt_rate_status.flag.d.DL;

        if (local_qer_priv->qer_ctrl_indic.d.NORD) {
            local_qer_cfg->ul_pkt_max = local_qer_priv->pkt_rate_status.remain_ul_packets;
            local_qer_cfg->dl_pkt_max = local_qer_priv->pkt_rate_status.remain_dl_packets;
        }

        if (local_qer_priv->qer_ctrl_indic.d.MOED) {
            local_qer_cfg->ul_pkt_max = local_qer_priv->pkt_rate_status.remain_ul_packets +
                local_qer_priv->pkt_rate_status.addit_remain_ul_packets;
            local_qer_cfg->dl_pkt_max = local_qer_priv->pkt_rate_status.remain_dl_packets +
                local_qer_priv->pkt_rate_status.addit_remain_dl_packets;
        }
        /* 只发送整秒的有效时间值 */
        local_qer_cfg->valid_time = local_qer_priv->pkt_rate_status.rate_ctrl_status_time >> 32;
    }

    /* Fill extension head */

    local_qer_cfg->gtpu_ext.content.s.ext_header = 0x85;
    local_qer_cfg->gtpu_ext.content.s.pdu_type = 0;
    local_qer_cfg->gtpu_ext.content.s.qmp = 0;
    local_qer_cfg->gtpu_ext.content.s.ppp = parse_qer->member_flag.d.ppi_present ? 1 : 0;
    local_qer_cfg->gtpu_ext.content.s.rqi = parse_qer->member_flag.d.ref_qos_present ? local_qer_priv->ref_qos : 0;
    local_qer_cfg->gtpu_ext.content.s.qfi = parse_qer->member_flag.d.qfi_present ? local_qer_priv->qfi : 0;

    if (parse_qer->member_flag.d.qfi_present ||
        parse_qer->member_flag.d.ref_qos_present ||
        parse_qer->member_flag.d.ppi_present ||
        local_qer_cfg->gtpu_ext.content.s.qmp) {

        local_qer_cfg->gtpu_ext.content.s.len = 1;
        if (parse_qer->member_flag.d.ppi_present) {
            comm_msg_gtpu_ext_ppi_field *ppi =
                (comm_msg_gtpu_ext_ppi_field *)local_qer_cfg->gtpu_ext.content.s.optional;
            ppi->s.ppi = local_qer_priv->paging_policy_indic;
            local_qer_cfg->gtpu_ext.content.s.len += 1;
        }

        if (local_qer_cfg->gtpu_ext.content.s.qmp) {
            local_qer_cfg->gtpu_ext.content.s.len += 1;
            /* 时间戳在fpu自行填充, 此处只设置时间戳填充的位置的偏移量 */
            if (local_qer_cfg->gtpu_ext.content.s.len == 2)
                local_qer_cfg->gtpu_ext.ts_ofs = 0;
            else if (local_qer_cfg->gtpu_ext.content.s.len == 3)
                local_qer_cfg->gtpu_ext.ts_ofs = 1;
        }

        local_qer_cfg->gtpu_ext.ext_len = (local_qer_cfg->gtpu_ext.content.s.len << 2) + 4;
    } else {
        local_qer_cfg->gtpu_ext.ext_len = 0;
    }
}

struct qer_table *qer_add(struct session_t *sess,
    session_qos_enforcement_rule *parse_qer_arr,
    uint32_t index, uint32_t *fail_id)
{
    struct qer_table *qer_tbl = NULL;
    session_qos_enforcement_rule *parse_qer = &parse_qer_arr[index];

    qer_tbl = qer_table_create(sess, parse_qer->qer_id);
    if (NULL == qer_tbl) {
        LOG(SESSION, ERR, "qer table create failed, qer_id %u.",
            parse_qer->qer_id);
        *fail_id = parse_qer->qer_id;
        return NULL;
    }

    ros_rwlock_write_lock(&qer_tbl->lock);/* lock */
    qer_content_copy(qer_tbl, parse_qer);
    ros_rwlock_write_unlock(&qer_tbl->lock);/* unlock */

    parse_qer->qer_index = qer_tbl->index;

    return qer_tbl;
}

struct qer_table *qer_add_predefined(session_qos_enforcement_rule *parse_qer_arr, uint32_t *fail_id)
{
    struct qer_table *qer_tbl = NULL;
    session_qos_enforcement_rule *parse_qer = parse_qer_arr;

    qer_tbl = qer_table_create_local(parse_qer->qer_id);
    if (NULL == qer_tbl) {
        LOG(SESSION, ERR, "qer table create failed, qer_id %u.",
            parse_qer->qer_id);
        *fail_id = parse_qer->qer_id;
        return NULL;
    }

    ros_rwlock_write_lock(&qer_tbl->lock);/* lock */
    qer_content_copy(qer_tbl, parse_qer);
    ros_rwlock_write_unlock(&qer_tbl->lock);/* unlock */

    return qer_tbl;
}

struct qer_table *qer_update(struct session_t *sess,
    session_qos_enforcement_rule *parse_qer_arr,
    uint32_t index, uint32_t *fail_id)
{
    struct qer_table *qer_tbl = NULL;
    session_qos_enforcement_rule *parse_qer = &parse_qer_arr[index];

    qer_tbl = qer_table_search(sess, parse_qer->qer_id);
    if (NULL == qer_tbl) {
        LOG(SESSION, ERR, "qer table create failed, qer_id %u.",
            parse_qer->qer_id);
        *fail_id = parse_qer->qer_id;
        return NULL;
    }

    ros_rwlock_write_lock(&qer_tbl->lock);/* lock */
    qer_content_copy(qer_tbl, parse_qer);
    ros_rwlock_write_unlock(&qer_tbl->lock);/* unlock */

    parse_qer->qer_index = qer_tbl->index;

    return qer_tbl;
}

static int urr_content_copy(comm_msg_urr_config *local_urr,
    session_usage_report_rule *parse_urr, struct session_t *sess)
{
    local_urr->urr_id = parse_urr->urr_id;
    /* method */
    if (parse_urr->member_flag.d.method_present) {
        local_urr->method.value = parse_urr->method.value;
    }
    /* trigger */
    if (parse_urr->member_flag.d.trigger_present) {
        local_urr->trigger.value = parse_urr->trigger.value;
    }
    /* period */
    if (parse_urr->member_flag.d.period_present) {
        local_urr->period = parse_urr->period;
    }
    /* vol_thres */
    if (parse_urr->member_flag.d.vol_thres_present) {
        local_urr->vol_thres.flag.value = parse_urr->vol_thres.flag.value;
        local_urr->vol_thres.total      = parse_urr->vol_thres.total;
        local_urr->vol_thres.uplink     = parse_urr->vol_thres.uplink;
        local_urr->vol_thres.downlink   = parse_urr->vol_thres.downlink;
    }
    /* vol_quota */
    if (parse_urr->member_flag.d.vol_quota_present) {
        local_urr->vol_quota.flag.value = parse_urr->vol_quota.flag.value;
        local_urr->vol_quota.total      = parse_urr->vol_quota.total;
        local_urr->vol_quota.uplink     = parse_urr->vol_quota.uplink;
        local_urr->vol_quota.downlink   = parse_urr->vol_quota.downlink;
    }
    /* eve_thres */
    if (parse_urr->member_flag.d.eve_thres_present) {
        local_urr->eve_thres = parse_urr->eve_thres;
    }
    /* eve_quota */
    if (parse_urr->member_flag.d.eve_quota_present) {
        local_urr->eve_quota = parse_urr->eve_quota;
    }
    /* tim_thres */
    if (parse_urr->member_flag.d.tim_thres_present) {
        local_urr->tim_thres = parse_urr->tim_thres;
    }
    /* tim_quota */
    if (parse_urr->member_flag.d.tim_quota_present) {
        local_urr->tim_quota = parse_urr->tim_quota;
    }
    /* quota_hold */
    if (parse_urr->member_flag.d.quota_hold_present) {
        local_urr->quota_hold = parse_urr->quota_hold;
    }
    /* drop_thres */
    if (parse_urr->member_flag.d.drop_thres_present) {
        local_urr->drop_thres.flag.value = parse_urr->drop_thres.flag.value;
        local_urr->drop_thres.packets   = parse_urr->drop_thres.packets;
        local_urr->drop_thres.bytes     = parse_urr->drop_thres.bytes;
    }
    /* mon_time */
    if (parse_urr->member_flag.d.mon_time_present) {
        local_urr->mon_time = parse_urr->mon_time;
    }
    /* sub_vol_thres */
    if (parse_urr->member_flag.d.sub_vol_thres_present) {
        local_urr->sub_vol_thres.flag.value =
            parse_urr->sub_vol_thres.flag.value;
        local_urr->sub_vol_thres.total      = parse_urr->sub_vol_thres.total;
        local_urr->sub_vol_thres.uplink     = parse_urr->sub_vol_thres.uplink;
        local_urr->sub_vol_thres.downlink   = parse_urr->sub_vol_thres.downlink;
    }
    /* sub_tim_thres */
    if (parse_urr->member_flag.d.sub_tim_thres_present) {
        local_urr->sub_tim_thres = parse_urr->sub_tim_thres;
    }
    /* sub_vol_quota */
    if (parse_urr->member_flag.d.sub_vol_quota_present) {
        local_urr->sub_vol_quota.flag.value =
            parse_urr->sub_vol_quota.flag.value;
        local_urr->sub_vol_quota.total      = parse_urr->sub_vol_quota.total;
        local_urr->sub_vol_quota.uplink     = parse_urr->sub_vol_quota.uplink;
        local_urr->sub_vol_quota.downlink   = parse_urr->sub_vol_quota.downlink;
    }
    /* sub_tim_quota */
    if (parse_urr->member_flag.d.sub_tim_quota_present) {
        local_urr->sub_tim_quota = parse_urr->sub_tim_quota;
    }
    /* sub_eve_thres */
    if (parse_urr->member_flag.d.sub_eve_thres_present) {
        local_urr->sub_eve_thres = parse_urr->sub_eve_thres;
    }
    /* sub_eve_quota */
    if (parse_urr->member_flag.d.sub_eve_quota_present) {
        local_urr->sub_eve_quota = parse_urr->sub_eve_quota;
    }
    /* inact_detect */
    if (parse_urr->member_flag.d.inact_detect_present) {
        local_urr->inact_detect = parse_urr->inact_detect;
    }
    /* measu_info */
    if (parse_urr->member_flag.d.measu_info_present) {
        local_urr->measu_info.value = parse_urr->measu_info.value;
    }
    /* quota_far */
    if (parse_urr->member_flag.d.quota_far_present) {
        if (G_FALSE ==
            upc_node_features_validity_query(UF_QUOAC)) {
            LOG(SESSION, ERR, "QUOAC feature not support,"
                " quota far invalid.");

            return -1;
        } else {
            /*struct far_table *far_tbl =
                far_table_search(sess, parse_urr->quota_far);
            if (NULL == far_tbl) {
                LOG(SESSION, ERR, "search far table failed, far id: %u",
                    parse_urr->quota_far);

                return -1;
            } else {
                local_urr->quota_far_present = 1;
                local_urr->quota_far = far_tbl->index;
            }*/
            local_urr->quota_far_present = 1;
            local_urr->quota_far = parse_urr->quota_far;
        }
    }
    /* eth_inact_time */
    if (parse_urr->member_flag.d.eth_inact_time_present) {
        local_urr->eth_inact_time = parse_urr->eth_inact_time;
    }
    /* linked_urr */
    if (parse_urr->linked_urr_number > 0) {
        uint8_t cnt = 0;

        local_urr->linked_urr_number = parse_urr->linked_urr_number;
        for (cnt = 0; cnt < local_urr->linked_urr_number; ++cnt) {
            local_urr->linked_urr[cnt] = parse_urr->linked_urr[cnt];
        }
    }
    /* add_mon_time */
    if (parse_urr->add_mon_time_number > 0) {
        uint8_t cnt = 0;
        comm_msg_urr_mon_time_t *dest_urr = NULL;
        session_urr_add_mon_time *src_urr = NULL;


        local_urr->add_mon_time_number = parse_urr->add_mon_time_number;
        for (cnt = 0; cnt < local_urr->add_mon_time_number; ++cnt) {
            dest_urr = &local_urr->add_mon_time[cnt];
            src_urr = &parse_urr->add_mon_time[cnt];
            /* mon_time */
            dest_urr->mon_time = src_urr->mon_time;

            /* sub_vol_thres */
            if (src_urr->member_flag.d.sub_vol_thres_present) {
                dest_urr->sub_vol_thres.flag.value =
                    src_urr->sub_vol_thres.flag.value;
                dest_urr->sub_vol_thres.total      =
                    src_urr->sub_vol_thres.total;
                dest_urr->sub_vol_thres.uplink     =
                    src_urr->sub_vol_thres.uplink;
                dest_urr->sub_vol_thres.downlink   =
                    src_urr->sub_vol_thres.downlink;
            }
            /* sub_tim_thres */
            if (src_urr->member_flag.d.sub_tim_thres_present) {
                dest_urr->sub_tim_thres = src_urr->sub_tim_thres;
            }
            /* sub_vol_quota */
            if (src_urr->member_flag.d.sub_vol_quota_present) {
                dest_urr->sub_vol_quota.flag.value =
                    src_urr->sub_vol_quota.flag.value;
                dest_urr->sub_vol_quota.total      = src_urr->sub_vol_quota.total;
                dest_urr->sub_vol_quota.uplink     = src_urr->sub_vol_quota.uplink;
                dest_urr->sub_vol_quota.downlink   = src_urr->sub_vol_quota.downlink;
            }
            /* sub_tim_quota */
            if (src_urr->member_flag.d.sub_tim_quota_present) {
                dest_urr->sub_tim_quota = src_urr->sub_tim_quota;
            }
            /* sub_eve_thres */
            if (src_urr->member_flag.d.sub_eve_thres_present) {
                dest_urr->sub_eve_thres = src_urr->sub_eve_thres;
            }
            /* sub_eve_quota */
            if (src_urr->member_flag.d.sub_eve_quota_present) {
                dest_urr->sub_eve_quota = src_urr->sub_eve_quota;
            }
        }
    }

    return 0;
}

struct urr_table *urr_add(struct session_t *sess,
    session_usage_report_rule *parse_urr_arr, uint32_t index, uint32_t *fail_id)
{
    struct urr_table *urr_tbl = NULL;
    session_usage_report_rule *parse_urr = &parse_urr_arr[index];

    urr_tbl = urr_table_create(sess, parse_urr->urr_id);
    if (NULL == urr_tbl) {
        LOG(SESSION, ERR, "urr table create failed, urr_id %u.",
            parse_urr->urr_id);
        *fail_id = parse_urr->urr_id;
        return NULL;
    }

    ros_rwlock_write_lock(&urr_tbl->lock);/* lock */
	if (0 > urr_content_copy(&urr_tbl->urr, parse_urr, sess)) {
        ros_rwlock_write_unlock(&urr_tbl->lock);/* unlock */

        uint32_t rm_id = parse_urr->urr_id;

        LOG(SESSION, ERR, "urr content copy failed, urr_id %u.",
            parse_urr->urr_id);
        urr_remove(sess, &rm_id, 1, NULL);
        *fail_id = rm_id;

        return NULL;
    }
    ros_rwlock_write_unlock(&urr_tbl->lock);/* unlock */

    parse_urr->urr_index = urr_tbl->index;

    return urr_tbl;
}

struct urr_table *urr_add_predefined(session_usage_report_rule *parse_urr_arr,uint32_t *fail_id)
{
    struct urr_table *urr_tbl = NULL;
    session_usage_report_rule *parse_urr = parse_urr_arr;

    urr_tbl = urr_table_create_local(parse_urr->urr_id);
    if (NULL == urr_tbl) {
        LOG(SESSION, ERR, "urr table create failed, urr_id %u.",
            parse_urr->urr_id);
        *fail_id = parse_urr->urr_id;
        return NULL;
    }

	ros_rwlock_write_lock(&urr_tbl->lock);/* lock */
	if (0 > urr_content_copy(&urr_tbl->urr, parse_urr, NULL)) {
        ros_rwlock_write_unlock(&urr_tbl->lock);/* unlock */

        uint32_t rm_id = parse_urr->urr_id;

        LOG(SESSION, ERR, "urr content copy failed, urr_id %u.",
            parse_urr->urr_id);

        *fail_id = rm_id;
        return NULL;
    }
	ros_rwlock_write_unlock(&urr_tbl->lock);/* unlock */

    return urr_tbl;
}

struct urr_table *urr_update(struct session_t *sess,
    session_usage_report_rule *parse_urr_arr, uint32_t index, uint32_t *fail_id)
{
    struct urr_table *urr_tbl = NULL;
    session_usage_report_rule *parse_urr = &parse_urr_arr[index];

	urr_tbl = urr_table_search(sess, parse_urr->urr_id);
    if (NULL == urr_tbl) {
        LOG(SESSION, ERR, "urr table create failed, urr_id %u.",
            parse_urr->urr_id);
        *fail_id = parse_urr->urr_id;
        return NULL;
    }

    ros_rwlock_write_lock(&urr_tbl->lock);/* lock */
    if (0 > urr_content_copy(&urr_tbl->urr, parse_urr, sess)) {
        ros_rwlock_write_unlock(&urr_tbl->lock);/* unlock */
        LOG(SESSION, ERR, "urr content copy failed, urr_id %u.",
            parse_urr->urr_id);
        urr_remove(sess, &parse_urr->urr_id, 1, NULL);

        return NULL;
    }
    ros_rwlock_write_unlock(&urr_tbl->lock);/* unlock */

    parse_urr->urr_index = urr_tbl->index;

    return urr_tbl;
}

static int assoc_traffic_endpoint_info_to_pdr(struct pdr_table *pdr_tbl, struct session_t *sess)
{
    uint8_t cnt;
    struct pkt_detection_info *local_pdi = &pdr_tbl->pdr.pdi_content;

    for (cnt = 0; cnt < local_pdi->traffic_endpoint_num; ++cnt) {
        struct traffic_endpoint_table *local_te = traffic_endpoint_table_search(sess,
            local_pdi->traffic_endpoint_id[cnt]);
        if (NULL == local_te) {
            LOG(SESSION, ERR, "Traffic endpoint(%d) associated with PDR(%d) does not exist.",
                local_pdi->traffic_endpoint_id[cnt], pdr_tbl->pdr.pdr_id);
            return -1;
        }

        if (local_te->te.member_flag.d.local_fteid_present) {
            if (local_pdi->local_fteid_num < 2) {
                ros_memcpy(&local_pdi->local_fteid[local_pdi->local_fteid_num].local_fteid,
                    &local_te->te.local_fteid, sizeof(session_f_teid));
                local_pdi->local_fteid[local_pdi->local_fteid_num].pdr_tbl = pdr_tbl;
                ++local_pdi->local_fteid_num;
            } else {
                LOG(SESSION, ERR, "PDI's local f-teid quantity exceeds the maximum(2).");
                return -1;
            }
        }
        if (local_te->te.member_flag.d.network_instance_present) {
            strcpy(local_pdi->network_instance, local_te->te.network_instance);
        }
        if (local_te->te.member_flag.d.redundant_transmission_present) {
        }
        if (local_te->te.ue_ipaddr_num) {
            uint8_t ueip_cnt;

            for (ueip_cnt = 0; ueip_cnt < local_te->te.ue_ipaddr_num; ++ueip_cnt) {
                if (local_pdi->ue_ipaddr_num < MAX_UE_IP_NUM) {
                    ros_memcpy(&local_pdi->ue_ipaddr[local_pdi->ue_ipaddr_num].ueip,
                        &local_te->te.ue_ipaddr[ueip_cnt], sizeof(session_ue_ip));
                    local_pdi->ue_ipaddr[local_pdi->ue_ipaddr_num].pdr_tbl = pdr_tbl;
                    ++local_pdi->ue_ipaddr_num;
                }  else {
                    LOG(SESSION, ERR, "PDI's ueip quantity exceeds the maximum(%d).", MAX_UE_IP_NUM);
                    return -1;
                }
            }
        }
        if (local_te->te.member_flag.d.eth_pdu_ses_info_present) {
            local_pdi->eth_pdu_ses_info.value = local_te->te.eth_pdu_ses_info.value;
        }
        if (local_te->te.framed_route_num) {
            uint8_t fr_cnt;

            for (fr_cnt = 0; fr_cnt < local_te->te.framed_route_num; ++fr_cnt) {
                if (local_pdi->framed_ipv4_route_num < MAX_FRAMED_ROUTE_NUM) {
                    ros_memcpy(&local_pdi->framed_ipv4_route[local_pdi->framed_ipv4_route_num].route,
                        &local_te->te.framed_route[fr_cnt], sizeof(session_framed_route));
                    local_pdi->framed_ipv4_route[local_pdi->framed_ipv4_route_num].pdr_tbl = pdr_tbl;
                    ++local_pdi->framed_ipv4_route_num;
                } else {
                    LOG(SESSION, ERR, "PDI's framed route quantity exceeds the maximum(%d).", MAX_FRAMED_ROUTE_NUM);
                    return -1;
                }
            }
        }
        if (local_te->te.member_flag.d.framed_routing_present) {
            local_pdi->framed_routing = local_te->te.framed_routing;
        }
        if (local_te->te.framed_ipv6_route_num) {
            uint8_t fr_cnt;

            for (fr_cnt = 0; fr_cnt < local_te->te.framed_ipv6_route_num; ++fr_cnt) {
                if (local_pdi->framed_ipv6_route_num < MAX_FRAMED_ROUTE_NUM) {
                    ros_memcpy(&local_pdi->framed_ipv6_route[local_pdi->framed_ipv6_route_num].route,
                        &local_te->te.framed_ipv6_route[fr_cnt], sizeof(session_framed_route_ipv6));
                    local_pdi->framed_ipv6_route[local_pdi->framed_ipv6_route_num].pdr_tbl = pdr_tbl;
                    ++local_pdi->framed_ipv6_route_num;
                } else {
                    LOG(SESSION, ERR, "PDI's framed ipv6 route quantity exceeds the maximum(%d).",
                        MAX_FRAMED_ROUTE_NUM);
                    return -1;
                }
            }
        }
        if (local_te->te.qfi_number) {
            if ((local_pdi->qfi_number + local_te->te.qfi_number) > MAX_QFI_NUM) {
                LOG(SESSION, ERR, "PDI's qfi quantity exceeds the maximum(%d).",
                    MAX_QFI_NUM);
                return -1;
            } else {
                ros_memcpy(&local_pdi->qfi_array[local_pdi->qfi_number], local_te->te.qfi_array,
                    sizeof(uint8_t) * local_te->te.qfi_number);
                local_pdi->qfi_number += local_te->te.qfi_number;
            }
        }
    }

    return 0;
}

static int clean_traffic_endpoint_info_of_pdr(struct pdr_table *pdr_tbl, struct session_t *sess)
{
    uint8_t cnt;
    struct pkt_detection_info *local_pdi = &pdr_tbl->pdr.pdi_content;

    for (cnt = local_pdi->traffic_endpoint_num - 1; cnt >= 0; --cnt) {
        struct traffic_endpoint_table *local_te = traffic_endpoint_table_search(sess,
            local_pdi->traffic_endpoint_id[cnt]);
        if (NULL == local_te) {
            LOG(SESSION, ERR, "Traffic endpoint(%d) associated with PDR(%d) does not exist.",
                local_pdi->traffic_endpoint_id[cnt], pdr_tbl->pdr.pdr_id);
            return -1;
        }

        if (local_te->te.member_flag.d.local_fteid_present) {
            --local_pdi->local_fteid_num;
        }
        if (local_te->te.member_flag.d.network_instance_present) {
            local_pdi->network_instance[0] = '\0';
        }
        if (local_te->te.member_flag.d.redundant_transmission_present) {
        }
        if (local_te->te.ue_ipaddr_num) {
                local_pdi->ue_ipaddr_num -= local_te->te.ue_ipaddr_num;
        }
        if (local_te->te.framed_route_num) {
            local_pdi->framed_ipv4_route_num -= local_te->te.framed_route_num;
        }
        if (local_te->te.member_flag.d.framed_routing_present) {
            local_pdi->framed_routing = 0;
        }
        if (local_te->te.framed_ipv6_route_num) {
            local_pdi->framed_ipv6_route_num -= local_te->te.framed_ipv6_route_num;
        }
        if (local_te->te.qfi_number) {
            local_pdi->qfi_number -= local_te->te.qfi_number;
        }
    }
    local_pdi->traffic_endpoint_num = 0;

    return 0;
}

static int pdr_create_content_copy(struct pdr_table *local_pdr_tbl,
    session_pdr_create *parse_pdr, struct session_t *sess)
{
    struct pkt_detection_rule *local_pdr = &local_pdr_tbl->pdr;
    uint8_t cnt;
    struct pkt_detection_info *local_pdi = &local_pdr->pdi_content;

    /* pdr_id */
    local_pdr->pdr_id = parse_pdr->pdr_id;
    /* precedence */
    if (parse_pdr->member_flag.d.precedence_present) {
        local_pdr->precedence = parse_pdr->precedence;
    }
    /* pdi_content */
    if (parse_pdr->member_flag.d.pdi_content_present) {
        /* si */
        local_pdi->si = parse_pdr->pdi_content.si;
        /* local_fteid */
        if (parse_pdr->pdi_content.member_flag.d.local_fteid_present) {
            local_pdi->local_fteid_num = 1;
            ros_memcpy(&local_pdi->local_fteid[0].local_fteid,
                &parse_pdr->pdi_content.local_fteid, sizeof(session_f_teid));
            local_pdi->local_fteid[0].pdr_tbl = local_pdr_tbl;
        }
        /* network_instance */
        if (parse_pdr->pdi_content.member_flag.d.network_instance_present) {
            ros_memcpy(&local_pdi->network_instance,
                &parse_pdr->pdi_content.network_instance, NETWORK_INSTANCE_LEN);
        }
        /* ue_ipaddr */
        local_pdi->ue_ipaddr_num = parse_pdr->pdi_content.ue_ipaddr_num;
        if (parse_pdr->pdi_content.ue_ipaddr_num) {
            for (cnt = 0; cnt < parse_pdr->pdi_content.ue_ipaddr_num; ++cnt) {
                ros_memcpy(&local_pdi->ue_ipaddr[cnt].ueip,
                    &parse_pdr->pdi_content.ue_ipaddr[cnt], sizeof(session_ue_ip));
                local_pdi->ue_ipaddr[cnt].pdr_tbl = local_pdr_tbl;
            }
        }
        /* traffic_endpoint_id */
        local_pdi->traffic_endpoint_num = parse_pdr->pdi_content.traffic_endpoint_num;
        if (parse_pdr->pdi_content.traffic_endpoint_num) {
            if (G_FALSE ==
                upc_node_features_validity_query(UF_PDIU)) {
                LOG(SESSION, ERR,
                    "PDIU feature not support, traffic endpoint id invalid.");
                return -1;
            }
            memcpy(local_pdi->traffic_endpoint_id,
                parse_pdr->pdi_content.traffic_endpoint_id, parse_pdr->pdi_content.traffic_endpoint_num);
        }
        /* application_id */
        if (parse_pdr->pdi_content.member_flag.d.application_id_present) {
            local_pdi->application_id_present = 1;
            ros_memcpy(&local_pdi->application_id,
                &parse_pdr->pdi_content.application_id, MAX_APP_ID_LEN);
        } else {
            local_pdi->application_id_present = 0;
        }
        /* eth_pdu_ses_info */
        if (parse_pdr->pdi_content.member_flag.d.eth_pdu_ses_info_present) {
            local_pdi->eth_pdu_ses_info.value =
                parse_pdr->pdi_content.eth_pdu_ses_info.value;
        }
        /* qfi_arr */
        if (parse_pdr->pdi_content.qfi_number > 0) {
            local_pdi->qfi_number = parse_pdr->pdi_content.qfi_number;
            for (cnt = 0; cnt < parse_pdr->pdi_content.qfi_number; ++cnt) {
                local_pdi->qfi_array[cnt] = parse_pdr->pdi_content.qfi_array[cnt];
            }
        }
        /* framed_route */
        if (parse_pdr->pdi_content.framed_route_num > 0) {
            if (G_FALSE ==
                upc_node_features_validity_query(UF_FRRT)) {
                LOG(SESSION, ERR,
                    "FRRT feature not support, framed route invalid.");
                return -1;
            } else {
                uint8_t fr_cnt = 0, fr_num = 0;
                struct pdr_framed_route *fr_v4 = NULL;
                session_framed_route *parse_fr = NULL;

                fr_num = parse_pdr->pdi_content.framed_route_num;
                fr_v4 = local_pdi->framed_ipv4_route;
                parse_fr = parse_pdr->pdi_content.framed_route;

                local_pdi->framed_ipv4_route_num = fr_num;
                for (fr_cnt = 0; fr_cnt < fr_num; ++fr_cnt) {
                    fr_v4[fr_cnt].pdr_tbl = local_pdr_tbl;
                    fr_v4[fr_cnt].route.dest_ip = parse_fr[fr_cnt].dest_ip;
                    fr_v4[fr_cnt].route.ip_mask = parse_fr[fr_cnt].ip_mask;
                    fr_v4[fr_cnt].route.gateway = parse_fr[fr_cnt].gateway;
                    fr_v4[fr_cnt].route.metrics = parse_fr[fr_cnt].metrics;
                }
            }
        }
        /* framed_routing */
        if (parse_pdr->pdi_content.member_flag.d.framed_routing_present) {
            if (G_FALSE ==
                upc_node_features_validity_query(UF_FRRT)) {
                LOG(SESSION, ERR,
                    "FRRT feature not support, framed route invalid.");
                return -1;
            } else {
                local_pdi->framed_routing = parse_pdr->pdi_content.framed_routing;
            }
        }
        /* framed_route_ipv6 */
        if (parse_pdr->pdi_content.framed_ipv6_route_num > 0) {
            if (G_FALSE ==
                upc_node_features_validity_query(UF_FRRT)) {
                LOG(SESSION, ERR,
                    "FRRT feature not support, framed route invalid.");
                return -1;
            } else {
                uint8_t fr_cnt = 0, fr_num = 0;
                struct pdr_framed_route_ipv6 *fr_v6 = NULL;
                session_framed_route_ipv6 *parse_fr = NULL;

                fr_num = parse_pdr->pdi_content.framed_ipv6_route_num;
                fr_v6 = local_pdi->framed_ipv6_route;
                parse_fr = parse_pdr->pdi_content.framed_ipv6_route;

                local_pdi->framed_ipv6_route_num = fr_num;
                for (fr_cnt = 0; fr_cnt < fr_num; ++fr_cnt) {
                    fr_v6[fr_cnt].pdr_tbl = local_pdr_tbl;
                    ros_memcpy(&fr_v6[fr_cnt].route, &parse_fr[fr_cnt],
                        sizeof(session_framed_route_ipv6));
                }
            }
        }
        /* src_if_type */
        if (parse_pdr->pdi_content.member_flag.d.src_if_type_present) {
            local_pdi->src_if_type.value =
                parse_pdr->pdi_content.src_if_type.value;
        }
    }
    /* OHR */
    if (parse_pdr->member_flag.d.OHR_present) {
        local_pdr->outer_header_removal.ohr_flag = 1;
        local_pdr->outer_header_removal.type =
            parse_pdr->outer_header_removal.type;
        local_pdr->outer_header_removal.flag =
            parse_pdr->outer_header_removal.gtp_u_exten;
    }
    /* far_id */
    if (parse_pdr->member_flag.d.far_id_present) {
        local_pdr->far_present = 1;
        local_pdr->far_id = parse_pdr->far_id;
    }
    /* urr_id_arr */
    if (parse_pdr->urr_id_number > 0) {
        uint8_t cnt = 0;

        local_pdr->urr_list_number = parse_pdr->urr_id_number;
        for (cnt = 0; cnt < parse_pdr->urr_id_number; ++cnt) {
            local_pdr->urr_id_array[cnt] = parse_pdr->urr_id_array[cnt];
        }
    }
    /* qer_id_arr */
    if (parse_pdr->qer_id_number > 0) {
        uint8_t cnt = 0;

        local_pdr->qer_list_number = parse_pdr->qer_id_number;
        for (cnt = 0; cnt < parse_pdr->qer_id_number; ++cnt) {
            local_pdr->qer_id_array[cnt] = parse_pdr->qer_id_array[cnt];
        }
    }
    /* act_time */
    if (parse_pdr->member_flag.d.act_time_present) {
        if (G_FALSE ==
            upc_node_features_validity_query(UF_DPDRA)) {
            LOG(SESSION, ERR,
                "DPDRA feature not support, activation time invalid.");
            return -1;
        } else {
            local_pdr->activation_time = parse_pdr->activation_time;
        }
    }
    /* deact_time */
    if (parse_pdr->member_flag.d.deact_time_present) {
        if (G_FALSE ==
            upc_node_features_validity_query(UF_DPDRA)) {
            LOG(SESSION, ERR,
                "DPDRA feature not support, deactivation time invalid.");
            return -1;
        } else {
            local_pdr->deactivation_time = parse_pdr->deactivation_time;
        }
    }
    /* mar_id */
    if (parse_pdr->member_flag.d.mar_id_present) {
        local_pdr->mar_present = 1;
        local_pdr->mar_id = parse_pdr->mar_id;
    }

    /* Associate Traffic Endpoint */
    if (0 > assoc_traffic_endpoint_info_to_pdr(local_pdr_tbl, sess)) {
        LOG(SESSION, ERR, "Association traffic endpoint info to PDR failed.");
        return -1;
    }

    return 0;
}

static int pdr_create_content_copy_local(struct pdr_table *local_pdr_tbl,
    session_pdr_create *parse_pdr)
{
    struct pkt_detection_rule *local_pdr = &local_pdr_tbl->pdr;
    uint8_t cnt;
    struct pkt_detection_info *local_pdi = &local_pdr->pdi_content;

    /* pdr_id */
    local_pdr->pdr_id = parse_pdr->pdr_id;
    /* precedence */
    if (parse_pdr->member_flag.d.precedence_present) {
        local_pdr->precedence = parse_pdr->precedence;
    }
    /* pdi_content */
    if (parse_pdr->member_flag.d.pdi_content_present) {
        /* si */
        local_pdi->si = parse_pdr->pdi_content.si;
        /* local_fteid */
        if (parse_pdr->pdi_content.member_flag.d.local_fteid_present) {
            local_pdi->local_fteid_num = 1;
            ros_memcpy(&local_pdi->local_fteid[0].local_fteid,
                &parse_pdr->pdi_content.local_fteid, sizeof(session_f_teid));
            local_pdi->local_fteid[0].pdr_tbl = local_pdr_tbl;
        }
        /* network_instance */
        if (parse_pdr->pdi_content.member_flag.d.network_instance_present) {
            ros_memcpy(&local_pdi->network_instance,
                &parse_pdr->pdi_content.network_instance, NETWORK_INSTANCE_LEN);
        }
        /* ue_ipaddr */
        local_pdi->ue_ipaddr_num = parse_pdr->pdi_content.ue_ipaddr_num;
        if (parse_pdr->pdi_content.ue_ipaddr_num) {
            for (cnt = 0; cnt < parse_pdr->pdi_content.ue_ipaddr_num; ++cnt) {
                ros_memcpy(&local_pdi->ue_ipaddr[cnt].ueip,
                    &parse_pdr->pdi_content.ue_ipaddr[cnt], sizeof(session_ue_ip));
                local_pdi->ue_ipaddr[cnt].pdr_tbl = local_pdr_tbl;
            }
        }

        /* application_id */
        if (parse_pdr->pdi_content.member_flag.d.application_id_present) {
            local_pdi->application_id_present = 1;
            ros_memcpy(&local_pdi->application_id,
                &parse_pdr->pdi_content.application_id, MAX_APP_ID_LEN);
        } else {
            local_pdi->application_id_present = 0;
        }
        /* eth_pdu_ses_info */
        if (parse_pdr->pdi_content.member_flag.d.eth_pdu_ses_info_present) {
            local_pdi->eth_pdu_ses_info.value =
                parse_pdr->pdi_content.eth_pdu_ses_info.value;
        }
        /* qfi_arr */
        if (parse_pdr->pdi_content.qfi_number > 0) {
            local_pdi->qfi_number = parse_pdr->pdi_content.qfi_number;
            for (cnt = 0; cnt < parse_pdr->pdi_content.qfi_number; ++cnt) {
                local_pdi->qfi_array[cnt] = parse_pdr->pdi_content.qfi_array[cnt];
            }
        }


        /* src_if_type */
        if (parse_pdr->pdi_content.member_flag.d.src_if_type_present) {
            local_pdi->src_if_type.value =
                parse_pdr->pdi_content.src_if_type.value;
        }
    }
    /* OHR */
    if (parse_pdr->member_flag.d.OHR_present) {
        local_pdr->outer_header_removal.ohr_flag = 1;
        local_pdr->outer_header_removal.type =
            parse_pdr->outer_header_removal.type;
        local_pdr->outer_header_removal.flag =
            parse_pdr->outer_header_removal.gtp_u_exten;
    }
    /* far_id */
    if (parse_pdr->member_flag.d.far_id_present) {
        local_pdr->far_present = 1;
        local_pdr->far_id = parse_pdr->far_id;
    }
    /* urr_id_arr */
    if (parse_pdr->urr_id_number > 0) {
        uint8_t cnt = 0;

        local_pdr->urr_list_number = parse_pdr->urr_id_number;
        for (cnt = 0; cnt < parse_pdr->urr_id_number; ++cnt) {
            local_pdr->urr_id_array[cnt] = parse_pdr->urr_id_array[cnt];
        }
    }
    /* qer_id_arr */
    if (parse_pdr->qer_id_number > 0) {
        uint8_t cnt = 0;

        local_pdr->qer_list_number = parse_pdr->qer_id_number;
        for (cnt = 0; cnt < parse_pdr->qer_id_number; ++cnt) {
            local_pdr->qer_id_array[cnt] = parse_pdr->qer_id_array[cnt];
        }
    }

    /* mar_id */
    if (parse_pdr->member_flag.d.mar_id_present) {
        local_pdr->mar_present = 1;
        local_pdr->mar_id = parse_pdr->mar_id;
    }

    return 0;
}

static int pdr_update_content_copy(struct pdr_table *local_pdr_tbl,
    session_pdr_update *parse_pdr, struct session_t *sess)
{
    struct pkt_detection_rule *local_pdr = &local_pdr_tbl->pdr;
    uint8_t cnt;
    struct pkt_detection_info *local_pdi = &local_pdr->pdi_content;

    /* pdr_id */
    local_pdr->pdr_id = parse_pdr->pdr_id;
    /* precedence */
    if (parse_pdr->member_flag.d.precedence_present) {
        local_pdr->precedence = parse_pdr->precedence;
    }
    /* pdi_content */
    if (parse_pdr->member_flag.d.pdi_content_present) {
        /* si */
        local_pdr->pdi_content.si = parse_pdr->pdi_content.si;
        /* local_fteid */
        if (parse_pdr->pdi_content.member_flag.d.local_fteid_present) {
            local_pdr->pdi_content.local_fteid_num = 1;
            ros_memcpy(&local_pdr->pdi_content.local_fteid[0].local_fteid,
                &parse_pdr->pdi_content.local_fteid, sizeof(session_f_teid));
            local_pdr->pdi_content.local_fteid[0].pdr_tbl = local_pdr_tbl;
        }
        /* network_instance */
        if (parse_pdr->pdi_content.member_flag.d.network_instance_present) {
            ros_memcpy(&local_pdr->pdi_content.network_instance,
                &parse_pdr->pdi_content.network_instance, NETWORK_INSTANCE_LEN);
        }
        /* ue_ipaddr */
        if (parse_pdr->pdi_content.ue_ipaddr_num) {
            uint8_t cnt;

            local_pdr->pdi_content.ue_ipaddr_num = parse_pdr->pdi_content.ue_ipaddr_num;
            for (cnt = 0; cnt < parse_pdr->pdi_content.ue_ipaddr_num; ++cnt) {
                ros_memcpy(&local_pdr->pdi_content.ue_ipaddr[cnt].ueip,
                    &parse_pdr->pdi_content.ue_ipaddr[cnt], sizeof(session_ue_ip));
                local_pdr->pdi_content.ue_ipaddr[cnt].pdr_tbl = local_pdr_tbl;
            }
        }
        /* traffic_endpoint_id */
        if (parse_pdr->pdi_content.traffic_endpoint_num) {
            /* 如果修改了traffic endpoint id需要先将之前同步到PDR的数据清除 */
            if (0 > clean_traffic_endpoint_info_of_pdr(local_pdr_tbl, sess)) {
                LOG(SESSION, ERR, "Clean traffic endpoint info of PDR failed.");
                return -1;
            }

            local_pdr->pdi_content.traffic_endpoint_num = parse_pdr->pdi_content.traffic_endpoint_num;
            memcpy(local_pdr->pdi_content.traffic_endpoint_id,
                parse_pdr->pdi_content.traffic_endpoint_id, parse_pdr->pdi_content.traffic_endpoint_num);
        }
        /* application_id */
        if (parse_pdr->pdi_content.member_flag.d.application_id_present) {
            local_pdi->application_id_present = 1;
            ros_memcpy(&local_pdr->pdi_content.application_id,
                &parse_pdr->pdi_content.application_id, MAX_APP_ID_LEN);
        }
        /* eth_pdu_ses_info */
        if (parse_pdr->pdi_content.member_flag.d.eth_pdu_ses_info_present) {
            local_pdr->pdi_content.eth_pdu_ses_info.value =
                parse_pdr->pdi_content.eth_pdu_ses_info.value;
        }
        /* qfi_arr */
        if (parse_pdr->pdi_content.qfi_number > 0) {
            uint8_t cnt = 0;

            local_pdr->pdi_content.qfi_number = parse_pdr->pdi_content.qfi_number;
            for (cnt = 0; cnt < parse_pdr->pdi_content.qfi_number; ++cnt) {
                local_pdr->pdi_content.qfi_array[cnt] =
                    parse_pdr->pdi_content.qfi_array[cnt];
            }
            /* 如果存在PDI和traffic endpoint 中都携带QFI IE就需要重新添加traffic endpoint的QFI
            *  为了让traffic endpoint的数据始终在数组的最后面 */
            if (parse_pdr->pdi_content.traffic_endpoint_num == 0 && local_pdr->pdi_content.traffic_endpoint_num) {
                for (cnt = 0; cnt < local_pdi->traffic_endpoint_num; ++cnt) {
                    struct traffic_endpoint_table *local_te = traffic_endpoint_table_search(sess,
                        local_pdi->traffic_endpoint_id[cnt]);
                    if (NULL == local_te) {
                        LOG(SESSION, ERR, "Traffic endpoint(%d) associated with PDR(%d) does not exist.",
                            local_pdi->traffic_endpoint_id[cnt], local_pdr->pdr_id);
                        return -1;
                    }

                    if (local_te->te.qfi_number) {
                        if ((local_pdi->qfi_number + local_te->te.qfi_number) > MAX_QFI_NUM) {
                            LOG(SESSION, ERR, "PDI's qfi quantity exceeds the maximum(%d).",
                                MAX_QFI_NUM);
                            return -1;
                        } else {
                            ros_memcpy(&local_pdi->qfi_array[local_pdi->qfi_number], local_te->te.qfi_array,
                                sizeof(uint8_t) * local_te->te.qfi_number);
                            local_pdi->qfi_number += local_te->te.qfi_number;
                        }
                    }
                }
            }
        }
        /* framed_route */
        if (parse_pdr->pdi_content.framed_route_num > 0) {
            if (G_FALSE == upc_node_features_validity_query(UF_FRRT)) {
                LOG(SESSION, ERR,
                    "FRRT feature not support, framed route invalid.");
                return -1;
            } else {
                uint8_t fr_cnt = 0, fr_num = 0;
                struct pdr_framed_route *fr_v4 = NULL;
                session_framed_route *parse_fr = NULL;

                fr_num = parse_pdr->pdi_content.framed_route_num;
                fr_v4 = local_pdr->pdi_content.framed_ipv4_route;
                parse_fr = parse_pdr->pdi_content.framed_route;

                local_pdr->pdi_content.framed_ipv4_route_num = fr_num;
                for (fr_cnt = 0; fr_cnt < fr_num; ++fr_cnt) {
                    fr_v4[fr_cnt].pdr_tbl = local_pdr_tbl;
                    fr_v4[fr_cnt].route.dest_ip = parse_fr[fr_cnt].dest_ip;
                    fr_v4[fr_cnt].route.ip_mask = parse_fr[fr_cnt].ip_mask;
                    fr_v4[fr_cnt].route.gateway = parse_fr[fr_cnt].gateway;
                    fr_v4[fr_cnt].route.metrics = parse_fr[fr_cnt].metrics;
                }

                /* 如果存在PDI和traffic endpoint 中都携带QFI IE就需要重新添加traffic endpoint的QFI
                *  为了让traffic endpoint的数据始终在数组的最后面 */
                if (parse_pdr->pdi_content.traffic_endpoint_num == 0 && local_pdr->pdi_content.traffic_endpoint_num) {
                    for (cnt = 0; cnt < local_pdi->traffic_endpoint_num; ++cnt) {
                        struct traffic_endpoint_table *local_te = traffic_endpoint_table_search(sess,
                            local_pdi->traffic_endpoint_id[cnt]);
                        if (NULL == local_te) {
                            LOG(SESSION, ERR, "Traffic endpoint(%d) associated with PDR(%d) does not exist.",
                                local_pdi->traffic_endpoint_id[cnt], local_pdr->pdr_id);
                            return -1;
                        }

                        if (local_te->te.framed_route_num) {
                            uint8_t fr_cnt;

                            for (fr_cnt = 0; fr_cnt < local_te->te.framed_route_num; ++fr_cnt) {
                                if (local_pdi->framed_ipv4_route_num < MAX_FRAMED_ROUTE_NUM) {
                                    ros_memcpy(&local_pdi->framed_ipv4_route[local_pdi->framed_ipv4_route_num].route,
                                        &local_te->te.framed_route[fr_cnt], sizeof(session_framed_route));
                                    local_pdi->framed_ipv4_route[local_pdi->framed_ipv4_route_num].pdr_tbl =
                                        local_pdr_tbl;
                                    ++local_pdi->framed_ipv4_route_num;
                                } else {
                                    LOG(SESSION, ERR, "PDI's framed route quantity exceeds the maximum(%d).",
                                        MAX_FRAMED_ROUTE_NUM);
                                    return -1;
                                }
                            }
                        }
                    }
                }
            }
        }
        /* framed_routing */
        if (parse_pdr->pdi_content.member_flag.d.framed_routing_present) {
            if (G_FALSE ==
                upc_node_features_validity_query(UF_FRRT)) {
                LOG(SESSION, ERR,
                    "FRRT feature not support, framed route invalid.");
                return -1;
            } else {
                local_pdr->pdi_content.framed_routing =
                    parse_pdr->pdi_content.framed_routing;
            }
        }
        /* framed_route_ipv6 */
        if (parse_pdr->pdi_content.framed_ipv6_route_num > 0) {
            if (G_FALSE ==
                upc_node_features_validity_query(UF_FRRT)) {
                LOG(SESSION, ERR,
                    "FRRT feature not support, framed route invalid.");
                return -1;
            } else {
                uint8_t fr_cnt = 0, fr_num = 0;
                struct pdr_framed_route_ipv6 *fr_v6 = NULL;
                session_framed_route_ipv6 *parse_fr = NULL;

                fr_num = parse_pdr->pdi_content.framed_ipv6_route_num;
                fr_v6 = local_pdr->pdi_content.framed_ipv6_route;
                parse_fr = parse_pdr->pdi_content.framed_ipv6_route;

                local_pdr->pdi_content.framed_ipv6_route_num = fr_num;
                for (fr_cnt = 0; fr_cnt < fr_num; ++fr_cnt) {
                    fr_v6[fr_cnt].pdr_tbl = local_pdr_tbl;
                    ros_memcpy(&fr_v6[fr_cnt].route, &parse_fr[fr_cnt],
                        sizeof(session_framed_route_ipv6));
                }

                /* 如果存在PDI和traffic endpoint 中都携带QFI IE就需要重新添加traffic endpoint的QFI
                *  为了让traffic endpoint的数据始终在数组的最后面 */
                if (parse_pdr->pdi_content.traffic_endpoint_num == 0 && local_pdr->pdi_content.traffic_endpoint_num) {
                    for (cnt = 0; cnt < local_pdi->traffic_endpoint_num; ++cnt) {
                        struct traffic_endpoint_table *local_te = traffic_endpoint_table_search(sess,
                            local_pdi->traffic_endpoint_id[cnt]);
                        if (NULL == local_te) {
                            LOG(SESSION, ERR, "Traffic endpoint(%d) associated with PDR(%d) does not exist.",
                                local_pdi->traffic_endpoint_id[cnt], local_pdr->pdr_id);
                            return -1;
                        }

                        if (local_te->te.framed_ipv6_route_num) {
                            uint8_t fr_cnt;

                            for (fr_cnt = 0; fr_cnt < local_te->te.framed_ipv6_route_num; ++fr_cnt) {
                                if (local_pdi->framed_ipv6_route_num < MAX_FRAMED_ROUTE_NUM) {
                                    ros_memcpy(&local_pdi->framed_ipv6_route[local_pdi->framed_ipv6_route_num].route,
                                        &local_te->te.framed_ipv6_route[fr_cnt], sizeof(session_framed_route_ipv6));
                                    local_pdi->framed_ipv6_route[local_pdi->framed_ipv6_route_num].pdr_tbl =
                                        local_pdr_tbl;
                                    ++local_pdi->framed_ipv6_route_num;
                                } else {
                                    LOG(SESSION, ERR, "PDI's framed ipv6 route quantity exceeds the maximum(%d).",
                                        MAX_FRAMED_ROUTE_NUM);
                                    return -1;
                                }
                            }
                        }
                    }
                }
            }
        }
        /* src_if_type */
        if (parse_pdr->pdi_content.member_flag.d.src_if_type_present) {
            local_pdr->pdi_content.src_if_type.value =
                parse_pdr->pdi_content.src_if_type.value;
        }
    }
    /* OHR */
    if (parse_pdr->member_flag.d.OHR_present) {
        local_pdr->outer_header_removal.type =
            parse_pdr->outer_header_removal.type;
    }
    /* far_id */
    if (parse_pdr->member_flag.d.far_id_present) {
        local_pdr->far_present = 1;
        local_pdr->far_id = parse_pdr->far_id;
    }
    /* urr_id_arr */
    if (parse_pdr->urr_id_number > 0) {
        uint8_t cnt = 0;

        local_pdr->urr_list_number = parse_pdr->urr_id_number;
        for (cnt = 0; cnt < parse_pdr->urr_id_number; ++cnt) {
            local_pdr->urr_id_array[cnt] = parse_pdr->urr_id_array[cnt];
        }
    }
    /* qer_id_arr */
    if (parse_pdr->qer_id_number > 0) {
        uint8_t cnt = 0;

        local_pdr->qer_list_number = parse_pdr->qer_id_number;
        for (cnt = 0; cnt < parse_pdr->qer_id_number; ++cnt) {
            local_pdr->qer_id_array[cnt] = parse_pdr->qer_id_array[cnt];
        }
    }
    /* act_time */
    if (parse_pdr->member_flag.d.act_time_present) {
        local_pdr->activation_time = parse_pdr->activation_time;
    }
    /* deact_time */
    if (parse_pdr->member_flag.d.deact_time_present) {
        local_pdr->deactivation_time = parse_pdr->deactivation_time;
    }

    /* Associate Traffic Endpoint */
    /* 修改了traffic endpoint id才去重新同步关联信息 */
    if (parse_pdr->pdi_content.traffic_endpoint_num) {
        if (0 > assoc_traffic_endpoint_info_to_pdr(local_pdr_tbl, sess)) {
            LOG(SESSION, ERR, "Association traffic endpoint info to PDR failed.");
            return -1;
        }
    }

    return 0;
}

void pdr_eth_filter_content_copy(struct eth_filter *local_eth,
    session_eth_filter *parse_eth)
{
    if (parse_eth->member_flag.d.eth_filter_id_present) {
        local_eth->eth_filter_id = parse_eth->eth_filter_id;
    }
    if (parse_eth->member_flag.d.eth_filter_prop_present) {
        local_eth->eth_filter_prop.value = parse_eth->eth_filter_prop.value;
    }
    local_eth->mac_addr_num = parse_eth->mac_addr_num;
    if (local_eth->mac_addr_num > 0) {
        ros_memcpy(local_eth->mac_addr, parse_eth->mac_addr,
            sizeof(session_mac_addr) * local_eth->mac_addr_num);
    }
    local_eth->eth_type = parse_eth->eth_type;
    local_eth->c_tag.value = parse_eth->c_tag.value;
    local_eth->s_tag.value = parse_eth->s_tag.value;
}

static int sdf_filter_insert(struct dl_list *sdf_list_head,
    session_sdf_filter *sdf_arr, uint8_t sdf_num)
{
    uint8_t cnt = 0;

    for (cnt = 0; cnt < sdf_num; ++cnt) {
        if (-1 == sdf_filter_create(sdf_list_head, &sdf_arr[cnt])) {
            LOG(SESSION, ERR, "sdf filter create failed.");
            return -1;
        }
    }

    return 0;
}

static int eth_filter_insert(struct dl_list *eth_list_head,
    session_eth_filter *eth_arr, uint8_t eth_num)
{
    struct eth_filter_entry *local_entry = NULL;
    uint8_t cnt = 0;

    for (cnt = 0; cnt < eth_num; ++cnt) {

        local_entry = eth_filter_create(eth_list_head, &eth_arr[cnt]);
        if (NULL == local_entry) {
            LOG(SESSION, ERR, "eth filter create failed.");
            return -1;
        }

        if (eth_arr[cnt].sdf_arr_num > 0) {
            if (-1 == sdf_filter_insert(&local_entry->eth_cfg.sdf_list,
                eth_arr[cnt].sdf_arr, eth_arr[cnt].sdf_arr_num)) {
                LOG(SESSION, ERR, "eth filter insert sdf filter failed.");
                return -1;
            }
        }
    }

    return 0;
}

int predefine_pdr_copyto_pdr(session_pdr_member_flags *member_flag,uint8_t *pfname,
	session_packet_detection_info *pdi_content_in,struct pdr_table *pdr_tbl,struct session_t *sess)
{
	struct predefine_table *pf_tbl = NULL;
	struct pdr_table    *pf_pdr_tbl = NULL;
	/*struct dl_list *pos = NULL;
    struct dl_list *next = NULL;
	struct sdf_filter_entry *sdfFilter = NULL;
    struct eth_filter_entry *ethFilter = NULL;
	struct pkt_detection_info *pdi_content = NULL;*/
	struct qer_table *qer_tbl = NULL;
	struct urr_table *urr_tbl = NULL;
	uint8_t i = 0,j = 0;

	if(pfname == NULL)
	{
		LOG(SESSION, ERR, "predefine_pdr_copyto_pdr pfname is NULL");
    	return -1;
	}

	if((pf_tbl=pf_rule_table_search(pfname)) == NULL)
	{
		LOG(SESSION, ERR, "pf_rule_table_search failed, pfname[%s]",pfname);
    	return -1;
	}

	LOG(SESSION, RUNNING, "pdi_content.si:%d [%d %d]",pdi_content_in->si,pf_tbl->pdr_index[0],pf_tbl->pdr_index[1]);
	if(pdi_content_in->si == 0)//接入侧
	{
		if((pf_pdr_tbl = pdr_get_table(pf_tbl->pdr_index[0])) == NULL)
		{
			LOG(SESSION, ERR, "pdr_get_table failed, pdr_index %u.",pf_tbl->pdr_index[0]);
        	return -1;
		}
	}
	else
	{
		if((pf_pdr_tbl = pdr_get_table(pf_tbl->pdr_index[1])) == NULL)
		{
			LOG(SESSION, ERR, "pdr_get_table failed, pdr_index %u.",pf_tbl->pdr_index[0]);
        	return -1;
		}
	}

	//如果pdr表里面没有携带far，则使用预定义的far
	if(pdr_tbl->pdr.far_present == 0)
	{
		pdr_tbl->pdr.far_present = pf_pdr_tbl->pdr.far_present;
		pdr_tbl->pdr.far_id = pf_pdr_tbl->pdr.far_id;
		pdr_tbl->pdr_pri.far_index = pf_pdr_tbl->pdr_pri.far_index;
	}

	if(pdr_tbl->pdr.mar_present == 0)
	{
		pdr_tbl->pdr.mar_present = pf_pdr_tbl->pdr.mar_present;
		pdr_tbl->pdr.mar_id = pf_pdr_tbl->pdr.mar_id;
		pdr_tbl->pdr_pri.mar_index = pf_pdr_tbl->pdr_pri.mar_index;
	}

	if(member_flag->d.OHR_present == 0)
		ros_memcpy(&pdr_tbl->pdr.outer_header_removal,&pf_pdr_tbl->pdr.outer_header_removal,sizeof(comm_msg_outh_rm_t));

	if(pdr_tbl->pdr.urr_list_number == 0)
	{
		ros_memcpy(&pdr_tbl->pdr.urr_id_array[pdr_tbl->pdr.urr_list_number],
			&pf_pdr_tbl->pdr.urr_id_array[0],sizeof(uint32_t)*(pf_pdr_tbl->pdr.urr_list_number));
		pdr_tbl->pdr.urr_list_number += pf_pdr_tbl->pdr.urr_list_number;

		//把本地urr表插入到session里面
		for(i=0;i<pf_pdr_tbl->pdr.urr_list_number && i<MAX_URR_NUM;i++)
		{
			for(j=0;j<pf_tbl->urr_num && j<MAX_PF_RULE_URR_TABLE;j++)
			{
				if(pf_pdr_tbl->pdr.urr_id_array[i] == pf_tbl->urr_id[j])
				{
					if((urr_tbl=urr_get_table(pf_tbl->urr_index[j])))
					{
						LOG(SESSION, RUNNING, "rbtree_insert session:[%x],index:[%d]",pf_pdr_tbl->pdr.urr_id_array[i],
							urr_tbl->index);
						ros_rwlock_write_lock(&sess->lock);// lock
						urr_tbl->sess = sess;
						urr_container_init(urr_tbl->index);//修改urr的上报方式后，每次引用都要初始化
						if (rbtree_insert(&sess->session.urr_root, &urr_tbl->urr_node,
					        &pf_pdr_tbl->pdr.urr_id_array[i], urr_id_compare) < 0) {
					        ros_rwlock_write_unlock(&sess->lock);// unlock
					        LOG(SESSION, ERR,
					            "urr insert failed, id: %u.", pf_pdr_tbl->pdr.urr_id_array[i]);
							continue;
					    }
						ros_rwlock_write_unlock(&sess->lock);// unlock
					}
				}
			}
		}
	}

	if(pdr_tbl->pdr.qer_list_number == 0)
	{
		ros_memcpy(&pdr_tbl->pdr.qer_id_array[pdr_tbl->pdr.qer_list_number],
			&pf_pdr_tbl->pdr.qer_id_array[0],sizeof(uint32_t)*(pf_pdr_tbl->pdr.qer_list_number));
		pdr_tbl->pdr.qer_list_number += pf_pdr_tbl->pdr.qer_list_number;
		//把本地qer表插入到session里面
		for(i=0;i<pf_pdr_tbl->pdr.qer_list_number && i<MAX_QER_NUM;i++)
		{
			for(j=0;j<pf_tbl->qer_num && j<MAX_PF_RULE_QER_TABLE;j++)
			{
				if(pf_pdr_tbl->pdr.qer_id_array[i] == pf_tbl->qer_id[j])
				{
					if((qer_tbl=qer_get_table(pf_tbl->qer_index[j])))
					{
						LOG(SESSION, RUNNING, "rbtree_insert session:[%x] index:[%d]",pf_pdr_tbl->pdr.qer_id_array[i],qer_tbl->index);
						ros_rwlock_write_lock(&sess->lock);// lock
						if (rbtree_insert(&sess->session.qer_root, &qer_tbl->qer_node,
					        &pf_pdr_tbl->pdr.qer_id_array[i], qer_id_compare_externel) < 0) {
					        ros_rwlock_write_unlock(&sess->lock);// unlock
					        LOG(SESSION, ERR,
					            "qer insert failed, id: %u.", pf_pdr_tbl->pdr.qer_id_array[i]);
							continue;
					    }
						ros_rwlock_write_unlock(&sess->lock);// unlock
					}
				}
			}
		}
	}

	/* application_id */
	if(pdi_content_in->member_flag.d.application_id_present == 0)
	{
		pdr_tbl->pdr.pdi_content.application_id_present = pf_pdr_tbl->pdr.pdi_content.application_id_present;
		ros_memcpy(&pdr_tbl->pdr.pdi_content.application_id,&pf_pdr_tbl->pdr.pdi_content.application_id, MAX_APP_ID_LEN);
	}

	//filter一般是在pdr里面带下来，而不是预定义里面配置，暂时去掉
	/*pdi_content = &pf_pdr_tbl->pdr.pdi_content;
	if ((pdi_content_in->eth_filter_num == 0) && (pdi_content->filter_type == FILTER_ETH)) {
		pdr_tbl->pdr.pdi_content.filter_type = FILTER_ETH;
		dl_list_init(&pdr_tbl->pdr.pdi_content.filter_list);
    	dl_list_for_each_safe(pos, next, &pdi_content->filter_list) {
        	ethFilter = (struct eth_filter_entry *)container_of(pos,
                             	struct eth_filter_entry, eth_filter_node);
			dl_list_add_tail(&pdr_tbl->pdr.pdi_content.filter_list, &ethFilter->eth_filter_node);
			pdr_local_eth_filter_insert_pdr(&pdr_tbl->pdr.pdi_content.filter_list, &ethFilter->eth_cfg);
        }
    } else if ((pdi_content_in->sdf_filter_num == 0) && (pdi_content->filter_type == FILTER_SDF)) {
    	pdr_tbl->pdr.pdi_content.filter_type = FILTER_SDF;
		dl_list_init(&pdr_tbl->pdr.pdi_content.filter_list);
        dl_list_for_each_safe(pos, next, &pdi_content->filter_list) {
            sdfFilter = (struct sdf_filter_entry *)container_of(pos,
                                 struct sdf_filter_entry, sdf_filter_node);
			dl_list_add_tail(&pdr_tbl->pdr.pdi_content.filter_list, &sdfFilter->sdf_filter_node);
			sdf_filter_create(&pdr_tbl->pdr.pdi_content.filter_list, &sdfFilter->sdf_cfg);
        }
    }*/

	pf_tbl->activate = 1;
	/*在预定义表里面记录下哪些pdr引用了这张预定义表，
	   用于去激活时删除pdr和inst表*/
	pf_tbl->quote_pdr_index[pf_tbl->quote_pdr_num++] = pdr_tbl->index;

	return 0;
}

struct pdr_table *pdr_add(struct session_t *sess,
    session_pdr_create *parse_pdr_arr, uint32_t index, uint32_t *fail_id)
{
    struct pdr_table    *pdr_tbl = NULL;
    session_pdr_create *parse_pdr = &parse_pdr_arr[index];

    /* create pdr table, maybe search at first */
    pdr_tbl = pdr_table_create(sess, parse_pdr->pdr_id);
    if (NULL == pdr_tbl) {
        LOG(SESSION, ERR, "pdr table create failed, pdr_id %u.",
            parse_pdr->pdr_id);
        *fail_id = parse_pdr->pdr_id;
        return NULL;
    }

    ros_rwlock_write_lock(&pdr_tbl->lock); /* lock */
	if (0 > pdr_create_content_copy(pdr_tbl, parse_pdr, sess)) {
        ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */
        uint16_t rm_id = parse_pdr->pdr_id;

        LOG(SESSION, ERR, "pdr create content copy failed.");
        pdr_remove(sess, &rm_id, 1, NULL, NULL);
        *fail_id = rm_id;

        return NULL;
    }
	dl_list_init(&pdr_tbl->pdr.pdi_content.filter_list);
    ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */

	LOG(SESSION, RUNNING, "pdr_add , act_pre_number %d.",parse_pdr->act_pre_number);

    /* Pre acquisition far index */
    if (pdr_tbl->pdr.far_present) {
        uint32_t search_id = pdr_tbl->pdr.far_id;

        struct far_table *far_tbl = far_table_search(sess, search_id);
        if (NULL == far_tbl) {
            uint16_t rm_id = pdr_tbl->pdr.pdr_id;

            LOG(SESSION, ERR, "search far table failed, far id: %u.",
                search_id);

            if (-1 == pdr_remove(sess, &rm_id, 1, NULL, NULL)) {
                LOG(SESSION, ERR,
                    "pdr remove failed, pdr id: %d.", rm_id);
            }
            *fail_id = rm_id;
            return NULL;
        }
        pdr_tbl->pdr_pri.far_index = far_tbl->index;
    }

    if (pdr_tbl->pdr.mar_present) {
        uint32_t search_id = pdr_tbl->pdr.mar_id;

        struct mar_table *mar_tbl = mar_table_search(sess, search_id);
        if (NULL == mar_tbl) {
            uint16_t rm_id = pdr_tbl->pdr.pdr_id;
            LOG(SESSION, ERR, "search mar table failed, mar id: %u.",
                search_id);

            if (-1 == pdr_remove(sess, &rm_id, 1, NULL, NULL)) {
                LOG(SESSION, ERR,
                    "pdr remove failed, pdr id: %d.", rm_id);
            }
            *fail_id = rm_id;
            return NULL;
        }
        pdr_tbl->pdr_pri.mar_index = mar_tbl->index;
    }

	if (0 < parse_pdr->pdi_content.sdf_filter_num) {
        pdr_tbl->pdr.pdi_content.filter_type = FILTER_SDF;
        if (0 > sdf_filter_insert(&pdr_tbl->pdr.pdi_content.filter_list,
            parse_pdr->pdi_content.sdf_filter,
            parse_pdr->pdi_content.sdf_filter_num)) {
            uint16_t rm_pdr_id = pdr_tbl->pdr.pdr_id;

            LOG(SESSION, ERR, "insert sdf filter failed.");
            if (-1 == pdr_remove(sess, &rm_pdr_id, 1, NULL, NULL)) {
                LOG(SESSION, ERR,
                    "pdr remove failed, pdr id: %d.", rm_pdr_id);
            }
            *fail_id = rm_pdr_id;

            return NULL;
        }
    } else if (0 < parse_pdr->pdi_content.eth_filter_num) {
        pdr_tbl->pdr.pdi_content.filter_type = FILTER_ETH;
        if (0 > eth_filter_insert(&pdr_tbl->pdr.pdi_content.filter_list,
            parse_pdr->pdi_content.eth_filter,
            parse_pdr->pdi_content.eth_filter_num)) {
            uint16_t rm_pdr_id = pdr_tbl->pdr.pdr_id;

            LOG(SESSION, ERR, "insert eth filter failed.");
            if (-1 == pdr_remove(sess, &rm_pdr_id, 1, NULL, NULL)) {
                LOG(SESSION, ERR,
                    "pdr remove failed, pdr id: %d.", rm_pdr_id);
            }
            *fail_id = rm_pdr_id;

            return NULL;
        }
    }

	if (parse_pdr->act_pre_number > 0) {
		/*找出同一名字的预定义表，根据pdr的源端口取上行
		还是下行pdr，然后填充新创建的pdr表*/
		//暂时只考虑激活一张预定义表的情况
		LOG(SESSION, RUNNING, "pfrule [%s].",parse_pdr->act_pre_arr[0].rules_name);
		if(predefine_pdr_copyto_pdr(&parse_pdr->member_flag,(uint8_t *)parse_pdr->act_pre_arr[0].rules_name,
			&parse_pdr->pdi_content,pdr_tbl,sess)<0)
		{
            uint16_t rm_id = pdr_tbl->pdr.pdr_id;

            LOG(SESSION, ERR, "predefine_pdr_copyto_pdr failed, rules_name: %s, si:%d",
                parse_pdr->act_pre_arr[0].rules_name,parse_pdr->pdi_content.si);

            if (-1 == pdr_remove(sess, &rm_id, 1, NULL, NULL)) {
                LOG(SESSION, ERR,
                    "pdr remove failed, pdr id: %d.", rm_id);
            }
            *fail_id = rm_id;
            return NULL;
	    }
		pdr_tbl->pdr.act_pre_number = parse_pdr->act_pre_number;
		memcpy(pdr_tbl->pdr.act_pre_arr,parse_pdr->act_pre_arr,
			    sizeof(session_act_predef_rules)*ACTIVATE_PREDEF_RULE_NUM);
		LOG(SESSION, RUNNING, "pdr_add predefine success, act_pre_number:%d",pdr_tbl->pdr.act_pre_number);
	}

    parse_pdr->pdr_index = pdr_tbl->index;

    return pdr_tbl;
}

struct pdr_table *pdr_update(struct session_t *sess,
    session_pdr_update *parse_pdr_arr, uint32_t index, uint32_t *fail_id)
{
    struct pdr_table *pdr_tbl = NULL;
	struct pdr_table *pf_pdr_tbl = NULL;
	struct predefine_table *pf_rule_tbl = NULL;
    session_pdr_update *parse_pdr = &parse_pdr_arr[index];
    uint8_t pdr_map_changed = 0;
	uint16_t	i;

    pdr_tbl = pdr_table_search(sess, parse_pdr->pdr_id);
    if (NULL == pdr_tbl) {
        LOG(SESSION, ERR,
            "pdr table search failed, pdr_id %u.", parse_pdr->pdr_id);
        *fail_id = parse_pdr->pdr_id;
        return NULL;
    }

    /* stop timer */
    ros_timer_stop(pdr_tbl->nocp_report_timer);
    ros_timer_stop(pdr_tbl->timer_id);

	if (parse_pdr->urr_id_number) {
		pdr_map_changed = 1;
	}
    if (parse_pdr->member_flag.d.pdi_content_present && (
        parse_pdr->pdi_content.member_flag.d.local_fteid_present ||
        parse_pdr->pdi_content.ue_ipaddr_num ||
        parse_pdr->pdi_content.framed_route_num ||
        parse_pdr->pdi_content.framed_ipv6_route_num ||
        parse_pdr->pdi_content.traffic_endpoint_num ||
        parse_pdr->pdi_content.sdf_filter_num)) {
        LOG(SESSION, DEBUG, "PDI content changed.");
        /* PDI修改的几种情况需要删除已有fast表:
        *   1) f-teid changed
        *   2) ueip changed and Source interface changed to DL
        *   3) framed route changed
        *   4) traffic endpoint id changed(默认当作会修改关键匹配信息)
        *   5) SDF filter changed
        */
        pdr_map_changed = 1;
        pdr_set_deactive_timer_cb(NULL, (uint64_t)pdr_tbl);
    } else if (parse_pdr->member_flag.d.precedence_present) {
        LOG(SESSION, DEBUG, "PDR precedence changed.");
        pdr_map_changed = 1;
        pdr_set_deactive_timer_cb(NULL, (uint64_t)pdr_tbl);
    } else if (parse_pdr->act_pre_number) {
        LOG(SESSION, DEBUG, "PDR act_pre_number changed.");
        pdr_map_changed = 1;
        pdr_set_deactive_timer_cb(NULL, (uint64_t)pdr_tbl);
    }

	//去激活预定义表时先删除inst表，保留pdr表。
	LOG(SESSION, RUNNING, "pdr update deact_pre_number[%d] [%s] ",parse_pdr->deact_pre_number,parse_pdr->deact_pre_arr[0].rules_name);
	if (parse_pdr->deact_pre_number > 0 && parse_pdr->deact_pre_number < ACTIVATE_PREDEF_RULE_NUM) {
		for (i = 0; i<parse_pdr->deact_pre_number; i++)
		{
            pf_rule_tbl = pf_rule_table_search((uint8_t *)parse_pdr->deact_pre_arr[i].rules_name);
			if (NULL != pf_rule_tbl)
			{
				LOG(SESSION, RUNNING, "pdr update quote_pdr_num[%d] [%d %d] ",pf_rule_tbl->quote_pdr_num,pf_rule_tbl->quote_pdr_index[0],
					pf_rule_tbl->quote_pdr_index[1]);
				for (i = 0; i<pf_rule_tbl->quote_pdr_num && i < MAX_PF_RULE_QUOTE_PDR_TABLE; i++)
				{
                    pf_pdr_tbl = pdr_get_table(pf_rule_tbl->quote_pdr_index[i]);
					if (NULL != pf_pdr_tbl)
					{
						pdr_set_deactive_timer_cb(NULL, (uint64_t)pf_pdr_tbl);;
					}
				}
				pf_rule_tbl->activate = 0;
			}
		}
	}

    ros_rwlock_write_lock(&pdr_tbl->lock); /* lock */
    if (0 > pdr_update_content_copy(pdr_tbl, parse_pdr, sess)) {
        ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */
        LOG(SESSION, ERR, "pdr update content copy failed.");
        *fail_id = parse_pdr->pdr_id;
        return NULL;
    }
    ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */

    if (parse_pdr->member_flag.d.far_id_present) {
        uint32_t search_id = pdr_tbl->pdr.far_id;

        struct far_table *far_tbl = far_table_search(sess, search_id);
        if (NULL == far_tbl) {
            LOG(SESSION, ERR, "search far table failed, far id: %u.",
                search_id);

            *fail_id = pdr_tbl->pdr.pdr_id;
            return NULL;
        }
        pdr_tbl->pdr_pri.far_index = far_tbl->index;
    }

    if (parse_pdr->member_flag.d.mar_id_present) {
        uint32_t search_id = pdr_tbl->pdr.mar_id;

        struct mar_table *mar_tbl = mar_table_search(sess, search_id);
        if (NULL == mar_tbl) {
            LOG(SESSION, ERR, "search mar table failed, mar id: %u.",
                search_id);

            *fail_id = pdr_tbl->pdr.pdr_id;
            return NULL;
        }
        pdr_tbl->pdr_pri.mar_index = mar_tbl->index;
    }

	if(parse_pdr->act_pre_number)
	{
		if(predefine_pdr_copyto_pdr(&parse_pdr->member_flag,(uint8_t *)parse_pdr->act_pre_arr[0].rules_name,
			&parse_pdr->pdi_content,pdr_tbl,sess)<0)
		{
			LOG(SESSION, ERR, "predefine_pdr_copyto_pdr failed, rules_name: %s, si:%d",
				parse_pdr->act_pre_arr[0].rules_name,parse_pdr->pdi_content.si);

			*fail_id = pdr_tbl->pdr.pdr_id;
			return NULL;
		}
	}

    if (pdr_map_changed) {
        if (0 > pdr_set_active(pdr_tbl)) {
	        LOG(SESSION, ERR, "Set pdr active failed.");
	    }
    }

    parse_pdr->pdr_index = pdr_tbl->index;

    return pdr_tbl;
}

static void mar_create_content_copy(struct mar_private *local_mar,
    session_mar_create *parse_mar, uint32_t node_index)
{
    /* steer_func */
    local_mar->steer_func = parse_mar->steer_func;

    /* steer_mod */
    local_mar->steer_mod = parse_mar->steer_mod;

    /* afai_1 */
    local_mar->afai_1_validity = 1;
    local_mar->afai_1.far_id = parse_mar->afai_1.far_id;
    local_mar->afai_1.member_flag.value = parse_mar->afai_1.member_flag.value;

    if (parse_mar->afai_1.member_flag.d.weight_present) {
        local_mar->afai_1.weight = parse_mar->afai_1.weight;
        local_mar->cur_weight[0] = local_mar->afai_1.weight;
    }

    if (parse_mar->afai_1.member_flag.d.priority_present) {
        local_mar->afai_1.priority = parse_mar->afai_1.priority;
    }

    if (parse_mar->afai_1.urr_num > 0) {
        uint8_t cnt = 0, max_num = parse_mar->afai_1.urr_num;
        local_mar->afai_1.urr_num = max_num;

        for (cnt = 0; cnt < max_num; ++cnt) {
            local_mar->afai_1.urr_id_arr[cnt] =
                parse_mar->afai_1.urr_id_arr[cnt];
        }
    }

    /* afai_2 */
    if (parse_mar->member_flag.d.afai_2_present) {
        local_mar->afai_2_validity = 1;
        local_mar->afai_2.far_id = parse_mar->afai_2.far_id;
        local_mar->afai_2.member_flag.value =
            parse_mar->afai_2.member_flag.value;

        if (parse_mar->afai_2.member_flag.d.weight_present) {
            local_mar->afai_2.weight = parse_mar->afai_2.weight;
            local_mar->cur_weight[1] = local_mar->afai_2.weight;
        }

        if (parse_mar->afai_2.member_flag.d.priority_present) {
            local_mar->afai_2.priority = parse_mar->afai_2.priority;
        }

        if (parse_mar->afai_2.urr_num > 0) {
            uint8_t cnt = 0, max_num = parse_mar->afai_2.urr_num;
            local_mar->afai_2.urr_num = max_num;

            for (cnt = 0; cnt < max_num; ++cnt) {
                local_mar->afai_2.urr_id_arr[cnt] =
                    parse_mar->afai_2.urr_id_arr[cnt];
            }
        }
    }
}

static void mar_update_content_copy(struct mar_private *local_mar,
    session_mar_update *parse_mar, uint32_t node_index)
{
    /* steer_func */
    if (parse_mar->member_flag.d.steer_func_present) {
        local_mar->steer_func = parse_mar->steer_func;
    }

    /* steer_mod */
    if (parse_mar->member_flag.d.steer_mod_present) {
        local_mar->steer_mod = parse_mar->steer_mod;
    }

    /* update_afai_1 */
    if (parse_mar->member_flag.d.update_afai_1_present) {
        uint8_t changed = 0;

        local_mar->afai_1.member_flag.value =
            parse_mar->update_afai_1.member_flag.value;
        if (parse_mar->update_afai_1.member_flag.d.far_id_present) {
            changed = 1;
            local_mar->afai_1.far_id = parse_mar->update_afai_1.far_id;
        }

        if (parse_mar->update_afai_1.member_flag.d.weight_present) {
            changed = 1;
            local_mar->afai_1.weight = parse_mar->update_afai_1.weight;
            local_mar->cur_weight[0] = local_mar->afai_1.weight;
        }

        if (parse_mar->update_afai_1.member_flag.d.priority_present) {
            changed = 1;
            local_mar->afai_1.priority = parse_mar->update_afai_1.priority;
        }

        if (parse_mar->update_afai_1.urr_num > 0) {
            uint8_t cnt = 0, max_num = parse_mar->update_afai_1.urr_num;
            local_mar->afai_1.urr_num = max_num;
            changed = 1;

            for (cnt = 0; cnt < max_num; ++cnt) {
                local_mar->afai_1.urr_id_arr[cnt] =
                    parse_mar->update_afai_1.urr_id_arr[cnt];
            }
        }

        if (0 == changed) {
            local_mar->afai_1_validity = 0;
        }
    }

    /* update_afai_2 */
    if (parse_mar->member_flag.d.update_afai_2_present) {
        uint8_t changed = 0;

        local_mar->afai_2.member_flag.value =
            parse_mar->update_afai_2.member_flag.value;
        if (parse_mar->update_afai_2.member_flag.d.far_id_present) {
            changed = 1;
            local_mar->afai_2.far_id = parse_mar->update_afai_2.far_id;
        }

        if (parse_mar->update_afai_2.member_flag.d.weight_present) {
            changed = 1;
            local_mar->afai_2.weight = parse_mar->update_afai_2.weight;
            local_mar->cur_weight[1] = local_mar->afai_2.weight;
        }

        if (parse_mar->update_afai_2.member_flag.d.priority_present) {
            changed = 1;
            local_mar->afai_2.priority = parse_mar->update_afai_2.priority;
        }

        if (parse_mar->update_afai_2.urr_num > 0) {
            uint8_t cnt = 0, max_num = parse_mar->update_afai_2.urr_num;
            local_mar->afai_2.urr_num = max_num;
            changed = 1;

            for (cnt = 0; cnt < max_num; ++cnt) {
                local_mar->afai_2.urr_id_arr[cnt] =
                    parse_mar->update_afai_2.urr_id_arr[cnt];
            }
        }

        if (0 == changed) {
            local_mar->afai_2_validity = 0;
        }
    }

    /* afai_1 */
    if (parse_mar->member_flag.d.afai_1_present) {
        local_mar->afai_1.far_id = parse_mar->afai_1.far_id;
        local_mar->afai_1_validity = 1;
        local_mar->afai_1.member_flag.value =
            parse_mar->afai_1.member_flag.value;

        if (parse_mar->afai_1.member_flag.d.weight_present) {
            local_mar->afai_1.weight = parse_mar->afai_1.weight;
            local_mar->cur_weight[0] = local_mar->afai_1.weight;
        }

        if (parse_mar->afai_1.member_flag.d.priority_present) {
            local_mar->afai_1.priority = parse_mar->afai_1.priority;
        }

        if (parse_mar->afai_1.urr_num > 0) {
            uint8_t cnt = 0, max_num = parse_mar->afai_1.urr_num;
            local_mar->afai_1.urr_num = max_num;

            for (cnt = 0; cnt < max_num; ++cnt) {
                local_mar->afai_1.urr_id_arr[cnt] =
                    parse_mar->afai_1.urr_id_arr[cnt];
            }
        }
    }

    /* afai_2 */
    if (parse_mar->member_flag.d.afai_2_present) {
        local_mar->afai_2.far_id = parse_mar->afai_2.far_id;
        local_mar->afai_2_validity = 1;
        local_mar->afai_2.member_flag.value =
            parse_mar->afai_2.member_flag.value;

        if (parse_mar->afai_2.member_flag.d.weight_present) {
            local_mar->afai_2.weight = parse_mar->afai_2.weight;
            local_mar->cur_weight[1] = local_mar->afai_2.weight;
        }

        if (parse_mar->afai_2.member_flag.d.priority_present) {
            local_mar->afai_2.priority = parse_mar->afai_2.priority;
        }

        if (parse_mar->afai_2.urr_num > 0) {
            uint8_t cnt = 0, max_num = parse_mar->afai_2.urr_num;
            local_mar->afai_2.urr_num = max_num;

            for (cnt = 0; cnt < max_num; ++cnt) {
                local_mar->afai_2.urr_id_arr[cnt] =
                    parse_mar->afai_2.urr_id_arr[cnt];
            }
        }
    }
}

struct mar_table *mar_add(struct session_t *sess,
    session_mar_create *parse_mar_arr, uint32_t index, uint32_t *fail_id)
{
    struct mar_table *mar_tbl = NULL;
    session_mar_create *parse_mar = &parse_mar_arr[index];

    /* create mar table */
    mar_tbl = mar_table_create(sess, parse_mar->mar_id);
    if (NULL == mar_tbl) {
        LOG(SESSION, ERR,
        	"mar table create failed, mar_id %u.", parse_mar->mar_id);
        *fail_id = parse_mar->mar_id;
        return NULL;
    }

    ros_rwlock_write_lock(&mar_tbl->lock);  /* lock */
    mar_create_content_copy(&mar_tbl->mar, parse_mar,
        sess->session.node_index);
    ros_rwlock_write_unlock(&mar_tbl->lock);  /* unlock */

    return mar_tbl;
}

struct mar_table *mar_update(struct session_t *sess,
    session_mar_update *parse_mar_arr, uint32_t index, uint32_t *fail_id)
{
    struct mar_table *mar_tbl = NULL;
    session_mar_update *parse_mar = &parse_mar_arr[index];

    /* search mar table */
    mar_tbl = mar_table_search(sess, parse_mar->mar_id);
    if (NULL == mar_tbl) {
        LOG(SESSION, ERR,
            "mar table search failed, mar_id %u.", parse_mar->mar_id);
        *fail_id = parse_mar->mar_id;
        return NULL;
    }

    ros_rwlock_write_lock(&mar_tbl->lock); /* lock */
    mar_update_content_copy(&mar_tbl->mar, parse_mar,
        sess->session.node_index);
    ros_rwlock_write_unlock(&mar_tbl->lock); /* unlock */

    return mar_tbl;
}

struct traffic_endpoint_table *traffic_endpoint_add(struct session_t *sess,
    session_tc_endpoint *parse_te_arr, uint8_t te_index)
{
    struct traffic_endpoint_table *te_tbl = NULL;
    session_tc_endpoint *parse_te = &parse_te_arr[te_index];

    te_tbl = traffic_endpoint_table_create(sess, parse_te_arr[te_index].endpoint_id);
    if (NULL == te_tbl) {
        LOG(SESSION, ERR, "traffic endpoint table create failed, traffic_endpoint_id %d.",
            parse_te_arr[te_index].endpoint_id);
        return NULL;
    }

    ros_rwlock_write_lock(&te_tbl->lock);// lock
    ros_memcpy(&te_tbl->te, parse_te, sizeof(*parse_te));
    ros_rwlock_write_unlock(&te_tbl->lock);// unlock

    return te_tbl;
}

struct traffic_endpoint_table * traffic_endpoint_update(struct session_t *sess,
    session_tc_endpoint *parse_te_arr, uint8_t te_index)
{
    struct traffic_endpoint_table *te_tbl = NULL;
    session_tc_endpoint *parse_te = &parse_te_arr[te_index];
    session_tc_endpoint old_te;

    te_tbl = traffic_endpoint_table_search(sess, parse_te->endpoint_id);
    if (NULL == te_tbl) {
        LOG(SESSION, ERR, "traffic endpoint table search failed, te_id %d.",
			parse_te->endpoint_id);
        return NULL;
    }
    ros_memcpy(&old_te, &te_tbl->te, sizeof(old_te));

    ros_rwlock_write_lock(&te_tbl->lock);// lock
    if (parse_te->member_flag.d.local_fteid_present) {
        te_tbl->te.member_flag.d.local_fteid_present = 1;
        ros_memcpy(&te_tbl->te.local_fteid, &parse_te->local_fteid, sizeof(session_f_teid));
    }
    if (parse_te->member_flag.d.network_instance_present) {
        te_tbl->te.member_flag.d.network_instance_present = 1;
        strcpy(te_tbl->te.network_instance, parse_te->network_instance);
    }
    if (parse_te->member_flag.d.redundant_transmission_present) {
        te_tbl->te.member_flag.d.redundant_transmission_present = 1;
        ros_memcpy(&te_tbl->te.redundant_transmission_param, &parse_te->redundant_transmission_param,
            sizeof(session_redundant_trans_param_in_pdi));
    }
    if (parse_te->ue_ipaddr_num) {
        te_tbl->te.ue_ipaddr_num = parse_te->ue_ipaddr_num;
        ros_memcpy(te_tbl->te.ue_ipaddr, parse_te->ue_ipaddr, sizeof(session_ue_ip) * parse_te->ue_ipaddr_num);
    }
    if (parse_te->framed_route_num) {
        te_tbl->te.framed_route_num = parse_te->framed_route_num;
        ros_memcpy(te_tbl->te.framed_route, parse_te->framed_route,
            sizeof(session_framed_route) * parse_te->framed_route_num);
    }
    if (parse_te->member_flag.d.framed_routing_present) {
        te_tbl->te.member_flag.d.framed_routing_present = 1;
        te_tbl->te.framed_routing = parse_te->framed_routing;
    }
    if (parse_te->framed_ipv6_route_num) {
        te_tbl->te.framed_ipv6_route_num = parse_te->framed_ipv6_route_num;
        ros_memcpy(te_tbl->te.framed_ipv6_route, parse_te->framed_ipv6_route,
            sizeof(session_framed_route_ipv6) * parse_te->framed_ipv6_route_num);
    }
    if (parse_te->qfi_number) {
        te_tbl->te.qfi_number = parse_te->qfi_number;
        ros_memcpy(te_tbl->te.qfi_array, parse_te->qfi_array,
            sizeof(uint8_t) * parse_te->qfi_number);
    }
    ros_rwlock_write_unlock(&te_tbl->lock);// unlock

    /* Update to PDR */
    struct pdr_table *pdr_tbl = NULL;
    struct pdr_table *pdr_tbl_arr[MAX_PDR_NUM];
    uint8_t pdr_tbl_cnt = 0, cnt, cnt_l2;
    session_pdr_update update_pdr = {0};

    /* 重新将traffic endpoint的数据同步给PDI */
    ros_rwlock_read_lock(&sess->lock);/* lock */
    pdr_tbl = (struct pdr_table *)rbtree_first(&sess->session.pdr_root);
    while (NULL != pdr_tbl) {
        for (cnt = 0; cnt < pdr_tbl->pdr.pdi_content.traffic_endpoint_num; ++cnt) {
            if (te_tbl->te.endpoint_id == pdr_tbl->pdr.pdi_content.traffic_endpoint_id[cnt]) {
                pdr_tbl_arr[pdr_tbl_cnt++] = pdr_tbl;
                break;
            }
        }

        pdr_tbl = (struct pdr_table *)rbtree_next(&pdr_tbl->pdr_node);
    }
    ros_rwlock_read_unlock(&sess->lock);/* unlock */

    for (cnt = 0; cnt < pdr_tbl_cnt; ++cnt) {
        pdr_tbl = pdr_tbl_arr[cnt];

        update_pdr.pdi_content.traffic_endpoint_num = pdr_tbl->pdr.pdi_content.traffic_endpoint_num;
        for (cnt_l2 = 0; cnt_l2 < update_pdr.pdi_content.traffic_endpoint_num; ++cnt_l2) {
            update_pdr.pdi_content.traffic_endpoint_id[cnt_l2] =
                pdr_tbl->pdr.pdi_content.traffic_endpoint_id[cnt_l2];
        }

        /* stop timer */
        ros_timer_stop(pdr_tbl->nocp_report_timer);
        ros_timer_stop(pdr_tbl->timer_id);

        pdr_set_deactive_timer_cb(NULL, (uint64_t)pdr_tbl);

        ros_rwlock_write_lock(&pdr_tbl->lock); /* lock */
        if (0 > pdr_update_content_copy(pdr_tbl, &update_pdr, sess)) {
            LOG(SESSION, ERR, "pdr update content copy failed.");
        }
        ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */

        if (0 > pdr_set_active(pdr_tbl)) {
            LOG(SESSION, ERR, "Set pdr active failed.");
        }
    }

    return te_tbl;
}

static inline void session_print_upuresponse(session_emd_response *res)
{
	LOG(SESSION, RUNNING, "res->local_seid\t\t0x%lx", res->local_seid);
	LOG(SESSION, RUNNING, "res->cp_seid\t\t0x%lx", res->cp_seid);
	LOG(SESSION, RUNNING, "res->cause\t\t%d", res->cause);

    if (res->cause > 1) {
        switch (res->failed_rule_id.rule_type) {
            case 0:
                LOG(SESSION, RUNNING, "failed rule type\tPDR");
                break;

            case 1:
                LOG(SESSION, RUNNING, "failed rule type\tFAR");
                break;

            case 2:
                LOG(SESSION, RUNNING, "failed rule type\tQER");
                break;

            case 3:
                LOG(SESSION, RUNNING, "failed rule type\tURR");
                break;

            case 4:
                LOG(SESSION, RUNNING, "failed rule type\tBAR");
                break;

            case 5:
                LOG(SESSION, RUNNING, "failed rule type\tMAR");
                break;

            default:
                LOG(SESSION, ERR, "unkonw fauled rule type %d",
                    res->failed_rule_id.rule_type);
                break;
        }

        LOG(SESSION, RUNNING, "failed rule id\t%d",
            res->failed_rule_id.rule_id);
    }
    LOG(SESSION, RUNNING, "done.\n");
}

void session_inactivity_timer_cb(void *timer, uint64_t para)
{
	struct session_t *sess = (struct session_t *)para;

	if (sess) {
		ros_timer_start(sess->inactivity_timer_id);

		if (-1 == session_report_inactivity(sess)) {
			 LOG(SESSION, ERR, "session inactivity report to upc failed.");
	   	}

	}
}

int session_predefine_rule_delete(uint8_t *predefine_name,uint32_t pf_index)
{
	struct predefine_table *pf_rule_tbl = NULL;

	if(predefine_name == NULL && pf_index == 0xffffffff)
	{
		LOG(SESSION, ERR, "predefine_name is NULL && pf_index == 0xffffffff, can't delete predefine rule table!");
		return -1;
	}

	if(predefine_name)
	{
		if((pf_rule_tbl = pf_rule_table_search(predefine_name)) == NULL)
		{
			LOG(SESSION, ERR, "pf_rule_table_search failed[%s].",predefine_name);
			return -1;
		}
	}
	else
	{
		pf_rule_tbl = pf_rule_table_get(pf_index);
	}

	/*if(pf_rule_tbl->activate)
	{
		LOG(SESSION, ERR, "predefine table[%s] is activated, can't delete!",pf_rule_tbl->predefine_name);
		return -1;
	}*/

	if(pf_rule_tbl->bar_num > 0)
	{
		bar_table_delete_local(pf_rule_tbl->bar_index);
	}

	if(pf_rule_tbl->far_num > 0)
	{
		far_table_delete_local(pf_rule_tbl->far_index,pf_rule_tbl->far_num);
	}

	if(pf_rule_tbl->qer_num > 0)
	{
		qer_table_delete_local(pf_rule_tbl->qer_index,pf_rule_tbl->qer_num);
	}

	if(pf_rule_tbl->urr_num > 0)
	{
		urr_table_delete_local(pf_rule_tbl->urr_index,pf_rule_tbl->urr_num);
	}

	if(pf_rule_tbl->pdr_num > 0)
	{
		pdr_table_delete_local(pf_rule_tbl->pdr_index,pf_rule_tbl->pdr_num);
	}

	pf_rule_table_delete(pf_rule_tbl->index);

	return 0;
}

int session_predefine_rule_create(session_content_create *session_content)
{
	uint32_t fail_id,pf_rule_id;
	uint32_t index_arr[MAX_FAR_NUM],index_cnt = 0;
	uint32_t success_cnt = 0,i=0;
	//uint32_t sdf_index;
	struct far_table *far_tbl = NULL;
	struct qer_table *qer_tbl = NULL;
	struct predefine_table *pf_rule_tbl = NULL;
	struct urr_table *urr_tbl = NULL;
	struct bar_table *bar_tbl = NULL;
	struct pdr_table *pdr_tbl = NULL;

	LOG(SESSION, RUNNING, "session_predefine_rule_create:%p",session_content);
	if(session_content == NULL)
	{
		LOG(SESSION, ERR, "sess_content is NULL, can't create predefine rule table!");
		return -1;
	}

	if((pf_rule_id = pf_rule_table_create()) < 0)
	{
		LOG(SESSION, ERR, "pf_rule_table_create failed.");
		return -1;
	}
	else
	{
		LOG(SESSION, RUNNING, "pf_rule_table_create success: %d",pf_rule_id);
		pf_rule_tbl = pf_rule_table_get(pf_rule_id);
	}

	if(pf_rule_tbl == NULL)
	{
		LOG(SESSION, ERR, "pf_rule_table_get failed.");
		return -1;
	}

	//创建bar表
	LOG(SESSION, RUNNING, "bar:%d",session_content->member_flag.d.bar_present);
	if(session_content->member_flag.d.bar_present)
	{
		if((bar_tbl=bar_add_predefined(&session_content->bar)) == NULL)
		{
			LOG(SESSION, ERR, "bar_add_predefined failed.");
			session_predefine_rule_delete(NULL,pf_rule_id);
			return -1;
		}
		else
		{
			bar_tbl->bar.time_max = 0;
			index_arr[0]=bar_tbl->index;
			index_cnt = 1;
			if (-1 == bar_fp_add_or_mod(index_arr, index_cnt, 1, MB_SEND2BE_BROADCAST_FD)) {
	            LOG(SESSION, ERR, "bar_fp_add_or_modexternal failed.");
				session_predefine_rule_delete(NULL,pf_rule_id);
				return -1;
	        }
			ros_rwlock_write_lock(&pf_rule_tbl->lock);  /* lock */
			pf_rule_tbl->bar_id =  bar_tbl->bar.bar_id;
			pf_rule_tbl->bar_index = bar_tbl->index;
			pf_rule_tbl->bar_num = 1;
			ros_rwlock_write_unlock(&pf_rule_tbl->lock);  /* unlock */
		}
	}

	//创建far表
	LOG(SESSION, RUNNING, "far_num:%d",session_content->far_num);
	if(session_content->far_num > 0)
	{
		success_cnt = 0;
		for (index_cnt = 0; index_cnt < session_content->far_num; ++index_cnt)
		{
			if((far_tbl=far_add_predefined(&session_content->far_arr[index_cnt],&fail_id)) == NULL)
			{
				LOG(SESSION, ERR, "far_add_predefined failed.");
				session_predefine_rule_delete(NULL,pf_rule_id);
				return -1;
			}
			else
			{
				if (far_tbl->far_priv.bar_id_present) {
		            ros_rwlock_write_lock(&far_tbl->lock);  /* lock */
		            far_tbl->far_cfg.choose.d.section_bar = 1;
		            far_tbl->far_cfg.bar_index = bar_tbl->index;
		            ros_rwlock_write_unlock(&far_tbl->lock);  /* unlock */
		        }

				//在fpu模块中创建far表。fpu和spu中的far表的index是一样的。
				index_arr[success_cnt]=far_tbl->index;
				success_cnt++;

				ros_rwlock_write_lock(&pf_rule_tbl->lock);  /* lock */
				pf_rule_tbl->far_id[index_cnt] = far_tbl->far_cfg.far_id;
				pf_rule_tbl->far_index[index_cnt] = far_tbl->index;
				ros_rwlock_write_unlock(&pf_rule_tbl->lock);  /* unlock */
			}
		}
		pf_rule_tbl->far_num = session_content->far_num;
		if (-1 == far_fp_add_or_mod(index_arr, success_cnt, 1, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "fp add|mod far failed.");
			session_predefine_rule_delete(NULL,pf_rule_id);
			return -1;
        }
	}

	//创建qer表
	LOG(SESSION, RUNNING, "qer_num:%d",session_content->qer_num);
	if(session_content->qer_num > 0)
	{
		success_cnt = 0;
		for (index_cnt = 0; index_cnt < session_content->qer_num; ++index_cnt)
		{
			if((qer_tbl=qer_add_predefined(&session_content->qer_arr[index_cnt],&fail_id)) == NULL)
			{
				LOG(SESSION, ERR, "qer_add_predefined failed.");
				session_predefine_rule_delete(NULL,pf_rule_id);
				return -1;
			}
			else
			{
				index_arr[success_cnt]=qer_tbl->index;
				success_cnt++;

				ros_rwlock_write_lock(&pf_rule_tbl->lock);  /* lock */
				pf_rule_tbl->qer_id[index_cnt] = session_content->qer_arr[index_cnt].qer_id;
				pf_rule_tbl->qer_index[index_cnt] = qer_tbl->index;
				ros_rwlock_write_unlock(&pf_rule_tbl->lock);  /* unlock */
			}
		}
		pf_rule_tbl->qer_num = session_content->qer_num;
		if (-1 == qer_fp_add_or_mod(index_arr, success_cnt, 1, MB_SEND2BE_BROADCAST_FD)) {
            LOG(SESSION, ERR, "fp add|mod qer failed.");
			session_predefine_rule_delete(NULL,pf_rule_id);
			return -1;
        }
	}

	//创建urr表
	LOG(SESSION, RUNNING, "urr_num:%d",session_content->urr_num);
	if(session_content->urr_num > 0)
	{
		for (index_cnt = 0; index_cnt < session_content->urr_num; ++index_cnt)
		{
			if((urr_tbl=urr_add_predefined(&session_content->urr_arr[index_cnt],&fail_id)) == NULL)
			{
				LOG(SESSION, ERR, "urr_add_predefined failed.");
				session_predefine_rule_delete(NULL,pf_rule_id);
				return -1;
			}
			else
			{
				urr_tbl->container.mon_cfg.mon_time = urr_tbl->urr.mon_time;
		        ros_memcpy(&urr_tbl->container.mon_cfg.sub_vol_thres,
		            &urr_tbl->urr.vol_thres, sizeof(comm_msg_urr_volume_t));
		        ros_memcpy(&urr_tbl->container.mon_cfg.sub_vol_quota,
		            &urr_tbl->urr.vol_quota, sizeof(comm_msg_urr_volume_t));
		        urr_tbl->container.mon_cfg.sub_tim_thres =
		            urr_tbl->urr.tim_thres;
		        urr_tbl->container.mon_cfg.sub_tim_quota =
		            urr_tbl->urr.tim_quota;
		        urr_tbl->container.mon_cfg.sub_eve_thres =
		            urr_tbl->urr.eve_thres;
		        urr_tbl->container.mon_cfg.sub_eve_quota =
		            urr_tbl->urr.eve_quota;

				LOG(SESSION, RUNNING,
		            "urr_tbl->index = %d!",urr_tbl->index);
				LOG(SESSION, RUNNING,
					"mon_time = %u!",
		            urr_tbl->container.mon_cfg.mon_time);
		        LOG(SESSION, RUNNING,
		            "sub_vol_thres flag = %d!",
		            urr_tbl->container.mon_cfg.sub_vol_thres.flag.value);
		        LOG(SESSION, RUNNING,
		            "sub_vol_thres total = %lu!",
		            urr_tbl->container.mon_cfg.sub_vol_thres.total);
		        LOG(SESSION, RUNNING,
		            "sub_vol_thres down = %lu!",
		            urr_tbl->container.mon_cfg.sub_vol_thres.downlink);
		        LOG(SESSION, RUNNING,
		            "sub_vol_thres up = %lu!",
		            urr_tbl->container.mon_cfg.sub_vol_thres.uplink);
		        LOG(SESSION, RUNNING,
		            "sub_tim_thres = %u!",
		            urr_tbl->container.mon_cfg.sub_tim_thres);
				urr_container_init(urr_tbl->index);

				ros_rwlock_write_lock(&pf_rule_tbl->lock);  /* lock */
				pf_rule_tbl->urr_id[index_cnt] = urr_tbl->urr.urr_id;
				pf_rule_tbl->urr_index[index_cnt] = urr_tbl->index;
				ros_rwlock_write_unlock(&pf_rule_tbl->lock);  /* unlock */
			}
		}
		pf_rule_tbl->urr_num = session_content->urr_num;
	}

	//创建pdr表
	LOG(SESSION, RUNNING, "pdr_num:%d",session_content->pdr_num);
	if(session_content->pdr_num > 0)
	{
		//预定义规则表里面只允许两张pdr表，上下行各一张
		for (index_cnt = 0; index_cnt < 2; ++index_cnt)
		{
		    if (NULL == (pdr_tbl = pdr_table_create_local(session_content->pdr_arr[index_cnt].pdr_id))) {
		        LOG(SESSION, ERR, "pdr table create failed, pdr_id %u.",
		            session_content->pdr_arr[index_cnt].pdr_id);
		        session_predefine_rule_delete(NULL,pf_rule_id);
				return -1;
		    }
			ros_rwlock_write_lock(&pdr_tbl->lock); /* lock */
			if (0 > pdr_create_content_copy_local(pdr_tbl, &session_content->pdr_arr[index_cnt])) {
		        ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */

		        LOG(SESSION, ERR, "pdr create content copy failed.");
		        session_predefine_rule_delete(NULL,pf_rule_id);
				return -1;
		    }
			dl_list_init(&pdr_tbl->pdr.pdi_content.filter_list);
		    ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */

			if(session_content->pdr_arr[index_cnt].pdi_content.si == 0)
			{
				//数组0记录接入侧
				pf_rule_tbl->pdr_id[0] = pdr_tbl->pdr.pdr_id;
				pf_rule_tbl->pdr_index[0] = pdr_tbl->index;
				pf_rule_tbl->pdr_num++;
			}
			else
			{
				pf_rule_tbl->pdr_id[1] = pdr_tbl->pdr.pdr_id;
				pf_rule_tbl->pdr_index[1] = pdr_tbl->index;
				pf_rule_tbl->pdr_num++;
			}

			 /* Pre acquisition far index */
		    if (pdr_tbl->pdr.far_present) {
				uint32_t search_id = pdr_tbl->pdr.far_id;
				for(i=0;i<pf_rule_tbl->far_num && i<MAX_FAR_NUM;i++)
				{
					if(pf_rule_tbl->far_id[i] == search_id)
						break;
				}
				if(i == pf_rule_tbl->far_num)
				{
					LOG(SESSION, ERR, "search far table failed, far id: %u.",
                	search_id);
					session_predefine_rule_delete(NULL,pf_rule_id);
					return -1;
				}
		        pdr_tbl->pdr_pri.far_index = pf_rule_tbl->far_index[i];
		    }

			if (0 < session_content->pdr_arr[index_cnt].pdi_content.sdf_filter_num) {
		        pdr_tbl->pdr.pdi_content.filter_type = FILTER_SDF;
		        if (0 > sdf_filter_insert(&pdr_tbl->pdr.pdi_content.filter_list,
		            session_content->pdr_arr[index_cnt].pdi_content.sdf_filter,
		            session_content->pdr_arr[index_cnt].pdi_content.sdf_filter_num)) {

		            LOG(SESSION, ERR, "insert sdf filter failed.");
		            session_predefine_rule_delete(NULL,pf_rule_id);
					return -1;
		        }
		    } else if (0 < session_content->pdr_arr[index_cnt].pdi_content.eth_filter_num) {
		        pdr_tbl->pdr.pdi_content.filter_type = FILTER_ETH;
		        if (0 > eth_filter_insert(&pdr_tbl->pdr.pdi_content.filter_list,
		            session_content->pdr_arr[index_cnt].pdi_content.eth_filter,
		            session_content->pdr_arr[index_cnt].pdi_content.eth_filter_num)) {

		            LOG(SESSION, ERR, "insert eth filter failed.");
		            session_predefine_rule_delete(NULL,pf_rule_id);
					return -1;
		        }
		    }
		}
	}

	strcpy((char *)(pf_rule_tbl->predefine_name),(char *)session_content->pdr_arr[0].act_pre_arr[0].rules_name);

	LOG(SESSION, RUNNING, "predefine_name:%s",pf_rule_tbl->predefine_name);
	LOG(SESSION, RUNNING, "index:%d",pf_rule_tbl->index);
	LOG(SESSION, RUNNING, "pdr_num:%d",pf_rule_tbl->pdr_num);
	LOG(SESSION, RUNNING, "pdr1:[%d %d] pdr2:[%d %d]",pf_rule_tbl->pdr_id[0],pf_rule_tbl->pdr_index[0],
		pf_rule_tbl->pdr_id[1],pf_rule_tbl->pdr_index[1]);
	LOG(SESSION, RUNNING, "far_num:%d",pf_rule_tbl->far_num);
	LOG(SESSION, RUNNING, "far1:[%d %d] far2:[%d %d]",pf_rule_tbl->far_id[0],pf_rule_tbl->far_index[0],
		pf_rule_tbl->far_id[1],pf_rule_tbl->far_index[1]);
	LOG(SESSION, RUNNING, "inuse:%d",pf_rule_tbl->inuse);
	LOG(SESSION, RUNNING, "activate:%d",pf_rule_tbl->activate);

	return 0;

}

void rules_sum_check(uint32_t ret_fp, struct FSM_t fsm[], uint32_t rule)
{
    struct fsm_audit *sum_audit;
    uint32_t ret_sp;

    switch (rule) {
        case EN_FAR_AUDIT:
            sum_audit = far_get_audit_simple();
            ret_sp = far_sum();
            break;

        case EN_BAR_AUDIT:
            sum_audit = bar_get_audit_simple();
            ret_sp = bar_sum();
            break;

        case EN_QER_AUDIT:
            sum_audit = qer_get_audit_simple();
            ret_sp = qer_sum();
            break;

        case EN_INST_AUDIT:
            sum_audit = session_instance_audit_simple();
            ret_sp = session_instance_sum();
            break;

        case EN_DNS_AUDIT:
            sum_audit = sdc_get_audit_simple();
            ret_sp = sdc_sum();
            break;

        default:
            LOG(SESSION, ERR, "Should not be to here, maybe coding error.");
            return;
    }

    LOG(SESSION, PERIOD, "Entry sum check, sp sum: %d, fp sum: %d.", ret_sp, ret_fp);
    if (ret_sp != ret_fp) {
        if (NORMAL == fsm[rule].cur_state) {
            if (sum_audit->last_sum_num == ret_sp) {
                LOG(SESSION, RUNNING, "Inconsistent number of entries detected.");

                if (0 > FSM_event_handle(&fsm[rule], SUM_AUDIT_FAILED)) {
                    LOG(SESSION, ERR, "FSM_event_handle process failed.");
                    LOG(SESSION, ERR, "cur state: %d, event: %d.",
                        fsm[rule].cur_state, SUM_AUDIT_FAILED);
                }
            }
        }
    }
}

void rules_stop_audit(uint32_t rule)
{
    struct fsm_audit *simple_audit;
    struct fsm_audit *_4am_audit;
    uint32_t audit_switch = get_audit_switch();

    switch (rule) {
        case EN_FAR_AUDIT:
            simple_audit = far_get_audit_simple();
            _4am_audit = far_get_audit_4am();
            break;

        case EN_BAR_AUDIT:
            simple_audit = bar_get_audit_simple();
            _4am_audit = bar_get_audit_4am();
            break;

        case EN_QER_AUDIT:
            simple_audit = qer_get_audit_simple();
            _4am_audit = qer_get_audit_4am();
            break;

        case EN_INST_AUDIT:
            simple_audit = session_instance_audit_simple();
            _4am_audit = session_instance_audit_4am();
            break;

        case EN_DNS_AUDIT:
            simple_audit = sdc_get_audit_simple();
            _4am_audit = sdc_get_audit_4am();
            break;

        default:
            LOG(SESSION, ERR, "Should not be to here, maybe coding error.");
            return;
    }

    if (audit_switch) {
        ros_timer_stop(simple_audit->audit_timer_id);
        ros_timer_stop(_4am_audit->audit_timer_id);
    }
}

void rules_start_audit(uint32_t rule)
{
    struct fsm_audit *simple_audit;
    struct fsm_audit *_4am_audit;
    uint32_t audit_switch = get_audit_switch();

    switch (rule) {
        case EN_FAR_AUDIT:
            simple_audit = far_get_audit_simple();
            _4am_audit = far_get_audit_4am();
            break;

        case EN_BAR_AUDIT:
            simple_audit = bar_get_audit_simple();
            _4am_audit = bar_get_audit_4am();
            break;

        case EN_QER_AUDIT:
            simple_audit = qer_get_audit_simple();
            _4am_audit = qer_get_audit_4am();
            break;

        case EN_INST_AUDIT:
            simple_audit = session_instance_audit_simple();
            _4am_audit = session_instance_audit_4am();
            break;

        case EN_DNS_AUDIT:
            simple_audit = sdc_get_audit_simple();
            _4am_audit = sdc_get_audit_4am();
            break;

        default:
            LOG(SESSION, ERR, "Should not be to here, maybe coding error.");
            return;
    }

    if (audit_switch) {
        uint64_t tm = get_timer_time();
        ros_timer_reset_time(_4am_audit->audit_timer_id, tm * _1_SECONDS_TIME);

        ros_timer_start(simple_audit->audit_timer_id);
    }
}

