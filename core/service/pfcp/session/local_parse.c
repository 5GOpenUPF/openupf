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
#include "white_list.h"
#include "upc_node.h"
#include "session_msg.h"
#include "urr_proc.h"
#include "session_instance.h"
#include "sp_backend_mgmt.h"
#include "sp_dns_cache.h"
#include "session_audit.h"
#include "predefine_rule_mgmt.h"

#include "local_parse.h"

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
        far_remove(sess, &rm_id, 1, NULL, NULL);
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

        local_qer_cfg->ul_pkt_max = local_qer_priv->pkt_rate_status.remain_ul_packets;
        local_qer_cfg->dl_pkt_max = local_qer_priv->pkt_rate_status.remain_dl_packets;

        local_qer_cfg->ul_pkt_max = local_qer_priv->pkt_rate_status.remain_ul_packets +
            local_qer_priv->pkt_rate_status.addit_remain_ul_packets;
        local_qer_cfg->dl_pkt_max = local_qer_priv->pkt_rate_status.remain_dl_packets +
            local_qer_priv->pkt_rate_status.addit_remain_dl_packets;
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

struct qer_table *qer_update(struct session_t *sess, session_qos_enforcement_rule *parse_qer_arr,
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
        urr_remove(sess, &rm_id, 1, NULL, NULL);
        *fail_id = rm_id;

        return NULL;
    }
    ros_rwlock_write_unlock(&urr_tbl->lock);/* unlock */

    parse_urr->urr_index = urr_tbl->index;

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
            ros_memcpy(local_pdi->network_instance,
                parse_pdr->pdi_content.network_instance, NETWORK_INSTANCE_LEN);
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
            ros_memcpy(local_pdi->application_id,
                parse_pdr->pdi_content.application_id, MAX_APP_ID_LEN);
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
            local_pdi->src_if_type_present = 1;
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
        local_pdr->urr_list_number = parse_pdr->urr_id_number;
        for (cnt = 0; cnt < parse_pdr->urr_id_number; ++cnt) {
            local_pdr->urr_id_array[cnt] = parse_pdr->urr_id_array[cnt];
        }
    }
    /* qer_id_arr */
    if (parse_pdr->qer_id_number > 0) {
        local_pdr->qer_list_number = parse_pdr->qer_id_number;
        for (cnt = 0; cnt < parse_pdr->qer_id_number; ++cnt) {
            local_pdr->qer_id_array[cnt] = parse_pdr->qer_id_array[cnt];
        }
    }
    /* Activate Predefined Rules */
    if (parse_pdr->act_pre_number > 0) {
        local_pdr->act_pre_number = parse_pdr->act_pre_number;
        ros_memcpy(local_pdr->act_pre_arr, parse_pdr->act_pre_arr,
            sizeof(session_act_predef_rules) * local_pdr->act_pre_number);
    }
    /* act_time */
    if (parse_pdr->member_flag.d.act_time_present) {
        if (G_FALSE == upc_node_features_validity_query(UF_DPDRA)) {
            LOG(SESSION, ERR,
                "DPDRA feature not support, activation time invalid.");
            return -1;
        } else {
            local_pdr->activation_time = parse_pdr->activation_time;
        }
    }
    /* deact_time */
    if (parse_pdr->member_flag.d.deact_time_present) {
        if (G_FALSE == upc_node_features_validity_query(UF_DPDRA)) {
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

static int pdr_update_content_copy(struct pdr_table *local_pdr_tbl,
    session_pdr_update *parse_pdr, struct session_t *sess)
{
    struct pkt_detection_rule *local_pdr = &local_pdr_tbl->pdr;
    struct pkt_detection_info *local_pdi = &local_pdr->pdi_content;
    uint8_t cnt;

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
            ros_memcpy(local_pdr->pdi_content.network_instance,
                parse_pdr->pdi_content.network_instance, NETWORK_INSTANCE_LEN);
        }
        /* ue_ipaddr */
        if (parse_pdr->pdi_content.ue_ipaddr_num) {
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
            ros_memcpy(local_pdr->pdi_content.application_id,
                parse_pdr->pdi_content.application_id, MAX_APP_ID_LEN);
        }
        /* eth_pdu_ses_info */
        if (parse_pdr->pdi_content.member_flag.d.eth_pdu_ses_info_present) {
            local_pdr->pdi_content.eth_pdu_ses_info.value =
                parse_pdr->pdi_content.eth_pdu_ses_info.value;
        }
        /* qfi_arr */
        if (parse_pdr->pdi_content.qfi_number > 0) {
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
            local_pdi->src_if_type_present = 1;
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
        local_pdr->urr_list_number = parse_pdr->urr_id_number;
        for (cnt = 0; cnt < parse_pdr->urr_id_number; ++cnt) {
            local_pdr->urr_id_array[cnt] = parse_pdr->urr_id_array[cnt];
        }
    }
    /* qer_id_arr */
    if (parse_pdr->qer_id_number > 0) {
        local_pdr->qer_list_number = parse_pdr->qer_id_number;
        for (cnt = 0; cnt < parse_pdr->qer_id_number; ++cnt) {
            local_pdr->qer_id_array[cnt] = parse_pdr->qer_id_array[cnt];
        }
    }
    /* Activate Predefined Rules */
    if (parse_pdr->act_pre_number > 0) {
        if (local_pdr->act_pre_number == 0) {
            local_pdr->act_pre_number = parse_pdr->act_pre_number;
            ros_memcpy(local_pdr->act_pre_arr, parse_pdr->act_pre_arr,
                sizeof(session_act_predef_rules) * local_pdr->act_pre_number);
        } else {
            LOG(SESSION, ERR, "Predefined rules are already active and cannot be activated repeatedly.");
            return -1;
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

static int pdr_predefined_content_copy(struct pdr_table *local_pdr_tbl,
    session_pdr_create *parse_pdr)
{
    struct pkt_detection_rule *local_pdr = &local_pdr_tbl->pdr;
    uint8_t cnt;
    struct pkt_detection_info *local_pdi = &local_pdr->pdi_content;

    /* pdi_content */
    if (parse_pdr->member_flag.d.pdi_content_present) {
        /* si */
        //local_pdi->si = parse_pdr->pdi_content.si;
        /* network_instance */
        if (parse_pdr->pdi_content.member_flag.d.network_instance_present) {
            ros_memcpy(&local_pdi->network_instance,
                parse_pdr->pdi_content.network_instance, NETWORK_INSTANCE_LEN);
        }
        /* application_id */
        if (parse_pdr->pdi_content.member_flag.d.application_id_present) {
            local_pdi->application_id_present = 1;
            ros_memcpy(local_pdi->application_id,
                parse_pdr->pdi_content.application_id, MAX_APP_ID_LEN);
        } else {
            local_pdi->application_id_present = 0;
        }
        /* eth_pdu_ses_info */
        if (parse_pdr->pdi_content.member_flag.d.eth_pdu_ses_info_present) {
            local_pdi->eth_pdu_ses_info.value =
                parse_pdr->pdi_content.eth_pdu_ses_info.value;
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
            if (G_FALSE == upc_node_features_validity_query(UF_FRRT)) {
                LOG(SESSION, ERR,
                    "FRRT feature not support, framed route invalid.");
                return -1;
            } else {
                local_pdi->framed_routing = parse_pdr->pdi_content.framed_routing;
            }
        }
        /* framed_route_ipv6 */
        if (parse_pdr->pdi_content.framed_ipv6_route_num > 0) {
            if (G_FALSE == upc_node_features_validity_query(UF_FRRT)) {
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
            local_pdi->src_if_type_present = 1;
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
    if (0 == local_pdr->far_present && parse_pdr->member_flag.d.far_id_present) {
        local_pdr->far_present = 1;
        local_pdr->far_id = parse_pdr->far_id;
    }
    /* urr_id_arr */
    if (parse_pdr->urr_id_number > 0) {
        if ((parse_pdr->urr_id_number + local_pdr->urr_list_number) > MAX_URR_NUM) {
            LOG(SESSION, ERR, "The number of URRs exceeds the limit.");
            return -1;
        }

        for (cnt = 0; cnt < parse_pdr->urr_id_number; ++cnt) {
            local_pdr->urr_id_array[local_pdr->urr_list_number + cnt] = parse_pdr->urr_id_array[cnt];
        }
        local_pdr->urr_list_number = parse_pdr->urr_id_number;
    }
    /* qer_id_arr */
    if (parse_pdr->qer_id_number > 0) {
        if ((parse_pdr->qer_id_number + local_pdr->qer_list_number) > MAX_QER_NUM) {
            LOG(SESSION, ERR, "The number of QERs exceeds the limit.");
            return -1;
        }

        for (cnt = 0; cnt < parse_pdr->qer_id_number; ++cnt) {
            local_pdr->qer_id_array[local_pdr->qer_list_number + cnt] = parse_pdr->qer_id_array[cnt];
        }
        local_pdr->qer_list_number = parse_pdr->qer_id_number;
    }
    /* act_time */
    if (parse_pdr->member_flag.d.act_time_present) {
        if (G_FALSE == upc_node_features_validity_query(UF_DPDRA)) {
            LOG(SESSION, ERR,
                "DPDRA feature not support, activation time invalid.");
            return -1;
        } else {
            local_pdr->activation_time = parse_pdr->activation_time;
        }
    }
    /* deact_time */
    if (parse_pdr->member_flag.d.deact_time_present) {
        if (G_FALSE == upc_node_features_validity_query(UF_DPDRA)) {
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

    return 0;
}

static int pdr_table_copy(struct pdr_table *dest_pdr_tbl, struct pdr_table *src_pdr_tbl)
{
    struct pkt_detection_rule *dest_pdr = &dest_pdr_tbl->pdr;
    struct pkt_detection_rule *src_pdr = &src_pdr_tbl->pdr;
    struct pkt_detection_info *dest_pdi = &dest_pdr->pdi_content;
    struct pkt_detection_info *src_pdi = &src_pdr->pdi_content;
    uint8_t cnt;

    /* precedence */
    dest_pdr->precedence = src_pdr->precedence;

    /* pdi_content */
    /* si */
    dest_pdi->si = src_pdi->si;

    /* dest_fteid */
    dest_pdi->local_fteid_num = src_pdi->local_fteid_num;
    for (cnt = 0; cnt < src_pdi->local_fteid_num; ++cnt) {
        ros_memcpy(&dest_pdi->local_fteid[cnt].local_fteid,
            &src_pdr->pdi_content.local_fteid[cnt].local_fteid, sizeof(session_f_teid));
        dest_pdi->local_fteid[cnt].pdr_tbl = dest_pdr_tbl;
    }
    /* network_instance */
    if (strlen(src_pdi->network_instance)) {
        strcpy(dest_pdi->network_instance, src_pdi->network_instance);
    }
    /* ue_ipaddr */
    dest_pdi->ue_ipaddr_num = src_pdi->ue_ipaddr_num;
    for (cnt = 0; cnt < src_pdi->ue_ipaddr_num; ++cnt) {
        ros_memcpy(&dest_pdi->ue_ipaddr[cnt].ueip,
            &src_pdi->ue_ipaddr[cnt].ueip, sizeof(session_ue_ip));
        dest_pdi->ue_ipaddr[cnt].pdr_tbl = dest_pdr_tbl;
    }
    /* traffic_endpoint_id */
    dest_pdi->traffic_endpoint_num = src_pdi->traffic_endpoint_num;
    if (src_pdi->traffic_endpoint_num) {
        if (G_FALSE == upc_node_features_validity_query(UF_PDIU)) {
            LOG(SESSION, ERR,
                "PDIU feature not support, traffic endpoint id invalid.");
            return -1;
        }
        memcpy(dest_pdi->traffic_endpoint_id,
            src_pdi->traffic_endpoint_id, src_pdi->traffic_endpoint_num);
    }
    /* application_id */
    if (src_pdi->application_id_present) {
        dest_pdi->application_id_present = 1;
        strcpy(dest_pdi->application_id, src_pdi->application_id);
    } else {
        dest_pdi->application_id_present = 0;
    }
    /* eth_pdu_ses_info */
    dest_pdi->eth_pdu_ses_info.value = src_pdi->eth_pdu_ses_info.value;
    /* qfi_arr */
    dest_pdi->qfi_number = src_pdi->qfi_number;
    for (cnt = 0; cnt < src_pdi->qfi_number; ++cnt) {
        dest_pdi->qfi_array[cnt] = src_pdi->qfi_array[cnt];
    }
    /* framed_route */
    if (src_pdi->framed_ipv4_route_num > 0) {
        uint8_t fr_cnt = 0, fr_num = 0;
        struct pdr_framed_route *fr_v4 = NULL;
        struct pdr_framed_route *parse_fr = NULL;

        fr_num = src_pdi->framed_ipv4_route_num;
        fr_v4 = dest_pdi->framed_ipv4_route;
        parse_fr = src_pdi->framed_ipv4_route;

        dest_pdi->framed_ipv4_route_num = fr_num;
        for (fr_cnt = 0; fr_cnt < fr_num; ++fr_cnt) {
            fr_v4[fr_cnt].pdr_tbl = dest_pdr_tbl;
            fr_v4[fr_cnt].route.dest_ip = parse_fr[fr_cnt].route.dest_ip;
            fr_v4[fr_cnt].route.ip_mask = parse_fr[fr_cnt].route.ip_mask;
            fr_v4[fr_cnt].route.gateway = parse_fr[fr_cnt].route.gateway;
            fr_v4[fr_cnt].route.metrics = parse_fr[fr_cnt].route.metrics;
        }
    }
    /* framed_routing */
    dest_pdi->framed_routing = src_pdi->framed_routing;
    /* framed_route_ipv6 */
    if (src_pdi->framed_ipv6_route_num > 0) {
        uint8_t fr_cnt = 0, fr_num = 0;
        struct pdr_framed_route_ipv6 *fr_v6 = NULL;
        struct pdr_framed_route_ipv6 *parse_fr = NULL;

        fr_num = src_pdi->framed_ipv6_route_num;
        fr_v6 = dest_pdi->framed_ipv6_route;
        parse_fr = src_pdi->framed_ipv6_route;

        dest_pdi->framed_ipv6_route_num = fr_num;
        for (fr_cnt = 0; fr_cnt < fr_num; ++fr_cnt) {
            fr_v6[fr_cnt].pdr_tbl = dest_pdr_tbl;
            ros_memcpy(&fr_v6[fr_cnt].route, &parse_fr[fr_cnt].route,
                sizeof(session_framed_route_ipv6));
        }
    }
    /* src_if_type */
    if (src_pdi->src_if_type_present) {
        dest_pdi->src_if_type_present = 1;
        dest_pdi->src_if_type.value = src_pdi->src_if_type.value;
    }

    /* OHR */
    if (src_pdr->outer_header_removal.ohr_flag) {
        dest_pdr->outer_header_removal.ohr_flag = 1;
        dest_pdr->outer_header_removal.type = src_pdr->outer_header_removal.type;
        dest_pdr->outer_header_removal.flag = src_pdr->outer_header_removal.flag;
    }
    /* far_id */
    if (src_pdr->far_present) {
        dest_pdr->far_present = 1;
        dest_pdr->far_id = src_pdr->far_id;
    }
    /* urr_id_arr */
    if (src_pdr->urr_list_number > 0) {
        dest_pdr->urr_list_number = src_pdr->urr_list_number;
        for (cnt = 0; cnt < src_pdr->urr_list_number; ++cnt) {
            dest_pdr->urr_id_array[cnt] = src_pdr->urr_id_array[cnt];
        }
    }
    /* qer_id_arr */
    if (src_pdr->qer_list_number > 0) {
        dest_pdr->qer_list_number = src_pdr->qer_list_number;
        for (cnt = 0; cnt < src_pdr->qer_list_number; ++cnt) {
            dest_pdr->qer_id_array[cnt] = src_pdr->qer_id_array[cnt];
        }
    }
    /* Activate Predefined Rules */
    /* It was already inserted when the PDR was created */
    /*if (src_pdr->act_pre_number > 0) {
        dest_pdr->act_pre_number = src_pdr->act_pre_number;
        ros_memcpy(dest_pdr->act_pre_arr, src_pdr->act_pre_arr,
            sizeof(session_act_predef_rules) * dest_pdr->act_pre_number);
    }*/
    /* act_time */
    dest_pdr->activation_time = src_pdr->activation_time;
    /* deact_time */
    dest_pdr->deactivation_time = src_pdr->deactivation_time;
    /* mar_id */
    if (src_pdr->mar_present) {
        dest_pdr->mar_present = 1;
        dest_pdr->mar_id = src_pdr->mar_id;
    }

    return 0;
}

int pdr_predefined_activate(struct session_t *sess, struct pdr_table *common_pdr, char *predef_name)
{
    struct pdr_table *pdr_tbl = NULL;
    predefined_pdr_entry *pdr_entry;
    session_pdr_create *predef_pdr;
    uint8_t erase_predef_rules = 0;

    if (NULL == sess || NULL == common_pdr || NULL == predef_name) {
        LOG(SESSION, ERR, "Abnormal parameters, sess(%p), common_pdr(%p), predef_pdr(%p).",
            sess, common_pdr, predef_name);
        return -1;
    }

    pdr_entry = predef_rules_search(predef_name);
    if (NULL == pdr_entry) {
        LOG(SESSION, ERR, "Activate pre-defined rules failed, no such name: %s",
            predef_name);
        return -1;
    }
    predef_pdr = &pdr_entry->pdr_cfg;

    /* create pdr table, maybe search at first */
    pdr_tbl = pdr_table_create_to_pdr_table(sess, common_pdr, predef_name);
    if (NULL == pdr_tbl) {
        LOG(SESSION, ERR, "PDR table create failed, predefined name: %s", predef_name);
        return -1;
    }

    ros_rwlock_write_lock(&pdr_tbl->lock); /* lock */
	if (0 > pdr_table_copy(pdr_tbl, common_pdr)) {
        ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */
        LOG(SESSION, ERR, "pdr create content copy failed.");

        goto cleanup;
    }
    /* Filling pre-defined rules */
    if (0 > pdr_predefined_content_copy(pdr_tbl, predef_pdr)) {
        ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */
        LOG(SESSION, ERR, "pdr create content copy failed.");

        goto cleanup;
    }

    if (0 > predef_rules_generate(sess, predef_name)) {
        ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */
        LOG(SESSION, ERR, "Generate pre-defined rules failed.");

        goto cleanup;
    }
    ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */
    erase_predef_rules = 1;

    /* Pre acquisition far index */
    if (pdr_tbl->pdr.far_present) {
        uint32_t search_id = pdr_tbl->pdr.far_id;
        struct far_table *far_tbl = far_table_search(sess, search_id);
        if (NULL == far_tbl) {
            LOG(SESSION, ERR, "search far table failed, far id: %u.",
                search_id);

            goto cleanup;
        }
        pdr_tbl->pdr_pri.far_index = far_tbl->index;
    }

    if (pdr_tbl->pdr.mar_present) {
        uint32_t search_id = pdr_tbl->pdr.mar_id;
        struct mar_table *mar_tbl = mar_table_search(sess, search_id);
        if (NULL == mar_tbl) {
            LOG(SESSION, ERR, "search mar table failed, mar id: %u.",
                search_id);

            goto cleanup;
        }
        pdr_tbl->pdr_pri.mar_index = mar_tbl->index;
    }

	if (0 < predef_pdr->pdi_content.sdf_filter_num) {
        pdr_tbl->pdr.pdi_content.filter_type = FILTER_SDF;
        if (0 > sdf_filter_insert(&pdr_tbl->pdr.pdi_content.filter_list,
            predef_pdr->pdi_content.sdf_filter,
            predef_pdr->pdi_content.sdf_filter_num)) {
            LOG(SESSION, ERR, "insert sdf filter failed.");

            goto cleanup;
        }
    } else if (0 < predef_pdr->pdi_content.eth_filter_num) {
        pdr_tbl->pdr.pdi_content.filter_type = FILTER_ETH;
        if (0 > eth_filter_insert(&pdr_tbl->pdr.pdi_content.filter_list,
            predef_pdr->pdi_content.eth_filter,
            predef_pdr->pdi_content.eth_filter_num)) {
            LOG(SESSION, ERR, "insert eth filter failed.");

            goto cleanup;
        }
    }
    //predef_pdr->pdr_index = pdr_tbl->index;

    if (-1 == pdr_set_active(pdr_tbl)) {
        LOG(SESSION, ERR, "PDR set active failed, predefined name: %s", predef_name);
    }

    LOG(SESSION, ERR, "Activate predefined PDR predefined name: %s", predef_name);
    pdr_table_show(pdr_tbl);

    return 0;

cleanup:

    if (-1 == pdr_remove_predefined_pdr(sess, common_pdr, predef_name)) {
        LOG(SESSION, ERR, "PDR cleanup failed, predefined name: %s", predef_name);
    }

    if (erase_predef_rules) {
        if (0 > predef_rules_erase(sess, predef_name)) {
            LOG(SESSION, ERR, "Erase pre-defined rules failed.");
        }
    }

    return -1;
}

int pdr_predefined_deactivate(struct session_t *sess, struct pdr_table *root_pdr, char *predef_name)
{
    if (NULL == sess || NULL == root_pdr || NULL == predef_name) {
        LOG(SESSION, ERR, "Abnormal parameters, sess(%p), root_pdr(%p), predef_name(%p).",
            sess, root_pdr, predef_name);
        return -1;
    }

    /* create pdr table, maybe search at first */
    if (-1 == pdr_remove_predefined_pdr(sess, root_pdr, predef_name)) {
        LOG(SESSION, DEBUG, "Predefined PDR delete failed, predefined name: %s",
            predef_name);
        /* Keep going */
    }

    if (0 > predef_rules_erase(sess, predef_name)) {
        LOG(SESSION, DEBUG, "Erase predefined rules failed.");
        /* Keep going */
    }

    return 0;
}

struct pdr_table *pdr_add(struct session_t *sess,
    session_pdr_create *parse_pdr_arr, uint32_t index, uint32_t *fail_id)
{
    struct pdr_table *pdr_tbl = NULL;
    session_pdr_create *parse_pdr = &parse_pdr_arr[index];
    uint16_t rm_pdr_id;
    uint8_t cnt;

    /* create pdr table, maybe search at first */
    pdr_tbl = pdr_table_create(sess, parse_pdr->pdr_id);
    if (NULL == pdr_tbl) {
        LOG(SESSION, ERR, "pdr table create failed, pdr_id %u.", parse_pdr->pdr_id);
        *fail_id = parse_pdr->pdr_id;
        return NULL;
    }

    ros_rwlock_write_lock(&pdr_tbl->lock); /* lock */
    if (0 > pdr_create_content_copy(pdr_tbl, parse_pdr, sess)) {
        ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */
        LOG(SESSION, ERR, "pdr create content copy failed.");

        goto cleanup;
    }
    ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */

    /* Activate pre-defined rules */
    for (cnt = 0; cnt < parse_pdr->act_pre_number; ++cnt) {
        LOG(SESSION, ERR, "Activate pre-defined rules name: %s",
            parse_pdr->act_pre_arr[cnt].rules_name);
        if (0 > pdr_predefined_activate(sess, pdr_tbl, parse_pdr->act_pre_arr[cnt].rules_name)) {
            LOG(SESSION, ERR, "Activate pre-defined PDR fail, name: %s",
                parse_pdr->act_pre_arr[cnt].rules_name);
            goto cleanup;
        }
    }

    /* Pre acquisition far index */
    if (pdr_tbl->pdr.far_present) {
        uint32_t search_id = pdr_tbl->pdr.far_id;
        struct far_table *far_tbl = far_table_search(sess, search_id);
        if (NULL == far_tbl) {
            LOG(SESSION, ERR, "search far table failed, far id: %u.",
                search_id);

            goto cleanup;
        }
        pdr_tbl->pdr_pri.far_index = far_tbl->index;
    }

    if (pdr_tbl->pdr.mar_present) {
        uint32_t search_id = pdr_tbl->pdr.mar_id;
        struct mar_table *mar_tbl = mar_table_search(sess, search_id);
        if (NULL == mar_tbl) {
            LOG(SESSION, ERR, "search mar table failed, mar id: %u.",
                search_id);

            goto cleanup;
        }
        pdr_tbl->pdr_pri.mar_index = mar_tbl->index;
    }

    if (0 < parse_pdr->pdi_content.sdf_filter_num) {
        pdr_tbl->pdr.pdi_content.filter_type = FILTER_SDF;
        if (0 > sdf_filter_insert(&pdr_tbl->pdr.pdi_content.filter_list,
            parse_pdr->pdi_content.sdf_filter,
            parse_pdr->pdi_content.sdf_filter_num)) {
            LOG(SESSION, ERR, "insert sdf filter failed.");

            goto cleanup;
        }
    } else if (0 < parse_pdr->pdi_content.eth_filter_num) {
        pdr_tbl->pdr.pdi_content.filter_type = FILTER_ETH;
        if (0 > eth_filter_insert(&pdr_tbl->pdr.pdi_content.filter_list,
            parse_pdr->pdi_content.eth_filter,
            parse_pdr->pdi_content.eth_filter_num)) {
            LOG(SESSION, ERR, "insert eth filter failed.");

            goto cleanup;
        }
    }
    parse_pdr->pdr_index = pdr_tbl->index;

    if (pdr_tbl->pdr.act_pre_number == 0) {
        if (-1 == pdr_set_active(pdr_tbl)) {
            LOG(SESSION, ERR, "pdr set active failed, pdr id: %d.",
                pdr_tbl->pdr.pdr_id);
        }
    } else {
        LOG(SESSION, RUNNING, "Include activation predefined rules.");
    }

    return pdr_tbl;

cleanup:
    rm_pdr_id = pdr_tbl->pdr.pdr_id;

    if (-1 == pdr_remove(sess, &rm_pdr_id, 1, NULL, NULL, NULL)) {
        LOG(SESSION, ERR, "pdr remove failed, pdr id: %d.", rm_pdr_id);
    }
    *fail_id = rm_pdr_id;

    for (cnt = 0; cnt < parse_pdr->act_pre_number; ++cnt) {
        if (0 > pdr_predefined_deactivate(sess, pdr_tbl, parse_pdr->act_pre_arr[cnt].rules_name)) {
            LOG(SESSION, ERR, "Deactivate pre-defined PDR fail, name: %s",
                parse_pdr->act_pre_arr[cnt].rules_name);
        }
    }

    return NULL;
}


/* Transaction consistency is not implemented in the process of rule modification */
struct pdr_table *pdr_update(struct session_t *sess,
    session_pdr_update *parse_pdr_arr, uint32_t index, uint32_t *fail_id)
{
    struct pdr_table *pdr_tbl = NULL;
    session_pdr_update *parse_pdr = &parse_pdr_arr[index];
    uint8_t pdr_map_changed = 0;
	uint8_t cnt;

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
        /* Several modification situations of PDI need to delete existing fast table:
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

	/* Deactivate predefined PDR */
    if (0 == pdr_tbl->pdr.act_pre_number && parse_pdr->deact_pre_number > 0) {
        LOG(SESSION, ERR, "Failed to deactivate the predefined rule. There is no activated predefined rule.");
    } else {
        session_act_predef_rules act_pre_arr[ACTIVATE_PREDEF_RULE_NUM];
        uint8_t act_remainder = 0;
        uint8_t act_predef_cnt;

        ros_memcpy(act_pre_arr, pdr_tbl->pdr.act_pre_arr,
            sizeof(session_act_predef_rules) * pdr_tbl->pdr.act_pre_number);
        for (cnt = 0; cnt < parse_pdr->deact_pre_number; ++cnt) {
            if (0 > pdr_predefined_deactivate(sess, pdr_tbl, parse_pdr->deact_pre_arr[cnt].rules_name)) {
                LOG(SESSION, ERR, "Deactivate pre-defined PDR fail, name: %s",
                    parse_pdr->deact_pre_arr[cnt].rules_name);
            } else {
                for (act_predef_cnt = 0; act_predef_cnt < pdr_tbl->pdr.act_pre_number; ++act_predef_cnt) {
                    if (0 == strcmp(act_pre_arr[act_predef_cnt].rules_name,
                        parse_pdr->deact_pre_arr[cnt].rules_name)) {
                        act_pre_arr[act_predef_cnt].rules_name[0] = 0;
                    }
                }
            }
        }
        for (act_predef_cnt = 0; act_predef_cnt < pdr_tbl->pdr.act_pre_number; ++act_predef_cnt) {
            if (strlen(act_pre_arr[act_predef_cnt].rules_name) > 0) {
                strcpy(pdr_tbl->pdr.act_pre_arr[act_remainder++].rules_name,
                    act_pre_arr[act_predef_cnt].rules_name);
            }
        }
        pdr_tbl->pdr.act_pre_number = act_remainder;
    }

    ros_rwlock_write_lock(&pdr_tbl->lock); /* lock */
    if (0 > pdr_update_content_copy(pdr_tbl, parse_pdr, sess)) {
        ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */
        LOG(SESSION, ERR, "pdr update content copy failed.");
        goto fail;
    }
    ros_rwlock_write_unlock(&pdr_tbl->lock); /* unlock */

    if (parse_pdr->member_flag.d.far_id_present) {
        uint32_t search_id = pdr_tbl->pdr.far_id;

        struct far_table *far_tbl = far_table_search(sess, search_id);
        if (NULL == far_tbl) {
            LOG(SESSION, ERR, "search far table failed, far id: %u.",
                search_id);

            goto fail;
        }
        pdr_tbl->pdr_pri.far_index = far_tbl->index;
    }

    if (parse_pdr->member_flag.d.mar_id_present) {
        uint32_t search_id = pdr_tbl->pdr.mar_id;

        struct mar_table *mar_tbl = mar_table_search(sess, search_id);
        if (NULL == mar_tbl) {
            LOG(SESSION, ERR, "search mar table failed, mar id: %u.",
                search_id);

            goto fail;
        }
        pdr_tbl->pdr_pri.mar_index = mar_tbl->index;
    }

    /* Activate predefined PDR */
    for (cnt = 0; cnt < parse_pdr->act_pre_number; ++cnt) {
        LOG(SESSION, ERR, "Activate pre-defined rules name: %s",
            parse_pdr->act_pre_arr[cnt].rules_name);
        if (0 > pdr_predefined_activate(sess, pdr_tbl, parse_pdr->act_pre_arr[cnt].rules_name)) {
            LOG(SESSION, ERR, "Activate pre-defined PDR fail, name: %s",
                parse_pdr->act_pre_arr[cnt].rules_name);
            /* In this case, rollback should be considered */
            goto fail;
        }
    }

    if (pdr_map_changed) {
        if (0 > pdr_set_active(pdr_tbl)) {
	        LOG(SESSION, ERR, "Set pdr active failed.");
	    }
    }

    parse_pdr->pdr_index = pdr_tbl->index;

    return pdr_tbl;

fail:

    *fail_id = parse_pdr->pdr_id;
    return NULL;
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
            sizeof(session_redundant_transmission_detection_param));
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

