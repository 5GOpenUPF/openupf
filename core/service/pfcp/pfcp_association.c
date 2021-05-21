/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "pfcp_def.h"
#include "upc_node.h"
#include "pfcp_client.h"
#include "pfcp_association.h"
#include "upc_seid.h"
#include "upc_session.h"
#include "upc_ueip.h"

static PFCP_CAUSE_TYPE pfcp_parse_alt_smf_ip_addr(session_alternative_smf_addr *asia,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            asia->flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* ipv4 address */
        if (asia->flag.d.v4) {
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                asia->ipv4 = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }
        /* ipv6 address */
        if (asia->flag.d.v6) {
            len_cnt += IPV6_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, IPV6_ALEN, asia->ipv6);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }
    } else {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE length error.");
    }

    if (len_cnt != obj_len) {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE parse length: %d != obj_len: %d.",
            len_cnt, obj_len);
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE pfcp_parse_entity_ip_address(session_cp_pfcp_entity_ip_address *entity_ip,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            entity_ip->flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        if (entity_ip->flag.d.v4) {
            /* ipv4 address */
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                entity_ip->ipv4 = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (entity_ip->flag.d.v6) {
            /* ipv6 address */
            len_cnt += IPV6_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, IPV6_ALEN, entity_ip->ipv6);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

    } else {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE length error.");
    }

    if (len_cnt != obj_len) {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE parse length: %d != obj_len: %d.",
            len_cnt, obj_len);
    }

    return res_cause;
}

PFCP_CAUSE_TYPE pfcp_parse_remote_gtpu_peer(session_remote_gtpu_peer *remote_gtpu,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            remote_gtpu->regtpr_flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        if (remote_gtpu->regtpr_flag.d.V4) {
            /* ipv4 address */
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                remote_gtpu->ipv4_addr = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (remote_gtpu->regtpr_flag.d.V6) {
            /* ipv6 address */
            len_cnt += IPV6_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, IPV6_ALEN, remote_gtpu->ipv6_addr);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (remote_gtpu->regtpr_flag.d.DI) {
            /* Destination Interface field */
            remote_gtpu->des_if_len = tlv_decode_uint16_t(buffer, buf_pos);
            len_cnt += remote_gtpu->des_if_len;
            if (len_cnt <= obj_len && remote_gtpu->des_if_len == 1) {
                remote_gtpu->dest_if = tlv_decode_uint8_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (remote_gtpu->regtpr_flag.d.NI) {
            /* Network Instance field */
            remote_gtpu->net_inst_len = tlv_decode_uint16_t(buffer, buf_pos);
            len_cnt += remote_gtpu->net_inst_len;
            if (len_cnt <= obj_len) {
                if (remote_gtpu->net_inst_len >= NETWORK_INSTANCE_LEN) {
                    LOG(UPC, ERR, "network instance length too long, should be less than %d.",
                        NETWORK_INSTANCE_LEN);
                }
                tlv_decode_binary(buffer, buf_pos, remote_gtpu->net_inst_len,
                    (uint8_t *)remote_gtpu->net_instance);
                remote_gtpu->net_instance[remote_gtpu->net_inst_len] = '\0';
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

    } else {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE length error.");
    }

    if (len_cnt != obj_len) {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE parse length: %d != obj_len: %d.",
            len_cnt, obj_len);
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE pfcp_parse_retention_info(session_retention_information *ri,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;

    LOG(UPC, RUNNING, "Parse PFCP Session Retention Information.");
    /* Parse packet */
    while (*buf_pos < buf_max) {
        if (((TLV_TYPE_LEN + TLV_LENGTH_LEN) + *buf_pos) <= buf_max) {
            obj_type = tlv_decode_type(buffer, buf_pos, buf_max);
            obj_len  = tlv_decode_length(buffer, buf_pos, buf_max);
        } else {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "buff len abnormal.");
            break;
        }

        if ((obj_len + *buf_pos) > buf_max) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING,
                "IE value length error, obj_len: %d, buf_pos: %d, buf_max: %d.",
                obj_len, *buf_pos, buf_max);
            break;
        }

        switch (obj_type) {
            case UPF_CP_PFCP_ENTITY_IP_ADDRESS:
                if (ri->cp_pfcp_entity_ip_num < CP_PFCP_ENTITY_IP_NUM) {
                    res_cause = pfcp_parse_entity_ip_address(
                        &ri->cp_pfcp_entity_ip[ri->cp_pfcp_entity_ip_num], buffer,
                        buf_pos, buf_max, obj_len);
                    ++ri->cp_pfcp_entity_ip_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of CP PFCP Entity IP Address number reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            default:
                LOG(UPC, RUNNING,
                    "type %d, not support.", obj_type);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        if (last_pos == *buf_pos) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "empty ie.");
            break;
        } else {
            last_pos = *buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            LOG(UPC, RUNNING, "parse abnormal.");
            break;
        }
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE pfcp_parse_gtpu_path_qos_ctrl_info(session_gtpu_path_qos_control_info *qos_ctrl,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse PFCP Session Retention Information.");
    /* Parse packet */
    while (*buf_pos < buf_max) {
        if (((TLV_TYPE_LEN + TLV_LENGTH_LEN) + *buf_pos) <= buf_max) {
            obj_type = tlv_decode_type(buffer, buf_pos, buf_max);
            obj_len  = tlv_decode_length(buffer, buf_pos, buf_max);
        } else {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "buff len abnormal.");
            break;
        }

        if ((obj_len + *buf_pos) > buf_max) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING,
                "IE value length error, obj_len: %d, buf_pos: %d, buf_max: %d.",
                obj_len, *buf_pos, buf_max);
            break;
        }

        switch (obj_type) {
            case UPF_REMOTE_GTP_U_PEER:
                if (qos_ctrl->remote_gtpu_peer_num < REMOTE_GTPU_PEER_NUM) {
                    res_cause = pfcp_parse_remote_gtpu_peer(
                        &qos_ctrl->remote_gtpu_peer[qos_ctrl->remote_gtpu_peer_num], buffer,
                        buf_pos, buf_max, obj_len);
                    ++qos_ctrl->remote_gtpu_peer_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of CP PFCP Entity IP Address number reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_GTP_U_PATH_INTERFACE_TYPE:
                if (sizeof(uint8_t) == obj_len) {
                    qos_ctrl->member_flag.d.gtpu_path_if_type_present = 1;
                    qos_ctrl->gtpu_path_if_type.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_QOS_REPORT_TRIGGER:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    qos_ctrl->qos_report_trigeer.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_TRANSPORT_LEVEL_MARKING:
                if (sizeof(uint16_t) == obj_len) {
                    qos_ctrl->member_flag.d.dscp_present = 1;
                    qos_ctrl->dscp.value = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MEASUREMENT_PERIOD:
                if (sizeof(uint32_t) == obj_len) {
                    qos_ctrl->member_flag.d.measurement_period_present = 1;
                    qos_ctrl->measurement_period = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_AVERAGE_PACKET_DELAY:
                if (sizeof(uint32_t) == obj_len) {
                    qos_ctrl->member_flag.d.ave_packet_delay_thr_present = 1;
                    qos_ctrl->ave_packet_delay_thr = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MINIMUM_PACKET_DELAY:
                if (sizeof(uint32_t) == obj_len) {
                    qos_ctrl->member_flag.d.min_packet_delay_thr_present = 1;
                    qos_ctrl->min_packet_delay_thr = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MAXIMUM_PACKET_DELAY:
                if (sizeof(uint32_t) == obj_len) {
                    qos_ctrl->member_flag.d.max_packet_delay_thr_present = 1;
                    qos_ctrl->max_packet_delay_thr = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_TIMER:
                if (sizeof(uint8_t) == obj_len) {
                    qos_ctrl->member_flag.d.min_waiting_time_present = 1;
                    qos_ctrl->min_waiting_time.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, RUNNING,
                    "type %d, not support.", obj_type);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        if (last_pos == *buf_pos) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "empty ie.");
            break;
        } else {
            last_pos = *buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            LOG(UPC, RUNNING, "parse abnormal.");
            break;
        }
    }

    if (m_opt == 0) {
        res_cause = SESS_MANDATORY_IE_MISSING;
        LOG(UPC, ERR, "Missing mandatory ie.");
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE pfcp_parse_clock_drift_ctrl_info(session_clock_drift_control_info *clock_info,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse PFCP Session Retention Information.");
    /* Parse packet */
    while (*buf_pos < buf_max) {
        if (((TLV_TYPE_LEN + TLV_LENGTH_LEN) + *buf_pos) <= buf_max) {
            obj_type = tlv_decode_type(buffer, buf_pos, buf_max);
            obj_len  = tlv_decode_length(buffer, buf_pos, buf_max);
        } else {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "buff len abnormal.");
            break;
        }

        if ((obj_len + *buf_pos) > buf_max) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING,
                "IE value length error, obj_len: %d, buf_pos: %d, buf_max: %d.",
                obj_len, *buf_pos, buf_max);
            break;
        }

        switch (obj_type) {
            case UPF_REQUESTED_CLOCK_DRIFT_INFORMATION:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    clock_info->requested_clock_drift_info.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_TSN_TIME_DOMAIN_NUMBER:
                if (clock_info->tsn_time_domain_number_num < TSN_TIME_DOMAIN_NUM) {
                    if (sizeof(uint8_t) == obj_len) {
                        clock_info->tsn_time_domain_number[clock_info->tsn_time_domain_number_num] =
                            tlv_decode_uint8_t(buffer, buf_pos);
                        ++clock_info->tsn_time_domain_number_num;
                    } else {
                        LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint8_t));
                        res_cause = SESS_INVALID_LENGTH;
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of TSN Time Domain Number number reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_TIME_OFFSET_THRESHOLD:
                if (sizeof(uint64_t) == obj_len) {
                    clock_info->time_offset_threshold_present = 1;
                    clock_info->time_offset_threshold = tlv_decode_uint64_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint64_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_CUMULATIVE_RATERATIO_THRESHOLD:
                if (sizeof(uint32_t) == obj_len) {
                    clock_info->cumulative_rateratio_threshold_present = 1;
                    clock_info->cumulative_rateratio_threshold = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, RUNNING,
                    "type %d, not support.", obj_type);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        if (last_pos == *buf_pos) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "empty ie.");
            break;
        } else {
            last_pos = *buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            LOG(UPC, RUNNING, "parse abnormal.");
            break;
        }
    }

    if (m_opt == 0) {
        res_cause = SESS_MANDATORY_IE_MISSING;
        LOG(UPC, ERR, "Missing mandatory ie.");
    }

    return res_cause;
}

static void pfcp_encode_up_features(uint8_t* resp_buffer, uint16_t *buf_pos)
{
    session_up_features        up_features;

    /* Encode up features */
    tlv_encode_type(resp_buffer, buf_pos, UPF_UP_FUNCTION_FEATURES);
    tlv_encode_length(resp_buffer, buf_pos, 6);
    up_features.value = upc_get_up_features();
    tlv_encode_int_6b(resp_buffer, buf_pos, up_features.value);
}

static void pfcp_encode_time_stamp(uint8_t* resp_buffer, uint16_t *buf_pos)
{
    tlv_encode_type(resp_buffer, buf_pos, UPF_RECOVERY_TIME_STAMP);
    tlv_encode_length(resp_buffer, buf_pos, sizeof(uint32_t));
    tlv_encode_uint32_t(resp_buffer, buf_pos, upc_node_get_local_time_stamp());
}

void pfcp_encode_node_id(uint8_t* resp_buffer, uint16_t *buf_pos, uint8_t type)
{
    pfcp_node_id        *node_id;

    tlv_encode_type(resp_buffer, buf_pos, UPF_NODE_ID);

    node_id = upc_node_get_local_node_id(type);
    switch (node_id->type.d.type) {
        case UPF_NODE_TYPE_IPV4:
            tlv_encode_length(resp_buffer, buf_pos, 5);
            tlv_encode_uint8_t(resp_buffer, buf_pos, UPF_NODE_TYPE_IPV4);
            tlv_encode_binary(resp_buffer, buf_pos, 4, node_id->node_id);
            break;
        case UPF_NODE_TYPE_IPV6:
            tlv_encode_length(resp_buffer, buf_pos, IPV6_ALEN + 1);
            tlv_encode_uint8_t(resp_buffer, buf_pos, UPF_NODE_TYPE_IPV6);
            tlv_encode_binary(resp_buffer, buf_pos, IPV6_ALEN, node_id->node_id);
            break;
        case UPF_NODE_TYPE_FQDN:
            tlv_encode_length(resp_buffer, buf_pos,
                strlen((char *)node_id->node_id) + 1);
            tlv_encode_uint8_t(resp_buffer, buf_pos, UPF_NODE_TYPE_FQDN);
            tlv_encode_binary(resp_buffer, buf_pos,
                strlen((char *)node_id->node_id), node_id->node_id);
            break;
        default:
            LOG(UPC, ERR, "Unsupport node type: %d", node_id->type.d.type);
            tlv_encode_length(resp_buffer, buf_pos, 5);
            tlv_encode_uint8_t(resp_buffer, buf_pos, UPF_NODE_TYPE_IPV4);
            tlv_encode_binary(resp_buffer, buf_pos, 4, node_id->node_id);
            break;
    }
}

static void pfcp_encode_ueip_addr_pool_info(uint8_t* resp_buffer, uint16_t *buf_pos)
{
    session_up_features up_features = {.value = upc_get_up_features()};
    uint8_t cnt;
    uint16_t ie_pos = 0, ie_len = 0;

    if (up_features.d.UEIP) {
        struct ueip_pool_table *ueip_table = ueip_pool_mgmt_get();
        uint8_t pool_id_len;

         for (cnt = 0; cnt < ueip_table->ip_pool_num; ++cnt) {
            tlv_encode_type(resp_buffer, buf_pos, UPF_UE_IP_ADDRESS_POOL_INFORMATION);
            ie_pos = *buf_pos;
            tlv_encode_length(resp_buffer, buf_pos, 0);
            ie_len = *buf_pos;

            /* Encode UE IP address Pool Identity */
            pool_id_len = strlen(ueip_table->pool_arr[cnt].pool_name);
            tlv_encode_type(resp_buffer, buf_pos, UPF_UE_IP_ADDRESS_POOL_IDENTITY);
            tlv_encode_length(resp_buffer, buf_pos, sizeof(uint16_t) + pool_id_len);
            tlv_encode_uint16_t(resp_buffer, buf_pos, pool_id_len);
            tlv_encode_binary(resp_buffer, buf_pos,
                pool_id_len, (uint8_t *)ueip_table->pool_arr[cnt].pool_name);

            /* Encode Network Instance */
            /*if (pool_info->network_instance_present) {
                tlv_encode_type(resp_buffer, buf_pos, UPF_NETWORK_INSTANCE);
                tlv_encode_length(resp_buffer, buf_pos, strlen(pool_info->network_instance));
                tlv_encode_binary(resp_buffer, buf_pos,
                    strlen(pool_info->network_instance), pool_info->network_instance);
            }*/

            /* Encode S-NSSAI */
            /* Several IEs with the same IE type may be present to represent multiple S-NSSAIs. */
            {
                session_s_nssai s_nssai = {.sst = 0x12, .sd = 0x25};

                tlv_encode_type(resp_buffer, buf_pos, UPF_S_NSSAI);
                tlv_encode_length(resp_buffer, buf_pos, sizeof(session_s_nssai));
                tlv_encode_uint8_t(resp_buffer, buf_pos, s_nssai.sst);
                tlv_encode_int_3b(resp_buffer, buf_pos, s_nssai.sd);
            }

            /* Encode IP version */
            tlv_encode_type(resp_buffer, buf_pos, UPF_IP_VERSION);
            tlv_encode_length(resp_buffer, buf_pos, 1);
            tlv_encode_uint8_t(resp_buffer, buf_pos, ueip_table->pool_arr[cnt].ip_info.ip_ver);

            ie_len = *buf_pos - ie_len;
            tlv_encode_length(resp_buffer, &ie_pos, ie_len);
        }
    }
}

static void pfcp_encode_ueip_addr_usage_info(uint8_t* resp_buffer, uint16_t *buf_pos)
{
    session_up_features up_features = {.value = upc_get_up_features()};
    uint8_t cnt;
    uint16_t ie_pos = 0, ie_len = 0;

    if (up_features.d.UEIP) {
        struct ueip_pool_table *ueip_table = ueip_pool_mgmt_get();
        uint8_t pool_id_len;

         for (cnt = 0; cnt < ueip_table->ip_pool_num; ++cnt) {
            tlv_encode_type(resp_buffer, buf_pos, UPF_UE_IP_ADDRESS_USAGE_INFORMATION);
            ie_pos = *buf_pos;
            tlv_encode_length(resp_buffer, buf_pos, 0);
            ie_len = *buf_pos;

            /* Encode UE IP Address Usage Sequence Number */
            tlv_encode_type(resp_buffer, buf_pos, UPF_SEQUENCE_NUMBER);
            tlv_encode_length(resp_buffer, buf_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, buf_pos, 112);

            /* Encode UE IP Address Usage Metric */
            tlv_encode_type(resp_buffer, buf_pos, UPF_METRIC);
            tlv_encode_length(resp_buffer, buf_pos, sizeof(uint8_t));
            tlv_encode_uint8_t(resp_buffer, buf_pos, 100);

            /* Encode Validity Timer */
            tlv_encode_type(resp_buffer, buf_pos, UPF_VALIDITY_TIMER);
            tlv_encode_length(resp_buffer, buf_pos, sizeof(uint16_t));
            tlv_encode_uint16_t(resp_buffer, buf_pos, 10);

            /* Encode Number of UE IP Addresses */
            tlv_encode_type(resp_buffer, buf_pos, UPF_NUMBER_OF_UE_IP_ADDRESSES);
            tlv_encode_length(resp_buffer, buf_pos, 5);
            tlv_encode_uint8_t(resp_buffer, buf_pos, ueip_table->pool_arr[cnt].ip_info.ip_ver);
            tlv_encode_uint32_t(resp_buffer, buf_pos,
                ros_atomic32_read(&ueip_table->pool_arr[cnt].use_num));

            /* Encode Network Instance */
            /*tlv_encode_type(resp_buffer, buf_pos, UPF_NETWORK_INSTANCE);
            tlv_encode_length(resp_buffer, buf_pos, strlen(ueip_table->pool_arr[cnt].pool_name));
            tlv_encode_binary(resp_buffer, buf_pos,
                strlen(ueip_table->pool_arr[cnt].pool_name), ueip_table->pool_arr[cnt].pool_name);*/

            /* Encode UE IP address Pool Identity */
            pool_id_len = strlen(ueip_table->pool_arr[cnt].pool_name);
            tlv_encode_type(resp_buffer, buf_pos, UPF_UE_IP_ADDRESS_POOL_IDENTITY);
            tlv_encode_length(resp_buffer, buf_pos, sizeof(uint16_t) + pool_id_len);
            tlv_encode_uint16_t(resp_buffer, buf_pos, pool_id_len);
            tlv_encode_binary(resp_buffer, buf_pos,
                pool_id_len, (uint8_t *)ueip_table->pool_arr[cnt].pool_name);

            ie_len = *buf_pos - ie_len;
            tlv_encode_length(resp_buffer, &ie_pos, ie_len);
        }
    }
}

static void pfcp_encode_cause(uint8_t* resp_buffer,
    uint16_t *buf_pos, uint8_t res_cause)
{
    tlv_encode_type(resp_buffer, buf_pos, UPF_CAUSE);
    tlv_encode_length(resp_buffer, buf_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, buf_pos, res_cause);
}

static void pfcp_encode_release_request_imm(uint8_t* resp_buffer, uint16_t *buf_pos,
    uint8_t sarr, uint8_t urss)
{
    session_asso_release_request rel_req;

    rel_req.d.sarr = sarr;
    rel_req.d.urss = urss;

    tlv_encode_type(resp_buffer, buf_pos, UPF_PFCP_ASSOCIATION_RELEASE_REQUEST);
    tlv_encode_length(resp_buffer, buf_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, buf_pos, rel_req.value);
}

static void pfcp_encode_release_request_delay(uint8_t* resp_buffer, uint16_t *buf_pos,
    uint32_t time_in_sec)
{
    session_timer time_struct;

    time_struct.value = upc_node_second_to_time_struct(time_in_sec);

    tlv_encode_type(resp_buffer, buf_pos, UPF_GRACEFUL_RELEASE_PERIOD);
    tlv_encode_length(resp_buffer, buf_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, buf_pos, time_struct.value);
}

static void pfcp_encode_aureq(uint8_t* resp_buffer, uint16_t *buf_pos, uint8_t aureq)
{
    session_asso_aureq_flag aureq1;

    aureq1.value = aureq;

    tlv_encode_type(resp_buffer, buf_pos, UPF_PFCPAUREQ_FLAGS);
    tlv_encode_length(resp_buffer, buf_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, buf_pos, aureq1.value);
}

int pfcp_local_association_setup(session_association_setup *assoc_setup)
{
    upc_node_cb                 *node_cb = NULL;

    node_cb = upc_node_add(assoc_setup->node_id_index, assoc_setup->node_id.type.d.type,
        assoc_setup->node_id.node_id, NULL);
    if (NULL == node_cb) {
        LOG(UPC, ERR, "add target node(id: %02x%02x%02x%02x) failed.",
            assoc_setup->node_id.node_id[0],
            assoc_setup->node_id.node_id[1],
            assoc_setup->node_id.node_id[2],
            assoc_setup->node_id.node_id[3]);
        return -1;
    }
    LOG(UPC, RUNNING, "add new node(id: %02x%02x%02x%02x).",
        assoc_setup->node_id.node_id[0],
        assoc_setup->node_id.node_id[1],
        assoc_setup->node_id.node_id[2],
        assoc_setup->node_id.node_id[3]);

    /* Add parameters */
    ros_rwlock_write_lock(&node_cb->lock); /* lock */
    memcpy(&node_cb->assoc_config, &assoc_setup, sizeof(assoc_setup));

    /* Merge features */
    upc_node_merge_features(node_cb);
    ros_rwlock_write_unlock(&node_cb->lock); /* unlock */

    return 0;
}

int pfcp_local_association_update(session_association_update *assoc_update)
{
    upc_node_cb *node_cb = NULL;

    /* If can't find matched node */
    node_cb = upc_node_get_of_index(assoc_update->node_id_index);
    if (NULL == node_cb) {
        LOG(UPC, RUNNING, "no matched node found.");
        return -1;
    }

    /* Add parameters */
    if (assoc_update->member_flag.d.cp_features_present) {
        node_cb->assoc_config.cp_features.value = assoc_update->cp_features.value;
    }

    if (assoc_update->gtpu_path_qos_ctrl_num > 0) {
        node_cb->assoc_config.gtpu_path_qos_ctrl_num = assoc_update->gtpu_path_qos_ctrl_num;
        memcpy(node_cb->assoc_config.gtpu_path_qos_ctrl_info, assoc_update->gtpu_path_qos_ctrl_info,
            sizeof(session_gtpu_path_qos_control_info) * assoc_update->gtpu_path_qos_ctrl_num);
    }

    if (assoc_update->clock_drift_ctrl_num) {
        node_cb->assoc_config.clock_drift_ctrl_num = assoc_update->clock_drift_ctrl_num;
        memcpy(node_cb->assoc_config.clock_drift_ctrl_info, assoc_update->clock_drift_ctrl_info,
            sizeof(session_clock_drift_control_info) * assoc_update->clock_drift_ctrl_num);
    }

    if (assoc_update->smf_ip_num) {
        node_cb->assoc_config.smf_ip_num = assoc_update->smf_ip_num;
        memcpy(node_cb->assoc_config.smf_ip_arr, assoc_update->smf_ip_arr,
            sizeof(session_alternative_smf_addr) * assoc_update->smf_ip_num);
    }

    /* Merge features */
    upc_node_merge_features(node_cb);

    return 0;
}

int pfcp_local_association_release(session_association_release_request *assoc_rels)
{
    upc_node_cb             *node_cb = NULL;

    node_cb = upc_node_get_of_index(assoc_rels->node_id_index);
    if (NULL == node_cb) {
        LOG(UPC, RUNNING, "no matched node found.");
        return -1;
    }

    if (0 > upc_node_del(node_cb)) {
        LOG(UPC, ERR, "Delete node failed.");

        return -1;
    }

    return 0;
}

void pfcp_parse_association_setup_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t resp_pos = 0;
    EN_UPC_HA_SYNC_EVENTS sync_event = HA_SYNC_EVENT_SUCC;
    uint8_t sync_blk_exist = FALSE;
    uint32_t sync_blk_index;
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint8_t  m_nodeid = G_FALSE, m_recover_time = G_FALSE, session_retention = G_FALSE;
    uint16_t obj_type, obj_len;
    upc_node_cb                 *node_cb = NULL;
    PFCP_CAUSE_TYPE             res_cause = SESS_REQUEST_ACCEPTED;
    session_association_setup assoc_setup = {{0}};

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    /* Parse packet */
    last_pos = buf_pos;
    while (buf_pos < buf_max) {

        obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
        obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);

        switch (obj_type) {
            case UPF_NODE_ID:
                /* Declear supported mandatory option */
                m_nodeid = G_TRUE;

                if (obj_len > PFCP_MAX_NODE_ID_LEN) {
                    LOG(UPC, ERR, "Node id length reaches the upper limit.");
                    res_cause = SESS_INVALID_LENGTH;
                    break;
                }
                tlv_decode_binary(buffer, &buf_pos, obj_len, (uint8_t *)&assoc_setup.node_id);

                LOG(UPC, RUNNING,
                    "decode node id, type %d, value %02x%02x%02x%02x",
                    assoc_setup.node_id.type.d.type,
                    assoc_setup.node_id.node_id[0],
                    assoc_setup.node_id.node_id[1],
                    assoc_setup.node_id.node_id[2],
                    assoc_setup.node_id.node_id[3]);
                break;

            case UPF_RECOVERY_TIME_STAMP:
                /* Declear supported mandatory option */
                if (sizeof(uint32_t) == obj_len) {
                    m_recover_time = G_TRUE;
                    assoc_setup.recov_time = tlv_decode_uint32_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }

                LOG(UPC, RUNNING, "decode recover time stamp, value %x",
                    assoc_setup.recov_time);
                break;

            case UPF_CP_FUNCTION_FEATURES:
                if (sizeof(uint16_t) == obj_len) {
                    assoc_setup.cp_features.value = tlv_decode_uint16_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }

                LOG(UPC, RUNNING,
                    "decode cp feature, value %04x", assoc_setup.cp_features.value);
                break;

            case UPF_ALTERNATIVE_SMF_IP_ADDRESS:
                if (assoc_setup.smf_ip_num < ALTERNATIVE_SMF_IP_NUM) {
                    res_cause = pfcp_parse_alt_smf_ip_addr(
                        &assoc_setup.smf_ip_arr[assoc_setup.smf_ip_num], buffer,
                        &buf_pos, buf_max, obj_len);
                    ++assoc_setup.smf_ip_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of alternative smf ip address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_SMF_SET_ID:
                assoc_setup.smf_set_id.spare = tlv_decode_uint8_t(buffer, &buf_pos);
                if ((obj_len - 1) <= FQDN_LEN) {
                    tlv_decode_binary(buffer, &buf_pos, obj_len - 1,
                        (uint8_t *)assoc_setup.smf_set_id.fqdn);
                    assoc_setup.smf_set_id.fqdn[obj_len - 1] = '\0';
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len - 1, FQDN_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PFCP_SESSION_RETENTION_INFORMATION:
                session_retention = G_TRUE;
                res_cause = pfcp_parse_retention_info(&assoc_setup.retention_information,
                     buffer, &buf_pos, buf_max);
                break;

            case UPF_GTP_U_PATH_QOS_CONTROL_INFORMATION:
                if (assoc_setup.gtpu_path_qos_ctrl_num < MONITOR_GTPU_PATH_NUM) {
                    res_cause = pfcp_parse_gtpu_path_qos_ctrl_info(
                        &assoc_setup.gtpu_path_qos_ctrl_info[assoc_setup.gtpu_path_qos_ctrl_num], buffer,
                        &buf_pos, buf_max);
                    ++assoc_setup.gtpu_path_qos_ctrl_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of alternative smf ip address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CLOCK_DRIFT_CONTROL_INFORMATION:
                if (assoc_setup.clock_drift_ctrl_num < CLOCK_DRIFT_CONTROL_NUM) {
                    res_cause = pfcp_parse_clock_drift_ctrl_info(
                        &assoc_setup.clock_drift_ctrl_info[assoc_setup.clock_drift_ctrl_num], buffer,
                        &buf_pos, buf_max);
                    ++assoc_setup.clock_drift_ctrl_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of alternative smf ip address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_NF_INSTANCE_ID:
                /* This IE only exists if the message is sent by UPF */
                PFCP_MOVE_FORWORD(buf_pos, obj_len);
                break;

            default:
                LOG(UPC, ERR, "IE type %d, not support, skip it.", obj_type);
                //res_cause = SESS_SERVICE_NOT_SUPPORTED;
                PFCP_MOVE_FORWORD(buf_pos, obj_len);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        LOG(UPC, RUNNING,
            "decode pos from %d to %d, %02x %02x ...",
            last_pos, buf_pos, buffer[last_pos], buffer[last_pos + 1]);
        if (last_pos == buf_pos) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, ERR, "empty ie.");
            break;
        } else {
            last_pos = buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            LOG(UPC, RUNNING, "parse abnormal.");
            goto fast_response;
        }
    }

    /* Check mandaytory option */
    if ((m_nodeid == G_FALSE) || (m_recover_time == G_FALSE)) {
        LOG(UPC, ERR,
            "no mandatory option node_id(%d) or recover_time_stamp(%d).",
            m_nodeid, m_recover_time);

        res_cause = SESS_MANDATORY_IE_MISSING;
        goto fast_response;
    }
    assoc_setup.up_features.value = upc_get_up_features();

    node_cb = upc_node_add(UPC_NODE_INVALID_INDEX, assoc_setup.node_id.type.d.type,
        assoc_setup.node_id.node_id, sa);
    if (NULL == node_cb) {
        res_cause = SESS_SERVICE_NOT_SUPPORTED;
        goto fast_response;
    }
    LOG(UPC, RUNNING, "add new node(id: %02x%02x%02x%02x).",
        assoc_setup.node_id.node_id[0],
        assoc_setup.node_id.node_id[1],
        assoc_setup.node_id.node_id[2],
        assoc_setup.node_id.node_id[3]);

    assoc_setup.msg_header.msg_type = SESS_ASSOCIATION_SETUP_REQUEST;
    assoc_setup.msg_header.node_id_index = node_cb->index;
    assoc_setup.msg_header.seq_num = pkt_seq;
    assoc_setup.node_id_index = node_cb->index;

    /* Add parameters */
    ros_rwlock_write_lock(&node_cb->lock); /* lock */
    memcpy(&node_cb->assoc_config, &assoc_setup, sizeof(assoc_setup));

    /* Merge features */
    upc_node_merge_features(node_cb);
    ros_rwlock_write_unlock(&node_cb->lock); /* unlock */

    if (upc_hk_build_data_block) {
        sync_blk_index = upc_hk_build_data_block(HA_SYNC_DATA_NODE, HA_CREATE, HA_SYNC_RECV_FROM_CP,
            sync_event, &assoc_setup);
        if (0 > sync_blk_index) {
            LOG(UPC, ERR, "Build session sync msg failed.");
            res_cause = SESS_CREATE_SYNC_DATA_BLOCK_FAILURE;

            goto fast_response;
        }
        sync_blk_exist = TRUE;
    }

fast_response:
    upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, sa);

    pfcp_build_association_setup_response(resp_buffer, &resp_pos, res_cause, pkt_seq,
        sa->sa_family == AF_INET ? UPF_NODE_TYPE_IPV4 : UPF_NODE_TYPE_IPV6, session_retention);

    if (0 > upc_buff_send2smf(resp_buffer, resp_pos, sa)) {
        LOG(UPC, ERR, "Send packet to SMF failed.");
    }

    if (sync_blk_exist) {
        if (upc_hk_change_sync_blk_status) {
            if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_REPLY_TO_CP, sync_event)) {
                LOG(UPC, ERR, "Change session sync msg failed, node_cb->index: %d.", node_cb->index);
            }
        }
    }
}

void pfcp_parse_association_setup_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max)
{
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint8_t  m_nodeid = G_FALSE, m_cause = G_FALSE, m_recover_time = G_FALSE;
    uint8_t  cause;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t obj_type, obj_len;
    upc_node_cb *node_cb = NULL;
    session_association_setup assoc_setup = {{0}};

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    /* Parse packet */
    last_pos = buf_pos;
    while (buf_pos < buf_max) {
        obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
        obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);

        switch (obj_type) {
            case UPF_NODE_ID:
                /* Declear supported mandatory option */
                m_nodeid = G_TRUE;

                if (obj_len > PFCP_MAX_NODE_ID_LEN) {
                    LOG(UPC, ERR, "Node id length reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                    break;
                }
                tlv_decode_binary(buffer, &buf_pos, obj_len, (uint8_t *)&assoc_setup.node_id);

                LOG(UPC, RUNNING,
                    "decode node id, type %d, value %02x%02x%02x%02x",
                    assoc_setup.node_id.type.d.type,
                    assoc_setup.node_id.node_id[0],
                    assoc_setup.node_id.node_id[1],
                    assoc_setup.node_id.node_id[2],
                    assoc_setup.node_id.node_id[3]);
                break;

            case UPF_CAUSE:
                /* Declear supported mandatory option */
                if (sizeof(uint8_t) == obj_len) {
                    m_cause = G_TRUE;

                    /* Parse cause */
                    cause = tlv_decode_uint8_t(buffer, &buf_pos);
                    LOG(UPC, RUNNING, "decode cause, value %02x", cause);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_RECOVERY_TIME_STAMP:
                /* Declear supported mandatory option */
                if (sizeof(uint16_t) == obj_len) {
                    m_recover_time = G_TRUE;
                    assoc_setup.recov_time = tlv_decode_uint32_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }

                LOG(UPC, RUNNING, "decode recover time stamp, value %x",
                    assoc_setup.recov_time);
                break;

            case UPF_CP_FUNCTION_FEATURES:
                if (sizeof(uint16_t) == obj_len) {
                    assoc_setup.cp_features.value = tlv_decode_uint16_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }

                LOG(UPC, RUNNING,
                    "decode cp feature, value %04x", assoc_setup.cp_features.value);
                break;

            case UPF_ALTERNATIVE_SMF_IP_ADDRESS:
                if (assoc_setup.smf_ip_num < ALTERNATIVE_SMF_IP_NUM) {
                    res_cause = pfcp_parse_alt_smf_ip_addr(
                        &assoc_setup.smf_ip_arr[assoc_setup.smf_ip_num], buffer,
                        &buf_pos, buf_max, obj_len);
                    ++assoc_setup.smf_ip_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of alternative smf ip address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_GTP_U_PATH_QOS_CONTROL_INFORMATION:
                if (assoc_setup.gtpu_path_qos_ctrl_num < MONITOR_GTPU_PATH_NUM) {
                    res_cause = pfcp_parse_gtpu_path_qos_ctrl_info(
                        &assoc_setup.gtpu_path_qos_ctrl_info[assoc_setup.gtpu_path_qos_ctrl_num], buffer,
                        &buf_pos, buf_max);
                    ++assoc_setup.gtpu_path_qos_ctrl_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of alternative smf ip address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CLOCK_DRIFT_CONTROL_INFORMATION:
                if (assoc_setup.clock_drift_ctrl_num < CLOCK_DRIFT_CONTROL_NUM) {
                    res_cause = pfcp_parse_clock_drift_ctrl_info(
                        &assoc_setup.clock_drift_ctrl_info[assoc_setup.clock_drift_ctrl_num], buffer,
                        &buf_pos, buf_max);
                    ++assoc_setup.clock_drift_ctrl_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of alternative smf ip address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_SMF_SET_ID:
                assoc_setup.smf_set_id.spare = tlv_decode_uint8_t(buffer, &buf_pos);
                if ((obj_len - 1) <= FQDN_LEN) {
                    tlv_decode_binary(buffer, &buf_pos, obj_len - 1,
                        (uint8_t *)assoc_setup.smf_set_id.fqdn);
                    assoc_setup.smf_set_id.fqdn[obj_len - 1] = '\0';
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len - 1, FQDN_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "IE type %d, not support, skip it.", obj_type);
                //res_cause = SESS_SERVICE_NOT_SUPPORTED;
                PFCP_MOVE_FORWORD(buf_pos, obj_len);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        LOG(UPC, RUNNING,
            "decode pos from %d to %d, %02x %02x ...",
            last_pos, buf_pos, buffer[last_pos], buffer[last_pos + 1]);
        if (last_pos == buf_pos) {
            LOG(UPC, RUNNING, "empty ie.");
            break;
        }
        else {
            last_pos = buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            LOG(UPC, RUNNING, "parse abnormal.");
            return;
        }
    }

    /* Check mandaytory option */
    if ((m_nodeid == G_FALSE)
      ||(m_cause == G_FALSE)
      ||(m_recover_time == G_FALSE)) {
        LOG(UPC, RUNNING,
            "no mandatory option node_id(%d) "
            "or recover_time_stamp(%d) or cause(%d).",
            m_nodeid, m_recover_time, m_cause);
        return;
    }

    /* If can't find matched node */
    node_cb = upc_node_get(assoc_setup.node_id.type.d.type, assoc_setup.node_id.node_id);
    if (NULL == node_cb) {
        LOG(UPC, RUNNING, "no matched node found.");
        return;
    }

    if (cause != SESS_REQUEST_ACCEPTED) {
        if (0 > upc_node_del(node_cb)) {
            LOG(UPC, ERR, "Node delete failed.");
        }
        return;
    }
    assoc_setup.node_id_index = node_cb->index;

    /* Add parameters */
    ros_rwlock_write_lock(&node_cb->lock); /* lock */
    memcpy(&node_cb->assoc_config, &assoc_setup, sizeof(assoc_setup));
    ros_rwlock_write_unlock(&node_cb->lock); /* unlock */

    if (upc_hk_build_data_block) {
        if (0 > upc_hk_build_data_block(HA_SYNC_DATA_NODE, HA_CREATE, HA_SYNC_FINAL_STATE,
            HA_SYNC_EVENT_SUCC, &assoc_setup)) {
            LOG(UPC, ERR, "Build session sync msg failed.");
        }
    }

    return;
}

void pfcp_parse_association_update_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t resp_pos = 0;
    EN_UPC_HA_SYNC_EVENTS sync_event = HA_SYNC_EVENT_SUCC;
    uint8_t sync_blk_exist = FALSE;
    uint32_t sync_blk_index;
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint8_t  m_nodeid = G_FALSE;
    uint16_t obj_type, obj_len;
    pfcp_node_id                *node_id = NULL;
    upc_node_cb                 *node_cb = NULL;
    PFCP_CAUSE_TYPE             res_cause = SESS_REQUEST_ACCEPTED;
    session_association_update assoc_update = {{0}};

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    /* Parse packet */
    last_pos = buf_pos;
    while (buf_pos < buf_max) {
        obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
        obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);

        switch (obj_type) {
            case UPF_NODE_ID:
                /* Declear supported mandatory option */
                m_nodeid = G_TRUE;

                /* Map data */
                node_id = (pfcp_node_id *)(buffer + buf_pos);
                PFCP_MOVE_FORWORD(buf_pos, obj_len);

                LOG(UPC, RUNNING,
                    "decode node id, type %d, value %02x%02x%02x%02x",
                    node_id->type.d.type,
                    node_id->node_id[0],
                    node_id->node_id[1],
                    node_id->node_id[2],
                    node_id->node_id[3]);
                break;

            case UPF_PFCPAUREQ_FLAGS:
                if (sizeof(uint8_t) == obj_len) {
                    assoc_update.pfcpau_req_flag.value = tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }

                LOG(UPC, RUNNING,
                    "decode aureq, value %02x", assoc_update.pfcpau_req_flag.value);
                break;

            case UPF_CP_FUNCTION_FEATURES:
                if (sizeof(uint16_t) == obj_len) {
                    assoc_update.cp_features.value = tlv_decode_uint16_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }

                LOG(UPC, RUNNING,
                    "decode cp feature, value %04x", assoc_update.cp_features.value);
                break;

            case UPF_ALTERNATIVE_SMF_IP_ADDRESS:
                if (assoc_update.smf_ip_num < ALTERNATIVE_SMF_IP_NUM) {
                    res_cause = pfcp_parse_alt_smf_ip_addr(
                        &assoc_update.smf_ip_arr[assoc_update.smf_ip_num], buffer,
                        &buf_pos, buf_max, obj_len);
                    ++assoc_update.smf_ip_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of alternative smf ip address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_SMF_SET_ID:
                assoc_update.smf_set_id.spare = tlv_decode_uint8_t(buffer, &buf_pos);
                if ((obj_len - 1) <= FQDN_LEN) {
                    tlv_decode_binary(buffer, &buf_pos, obj_len - 1,
                        (uint8_t *)assoc_update.smf_set_id.fqdn);
                    assoc_update.smf_set_id.fqdn[obj_len - 1] = '\0';
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len - 1, FQDN_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_GTP_U_PATH_QOS_CONTROL_INFORMATION:
                if (assoc_update.gtpu_path_qos_ctrl_num < MONITOR_GTPU_PATH_NUM) {
                    res_cause = pfcp_parse_gtpu_path_qos_ctrl_info(
                        &assoc_update.gtpu_path_qos_ctrl_info[assoc_update.gtpu_path_qos_ctrl_num],
                        buffer, &buf_pos, buf_max);
                    ++assoc_update.gtpu_path_qos_ctrl_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of alternative smf ip address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CLOCK_DRIFT_CONTROL_INFORMATION:
                if (assoc_update.clock_drift_ctrl_num < CLOCK_DRIFT_CONTROL_NUM) {
                    res_cause = pfcp_parse_clock_drift_ctrl_info(
                        &assoc_update.clock_drift_ctrl_info[assoc_update.clock_drift_ctrl_num], buffer,
                        &buf_pos, buf_max);
                    ++assoc_update.clock_drift_ctrl_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of alternative smf ip address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            default:
                LOG(UPC, ERR, "IE type %d, not support, skip it.", obj_type);
                //res_cause = SESS_SERVICE_NOT_SUPPORTED;
                PFCP_MOVE_FORWORD(buf_pos, obj_len);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        LOG(UPC, RUNNING,
            "decode pos from %d to %d, %02x %02x ...",
            last_pos, buf_pos, buffer[last_pos], buffer[last_pos + 1]);
        if (last_pos == buf_pos) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "empty ie.");
            break;
        }
        else {
            last_pos = buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            LOG(UPC, RUNNING, "parse abnormal.");
            goto resp;;
        }
    }

    /* Check mandaytory option */
    if (m_nodeid == G_FALSE) {
        LOG(UPC, RUNNING,
            "no mandatory option node_id(%d).",
            m_nodeid);

        res_cause = SESS_MANDATORY_IE_MISSING;
        goto resp;
    }

    /* If can't find matched node */
    node_cb = upc_node_get(node_id->type.d.type, node_id->node_id);
    if (!node_cb) {
        LOG(UPC, RUNNING, "no matched node found.");
        res_cause = SESS_NO_ESTABLISHED_PFCP_ASSOCIATION;
        goto resp;
    }

    assoc_update.msg_header.msg_type = SESS_ASSOCIATION_UPDATE_REQUEST;
    assoc_update.msg_header.node_id_index = node_cb->index;
    assoc_update.msg_header.seq_num = pkt_seq;

    upc_node_update_peer_sa(node_cb, sa);

    /* Add parameters */
    if (assoc_update.member_flag.d.cp_features_present) {
        node_cb->assoc_config.cp_features.value = assoc_update.cp_features.value;
    }

    if (assoc_update.gtpu_path_qos_ctrl_num > 0) {
        node_cb->assoc_config.gtpu_path_qos_ctrl_num = assoc_update.gtpu_path_qos_ctrl_num;
        memcpy(node_cb->assoc_config.gtpu_path_qos_ctrl_info, assoc_update.gtpu_path_qos_ctrl_info,
            sizeof(session_gtpu_path_qos_control_info) * assoc_update.gtpu_path_qos_ctrl_num);
    }

    if (assoc_update.clock_drift_ctrl_num) {
        node_cb->assoc_config.clock_drift_ctrl_num = assoc_update.clock_drift_ctrl_num;
        memcpy(node_cb->assoc_config.clock_drift_ctrl_info, assoc_update.clock_drift_ctrl_info,
            sizeof(session_clock_drift_control_info) * assoc_update.clock_drift_ctrl_num);
    }

    if (assoc_update.smf_ip_num) {
        node_cb->assoc_config.smf_ip_num = assoc_update.smf_ip_num;
        memcpy(node_cb->assoc_config.smf_ip_arr, assoc_update.smf_ip_arr,
            sizeof(session_alternative_smf_addr) * assoc_update.smf_ip_num);
    }

    /* Merge features */
    upc_node_merge_features(node_cb);

    /* If set aureq, need notify SP to report */
    if (assoc_update.pfcpau_req_flag.d.parps) {
        upc_node_notify_session_report(node_cb);
    }

    if (upc_hk_build_data_block) {
        sync_blk_index = upc_hk_build_data_block(HA_SYNC_DATA_NODE, HA_UPDATE, HA_SYNC_RECV_FROM_CP,
            sync_event, node_cb);
        if (0 > sync_blk_index) {
            LOG(UPC, ERR, "Build session sync msg failed.");
        }
        sync_blk_exist = TRUE;
    }

resp:
    upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, sa);

    pfcp_build_association_update_response(resp_buffer, &resp_pos, res_cause, pkt_seq,
        sa->sa_family == AF_INET ? UPF_NODE_TYPE_IPV4 : UPF_NODE_TYPE_IPV6);

    if (0 > upc_buff_send2smf(resp_buffer, resp_pos, sa)) {
        LOG(UPC, ERR, "Send packet to SMF failed.");
    }

    if (sync_blk_exist) {
        if (upc_hk_change_sync_blk_status) {
            if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_REPLY_TO_CP, sync_event)) {
                LOG(UPC, ERR, "Change session sync msg failed, node_cb->index: %d.", node_cb->index);
            }
        }
    }
}

void pfcp_parse_association_update_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max)
{
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint8_t  m_cause = G_FALSE;
    uint8_t  cause = SESS_REQUEST_REJECTED;
    uint16_t obj_type, obj_len;
    pfcp_node_id *node_id = NULL;
    upc_node_cb *node_cb = NULL;
    session_association_update assoc_update = {{0}};

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    /* Parse packet */
    last_pos = buf_pos;
    while (buf_pos < buf_max) {

        obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
        obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);

        switch (obj_type) {
            case UPF_NODE_ID:
                /* Declear supported mandatory option */

                /* Map data */
                node_id = (pfcp_node_id *)(buffer + buf_pos);
                PFCP_MOVE_FORWORD(buf_pos, obj_len);

                LOG(UPC, RUNNING,
                    "decode node id, type %d, value %02x%02x%02x%02x",
                    node_id->type.d.type,
                    node_id->node_id[0],
                    node_id->node_id[1],
                    node_id->node_id[2],
                    node_id->node_id[3]);
                break;

            case UPF_CAUSE:
                if (sizeof(uint8_t) == obj_len) {
                    /* Declear supported mandatory option */
                    m_cause = G_TRUE;

                    /* Parse cause */
                    cause = tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    PFCP_MOVE_FORWORD(buf_pos, obj_len);
                }

                LOG(UPC, RUNNING, "decode cause, value %02x", cause);
                break;

            case UPF_CP_FUNCTION_FEATURES:
                if (sizeof(uint16_t) == obj_len) {
                    assoc_update.cp_features.value = tlv_decode_uint8_t(buffer, &buf_pos);
                    assoc_update.member_flag.d.cp_features_present = TRUE;
                    LOG(UPC, RUNNING, "decode cp feature, value %04x", assoc_update.cp_features.value);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    PFCP_MOVE_FORWORD(buf_pos, obj_len);
                }
                break;

            default:
                LOG(UPC, ERR, "IE type %d, not support, skip it.", obj_type);
                //res_cause = SESS_SERVICE_NOT_SUPPORTED;
                PFCP_MOVE_FORWORD(buf_pos, obj_len);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        LOG(UPC, RUNNING,
            "decode pos from %d to %d, %02x %02x ...",
            last_pos, buf_pos, buffer[last_pos], buffer[last_pos + 1]);
        if (last_pos == buf_pos) {
            LOG(UPC, RUNNING, "empty ie.");
            break;
        }
        else {
            last_pos = buf_pos;
        }
    }

    /* Check mandaytory option */
    if ((NULL == node_id)||(m_cause == G_FALSE)) {
        LOG(UPC, ERR,
            "no mandatory option node_id(%p) or cause(%d).",
            node_id, m_cause);

        return;
    }

    if (cause != SESS_REQUEST_ACCEPTED) {
        LOG(UPC, ERR, "Node update failed.");
        return;
    }

    /* If can't find matched node */
    node_cb = upc_node_get(node_id->type.d.type, node_id->node_id);
    if (NULL == node_cb) {
        LOG(UPC, ERR, "no matched node found.");
        return;
    }

    /* Add parameters */
    ros_rwlock_write_lock(&node_cb->lock); /* lock */
    if (assoc_update.member_flag.d.cp_features_present) {
        node_cb->assoc_config.cp_features.value = assoc_update.cp_features.value;
    }
    ros_rwlock_write_unlock(&node_cb->lock); /* unlock */

    /* Merge features */
    upc_node_merge_features(node_cb);

    if (upc_hk_build_data_block) {
        if (0 > upc_hk_build_data_block(HA_SYNC_DATA_NODE, HA_UPDATE, HA_SYNC_FINAL_STATE,
            HA_SYNC_EVENT_SUCC, &assoc_update)) {
            LOG(UPC, ERR, "Build session sync msg failed.");
        }
    }

    return;
}

void pfcp_parse_association_release_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t resp_pos = 0;
    EN_UPC_HA_SYNC_EVENTS sync_event = HA_SYNC_EVENT_SUCC;
    uint8_t sync_blk_exist = FALSE;
    uint32_t sync_blk_index;
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint8_t  m_nodeid = G_FALSE;
    uint16_t obj_type, obj_len;
    pfcp_node_id            *node_id;
    upc_node_cb             *node_cb = NULL;
    PFCP_CAUSE_TYPE         res_cause = SESS_REQUEST_ACCEPTED;
    session_association_release_request assoc_rels = {{0}};

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    /* Parse packet */
    last_pos = buf_pos;
    while (buf_pos < buf_max) {

        obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
        obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);

        switch (obj_type) {
            case UPF_NODE_ID:
                /* Declear supported mandatory option */
                m_nodeid = G_TRUE;

                /* Map data */
                node_id = (pfcp_node_id *)(buffer + buf_pos);
                PFCP_MOVE_FORWORD(buf_pos, obj_len);

                LOG(UPC, RUNNING,
                    "decode node id, type %d, value %02x%02x%02x%02x",
                    node_id->type.d.type,
                    node_id->node_id[0],
                    node_id->node_id[1],
                    node_id->node_id[2],
                    node_id->node_id[3]);
                break;

            default:
                LOG(UPC, ERR, "IE type %d, not support, skip it.", obj_type);
                //res_cause = SESS_SERVICE_NOT_SUPPORTED;
                PFCP_MOVE_FORWORD(buf_pos, obj_len);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        LOG(UPC, RUNNING,
            "decode pos from %d to %d, %02x %02x ...",
            last_pos, buf_pos, buffer[last_pos], buffer[last_pos + 1]);
        if (last_pos == buf_pos) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "empty ie.");
            break;
        }
        else {
            last_pos = buf_pos;
        }
    }

    /* Check mandaytory option */
    if (m_nodeid == G_FALSE) {
        LOG(UPC, RUNNING,
            "no mandatory option node_id(%d).", m_nodeid);

        res_cause = SESS_MANDATORY_IE_MISSING;
        goto resp;
    }

    /* If can't find matched node */
    node_cb = upc_node_get(node_id->type.d.type, node_id->node_id);
    if (!node_cb) {
        LOG(UPC, RUNNING, "no matched node found.");
        res_cause = SESS_NO_ESTABLISHED_PFCP_ASSOCIATION;
        goto resp;
    }

    if (0 > upc_node_del(node_cb)) {
        LOG(UPC, ERR, "Delete node failed.");
        res_cause = SESS_NO_ESTABLISHED_PFCP_ASSOCIATION;

        goto resp;
    }
    assoc_rels.msg_header.msg_type = SESS_ASSOCIATION_RELEASE_REQUEST;
    assoc_rels.msg_header.node_id_index = node_cb->index;
    assoc_rels.msg_header.seq_num = pkt_seq;
    assoc_rels.node_id_index = node_cb->index;

    if (upc_hk_build_data_block) {
        sync_blk_index = upc_hk_build_data_block(HA_SYNC_DATA_NODE, HA_REMOVE, HA_SYNC_RECV_FROM_CP,
            sync_event, &assoc_rels);
        if (0 > sync_blk_index) {
            LOG(UPC, ERR, "Build session sync msg failed.");
        }
        sync_blk_exist = TRUE;
    }

resp:
    upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, sa);

    pfcp_build_association_release_response(resp_buffer, &resp_pos, res_cause, pkt_seq,
        sa->sa_family == AF_INET ? UPF_NODE_TYPE_IPV4 : UPF_NODE_TYPE_IPV6);

    if (0 > upc_buff_send2smf(resp_buffer, resp_pos, sa)) {
        LOG(UPC, ERR, "Send packet to SMF failed.");
    }

    if (sync_blk_exist) {
        if (upc_hk_change_sync_blk_status) {
            if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_REPLY_TO_CP, sync_event)) {
                LOG(UPC, ERR, "Change session sync msg failed, node_cb->index: %d.", node_cb->index);
            }
        }
    }
}

void pfcp_parse_association_release_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max)
{
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint8_t  m_nodeid = G_FALSE;
    uint16_t obj_type, obj_len;
    pfcp_node_id            *node_id;
    upc_node_cb             *node_cb = NULL;
    session_association_release_request assoc_rels = {{0}};

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    /* Parse packet */
    last_pos = buf_pos;
    while (buf_pos < buf_max) {

        obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
        obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);

        switch (obj_type) {
            case UPF_NODE_ID:
                /* Declear supported mandatory option */
                m_nodeid = G_TRUE;

                /* Map data */
                node_id = (pfcp_node_id *)(buffer + buf_pos);
                PFCP_MOVE_FORWORD(buf_pos, obj_len);

                LOG(UPC, RUNNING,
                    "decode node id, type %d, value %02x%02x%02x%02x",
                    node_id->type.d.type,
                    node_id->node_id[0],
                    node_id->node_id[1],
                    node_id->node_id[2],
                    node_id->node_id[3]);
                break;

            default:
                LOG(UPC, ERR, "IE type %d, not support, skip it.", obj_type);
                PFCP_MOVE_FORWORD(buf_pos, obj_len);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        LOG(UPC, RUNNING,
            "decode pos from %d to %d, %02x %02x ...",
            last_pos, buf_pos, buffer[last_pos], buffer[last_pos + 1]);
        if (last_pos == buf_pos) {
            LOG(UPC, RUNNING, "empty ie.");
            break;
        }
        else {
            last_pos = buf_pos;
        }
    }

    /* Check mandaytory option */
    if (m_nodeid == G_FALSE) {
        LOG(UPC, RUNNING, "no mandatory option node_id(%d).", m_nodeid);
        return;
    }

    /* If can't find matched node */
    node_cb = upc_node_get(node_id->type.d.type, node_id->node_id);
    if (NULL == node_cb) {
        LOG(UPC, RUNNING, "no matched node found.");
        return;
    }

    if (0 > upc_node_del(node_cb)) {
        LOG(UPC, ERR, "Delete node failed.");
    }
    assoc_rels.node_id_index = node_cb->index;

    if (upc_hk_build_data_block) {
        if (0 > upc_hk_build_data_block(HA_SYNC_DATA_NODE, HA_REMOVE, HA_SYNC_FINAL_STATE,
            HA_SYNC_EVENT_SUCC, &assoc_rels)) {
            LOG(UPC, ERR, "Build session sync msg failed.");
        }
    }
}

void pfcp_build_association_setup_request(upc_node_cb *node)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t buf_pos = 0, msg_hdr_pos;

    upc_fill_ip_udp_hdr(resp_buffer, &buf_pos, &node->peer_sa);

    msg_hdr_pos = buf_pos;
    pfcp_client_encode_header(resp_buffer, &buf_pos, 0, 0,
        SESS_ASSOCIATION_SETUP_REQUEST, 0, ros_atomic32_add_return(&node->local_seq, 1));

    /* Enconde local node id */
    pfcp_encode_node_id(resp_buffer, &buf_pos, node->peer_id.type.d.type);
    LOG(UPC, RUNNING, "encode node id.");

    /* Encode recover time stamp */
    pfcp_encode_time_stamp(resp_buffer, &buf_pos);
    LOG(UPC, RUNNING, "encode local recover time stamp.");

    /* Encode UP Function Features */
    pfcp_encode_up_features(resp_buffer, &buf_pos);
    LOG(UPC, RUNNING, "encode local up features.");

    /* Encode UE IP address Pool Information */
    pfcp_encode_ueip_addr_pool_info(resp_buffer, &buf_pos);

    /* Encode UPF Instance ID */
    tlv_encode_type(resp_buffer, &buf_pos, UPF_NF_INSTANCE_ID);
    tlv_encode_length(resp_buffer, &buf_pos, 16);
    tlv_encode_binary(resp_buffer, &buf_pos, 16, node->guid.value);

    /* Encode PFCPASReq-Flags */
    /* Need to support IPUPS */
    if (0) {
        tlv_encode_type(resp_buffer, &buf_pos, UPF_PFCPASREQ_FLAGS);
        tlv_encode_length(resp_buffer, &buf_pos, 1);
        tlv_encode_uint8_t(resp_buffer, &buf_pos, 1);
    }

    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, buf_pos);

    upc_buff_send2smf(resp_buffer, buf_pos, &node->peer_sa);

    return;
}

void pfcp_build_association_setup_response(uint8_t *resp_buffer,
    uint16_t *buf_pos, uint8_t res_cause, uint32_t pkt_seq, uint8_t node_type, uint8_t sess_retention)
{
    uint16_t msg_hdr_pos = *buf_pos;

    /* Encode msg header */
    pfcp_client_encode_header(resp_buffer, buf_pos, 0, 0,
        SESS_ASSOCIATION_SETUP_RESPONSE, 0, pkt_seq);

    /* Enconde local node id */
    pfcp_encode_node_id(resp_buffer, buf_pos, node_type);
    LOG(UPC, RUNNING, "encode node id.");

    /* Encode cause */
    pfcp_encode_cause(resp_buffer, buf_pos, res_cause);
    LOG(UPC, RUNNING, "encode cause %d.", res_cause);

    /* Encode recover time stamp */
    pfcp_encode_time_stamp(resp_buffer, buf_pos);
    LOG(UPC, RUNNING, "encode local recover time stamp.");

    pfcp_encode_up_features(resp_buffer, buf_pos);
    LOG(UPC, RUNNING, "encode local up features.");

    /* Encode UE IP address Pool Information */
    pfcp_encode_ueip_addr_pool_info(resp_buffer, buf_pos);

    /* Encode UPF Instance ID */
    tlv_encode_type(resp_buffer, buf_pos, UPF_NF_INSTANCE_ID);
    tlv_encode_length(resp_buffer, buf_pos, 16);
    tlv_encode_binary(resp_buffer, buf_pos, 16, upc_upf_guid_get());

    /* Encode PFCPASRsp-Flags */
    /* Need to support IPUPS */
    if (sess_retention) {
        tlv_encode_type(resp_buffer, buf_pos, UPF_PFCPASRSP_FLAGS);
        tlv_encode_length(resp_buffer, buf_pos, 1);
        tlv_encode_uint8_t(resp_buffer, buf_pos, 1);
    }

    /* Filling msg header length */
    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, *buf_pos);
}

void pfcp_build_association_update_request(upc_node_cb *node, uint8_t rel_flag,
    uint8_t gra_flag, uint8_t aur_flag)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t buf_pos = 0, msg_hdr_pos;

    upc_fill_ip_udp_hdr(resp_buffer, &buf_pos, &node->peer_sa);

    msg_hdr_pos = buf_pos;
    pfcp_client_encode_header(resp_buffer, &buf_pos, 0, 0,
        SESS_ASSOCIATION_UPDATE_REQUEST, 0, ros_atomic32_add_return(&node->local_seq, 1));

    /* Enconde local node id */
    pfcp_encode_node_id(resp_buffer, &buf_pos, node->peer_id.type.d.type);
    LOG(UPC, RUNNING, "encode node id.");

	if (rel_flag == 0 && gra_flag == 0 && aur_flag == 0) {
	    pfcp_encode_up_features(resp_buffer, &buf_pos);
	    LOG(UPC, RUNNING, "encode local up features.");
	}

    if (rel_flag) {
        if (node->status == UPC_NODE_STATUS_RUN) {
            pfcp_encode_release_request_imm(resp_buffer, &buf_pos, 1, 0);
            //node->status = UPC_NODE_STATUS_REPORT;
        }
		/*
        if (node->status == UPC_NODE_STATUS_REPORT) {
            pfcp_encode_release_request_imm(resp_buffer, &buf_pos, 0, 1);
            node->status = UPC_NODE_STATUS_SHUT;
        }
        */
    }

    if (gra_flag) {
        uint32_t time_in_sec;

        time_in_sec = ros_atomic32_read(&node->session_num) / UPC_NODE_WAIT_RATE + 2;
        pfcp_encode_release_request_delay(resp_buffer, &buf_pos, time_in_sec);
    }

    if (aur_flag) {
        session_asso_aureq_flag aureq1;

        aureq1.value = 0;
        aureq1.d.parps = 1;

        pfcp_encode_aureq(resp_buffer, &buf_pos, aureq1.value);
    }

    /* Encode UE IP address Pool Information */
    pfcp_encode_ueip_addr_pool_info(resp_buffer, &buf_pos);

    /* Encode UE IP Address Usage Information */
    pfcp_encode_ueip_addr_usage_info(resp_buffer, &buf_pos);

    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, buf_pos);

    upc_buff_send2smf(resp_buffer, buf_pos, &node->peer_sa);

    return;
}

void pfcp_build_association_update_response(uint8_t* resp_buffer,
    uint16_t *buf_pos, uint8_t res_cause, uint32_t pkt_seq, uint8_t node_type)
{
    uint16_t msg_hdr_pos;

    msg_hdr_pos = *buf_pos;
    /* Encode msg header */
    pfcp_client_encode_header(resp_buffer, buf_pos, 0, 0,
        SESS_ASSOCIATION_UPDATE_RESPONSE, 0, pkt_seq);

    /* Enconde local node id */
    pfcp_encode_node_id(resp_buffer, buf_pos, node_type);
    LOG(UPC, RUNNING, "encode node id.");

    /* Encode cause */
    pfcp_encode_cause(resp_buffer, buf_pos, res_cause);
    LOG(UPC, RUNNING, "encode cause %d.", res_cause);

    /* Encode UE IP Address Usage Information */
    pfcp_encode_ueip_addr_usage_info(resp_buffer, buf_pos);

    /* Filling msg header length */
    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, *buf_pos);
}

void pfcp_build_association_release_request(upc_node_cb *node)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t buf_pos = 0, msg_hdr_pos;

    upc_fill_ip_udp_hdr(resp_buffer, &buf_pos, &node->peer_sa);

    msg_hdr_pos = buf_pos;
    pfcp_client_encode_header(resp_buffer, &buf_pos, 0, 0,
        SESS_ASSOCIATION_RELEASE_REQUEST, 0, ros_atomic32_add_return(&node->local_seq, 1));

    /* Enconde local node id */
    pfcp_encode_node_id(resp_buffer, &buf_pos, node->peer_id.type.d.type);
    LOG(UPC, RUNNING, "encode node id.");

    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, buf_pos);

    upc_buff_send2smf(resp_buffer, buf_pos, &node->peer_sa);
}

void pfcp_build_association_release_response(uint8_t* resp_buffer,
    uint16_t *buf_pos, uint8_t res_cause, uint32_t pkt_seq, uint8_t node_type)
{
    uint16_t msg_hdr_pos = *buf_pos;

    /* Encode msg header */
    pfcp_client_encode_header(resp_buffer, buf_pos, 0, 0,
        SESS_ASSOCIATION_RELEASE_RESPONSE, 0, pkt_seq);

    /* Enconde local node id */
    pfcp_encode_node_id(resp_buffer, buf_pos, node_type);
    LOG(UPC, RUNNING, "encode node id.");

    /* Encode cause */
    pfcp_encode_cause(resp_buffer, buf_pos, res_cause);
    LOG(UPC, RUNNING, "encode cause %d.", res_cause);

    /* Filling msg header length */
    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, *buf_pos);
}


