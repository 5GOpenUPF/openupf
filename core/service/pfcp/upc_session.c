/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "upc_node.h"
#include "pfcp_association.h"
#include "pfcp_client.h"

#include "upc_seid.h"
#include "upc_ueip.h"
#include "upc_teid.h"
#include "upc_temp_buffer.h"
#include "pfcp_pfd_mgmt.h"
#include "upc_session.h"
#include "upc_prerule.h"
#include "session_mgmt.h"

extern user_Signaling_trace_t user_sig_trace;
static int upc_assign_ueip(session_pdr_create *pdr);
static int upc_collect_ueip(session_pdr_create *pdr);
static int upc_assign_teid(uint32_t node_index,
    session_packet_detection_info *pdi, struct upc_choose_id_mgmt *choose_mgmt);
static int upc_collect_teid(session_packet_detection_info *pdi);


static PFCP_CAUSE_TYPE upc_parse_f_teid(session_f_teid *f_teid,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;
    session_up_features uf = {.value = upc_get_up_features()};

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* f-teid flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            f_teid->f_teid_flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* f-teid choose */
        if (0 == f_teid->f_teid_flag.d.ch) {
            /* f-teid teid */
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                f_teid->teid = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
            /* f-teid ipv4 address */
            if (f_teid->f_teid_flag.d.v4) {
                len_cnt += sizeof(uint32_t);
                if (len_cnt <= obj_len) {
                    f_teid->ipv4_addr = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, len_cnt);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            }
            /* f-teid ipv6 address */
            if (f_teid->f_teid_flag.d.v6) {
                len_cnt += IPV6_ALEN;
                if (len_cnt <= obj_len) {
                    tlv_decode_binary(buffer, buf_pos, IPV6_ALEN,
                        f_teid->ipv6_addr);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, len_cnt);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            }

            if (uf.d.FTUP) {
                LOG(UPC, ERR,
                    "Configuration error, teid is set,"
                    " but FTUP of UP features is set.");
                res_cause = SESS_INVALID_F_TEID_ALLOCATION_OPTION;
                return res_cause;
            }
        } else {
            if (0 == uf.d.FTUP) {
                LOG(UPC, ERR,
                    "Configuration error, CHOOSE flag of f-teid is set,"
                    " but FTUP of UP features not set.");
                res_cause = SESS_INVALID_F_TEID_ALLOCATION_OPTION;
                return res_cause;
            }

            if (f_teid->f_teid_flag.d.chid) {
                len_cnt += sizeof(uint8_t);
                if (len_cnt <= obj_len) {
                    f_teid->choose_id = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, len_cnt);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
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

static PFCP_CAUSE_TYPE upc_parse_ue_ip(session_ue_ip *ueip,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;
    session_up_features uf = {.value = upc_get_up_features()};
    int ch_flag = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* ueip flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            ueip->ueip_flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        if (ueip->ueip_flag.d.v4) {
            /* ueip ipv4 address */
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                ueip->ipv4_addr = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            /*if (uf.d.UEIP) {
                LOG(UPC, ERR,
                    "Configuration error, UEIP address is set,"
                    " but UEIP of UP features is set.");
                res_cause = SESS_REQUEST_REJECTED;
                return res_cause;
            }*/
        }
        else if (ueip->ueip_flag.d.chv4) {
            ch_flag = 1;
        }

        if (ueip->ueip_flag.d.v6) {
            /* ueip ipv6 address */
            len_cnt += IPV6_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, IPV6_ALEN,
                    ueip->ipv6_addr);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            /*if (uf.d.UEIP) {
                LOG(UPC, ERR,
                    "Configuration error, UEIP address is set,"
                    " but UEIP of UP features is set.");
                res_cause = SESS_REQUEST_REJECTED;
                return res_cause;
            }*/
        }
        else if (ueip->ueip_flag.d.chv6) {
            ch_flag = 1;
        }

        if (ch_flag ^ uf.d.UEIP) {
            LOG(UPC, ERR,
                "Configuration error, CHOOSE flag of UEIP is set,"
                " but UEIP of UP features not set.");
            res_cause = SESS_REQUEST_REJECTED;
            return res_cause;
        }

        /* IPv6 Prefix Delegation Bits */
        if (ueip->ueip_flag.d.ipv6d) {
            len_cnt += sizeof(uint8_t);
            if (len_cnt <= obj_len) {
                ueip->ipv6_prefix = tlv_decode_uint8_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* IPv6 Prefix Length */
        if (ueip->ueip_flag.d.ip6pl) {
            len_cnt += sizeof(uint8_t);
            if (len_cnt <= obj_len) {
                ueip->ipv6_prefix_len = tlv_decode_uint8_t(buffer, buf_pos);
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

static PFCP_CAUSE_TYPE upc_parse_f_seid(session_f_seid *f_seid,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            f_seid->ip_version.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* seid */
        len_cnt += sizeof(uint64_t);
        if (len_cnt <= obj_len) {
            f_seid->seid = tlv_decode_uint64_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* ipv4 address */
        if (f_seid->ip_version.d.v4) {
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                f_seid->ipv4_addr = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }
        /* ipv6 address */
        if (f_seid->ip_version.d.v6) {
            len_cnt += IPV6_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, IPV6_ALEN, f_seid->ipv6_addr);
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

static PFCP_CAUSE_TYPE upc_parse_packet_rate_status(session_packet_rate_status *prs,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            prs->flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* UL */
        if (prs->flag.d.UL) {
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                prs->remain_ul_packets = tlv_decode_uint16_t(buffer, buf_pos);

                if (prs->flag.d.APR) {
                    len_cnt += sizeof(uint16_t);
                    if (len_cnt <= obj_len) {
                        prs->addit_remain_ul_packets = tlv_decode_uint16_t(buffer, buf_pos);

                    } else {
                        LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                            obj_len, len_cnt);
                        res_cause = SESS_INVALID_LENGTH;
                        return res_cause;
                    }
                }
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* DL */
        if (prs->flag.d.DL) {
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                prs->remain_dl_packets = tlv_decode_uint16_t(buffer, buf_pos);

                if (prs->flag.d.APR) {
                    len_cnt += sizeof(uint16_t);
                    if (len_cnt <= obj_len) {
                        prs->addit_remain_dl_packets = tlv_decode_uint16_t(buffer, buf_pos);

                    } else {
                        LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                            obj_len, len_cnt);
                        res_cause = SESS_INVALID_LENGTH;
                        return res_cause;
                    }
                }
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* Rate Control Status Validity Time */
        if (prs->flag.d.DL || prs->flag.d.UL) {
            len_cnt += sizeof(uint64_t);
            if (len_cnt <= obj_len) {
                prs->rate_ctrl_status_time = tlv_decode_uint64_t(buffer, buf_pos);
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

static PFCP_CAUSE_TYPE upc_parse_flow_description(session_flow_desc *fd,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;

    if (obj_len) {
        char src[obj_len + 1];
        char *s = src;
        char delim[] = " ";
        char *token = NULL;
        uint8_t spil_times = 0;

        ros_memcpy(src, (buffer + *buf_pos), obj_len);
        src[obj_len] = 0;
        PFCP_MOVE_FORWORD(*buf_pos, obj_len);

        fd->no_sp = fd->no_dp = 1;

        for (token = strsep(&s, delim); token != NULL;
            token = strsep(&s, delim), ++spil_times) {
            if (*token == 0) {
                continue;
            }

            switch (spil_times) {
                case 0:
                    if (strncmp(token, "permit", 6)) {
                        LOG(UPC, ERR, "parse flow description failed, <action> error: %s.", token);
                        res_cause = SESS_INVALID_LENGTH;
                    }
                    break;

                case 1:
                    if (strncmp(token, "out", 3)) {
                        LOG(UPC, ERR, "parse flow description failed, <dir> error: %s.", token);
                        res_cause = SESS_INVALID_LENGTH;
                    }
                    break;

                case 2:
                    /* protocol */
                    if (0 == strncmp(token, "ip", 2)) {
                        fd->protocol = 0;
                    } else {
                        fd->protocol = atoi(token);
                    }
                    break;

                case 3:
                    if (strncmp(token, "from", 4)) {
                        LOG(UPC, ERR, "parse flow description failed, <from> error: %s.", token);
                        res_cause = SESS_INVALID_LENGTH;
                    }
                    break;

                case 4:
                    {
                        /* source ip */
                        char ch[] = "/";
                        char *tk = NULL;

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            if (0 == strncmp(tk, "any", 3)) {
                                ros_memset(&fd->sip, 0, IPV6_ALEN);
                                ros_memset(&fd->smask, 0, IPV6_ALEN);
                                fd->ip_type = SESSION_IP_V4V6;
                                break;
                            } else if (strchr(tk, ':')) {
                                /* ipv6 */
                                if (1 != inet_pton(AF_INET6, tk, fd->sip.sipv6)) {
                                    LOG(UPC, ERR,
                                        "parse flow description source failed, ipv6: %s.", tk);
                                    res_cause = SESS_INVALID_LENGTH;
                                }
                                fd->ip_type = SESSION_IP_V6;
                            } else {
                                /* ipv4 */
                                if (1 != inet_pton(AF_INET, tk, &fd->sip.sipv4)) {
                                    LOG(UPC, ERR,
                                        "parse flow description source failed, ipv4: %s.", tk);
                                    res_cause = SESS_INVALID_LENGTH;
                                }
                                fd->sip.sipv4 = ntohl(fd->sip.sipv4);
                                fd->ip_type = SESSION_IP_V4;
                            }
                        } else {
                            LOG(UPC, ERR, "parse flow description failed, missing source ip.");
                            res_cause = SESS_INVALID_LENGTH;
                        }

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            uint8_t prefix = atoi(tk);

                            if (fd->ip_type == SESSION_IP_V4) {
                                fd->smask.sipv4_mask = num_to_mask(prefix);
                            } else {
                                ipv6_prefix_to_mask(fd->smask.sipv6_mask, prefix);
                            }
                        } else {
                            if (fd->ip_type == SESSION_IP_V4) {
                                fd->smask.sipv4_mask = 0xFFFFFFFF;
                            } else {
                                ros_memset(fd->smask.sipv6_mask, 0xFF, IPV6_ALEN);
                            }
                        }
                    }
                    break;

                case 5:
                    {
                        /* source port */
                        char ch[] = "-";
                        char *tk = NULL;

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            /* 端口可能不存在 */
                            if (0 == strncmp(tk, "to", 2)) {
                                fd->no_sp = 1;
                                ++spil_times;
                                break;
                            }

                            fd->no_sp = 0;
                            fd->sp_min = atoi(tk);
                        } else {
                            LOG(UPC, ERR, "parse flow description failed, Incomplete field.");
                            res_cause = SESS_INVALID_LENGTH;
                        }

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            fd->sp_max = atoi(tk);
                        } else {
                            fd->sp_max = fd->sp_min;
                        }
                    }
                    break;

                case 6:
                    if (strncmp(token, "to", 2)) {
                        LOG(UPC, ERR, "parse flow description failed, <to> error: %s.", token);
                        res_cause = SESS_INVALID_LENGTH;
                    }
                    break;

                case 7:
                    {
                        /* dest ip */
                        char ch[] = "/";
                        char *tk = NULL;

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            if (0 == strncmp(tk, "assigned", 8) || 0 == strncmp(tk, "any", 3)) {
                                ros_memset(&fd->dip, 0, IPV6_ALEN);
                                ros_memset(&fd->dmask, 0, IPV6_ALEN);
                                fd->ip_type = SESSION_IP_V4V6;
                                break;
                            } else if (strchr(tk, ':')) {
                                /* ipv6 */
                                if (1 != inet_pton(AF_INET6, tk, fd->dip.dipv6)) {
                                    LOG(UPC, ERR,
                                        "parse flow description source failed, ipv6: %s.", tk);
                                    res_cause = SESS_INVALID_LENGTH;
                                }
                                fd->ip_type = SESSION_IP_V6;
                            } else {
                                /* ipv4 */
                                if (1 != inet_pton(AF_INET, tk, &fd->dip.dipv4)) {
                                    LOG(UPC, ERR,
                                        "parse flow description source failed, ipv4: %s.", tk);
                                    res_cause = SESS_INVALID_LENGTH;
                                }
                                fd->dip.dipv4 = ntohl(fd->dip.dipv4);
                                fd->ip_type = SESSION_IP_V4;
                            }
                        } else {
                            LOG(UPC, ERR, "parse flow description failed, missing source ip.");
                            res_cause = SESS_INVALID_LENGTH;
                        }

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            uint8_t prefix = atoi(tk);

                            if (fd->ip_type == SESSION_IP_V4) {
                                fd->dmask.dipv4_mask = num_to_mask(prefix);
                            } else {
                                ipv6_prefix_to_mask(fd->dmask.dipv6_mask, prefix);
                            }
                        } else {
                            if (fd->ip_type == SESSION_IP_V4) {
                                fd->dmask.dipv4_mask = 0xFFFFFFFF;
                            } else {
                                ros_memset(fd->dmask.dipv6_mask, 0xFF, IPV6_ALEN);
                            }
                        }
                    }
                    break;

                case 8:
                    {
                        /* dest port */
                        char ch[] = "-";
                        char *tk = NULL;

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            fd->no_dp = 0;
                            fd->dp_min = atoi(tk);
                        } else {
                            fd->no_dp = 1;
                            break;
                        }

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            fd->dp_max = atoi(tk);
                        } else {
                            fd->dp_max = fd->dp_min;
                        }
                    }
                    break;

                default:
                    LOG(UPC, ERR,
                        "parse flow description failed, abnormal spil_times: %d, token: %s.",
                        spil_times, token ? token : "NULL");
                    res_cause = SESS_INVALID_LENGTH;
                    break;
            }
        }


    } else {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE length error.");
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_sdf_filter(session_sdf_filter *sdf,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* sdf flag */
        len_cnt += sizeof(uint16_t);
        if (len_cnt <= obj_len) {
            sdf->sdf_flag.value = tlv_decode_uint16_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Flow Description */
        if (sdf->sdf_flag.d.fd) {
            uint16_t fd_length;

            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                fd_length = tlv_decode_uint16_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
            len_cnt += fd_length;
            if (len_cnt <= obj_len) {
                /* Flow Description info */
                res_cause = upc_parse_flow_description(&sdf->desc,
                    buffer, buf_pos, buf_max, fd_length);
                if (res_cause != SESS_REQUEST_ACCEPTED) {
                    LOG(UPC, ERR, "Parse SDF flow description fail.");
                    return res_cause;
                }
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* ToS Traffic Class */
        if (sdf->sdf_flag.d.ttc) {
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                sdf->tos_traffic_class.value = tlv_decode_uint16_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* Security Parameter Index */
        if (sdf->sdf_flag.d.spi) {
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                sdf->ipsec_spi = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* Flow Label */
        if (sdf->sdf_flag.d.fl) {
            len_cnt += 3;
            if (len_cnt <= obj_len) {
                sdf->label.value = tlv_decode_int_3b(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* SDF Filter ID */
        if (sdf->sdf_flag.d.bid) {
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                sdf->sdf_id = tlv_decode_uint32_t(buffer, buf_pos);
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

static PFCP_CAUSE_TYPE upc_parse_mac_address(session_mac_addr *mac,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* mac flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            mac->mac_flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Source MAC address */
        if (mac->mac_flag.d.sour) {
            len_cnt += ETH_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, ETH_ALEN, mac->src);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* Destination MAC address */
        if (mac->mac_flag.d.dest) {
            len_cnt += ETH_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, ETH_ALEN, mac->dst);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* Upper Source MAC address */
        if (mac->mac_flag.d.usou) {
            len_cnt += ETH_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, ETH_ALEN, mac->upper_src);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* Upper Destination MAC address */
        if (mac->mac_flag.d.udes) {
            len_cnt += ETH_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, ETH_ALEN, mac->upper_dst);
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

static PFCP_CAUSE_TYPE upc_parse_eth_filter(session_eth_filter *eth_filter,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;

    LOG(UPC, RUNNING, "Parse Eth filter.");
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
            case UPF_ETHERNET_FILTER_ID:
                if (sizeof(uint32_t) == obj_len) {
                    eth_filter->member_flag.d.eth_filter_id_present = 1;
                    eth_filter->eth_filter_id =
                        tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_ETHERNET_FILTER_PROPERTIES:
                if (sizeof(uint8_t) == obj_len) {
                    eth_filter->member_flag.d.eth_filter_prop_present = 1;
                    eth_filter->eth_filter_prop.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MAC_ADDRESS:
                if (eth_filter->mac_addr_num < MAX_MAC_ADDRESS_NUM) {
                    res_cause = upc_parse_mac_address(
                        &eth_filter->mac_addr[eth_filter->mac_addr_num], buffer,
                        buf_pos, buf_max, obj_len);
                    ++eth_filter->mac_addr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of MAC address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_ETHERTYPE:
                if (sizeof(uint16_t) == obj_len) {
                    eth_filter->member_flag.d.eth_type_present = 1;
                    eth_filter->eth_type = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_C_TAG:
                if (3 == obj_len) {
                    eth_filter->c_tag.flags.value = tlv_decode_uint8_t(buffer, buf_pos);
                    eth_filter->c_tag.value.value = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, 3);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_S_TAG:
                if (3 == obj_len) {
                    eth_filter->s_tag.flags.value = tlv_decode_uint8_t(buffer, buf_pos);
                    eth_filter->s_tag.value.value = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, 3);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SDF_FILTER:
                if (eth_filter->sdf_arr_num < MAX_SDF_FILTER_NUM) {
                    res_cause = upc_parse_sdf_filter(
                        &eth_filter->sdf_arr[eth_filter->sdf_arr_num], buffer,
                        buf_pos, buf_max, obj_len);
                    ++eth_filter->sdf_arr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of SDF filter reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (eth_filter->eth_filter_prop.d.bide ^ eth_filter->member_flag.d.eth_filter_id_present)) {
        LOG(UPC, ERR, "Ethernet Filter ID  is miss.");
        res_cause = SESS_CONDITIONAL_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_framed_route(session_framed_route *fr,
    uint8_t *buffer, uint16_t *buf_pos, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;

    if (obj_len) {
        char src[obj_len + 1];
        char *s = src;
        char delim[] = " ";
        char *token = NULL;
        uint8_t spil_times = 0;

        ros_memcpy(src, (buffer + *buf_pos), obj_len);
        src[obj_len] = 0;
        PFCP_MOVE_FORWORD(*buf_pos, obj_len);

        for (token = strsep(&s, delim); token != NULL;
            token = strsep(&s, delim), ++spil_times) {
            if (*token == 0) {
                continue;
            }

            switch (spil_times) {
                case 0:
                    {
                        char ch[] = "/";
                        char *tk = NULL;

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            if (1 != inet_pton(AF_INET, tk, &fr->dest_ip)) {
                                LOG(UPC, ERR,
                                    "parse framed route failed, tk: %s.", tk);
                                res_cause = SESS_INVALID_LENGTH;
                            }
                            fr->dest_ip = ntohl(fr->dest_ip);
                        }
                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            fr->ip_mask = atoi(tk);
                        } else {
                            uint8_t tmp = fr->dest_ip >> 24;

                            if (tmp < 128) {
                                /* class A */
                                fr->ip_mask = 8;
                            } else if (tmp < 192) {
                                /* class B */
                                fr->ip_mask = 16;
                            } else if (tmp < 224) {
                                /* class B */
                                fr->ip_mask = 24;
                            } else {
                                LOG(UPC, ERR,
                                    "parse framed route failed,"
                                    "error address type.");
                                res_cause = SESS_INVALID_LENGTH;
                            }
                        }
                        fr->ip_mask = num_to_mask(fr->ip_mask);
                    }
                    break;

                case 1:
                    if (1 != inet_pton(AF_INET, token, &fr->gateway)) {
                        LOG(UPC, ERR,
                            "parse framed route failed.");
                        res_cause = SESS_INVALID_LENGTH;
                    }
                    fr->gateway = ntohl(fr->gateway);
                    break;

                case 2:
                    fr->metrics = atoi(token);
                    break;

                default:
                    LOG(UPC, ERR, "parse framed route failed, abnormal spil_times: %d.",
                        spil_times);
                    res_cause = SESS_INVALID_LENGTH;
                    break;
            }
        }


    } else {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE length error.");
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_framed_route_v6(
    session_framed_route_ipv6 *fr_v6,
    uint8_t *buffer, uint16_t *buf_pos, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;

    if (obj_len) {
        char src[obj_len + 1];
        char *s = src;
        char delim[] = " ";
        char *token = NULL;
        uint8_t spil_times = 0;

        ros_memcpy(src, (buffer + *buf_pos), obj_len);
        src[obj_len] = 0;
        PFCP_MOVE_FORWORD(*buf_pos, obj_len);

        for (token = strsep(&s, delim); token != NULL;
            token = strsep(&s, delim), ++spil_times) {
            if (*token == 0) {
                continue;
            }

            switch (spil_times) {
                case 0:
                    {
                        char ch[] = "/";
                        char *tk = NULL;

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            if (1 != inet_pton(AF_INET6, tk, fr_v6->dest_ip)) {
                                LOG(UPC, ERR,
                                    "parse framed route ipv6 failed,"
                                    " string: %s.", tk);
                                res_cause = SESS_INVALID_LENGTH;
                            }
                        }
                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            uint8_t prefix = atoi(tk);

                            ipv6_prefix_to_mask(fr_v6->ip_mask, prefix);
                        } else {
                            uint8_t prefix = 64;

                            ipv6_prefix_to_mask(fr_v6->ip_mask, prefix);
                        }
                    }
                    break;

                case 1:
                    if (1 != inet_pton(AF_INET6, token, fr_v6->gateway)) {
                        LOG(UPC, ERR,
                            "parse framed route ipv6 failed.");
                        res_cause = SESS_INVALID_LENGTH;
                    }
                    break;

                case 2:
                    fr_v6->metrics = atoi(token);
                    break;

                default:
                    LOG(UPC, ERR,
                        "parse framed route failed, abnormal spil_times: %d.",
                        spil_times);
                    res_cause = SESS_INVALID_LENGTH;
                    break;
            }
        }


    } else {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE length error.");
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_ueip_addr_pool_id(session_ue_ip_address_pool_identity *pool_id,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* length */
        len_cnt += sizeof(uint16_t);
        if (len_cnt <= obj_len) {
            pool_id->pool_id_len = tlv_decode_uint16_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* pool id */
        if (pool_id->pool_id_len < UE_IP_ADDRESS_POOL_LEN) {
            len_cnt += pool_id->pool_id_len;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, pool_id->pool_id_len, (uint8_t *)pool_id->pool_identity);
                pool_id->pool_identity[pool_id->pool_id_len] = '\0';
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        } else {
            LOG(UPC, ERR, "pool_id_length: %d abnormal, Should be Less than %d.",
                pool_id->pool_id_len, UE_IP_ADDRESS_POOL_LEN);
            res_cause = SESS_INVALID_LENGTH;
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

static PFCP_CAUSE_TYPE upc_parse_ip_mul_address(session_ip_multicast_address *ip_mul,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;
    //session_up_features uf = {.value = upc_get_up_features()};

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* ueip flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            ip_mul->flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        if (ip_mul->flag.d.V4) {
            /* Start ipv4 address */
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                ip_mul->start_ip.ipv4 = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (ip_mul->flag.d.V6) {
            /* Start ipv6 address */
            len_cnt += IPV6_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, IPV6_ALEN,
                    ip_mul->start_ip.ipv6);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (ip_mul->flag.d.R) {
            if (ip_mul->flag.d.V4) {
                /* End ipv4 address */
                len_cnt += sizeof(uint32_t);
                if (len_cnt <= obj_len) {
                    ip_mul->end_ip.ipv4 = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, len_cnt);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            }

            if (ip_mul->flag.d.V6) {
                /* End ipv6 address */
                len_cnt += IPV6_ALEN;
                if (len_cnt <= obj_len) {
                    tlv_decode_binary(buffer, buf_pos, IPV6_ALEN,
                        ip_mul->end_ip.ipv6);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, len_cnt);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
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

static PFCP_CAUSE_TYPE upc_parse_source_ip_address(session_source_ip_address *source_ip,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* ueip flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            source_ip->flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        if (source_ip->flag.d.v4) {
            /* Start ipv4 address */
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                source_ip->ipv4 = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (source_ip->flag.d.v6) {
            /* Start ipv6 address */
            len_cnt += IPV6_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, IPV6_ALEN,
                    source_ip->ipv6);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (source_ip->flag.d.mpl) {
            len_cnt += sizeof(uint8_t);
            if (len_cnt <= obj_len) {
                source_ip->prefix_len = tlv_decode_uint8_t(buffer, buf_pos);
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

static PFCP_CAUSE_TYPE upc_parse_ip_mul_addr_info(session_ip_multicast_addr_info *imai,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse IP Multicast Addressing Info.");
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
            case UPF_IP_MULTICAST_ADDRESS:
                m_opt = 1;
                res_cause = upc_parse_ip_mul_address(&imai->ip_mul_addr, buffer,
                    buf_pos, buf_max, obj_len);
                break;

            case UPF_SOURCE_IP_ADDRESS:
                if (imai->source_ip_num < IP_MUL_SOURCE_IP_NUM) {
                    res_cause = upc_parse_source_ip_address(
                        &imai->source_ip[imai->source_ip_num], buffer,
                        buf_pos, buf_max, obj_len);
                    ++imai->source_ip_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of Source IP Address reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_redundant_trans_para_in_pdi(session_redundant_trans_param_in_pdi *rtp,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse redundant transmission parameters.");
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
            case UPF_F_TEID:
                m_opt = 1;
                res_cause = upc_parse_f_teid(&rtp->fteid, buffer,
                    buf_pos, buf_max, obj_len);
                break;

            case UPF_NETWORK_INSTANCE:
                if (obj_len && (NETWORK_INSTANCE_LEN > obj_len)) {
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)rtp->network_instance);
                    rtp->network_instance[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, NETWORK_INSTANCE_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_pdi(session_packet_detection_info *pdi,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;
    session_up_features uf = {.value = upc_get_up_features()};

    LOG(UPC, RUNNING, "Parse PDI.");
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
            case UPF_SOURCE_INTERFACE:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    pdi->si = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_F_TEID:
                pdi->member_flag.d.local_fteid_present = 1;
                res_cause = upc_parse_f_teid(&pdi->local_fteid, buffer,
                    buf_pos, buf_max, obj_len);
                break;

            case UPF_NETWORK_INSTANCE:
                if (obj_len && (NETWORK_INSTANCE_LEN > obj_len)) {
                    pdi->member_flag.d.network_instance_present = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)pdi->network_instance);
                    pdi->network_instance[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, NETWORK_INSTANCE_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_REDUNDANT_TRANSMISSION_PARAMETERS:
                pdi->member_flag.d.redundant_transmission_present = 1;
                res_cause = upc_parse_redundant_trans_para_in_pdi(&pdi->redundant_transmission_param, buffer,
                    buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            case UPF_UE_IP_ADDRESS:
                if (pdi->ue_ipaddr_num < MAX_UE_IP_NUM) {
                    res_cause = upc_parse_ue_ip(
                        &pdi->ue_ipaddr[pdi->ue_ipaddr_num], buffer,
                        buf_pos, buf_max, obj_len);
                    ++pdi->ue_ipaddr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of UE IP reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_TRAFFIC_ENDPOINT_ID:
                if (sizeof(uint8_t) == obj_len) {
                    pdi->traffic_endpoint_id[pdi->traffic_endpoint_num] =
                        tlv_decode_uint8_t(buffer, buf_pos);
                    ++pdi->traffic_endpoint_num;
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SDF_FILTER:
                if (pdi->sdf_filter_num < MAX_SDF_FILTER_NUM) {
                    res_cause = upc_parse_sdf_filter(
                        &pdi->sdf_filter[pdi->sdf_filter_num], buffer,
                        buf_pos, buf_max, obj_len);
                    ++pdi->sdf_filter_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of SDF filter reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_APPLICATION_ID:
                if (obj_len && (MAX_APP_ID_LEN > obj_len)) {
                    pdi->member_flag.d.application_id_present = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)pdi->application_id);
                    pdi->application_id[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, MAX_APP_ID_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_ETHERNET_PDU_SESSION_INFORMATION:
                if (sizeof(uint8_t) == obj_len) {
                    pdi->member_flag.d.eth_pdu_ses_info_present = 1;
                    pdi->eth_pdu_ses_info.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_ETHERNET_PACKET_FILTER:
                if (pdi->eth_filter_num < MAX_ETH_FILTER_NUM) {
                    res_cause = upc_parse_eth_filter(
                        &pdi->eth_filter[pdi->eth_filter_num], buffer,
                        buf_pos, *buf_pos + obj_len, sess_rep);
                    ++pdi->eth_filter_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of ETH filter reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_QFI:
                if (pdi->qfi_number < MAX_QFI_NUM) {
                    if (sizeof(uint8_t) == obj_len) {
                        pdi->qfi_array[pdi->qfi_number] =
                            tlv_decode_uint8_t(buffer, buf_pos);
                        ++pdi->qfi_number;
                    } else {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint8_t));
                        res_cause = SESS_INVALID_LENGTH;
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of QFI reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_FRAMED_ROUTE:
                if (pdi->framed_route_num < MAX_FRAMED_ROUTE_NUM) {
                    res_cause = upc_parse_framed_route(
                        &pdi->framed_route[pdi->framed_route_num], buffer,
                        buf_pos, obj_len);

                    ++pdi->framed_route_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of framed route reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_FRAMED_ROUTING:
                if (4 == obj_len) {
                    pdi->member_flag.d.framed_routing_present = 1;
                    pdi->framed_routing = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, 4);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_FRAMED_IPV6_ROUTE:
                if (pdi->framed_ipv6_route_num < MAX_FRAMED_ROUTE_NUM) {
                    res_cause = upc_parse_framed_route_v6(
                        &pdi->framed_ipv6_route[pdi->framed_ipv6_route_num],
                        buffer, buf_pos, obj_len);

                    ++pdi->framed_ipv6_route_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of framed ipv6 route reaches"
                        " the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_3GPP_INTERFACE_TYPE:
                if (sizeof(uint8_t) == obj_len) {
                    pdi->member_flag.d.src_if_type_present = 1;
                    pdi->src_if_type.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_IP_MULTICAST_ADDRESSING_INFO_WITHIN_PFCP_SESSION_ESTABLISHMENT_REQUEST:
                if (pdi->ip_mul_addr_num < IP_MUL_ADDR_INFO_NUM) {
                    res_cause = upc_parse_ip_mul_addr_info(
                        &pdi->ip_mul_addr_info[pdi->ip_mul_addr_num], buffer,
                        buf_pos, buf_max, sess_rep);
                    ++pdi->ip_mul_addr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of IP Multicast Addressing Info reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    if (0 == uf.d.IP6PL && pdi->ue_ipaddr_num > 1) {
        LOG(UPC, ERR, "UP features unsupport IP6PL, But the number of UE IP address IE is greater than one.");
        res_cause = SESS_SERVICE_NOT_SUPPORTED;
        return res_cause;
    }

    if (pdi->traffic_endpoint_num) {
        if (0 == uf.d.PDIU) {
            LOG(UPC, ERR,
                "UP features unsupport PDIU, But the Traffic Endpoint ID IE is present.");
            res_cause = SESS_SERVICE_NOT_SUPPORTED;
            return res_cause;
        }

        if (0 == uf.d.MTE && pdi->traffic_endpoint_num > 1) {
            LOG(UPC, ERR,
                "UP features unsupport MTE, But the number of Traffic Endpoint ID IE is greater than one.");
            res_cause = SESS_SERVICE_NOT_SUPPORTED;
            return res_cause;
        }

        if (pdi->traffic_endpoint_num &&
            (pdi->ue_ipaddr_num || pdi->member_flag.d.local_fteid_present ||
            pdi->member_flag.d.network_instance_present)) {
            LOG(UPC, ERR, "Traffic Endpoint ID settings conflict.");
            res_cause = SESS_REQUEST_REJECTED;
            return res_cause;
        }
    }

    if (pdi->eth_filter_num && pdi->sdf_filter_num) {
        LOG(UPC, ERR,
            "Ethernet Packet Filter is set, but Optional SDF Filter IE is set.");
        res_cause = SESS_REQUEST_REJECTED;
        return res_cause;
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_create_pdr(session_pdr_create *pdr,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    upc_create_pdr_m_opt m_opt = {.value = 0};

    LOG(UPC, RUNNING, "Parse create PDR.");
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
            case UPF_PDR_ID:
                if (sizeof(uint16_t) == obj_len) {
                    m_opt.d.pdr_id = 1;
                    pdr->pdr_id = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PRECEDENCE:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt.d.precedence = 1;
                    pdr->member_flag.d.precedence_present = 1;
                    pdr->precedence = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PDI:
                m_opt.d.pdi = 1;
                pdr->member_flag.d.pdi_content_present = 1;
                res_cause = upc_parse_pdi(&pdr->pdi_content, buffer,
                    buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            case UPF_OUTER_HEADER_REMOVAL:
                if (sizeof(uint8_t) == obj_len) {
                    pdr->member_flag.d.OHR_present = 1;
                    pdr->outer_header_removal.type =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else if (sizeof(uint16_t) == obj_len) {
                    pdr->member_flag.d.OHR_present = 1;
                    pdr->outer_header_removal.type =
                        tlv_decode_uint8_t(buffer, buf_pos);
                    pdr->outer_header_removal.gtp_u_exten =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be %lu or %lu.",
                        obj_len, sizeof(uint8_t), sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_FAR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    pdr->member_flag.d.far_id_present = 1;
                    pdr->far_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_URR_ID:
                if (pdr->urr_id_number < MAX_URR_NUM) {
                    if (sizeof(uint32_t) == obj_len) {
                        pdr->urr_id_array[pdr->urr_id_number] =
                            tlv_decode_uint32_t(buffer, buf_pos);
                        ++pdr->urr_id_number;
                    } else {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint32_t));
                        res_cause = SESS_INVALID_LENGTH;
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of URR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_QER_ID:
                if (pdr->qer_id_number < MAX_QER_NUM) {
                    if (sizeof(uint32_t) == obj_len) {
                        pdr->qer_id_array[pdr->qer_id_number] =
                            tlv_decode_uint32_t(buffer, buf_pos);
                        ++pdr->qer_id_number;
                    } else {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint32_t));
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of QER reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_ACTIVATE_PREDEFINED_RULES_:
                if (pdr->act_pre_number < ACTIVATE_PREDEF_RULE_NUM) {
                    if (obj_len > ACTIVATE_PREDEF_LEN) {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %d.",
                            obj_len, ACTIVATE_PREDEF_LEN);
                    }
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)pdr->act_pre_arr[pdr->act_pre_number].rules_name);
                    pdr->act_pre_arr[pdr->act_pre_number].rules_name[obj_len] = '\0';
                    ++pdr->act_pre_number;
                } else {
                    LOG(UPC, ERR,
                        "The number of activate predefined rules"
                        " reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_ACTIVATION_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    pdr->member_flag.d.act_time_present = 1;
                    pdr->activation_time = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_DEACTIVATION_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    pdr->member_flag.d.deact_time_present = 1;
                    pdr->deactivation_time =
                        tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MAR_ID:
                if (sizeof(uint16_t) == obj_len) {
                    pdr->member_flag.d.mar_id_present = 1;
                    pdr->mar_id = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PACKET_REPLICATION_AND_DETECTION_CARRY_ON_INFORMATION:
                if (sizeof(uint8_t) == obj_len) {
                    pdr->member_flag.d.pkt_rd_carry_on_info_present = 1;
                    pdr->pkt_rd_carry_on_info.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_IP_MULTICAST_ADDRESSING_INFO_WITHIN_PFCP_SESSION_ESTABLISHMENT_REQUEST:
                if (pdr->ip_mul_addr_num < IP_MUL_ADDR_INFO_NUM) {
                    res_cause = upc_parse_ip_mul_addr_info(
                        &pdr->ip_mul_addr_info[pdr->ip_mul_addr_num], buffer,
                        buf_pos, buf_max, sess_rep);
                    ++pdr->ip_mul_addr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of IP Multicast Addressing Info reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_UE_IP_ADDRESS_POOL_IDENTITY:
                if (pdr->ueip_addr_pool_identity_num < 2) {
                    res_cause = upc_parse_ueip_addr_pool_id(
                        &pdr->ueip_addr_pool_identity[pdr->ueip_addr_pool_identity_num],
                        buffer, buf_pos, *buf_pos + obj_len, obj_len);
                    ++pdr->ueip_addr_pool_identity_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of UEIP Address pool identity reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_PDR;
            sess_rep->failed_rule_id.rule_id = pdr->pdr_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt.value ^ UPC_CREATE_PDR_M_OPT_MASK)) {
        LOG(UPC, ERR,
            "mandatory IE missing, value: %d.", m_opt.value);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_update_pdr(session_pdr_update *pdr,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse update PDR.");
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
            case UPF_PDR_ID:
                if (sizeof(uint16_t) == obj_len) {
                    m_opt = 1;
                    pdr->pdr_id = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PRECEDENCE:
                if (sizeof(uint32_t) == obj_len) {
                    pdr->member_flag.d.precedence_present = 1;
                    pdr->precedence = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PDI:
                pdr->member_flag.d.pdi_content_present = 1;
                res_cause = upc_parse_pdi(&pdr->pdi_content, buffer,
                    buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            case UPF_OUTER_HEADER_REMOVAL:
                if (sizeof(uint16_t) == obj_len) {
                    pdr->member_flag.d.OHR_present = 1;
                    pdr->outer_header_removal.type =
                        tlv_decode_uint8_t(buffer, buf_pos);
                    pdr->outer_header_removal.gtp_u_exten =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_FAR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    pdr->member_flag.d.far_id_present = 1;
                    pdr->far_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_URR_ID:
                if (pdr->urr_id_number < MAX_URR_NUM) {
                    if (sizeof(uint32_t) == obj_len) {
                        pdr->urr_id_array[pdr->urr_id_number] =
                            tlv_decode_uint32_t(buffer, buf_pos);
                        ++pdr->urr_id_number;
                    } else {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint32_t));
                        res_cause = SESS_INVALID_LENGTH;
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of URR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_QER_ID:
                if (pdr->qer_id_number < MAX_QER_NUM) {
                    if (sizeof(uint32_t) == obj_len) {
                        pdr->qer_id_array[pdr->qer_id_number] =
                            tlv_decode_uint32_t(buffer, buf_pos);
                        ++pdr->qer_id_number;
                    } else {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint32_t));
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of QER reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_ACTIVATE_PREDEFINED_RULES_:
                if (pdr->act_pre_number < ACTIVATE_PREDEF_RULE_NUM) {
                    /* not support */
                    if (obj_len > ACTIVATE_PREDEF_LEN) {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %d.",
                            obj_len, ACTIVATE_PREDEF_LEN);
                    }
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)pdr->act_pre_arr[pdr->act_pre_number].rules_name);
                    pdr->act_pre_arr[pdr->act_pre_number].rules_name[obj_len] = '\0';
                    ++pdr->act_pre_number;
                } else {
                    LOG(UPC, ERR,
                        "The number of activate predefined rules"
                        " reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_DEACTIVATE_PREDEFINED_RULES_:
                if (pdr->deact_pre_number < ACTIVATE_PREDEF_RULE_NUM) {
                    /* not support */
                    if (obj_len > ACTIVATE_PREDEF_LEN) {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %d.",
                            obj_len, ACTIVATE_PREDEF_LEN);
                    }
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)pdr->deact_pre_arr[pdr->deact_pre_number].rules_name);
                    pdr->deact_pre_arr[pdr->deact_pre_number].rules_name[obj_len] = '\0';
                    ++pdr->deact_pre_number;
                } else {
                    LOG(UPC, ERR,
                        "The number of deactivate predefined rules"
                        " reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_ACTIVATION_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    pdr->member_flag.d.act_time_present = 1;
                    pdr->activation_time = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_DEACTIVATION_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    pdr->member_flag.d.deact_time_present = 1;
                    pdr->deactivation_time =
                        tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_PDR;
            sess_rep->failed_rule_id.rule_id = pdr->pdr_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_remove_pdr(uint16_t *pdr_id,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse remove PDR.");
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
            case UPF_PDR_ID:
                if (sizeof(uint16_t) == obj_len) {
                    m_opt = 1;
                    *pdr_id = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_PDR;
            sess_rep->failed_rule_id.rule_id = *pdr_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_redirect_address(
    session_redirect_server *redir_addr, uint8_t redir_type,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    char ip_addr[512] = {0};

    if (sizeof(ip_addr) < obj_len) {
        LOG(UPC, ERR, "The alloc variable size is too small.\n");
        res_cause = SESS_INVALID_LENGTH;
        return res_cause;
    }

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* Redirect Server Address */
        switch (redir_type) {
            case 0:
                tlv_decode_binary(buffer, buf_pos, obj_len, (uint8_t *)ip_addr);
                ip_addr[obj_len] = '\0';
                if (1 != inet_pton(AF_INET, ip_addr, &redir_addr->ipv4_addr)) {
                    LOG(UPC, ERR, "parse ipv4 address failed.");
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
                redir_addr->ipv4_addr = ntohl(redir_addr->ipv4_addr);
                break;
            case 1:
                tlv_decode_binary(buffer, buf_pos, obj_len, (uint8_t *)ip_addr);
                ip_addr[obj_len] = '\0';
                if (1 != inet_pton(AF_INET6, ip_addr, redir_addr->ipv6_addr)) {
                    LOG(UPC, ERR, "parse ipv6 address failed.");
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
                break;
            case 2:
                if (obj_len <= REDIRECT_SERVER_ADDR_LEN) {
                        tlv_decode_binary(buffer, buf_pos,
                            obj_len, (uint8_t *)redir_addr->url);
                        redir_addr->url[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, REDIRECT_SERVER_ADDR_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
                break;
            case 3:
                if (obj_len <= REDIRECT_SERVER_ADDR_LEN) {
                        tlv_decode_binary(buffer, buf_pos,
                            obj_len, (uint8_t *)redir_addr->sip_url);
                        redir_addr->sip_url[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, REDIRECT_SERVER_ADDR_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
                break;
            case 4:
                {
                    tlv_decode_binary(buffer, buf_pos, obj_len, (uint8_t *)ip_addr);
                    ip_addr[obj_len] = '\0';
                    if (strchr(ip_addr, ':')) {
                        if (1 != inet_pton(AF_INET6, ip_addr, redir_addr->v4_v6.ipv6)) {
                            LOG(UPC, ERR, "parse ipv6 address failed.");
                            res_cause = SESS_INVALID_LENGTH;
                            return res_cause;
                        }
                    } else if (strchr(ip_addr, '.')) {
                        if (1 != inet_pton(AF_INET, ip_addr, &redir_addr->v4_v6.ipv4)) {
                            LOG(UPC, ERR, "parse ipv4 address failed.");
                            res_cause = SESS_INVALID_LENGTH;
                            return res_cause;
                        }
                        redir_addr->v4_v6.ipv4 = ntohl(redir_addr->v4_v6.ipv4);
                    } else {
                        LOG(UPC, ERR, "Should not be here.\n");
                        break;
                    }
                }
                break;
            default:
                LOG(UPC, ERR, "redirect address type %d abnormal.",
                    redir_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
                break;
        }

    } else {
        res_cause = SESS_INVALID_LENGTH;
        LOG(UPC, RUNNING, "IE length error.");
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_redirect_info(session_redirect_info *redir,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0, addr_len, other_addr_len;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* redirect Address type */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            redir->addr_type = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }
        /* redirect Server Address Length */
        len_cnt += sizeof(uint16_t);
        if (len_cnt <= obj_len) {
            addr_len = tlv_decode_uint16_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        len_cnt += addr_len;
        if (len_cnt > obj_len) {
            LOG(UPC, ERR, "obj_len: %d abnormal, more than the %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Redirect Server Address */
        res_cause = upc_parse_redirect_address(&redir->address,
            redir->addr_type, buffer, buf_pos, buf_max, addr_len);
        if (res_cause != SESS_REQUEST_ACCEPTED) {
            LOG(UPC, ERR, "prase redirect failed.");
            return res_cause;
        }

        /* other redirect Server Address Length */
        len_cnt += sizeof(uint16_t);
        if (len_cnt <= obj_len) {
            other_addr_len = tlv_decode_uint16_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        len_cnt += other_addr_len;
        if (len_cnt > obj_len) {
            LOG(UPC, ERR, "obj_len: %d abnormal, more than the %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* other redirect Server Address */
        if (other_addr_len > 0) {
            res_cause = upc_parse_redirect_address(&redir->address,
                redir->addr_type, buffer, buf_pos, buf_max, other_addr_len);
            if (res_cause != SESS_REQUEST_ACCEPTED) {
                LOG(UPC, ERR, "prase other redirect failed.");
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

/* outer header creation */
static PFCP_CAUSE_TYPE upc_parse_OHC(session_outer_header_create *ohc,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* Outer Header Creation Description */
        len_cnt += sizeof(uint16_t);
        if (len_cnt <= obj_len) {
            ohc->type.value = tlv_decode_uint16_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* GTP-U/UDP/IPv4 | GTP-U/UDP/IPv6 == 0x03 */
        if (ohc->type.value & 0x300) {
            /* TEID */
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                ohc->teid = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* GTP-U/UDP/IPv4 | UDP/IPv4 | IPv4 == 0x15 */
        if (ohc->type.value & 0x1500) {
            /* IPv4 Address */
            len_cnt += sizeof(uint32_t);
            if (len_cnt <= obj_len) {
                ohc->ipv4 = tlv_decode_uint32_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* GTP-U/UDP/IPv6 | UDP/IPv6 | IPv6 == 0x2A */
        if (ohc->type.value & 0x2A00) {
            /* IPv6 Address */
            len_cnt += IPV6_ALEN;
            if (len_cnt <= obj_len) {
                tlv_decode_binary(buffer, buf_pos, IPV6_ALEN, ohc->ipv6);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* UDP/IPv4 | UDP/IPv6 == 0x0F */
        if (ohc->type.value & 0x0C00) {
            /* Port Number */
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                ohc->port = tlv_decode_uint16_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* C-TAG */
        if (ohc->type.d.ctag) {
            len_cnt += 3;
            if (len_cnt <= obj_len) {
                ohc->ctag.flags.value = tlv_decode_uint8_t(buffer, buf_pos);
                ohc->ctag.value.value = tlv_decode_uint16_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* S-TAG */
        if (ohc->type.d.stag) {
            len_cnt += 3;
            if (len_cnt <= obj_len) {
                ohc->stag.flags.value = tlv_decode_uint8_t(buffer, buf_pos);
                ohc->stag.value.value = tlv_decode_uint16_t(buffer, buf_pos);
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

static PFCP_CAUSE_TYPE upc_parse_header_enrich(session_header_enrichment *he,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* Header Type */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            he->header_type = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                obj_len, sizeof(uint8_t));
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }
        /* Length of Header Field Name */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            he->name_length = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                obj_len, sizeof(uint8_t));
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }
        /* Header Field Name */
        len_cnt += he->name_length;
        if (he->name_length < SESSION_MAX_HEADER_FIELD_LEN) {
                tlv_decode_binary(buffer, buf_pos,
                    he->name_length, (uint8_t *)he->name);
                he->name[he->name_length] = '\0';
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                he->name_length, SESSION_MAX_HEADER_FIELD_LEN);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Length of Header Field Value */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            he->value_length = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                obj_len, sizeof(uint8_t));
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Header Field Value */
        len_cnt += he->value_length;
        if (he->value_length < SESSION_MAX_HEADER_FIELD_LEN) {
                tlv_decode_binary(buffer, buf_pos,
                    he->value_length, (uint8_t *)he->value);
                 he->value[he->value_length] = '\0';
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                he->value_length, SESSION_MAX_HEADER_FIELD_LEN);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
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

static PFCP_CAUSE_TYPE upc_parse_redundant_trans_para_in_far(session_redundant_trans_param_in_far *rtp,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse redundant transmission parameters.");
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
            case UPF_OUTER_HEADER_CREATION:
                m_opt = 1;
                res_cause = upc_parse_OHC(&rtp->ohc, buffer,
                    buf_pos, buf_max, obj_len);
                break;

            case UPF_NETWORK_INSTANCE:
                if (obj_len && (NETWORK_INSTANCE_LEN > obj_len)) {
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)rtp->network_instance);
                    rtp->network_instance[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, NETWORK_INSTANCE_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_fwd_param(session_forward_params *fwd_para,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse forward parameters.");
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
            case UPF_DESTINATION_INTERFACE:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    fwd_para->member_flag.d.dest_if_present = 1;
                    fwd_para->dest_if = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_NETWORK_INSTANCE:
                if (obj_len && (NETWORK_INSTANCE_LEN > obj_len)) {
                    fwd_para->member_flag.d.network_instance_present = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)fwd_para->network_instance);
                    fwd_para->network_instance[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, NETWORK_INSTANCE_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_REDIRECT_INFORMATION:
                fwd_para->member_flag.d.redirect_present = 1;
                res_cause = upc_parse_redirect_info(&fwd_para->redirect_addr,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_OUTER_HEADER_CREATION:
                fwd_para->member_flag.d.ohc_present = 1;
                res_cause = upc_parse_OHC(&fwd_para->outer_header_creation,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_TRANSPORT_LEVEL_MARKING:
                if (sizeof(uint16_t) == obj_len) {
                    fwd_para->member_flag.d.trans_present = 1;
                    fwd_para->trans.value = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
                break;

            case UPF_FORWARDING_POLICY:
                if (obj_len && (FORWARDING_POLICY_LEN > obj_len)) {
                    fwd_para->member_flag.d.forwarding_policy_present = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)fwd_para->forwarding_policy);
                    fwd_para->forwarding_policy[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, FORWARDING_POLICY_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_HEADER_ENRICHMENT:
                fwd_para->member_flag.d.header_enrichment_present = 1;
                res_cause = upc_parse_header_enrich(
                    &fwd_para->header_enrichment,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_TRAFFIC_ENDPOINT_ID:
                if (sizeof(uint8_t) == obj_len) {
                    fwd_para->member_flag.d.traffic_endpoint_id_present = 1;
                    fwd_para->traffic_endpoint_id =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PROXYING:
                if (sizeof(uint8_t) == obj_len) {
                    fwd_para->member_flag.d.proxying_present = 1;
                    fwd_para->proxying.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_3GPP_INTERFACE_TYPE:
                if (sizeof(uint8_t) == obj_len) {
                    fwd_para->member_flag.d.dest_if_type_present = 1;
                    fwd_para->dest_if_type.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_DATA_NETWORK_ACCESS_IDENTIFIER:
                if (obj_len && (DATA_NET_ACCESS_ID_LEN > obj_len)) {
                    fwd_para->member_flag.d.data_net_access_id_present = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)fwd_para->data_network_access_id);
                    fwd_para->data_network_access_id[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, DATA_NET_ACCESS_ID_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, dest if(%d).", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_update_fwd_param(
    session_update_forward_params *fwd_para, uint8_t* buffer,
    uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;

    LOG(UPC, RUNNING, "Parse update forward parameters.");
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
            case UPF_DESTINATION_INTERFACE:
                if (sizeof(uint8_t) == obj_len) {
                    fwd_para->member_flag.d.dest_if_present = 1;
                    fwd_para->dest_if = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_NETWORK_INSTANCE:
                if (obj_len && (NETWORK_INSTANCE_LEN > obj_len)) {
                    fwd_para->member_flag.d.network_instance_present = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)fwd_para->network_instance);
                    fwd_para->network_instance[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, NETWORK_INSTANCE_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_REDIRECT_INFORMATION:
                fwd_para->member_flag.d.redirect_present = 1;
                res_cause = upc_parse_redirect_info(&fwd_para->redirect_addr,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_OUTER_HEADER_CREATION:
                fwd_para->member_flag.d.ohc_present = 1;
                res_cause = upc_parse_OHC(&fwd_para->outer_header_creation,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_TRANSPORT_LEVEL_MARKING:
                if (sizeof(uint16_t) == obj_len) {
                    fwd_para->member_flag.d.trans_present = 1;
                    fwd_para->trans.value = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
                break;

            case UPF_FORWARDING_POLICY:
                if (obj_len && (FORWARDING_POLICY_LEN > obj_len)) {
                    fwd_para->member_flag.d.forwarding_policy_present = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)fwd_para->forwarding_policy);
                    fwd_para->forwarding_policy[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, FORWARDING_POLICY_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_HEADER_ENRICHMENT:
                fwd_para->member_flag.d.header_enrichment_present = 1;
                res_cause = upc_parse_header_enrich(
                    &fwd_para->header_enrichment,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_TRAFFIC_ENDPOINT_ID:
                if (sizeof(uint8_t) == obj_len) {
                    fwd_para->member_flag.d.traffic_endpoint_id_present = 1;
                    fwd_para->traffic_endpoint_id =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PFCPSMREQ_FLAGS:
                if (sizeof(uint8_t) == obj_len) {
                    fwd_para->pfcpsm_req_flag.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_3GPP_INTERFACE_TYPE:
                if (sizeof(uint8_t) == obj_len) {
                    fwd_para->member_flag.d.dest_if_type_present = 1;
                    fwd_para->dest_if_type.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    return res_cause;
}

PFCP_CAUSE_TYPE upc_parse_dupl_param(session_dupl_params *dupl_para,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse dupl parameters.");
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
            case UPF_DESTINATION_INTERFACE:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    dupl_para->member_flag.d.dupl_if_present = 1;
                    dupl_para->dupl_if = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_OUTER_HEADER_CREATION:
                dupl_para->member_flag.d.ohc_present = 1;
                res_cause = upc_parse_OHC(&dupl_para->ohc,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_TRANSPORT_LEVEL_MARKING:
                if (sizeof(uint16_t) == obj_len) {
                    dupl_para->member_flag.d.trans_present = 1;
                    dupl_para->trans.value = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
                break;

            case UPF_FORWARDING_POLICY:
                if (obj_len && (FORWARDING_POLICY_LEN > obj_len)) {
                    dupl_para->member_flag.d.forwarding_policy_present = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)dupl_para->forwarding_policy);
                    dupl_para->forwarding_policy[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, FORWARDING_POLICY_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_create_far(session_far_create *far_tbl,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    upc_create_far_m_opt m_opt = {.value = 0};

    LOG(UPC, RUNNING, "Parse create FAR.");
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
            case UPF_FAR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt.d.far_id = 1;
                    far_tbl->far_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_APPLY_ACTION:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt.d.action = 1;
                    far_tbl->member_flag.d.action_present = 1;
                    far_tbl->action.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_FORWARDING_PARAMETERS:
                far_tbl->member_flag.d.forw_param_present = 1;
                res_cause = upc_parse_fwd_param(&far_tbl->forw_param,
                    buffer, buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            /*case UPF_DUPLICATING_PARAMETERS:
                if (far_tbl->dupl_param_num < MAX_DUPL_PARAM_NUM) {
                    res_cause = upc_parse_dupl_param(
                        &far_tbl->dupl_params[far_tbl->dupl_param_num], buffer,
                        buf_pos, *buf_pos + obj_len, sess_rep);
                    ++far_tbl->dupl_param_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of DUPL param reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;*/

            case UPF_BAR_ID:
                if (sizeof(uint8_t) == obj_len) {
                    far_tbl->member_flag.d.bar_id_present = 1;
                    far_tbl->bar_id = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_REDUNDANT_TRANSMISSION_PARAMETERS:
                far_tbl->member_flag.d.redu_trans_param_present = 1;
                res_cause = upc_parse_redundant_trans_para_in_far(&far_tbl->rt_para, buffer,
                    buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_FAR;
            sess_rep->failed_rule_id.rule_id = far_tbl->far_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt.value ^ UPC_CREATE_FAR_M_OPT_MASK)) {
        LOG(UPC, ERR,
            "mandatory IE missing, value: %d.", m_opt.value);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_update_far(session_far_update *far_tbl,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse update FAR.");
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
            case UPF_FAR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt = 1;
                    far_tbl->far_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_APPLY_ACTION:
                if (sizeof(uint8_t) == obj_len) {
                    far_tbl->member_flag.d.action_present = 1;
                    far_tbl->action.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_UPDATE_FORWARDING_PARAMETERS:
                far_tbl->member_flag.d.forw_param_present = 1;
                res_cause = upc_parse_update_fwd_param(&far_tbl->forw_param,
                    buffer, buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            /*case UPF_UPDATE_DUPLICATING_PARAMETERS:
                if (far_tbl->dupl_param_num < MAX_DUPL_PARAM_NUM) {
                    res_cause = upc_parse_dupl_param(
                        &far_tbl->dupl_params[far_tbl->dupl_param_num], buffer,
                        buf_pos, *buf_pos + obj_len, sess_rep);
                    ++far_tbl->dupl_param_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of DUPL param reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;*/

            case UPF_BAR_ID:
                if (sizeof(uint8_t) == obj_len) {
                    far_tbl->member_flag.d.bar_id_present = 1;
                    far_tbl->bar_id = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_REDUNDANT_TRANSMISSION_PARAMETERS:
                far_tbl->member_flag.d.redu_trans_param_present = 1;
                res_cause = upc_parse_redundant_trans_para_in_far(&far_tbl->redu_trans_param, buffer,
                    buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_FAR;
            sess_rep->failed_rule_id.rule_id = far_tbl->far_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_remove_far(uint32_t *far_id,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse remove FAR.");
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
            case UPF_FAR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt = 1;
                    *far_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_FAR;
            sess_rep->failed_rule_id.rule_id = *far_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_volume(session_urr_volume *vol,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* volume flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            vol->flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* total volume */
        if (vol->flag.d.tovol) {
            len_cnt += sizeof(uint64_t);
            if (len_cnt <= obj_len) {
                vol->total = tlv_decode_uint64_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* Uplink volume */
        if (vol->flag.d.ulvol) {
            len_cnt += sizeof(uint64_t);
            if (len_cnt <= obj_len) {
                vol->uplink = tlv_decode_uint64_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* Downlink volume */
        if (vol->flag.d.dlvol) {
            len_cnt += sizeof(uint64_t);
            if (len_cnt <= obj_len) {
                vol->downlink = tlv_decode_uint64_t(buffer, buf_pos);
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

static PFCP_CAUSE_TYPE upc_parse_drop_dl_thres(session_urr_drop_thres *dt,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* drop dl traffic threshold flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            dt->flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* downlink packets */
        if (dt->flag.d.dlpa) {
            len_cnt += sizeof(uint64_t);
            if (len_cnt <= obj_len) {
                dt->packets = tlv_decode_uint64_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* Number of Bytes of Downlink Data */
        if (dt->flag.d.dlby) {
            len_cnt += sizeof(uint64_t);
            if (len_cnt <= obj_len) {
                dt->bytes = tlv_decode_uint64_t(buffer, buf_pos);
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

static PFCP_CAUSE_TYPE upc_parse_added_monitor_time(
    session_urr_add_mon_time *amt, uint8_t* buffer,
    uint16_t *buf_pos, int buf_max, session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse added monitor time.");
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
            case UPF_MONITORING_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt = 1;
                    amt->mon_time = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUBSEQUENT_VOLUME_THRESHOLD:
                amt->member_flag.d.sub_vol_thres_present = 1;
                res_cause = upc_parse_volume(&amt->sub_vol_thres,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_SUBSEQUENT_TIME_THRESHOLD:
                if (sizeof(uint32_t) == obj_len) {
                    amt->member_flag.d.sub_tim_thres_present = 1;
                    amt->sub_tim_thres = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUBSEQUENT_VOLUME_QUOTA:
                amt->member_flag.d.sub_vol_quota_present = 1;
                res_cause = upc_parse_volume(&amt->sub_vol_quota,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_SUBSEQUENT_TIME_QUOTA:
                if (sizeof(uint32_t) == obj_len) {
                    amt->member_flag.d.sub_tim_quota_present = 1;
                    amt->sub_tim_quota  = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUBSEQUENT_EVENT_THRESHOLD:
                if (sizeof(uint32_t) == obj_len) {
                    amt->member_flag.d.sub_eve_thres_present = 1;
                    amt->sub_eve_thres = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUBSEQUENT_EVENT_QUOTA:
                if (sizeof(uint32_t) == obj_len) {
                    amt->member_flag.d.sub_eve_quota_present = 1;
                    amt->sub_eve_quota = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_create_urr(session_usage_report_rule *urr,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep, uint8_t update_mode)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    upc_create_urr_m_opt m_opt = {.value = update_mode ? 6 : 0};

    LOG(UPC, RUNNING, "Parse create URR.");
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
            case UPF_URR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt.d.urr_id = 1;
                    urr->urr_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;
            case UPF_MEASUREMENT_METHOD:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt.d.method = 1;
                    urr->member_flag.d.method_present = 1;
                    urr->method.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_REPORTING_TRIGGERS:
                if (sizeof(uint16_t) == obj_len) {
                    m_opt.d.triggers = 1;
                    urr->member_flag.d.trigger_present = 1;
                    urr->trigger.value = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MEASUREMENT_PERIOD:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.period_present = 1;
                    urr->period = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_VOLUME_THRESHOLD:
                urr->member_flag.d.vol_thres_present = 1;
                res_cause = upc_parse_volume(&urr->vol_thres,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_VOLUME_QUOTA:
                urr->member_flag.d.vol_quota_present = 1;
                res_cause = upc_parse_volume(&urr->vol_quota,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_EVENT_THRESHOLD:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.eve_thres_present = 1;
                    urr->eve_thres = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_EVENT_QUOTA:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.eve_quota_present = 1;
                    urr->eve_quota = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_TIME_THRESHOLD:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.tim_thres_present = 1;
                    urr->tim_thres = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_TIME_QUOTA:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.tim_quota_present = 1;
                    urr->tim_quota = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_QUOTA_HOLDING_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.quota_hold_present = 1;
                    urr->quota_hold = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_DROPPED_DL_TRAFFIC_THRESHOLD:
                urr->member_flag.d.drop_thres_present = 1;
                res_cause = upc_parse_drop_dl_thres(&urr->drop_thres,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_QUOTA_VALIDITY_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.quota_validity_time_present = 1;
                    urr->quota_validity_time = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MONITORING_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.mon_time_present = 1;
                    urr->mon_time = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUBSEQUENT_VOLUME_THRESHOLD:
                urr->member_flag.d.sub_vol_thres_present = 1;
                res_cause = upc_parse_volume(&urr->sub_vol_thres,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_SUBSEQUENT_TIME_THRESHOLD:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.sub_tim_thres_present = 1;
                    urr->sub_tim_thres = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUBSEQUENT_VOLUME_QUOTA:
                urr->member_flag.d.sub_vol_quota_present = 1;
                res_cause = upc_parse_volume(&urr->sub_vol_quota,
                    buffer, buf_pos, buf_max, obj_len);
                break;

            case UPF_SUBSEQUENT_TIME_QUOTA:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.sub_tim_quota_present = 1;
                    urr->sub_tim_quota  = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUBSEQUENT_EVENT_THRESHOLD:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.sub_eve_thres_present = 1;
                    urr->sub_eve_thres = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUBSEQUENT_EVENT_QUOTA:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.sub_eve_quota_present = 1;
                    urr->sub_eve_quota = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_INACTIVITY_DETECTION_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.inact_detect_present = 1;
                    urr->inact_detect = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_LINKED_URR_ID:
                if (urr->linked_urr_number < MAX_URR_NUM) {
                    if (sizeof(uint32_t) == obj_len) {
                        urr->linked_urr[urr->linked_urr_number] =
                            tlv_decode_uint32_t(buffer, buf_pos);
                        ++urr->linked_urr_number;
                    } else {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint32_t));
                        res_cause = SESS_INVALID_LENGTH;
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of LINKED URR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_MEASUREMENT_INFORMATION:
                if (sizeof(uint8_t) == obj_len) {
                    urr->member_flag.d.measu_info_present = 1;
                    urr->measu_info.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_FAR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.quota_far_present = 1;
                    urr->quota_far = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_ETHERNET_INACTIVITY_TIMER:
                if (sizeof(uint32_t) == obj_len) {
                    urr->member_flag.d.eth_inact_time_present = 1;
                    urr->eth_inact_time = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_ADDITIONAL_MONITORING_TIME:
                if (urr->add_mon_time_number < MAX_ADDED_MONITOR_TIME_NUM) {
                    res_cause = upc_parse_added_monitor_time(
                        &urr->add_mon_time[urr->add_mon_time_number], buffer,
                        buf_pos, *buf_pos + obj_len, sess_rep);
                    ++urr->add_mon_time_number;
                } else {
                    LOG(UPC, ERR,
                        "The number of added monitor time"
                        " reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_NUMBER_OF_REPORTS:
                if (sizeof(uint16_t) == obj_len) {
                    urr->member_flag.d.number_of_reports_present = 1;
                    urr->number_of_reports = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_URR;
            sess_rep->failed_rule_id.rule_id = urr->urr_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt.value ^ UPC_CREATE_URR_M_OPT_MASK)) {
        LOG(UPC, ERR,
            "mandatory IE missing, value: %d.", m_opt.value);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    /* Check conditional option */
    if (res_cause == SESS_REQUEST_ACCEPTED) {
        if (urr->method.d.volum) {
            if (urr->trigger.d.volth ^ urr->member_flag.d.vol_thres_present) {
                LOG(UPC, ERR,"conditional IE Volume Threshold  missing.");
                res_cause = SESS_CONDITIONAL_IE_MISSING;
            } else if (urr->trigger.d.volqu ^ urr->member_flag.d.vol_quota_present) {
                LOG(UPC, ERR,"conditional IE Volume Quota  missing.");
                res_cause = SESS_CONDITIONAL_IE_MISSING;
            } else if (urr->trigger.d.droth ^ urr->member_flag.d.drop_thres_present) {
                LOG(UPC, ERR, "conditional IE Dropped DL Traffic Threshold missing.");
                res_cause = SESS_CONDITIONAL_IE_MISSING;
            }
        } else if (urr->method.d.event) {
            if (urr->trigger.d.evequ ^ urr->member_flag.d.eve_quota_present) {
                LOG(UPC, ERR, "conditional IE Event Quota missing.");
                res_cause = SESS_CONDITIONAL_IE_MISSING;
            } else if (urr->trigger.d.eveth ^ urr->member_flag.d.eve_thres_present) {
                LOG(UPC, ERR, "conditional IE Event Threshold missing.");
                res_cause = SESS_CONDITIONAL_IE_MISSING;
            }
        } else if (urr->method.d.durat) {
            if (urr->trigger.d.timth ^ urr->member_flag.d.tim_thres_present) {
                LOG(UPC, ERR, "conditional IE Time Threshold missing.");
                res_cause = SESS_CONDITIONAL_IE_MISSING;
            } else if (urr->trigger.d.timqu ^ urr->member_flag.d.tim_quota_present) {
                LOG(UPC, ERR, "conditional IE Time Quota missing.");
                res_cause = SESS_CONDITIONAL_IE_MISSING;
            }
        }
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_remove_urr(uint32_t *urr_id,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse remove URR.");
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
            case UPF_URR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt  = 1;
                    *urr_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_URR;
            sess_rep->failed_rule_id.rule_id = *urr_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_create_qer(session_qos_enforcement_rule *qer,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep, uint8_t update_mode)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    upc_create_qer_m_opt m_opt = {.value = update_mode ? 2 : 0};

    LOG(UPC, RUNNING, "Parse create QER.");
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
            case UPF_QER_ID:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt.d.qer_id = 1;
                    qer->qer_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_QER_CORRELATION_ID:
                if (sizeof(uint32_t) == obj_len) {
                    qer->member_flag.d.qer_corr_id_present = 1;
                    qer->qer_corr_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_GATE_STATUS:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt.d.gate_status = 1;
                    qer->member_flag.d.gate_status_present = 1;
                    qer->gate_status.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MBR:
                if (10 == obj_len) {
                    qer->member_flag.d.mbr_value_present = 1;
                    qer->mbr_value.ul_mbr =
                        tlv_decode_int_5b(buffer, buf_pos);
                    qer->mbr_value.dl_mbr =
                        tlv_decode_int_5b(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, 10);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_GBR:
                if (10 == obj_len) {
                    qer->member_flag.d.gbr_value_present = 1;
                    qer->gbr_value.ul_gbr =
                        tlv_decode_int_5b(buffer, buf_pos);
                    qer->gbr_value.dl_gbr =
                        tlv_decode_int_5b(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, 10);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PACKET_RATE_STATUS:
                qer->member_flag.d.packet_rate_status_present = 1;
                res_cause = upc_parse_packet_rate_status(&qer->pkt_rate_status, buffer,
                    buf_pos, buf_max, obj_len);
                break;

            case UPF_QFI:
                if (sizeof(uint8_t) == obj_len) {
                    qer->member_flag.d.qfi_present = 1;
                    qer->qfi =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_RQI:
                if (sizeof(uint8_t) == obj_len) {
                    qer->member_flag.d.ref_qos_present = 1;
                    qer->ref_qos=
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PAGING_POLICY_INDICATOR:
                if (sizeof(uint8_t) == obj_len) {
                    qer->member_flag.d.ppi_present = 1;
                    qer->paging_policy_indic =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_AVERAGING_WINDOW:
                if (sizeof(uint32_t) == obj_len) {
                    qer->member_flag.d.averaging_window_present = 1;
                    qer->averaging_window =
                        tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_QER_CONTROL_INDICATIONS:
                if (sizeof(uint8_t) == obj_len) {
                    qer->qer_ctrl_indic.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_QER;
            sess_rep->failed_rule_id.rule_id = qer->qer_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt.value ^ UPC_CREATE_QER_M_OPT_MASK)) {
        LOG(UPC, ERR,
            "mandatory IE missing, value: %d.", m_opt.value);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_remove_qer(uint32_t *qer_id,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse remove QER.");
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
            case UPF_QER_ID:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt  = 1;
                    *qer_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_QER;
            sess_rep->failed_rule_id.rule_id = *qer_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_create_bar(session_buffer_action_rule *bar,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse create BAR.");
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
            case UPF_BAR_ID:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    bar->bar_id = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_DOWNLINK_DATA_NOTIFICATION_DELAY:
                if (sizeof(uint8_t) == obj_len) {
                    bar->member_flag.d.notify_delay_present = 1;
                    bar->notify_delay = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUGGESTED_BUFFERING_PACKETS_COUNT:
                if (sizeof(uint8_t) == obj_len) {
                    bar->member_flag.d.buffer_pkts_cnt_present = 1;
                    bar->buffer_pkts_cnt = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_BAR;
            sess_rep->failed_rule_id.rule_id = bar->bar_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt == 0)) {
        LOG(UPC, ERR,
            "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_remove_bar(uint8_t *bar_id,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse create BAR.");
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
            case UPF_BAR_ID:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    *bar_id = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_BAR;
            sess_rep->failed_rule_id.rule_id = *bar_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt == 0)) {
        LOG(UPC, ERR,
            "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_report_update_bar(
    session_bar_response_update *bar,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse report update BAR.");
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
            case UPF_BAR_ID:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    bar->bar_id = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_DOWNLINK_DATA_NOTIFICATION_DELAY:
                if (sizeof(uint8_t) == obj_len) {
                    bar->member_flag.d.notify_delay_present = 1;
                    bar->notify_delay = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_SUGGESTED_BUFFERING_PACKETS_COUNT:
                if (sizeof(uint8_t) == obj_len) {
                    bar->member_flag.d.buffer_pkts_cnt_present = 1;
                    bar->buffer_pkts_cnt = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_DL_BUFFERING_DURATION:
                if (sizeof(uint8_t) == obj_len) {
                    bar->member_flag.d.dl_buff_duration_present = 1;
                    bar->dl_buff_duration.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_DL_BUFFERING_SUGGESTED_PACKET_COUNT:
                if (sizeof(uint16_t) == obj_len) {
                    bar->member_flag.d.dl_buff_pkts_cnt_present = 1;
                    bar->dl_buff_pkts_cnt = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

/* create traffic endpoint */
static PFCP_CAUSE_TYPE upc_parse_create_traffic_endpoint(
    session_tc_endpoint *tc, uint8_t *buffer,
    uint16_t *buf_pos, int buf_max, session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse traffic endpoint.");
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
            case UPF_TRAFFIC_ENDPOINT_ID:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    tc->endpoint_id = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_F_TEID:
                tc->member_flag.d.local_fteid_present = 1;
                res_cause = upc_parse_f_teid(&tc->local_fteid, buffer,
                    buf_pos, buf_max, obj_len);
                break;

            case UPF_NETWORK_INSTANCE:
                if (obj_len && (NETWORK_INSTANCE_LEN > obj_len)) {
                    tc->member_flag.d.network_instance_present = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)tc->network_instance);
                    tc->network_instance[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, NETWORK_INSTANCE_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_REDUNDANT_TRANSMISSION_PARAMETERS:
                tc->member_flag.d.redundant_transmission_present = 1;
                res_cause = upc_parse_redundant_trans_para_in_pdi(&tc->redundant_transmission_param, buffer,
                    buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            case UPF_UE_IP_ADDRESS:
                if (tc->ue_ipaddr_num < MAX_UE_IP_NUM) {
                    res_cause = upc_parse_ue_ip(
                        &tc->ue_ipaddr[tc->ue_ipaddr_num], buffer,
                        buf_pos, buf_max, obj_len);
                    ++tc->ue_ipaddr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of UE IP reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_ETHERNET_PDU_SESSION_INFORMATION:
                if (sizeof(uint8_t) == obj_len) {
                    tc->member_flag.d.eth_pdu_ses_info_present = 1;
                    tc->eth_pdu_ses_info.value =
                        tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_FRAMED_ROUTE:
                if (tc->framed_route_num < MAX_FRAMED_ROUTE_NUM) {
                    res_cause = upc_parse_framed_route(
                        &tc->framed_route[tc->framed_route_num], buffer,
                        buf_pos, obj_len);

                    ++tc->framed_route_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of framed route reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_FRAMED_ROUTING:
                if (4 == obj_len) {
                    tc->member_flag.d.framed_routing_present = 1;
                    tc->framed_routing = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                        obj_len, 4);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_FRAMED_IPV6_ROUTE:
                if (tc->framed_ipv6_route_num < MAX_FRAMED_ROUTE_NUM) {
                    res_cause = upc_parse_framed_route_v6(
                        &tc->framed_ipv6_route[tc->framed_ipv6_route_num],
                        buffer, buf_pos, obj_len);

                    ++tc->framed_ipv6_route_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of framed ipv6 route reaches"
                        " the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_QFI:
                if (tc->qfi_number < MAX_QFI_NUM) {
                    if (sizeof(uint8_t) == obj_len) {
                        tc->qfi_array[tc->qfi_number] =
                            tlv_decode_uint8_t(buffer, buf_pos);
                        ++tc->qfi_number;
                    } else {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint8_t));
                        res_cause = SESS_INVALID_LENGTH;
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of QFI reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_remove_traffic_endpoint(uint8_t *tc_id, uint8_t *buffer,
    uint16_t *buf_pos, int buf_max, session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse remove traffic endpoint.");
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
            case UPF_TRAFFIC_ENDPOINT_ID:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    *tc_id = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_user_id(session_user_id *user_id,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* user id flag */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            user_id->user_id_flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* IMSI */
        if (user_id->user_id_flag.d.imsif) {
            len_cnt += sizeof(uint8_t);
            if (len_cnt <= obj_len) {
                user_id->imsi_len = tlv_decode_uint8_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            len_cnt += user_id->imsi_len;
            if (user_id->imsi_len && (len_cnt <= obj_len) &&
                (SESSION_MAX_BCD_BYTES >= user_id->imsi_len)) {

                tlv_decode_binary(buffer, buf_pos, user_id->imsi_len,
                    user_id->imsi);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal.", obj_len);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* IMEI */
        if (user_id->user_id_flag.d.imeif) {
            len_cnt += sizeof(uint8_t);
            if (len_cnt <= obj_len) {
                user_id->imei_len = tlv_decode_uint8_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            len_cnt += user_id->imei_len;
            if (user_id->imei_len && (len_cnt <= obj_len) &&
                (SESSION_MAX_BCD_BYTES >= user_id->imei_len)) {

                tlv_decode_binary(buffer, buf_pos, user_id->imei_len,
                    user_id->imei);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal.", obj_len);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* MSISDN */
        if (user_id->user_id_flag.d.msisdnf) {
            len_cnt += sizeof(uint8_t);
            if (len_cnt <= obj_len) {
                user_id->msisdn_len = tlv_decode_uint8_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            len_cnt += user_id->msisdn_len;
            if (user_id->msisdn_len && (len_cnt <= obj_len) &&
                (SESSION_MAX_BCD_BYTES >= user_id->msisdn_len)) {

                tlv_decode_binary(buffer, buf_pos, user_id->msisdn_len,
                    user_id->msisdn);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal.", obj_len);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        /* NAI */
        if (user_id->user_id_flag.d.naif) {
            len_cnt += sizeof(uint8_t);
            if (len_cnt <= obj_len) {
                user_id->nai_len = tlv_decode_uint8_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            len_cnt += user_id->nai_len;
            if (user_id->nai_len && (len_cnt <= obj_len) &&
                (SESSION_MAX_NAI_LEN >= user_id->nai_len)) {

                tlv_decode_binary(buffer, buf_pos, user_id->nai_len,
                    (uint8_t *)user_id->nai);
                user_id->nai[user_id->nai_len] = '\0';
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal.", obj_len);
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

static PFCP_CAUSE_TYPE upc_parse_trace_info(session_trace_info *trace,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* Trace Information flag */
        len_cnt += 3;
        if (len_cnt <= obj_len) {
            trace->trace_ref_flag.value = tlv_decode_int_3b(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Trace id */
        len_cnt += 3;
        if (len_cnt <= obj_len) {
            trace->trace_id = tlv_decode_int_3b(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Triggering Events */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            trace->trigger_events_len = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        len_cnt += trace->trigger_events_len;
        if (trace->trigger_events_len && (len_cnt <= obj_len) &&
            (MAX_TRIGGERING_EVENTS_LEN >= trace->trigger_events_len)) {

            tlv_decode_binary(buffer, buf_pos, trace->trigger_events_len,
                trace->trigger_events);
            trace->trigger_events[trace->trigger_events_len] = '\0';
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal.", obj_len);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Session Trace Depth */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            trace->sess_trace_depth = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* List of Interfaces */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            trace->if_list_len = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        len_cnt += trace->if_list_len;
        if (trace->if_list_len && (len_cnt <= obj_len) &&
            (MAX_LIST_OF_INTERFACES_LEN >= trace->if_list_len)) {

            tlv_decode_binary(buffer, buf_pos, trace->if_list_len,
                trace->if_list);
            trace->if_list[trace->if_list_len] = '\0';
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal.", obj_len);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* IP Address of Trace Collection Entity */
        len_cnt += sizeof(uint8_t);
        if (len_cnt <= obj_len) {
            trace->ip_addr_len = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        len_cnt += trace->ip_addr_len;
        if (trace->ip_addr_len && (len_cnt <= obj_len)) {

            if (trace->ip_addr_len == 4) {
                trace->ip_addr_of_trace.addr4 =
                    tlv_decode_uint32_t(buffer, buf_pos);
            } else if (trace->ip_addr_len == IPV6_ALEN) {
                tlv_decode_binary(buffer, buf_pos, IPV6_ALEN,
                    trace->ip_addr_of_trace.addr6);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal.", obj_len);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal.", obj_len);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
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

static PFCP_CAUSE_TYPE upc_parse_afai(session_access_forwarding_action *afai,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse AFAI.");
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
            case UPF_FAR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    m_opt = 1;
                    afai->member_flag.d.far_id_present = 1;
                    afai->far_id = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_WEIGHT:
                if (sizeof(uint8_t) == obj_len) {
                    afai->member_flag.d.weight_present = 1;
                    afai->weight = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PRIORITY:
                if (sizeof(uint8_t) == obj_len) {
                    afai->member_flag.d.priority_present = 1;
                    afai->priority = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_URR_ID:
                if (sizeof(uint32_t) == obj_len) {
                    if (MAX_URR_NUM > afai->urr_num)
                    afai->urr_id_arr[afai->urr_num] =
                        tlv_decode_uint32_t(buffer, buf_pos);
                    ++afai->urr_num;
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_create_mar(session_mar_create *mar_tbl,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    upc_create_mar_m_opt m_opt = {.value = 0};

    LOG(UPC, RUNNING, "Parse create MAR.");
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
            case UPF_MAR_ID:
                if (sizeof(uint16_t) == obj_len) {
                    m_opt.d.mar_id = 1;
                    mar_tbl->mar_id = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_STEERING_FUNCTIONALITY:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt.d.func = 1;
                    mar_tbl->steer_func = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_STEERING_MODE:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt.d.mode = 1;
                    mar_tbl->steer_mod = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION:
                m_opt.d.afai1 = 1;
                mar_tbl->member_flag.d.afai_1_present = 1;
                res_cause = upc_parse_afai(&mar_tbl->afai_1,
                    buffer, buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            case UPF_NON_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION:
                mar_tbl->member_flag.d.afai_2_present = 1;
                res_cause = upc_parse_afai(&mar_tbl->afai_2,
                    buffer, buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_MAR;
            sess_rep->failed_rule_id.rule_id = mar_tbl->mar_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt.value ^ UPC_CREATE_MAR_M_OPT_MASK)) {
        LOG(UPC, ERR,
            "mandatory IE missing, value: %d.", m_opt.value);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    if (res_cause == SESS_REQUEST_ACCEPTED) {
        if ((mar_tbl->steer_mod == 2) ^ mar_tbl->afai_1.member_flag.d.weight_present) {
            LOG(UPC, ERR, "conditional  IE  Weight missing.");
            res_cause = SESS_CONDITIONAL_IE_MISSING;
        }

        if (((mar_tbl->steer_mod == 0) || (mar_tbl->steer_mod == 3)) ^
            mar_tbl->afai_1.member_flag.d.priority_present) {
            LOG(UPC, ERR, "conditional  IE Priority  missing.");
            res_cause = SESS_CONDITIONAL_IE_MISSING;
        }
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_update_mar(session_mar_update *mar_tbl,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse update MAR.");
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
            case UPF_MAR_ID:
                if (sizeof(uint16_t) == obj_len) {
                    m_opt = 1;
                    mar_tbl->mar_id = tlv_decode_uint16_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_STEERING_FUNCTIONALITY:
                if (sizeof(uint8_t) == obj_len) {
                    mar_tbl->member_flag.d.steer_func_present = 1;
                    mar_tbl->steer_func = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_STEERING_MODE:
                if (sizeof(uint8_t) == obj_len) {
                    mar_tbl->member_flag.d.steer_mod_present = 1;
                    mar_tbl->steer_mod = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_UPDATE_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION:
                mar_tbl->member_flag.d.update_afai_1_present = 1;
                res_cause = upc_parse_afai(&mar_tbl->update_afai_1,
                    buffer, buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            case UPF_UPDATE_NON_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION:
                mar_tbl->member_flag.d.update_afai_2_present = 1;
                res_cause = upc_parse_afai(&mar_tbl->update_afai_2,
                    buffer, buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            case UPF_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION:
                mar_tbl->member_flag.d.afai_1_present = 1;
                res_cause = upc_parse_afai(&mar_tbl->afai_1,
                    buffer, buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            case UPF_NON_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION:

                mar_tbl->member_flag.d.afai_2_present = 1;
                res_cause = upc_parse_afai(&mar_tbl->afai_2,
                    buffer, buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_MAR;
            sess_rep->failed_rule_id.rule_id = mar_tbl->mar_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_access_avail_ctrl_info(session_access_avail_control_info *aaci,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse AFAI.");
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
            case UPF_REQUESTED_ACCESS_AVAILABILITY_INFORMATION:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    aaci->requested_access_avail_info.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) && (m_opt == 0)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_packet_delay_thresholds(session_packet_delay_thresholds *pdt,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0;

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* flag */
        len_cnt += 1;
        if (len_cnt <= obj_len) {
            pdt->flag.value = tlv_decode_uint8_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Downlink packet delay threshold */
        len_cnt += sizeof(uint32_t);
        if (len_cnt <= obj_len) {
            pdt->dl_packet_delay = tlv_decode_uint32_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Uplink packet delay threshold */
        len_cnt += sizeof(uint32_t);
        if (len_cnt <= obj_len) {
            pdt->ul_packet_delay = tlv_decode_uint32_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        /* Uplink packet delay threshold */
        len_cnt += sizeof(uint32_t);
        if (len_cnt <= obj_len) {
            pdt->rt_packet_delay = tlv_decode_uint32_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
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

static PFCP_CAUSE_TYPE upc_parse_qos_monitor_per_qfci(session_monitor_per_qf_ctrl_info *info,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;/* qfi: 1  Requested QoS Monitoring: 2  Reporting Frequency: 4 */

    LOG(UPC, RUNNING, "Parse create SRR.");
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
            case UPF_QFI:
                if (info->qfi_num < MAX_QFI_NUM) {
                    if (sizeof(uint8_t) == obj_len) {
                        m_opt |= 1;
                        info->qfi[info->qfi_num] = tlv_decode_uint8_t(buffer, buf_pos);
                        ++info->qfi_num;
                    } else {
                        LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint8_t));
                        res_cause = SESS_INVALID_LENGTH;
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of QFI reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_REQUESTED_QOS_MONITORING:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt |= 2;
                    info->requested_qos_monitor.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_REPORTING_FREQUENCY:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt |= 4;
                    info->reporting_frequency.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PACKET_DELAY_THRESHOLDS:
                if (sizeof(uint32_t) == obj_len) {
                    info->packet_delay_thresholds_present = 1;
                    res_cause = upc_parse_packet_delay_thresholds(&info->packet_delay_thresholds, buffer,
                    buf_pos, buf_max, obj_len);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MINIMUM_WAIT_TIME:
                if (sizeof(uint32_t) == obj_len) {
                    info->min_wait_time_present = 1;
                    info->min_wait_time = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_MEASUREMENT_PERIOD:
                if (sizeof(uint32_t) == obj_len) {
                    info->measurement_period_present = 1;
                    info->measurement_period = tlv_decode_uint32_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt ^ 7)) {
        LOG(UPC, ERR, "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_create_srr(session_srr_create *srr,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse create SRR.");
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
            case UPF_SRR_ID:
                if (sizeof(uint8_t) == obj_len) {
                    m_opt = 1;
                    srr->ssr_id = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_ACCESS_AVAILABILITY_CONTROL_INFORMATION:
                srr->access_avail_control_info_present = 1;
                res_cause = upc_parse_access_avail_ctrl_info(&srr->access_avail_control_info,
                    buffer, buf_pos, *buf_pos + obj_len, sess_rep);
                break;

            case UPF_QOS_MONITORING_PER_QOS_FLOW_CONTROL_INFORMATION:
                if (srr->monitor_per_qf_ctrl_info_num < QOS_MONITOR_NUM) {
                    res_cause = upc_parse_qos_monitor_per_qfci(
                        &srr->monitor_per_qf_ctrl_info[srr->monitor_per_qf_ctrl_info_num], buffer,
                        buf_pos, *buf_pos + obj_len, sess_rep);
                    ++srr->monitor_per_qf_ctrl_info_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of QoS Monitoring per QoS flow Control Information reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            sess_rep->member_flag.d.failed_rule_id_present = 1;
            sess_rep->failed_rule_id.rule_type = SESS_FAILED_SRR;
            sess_rep->failed_rule_id.rule_id = srr->ssr_id;

            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt == 0)) {
        LOG(UPC, ERR,
            "mandatory IE missing, value: %d.", m_opt);

        res_cause = SESS_MANDATORY_IE_MISSING;
    }

    return res_cause;
}

static PFCP_CAUSE_TYPE upc_parse_provid_atsss_ctrl_info(session_provide_atsss_ctrl_info *paci,
    uint8_t *buffer, uint16_t *buf_pos, int buf_max,
    session_emd_response *sess_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;

    LOG(UPC, RUNNING, "Parse create SRR.");
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
            case UPF_MPTCP_CONTROL_INFORMATION:
                if (sizeof(uint8_t) == obj_len) {
                    paci->mptcp_control_info.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_ATSSS_LL_CONTROL_INFORMATION:
                if (sizeof(uint8_t) == obj_len) {
                    paci->atsss_ll_control_info.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PMF_CONTROL_INFORMATION:
                if (sizeof(uint8_t) == obj_len) {
                    paci->pmf_control_info.value = tlv_decode_uint8_t(buffer, buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            default:
                LOG(UPC, ERR, "type %d, not support.", obj_type);
                res_cause = SESS_SERVICE_NOT_SUPPORTED;
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
            if (0 == sess_rep->member_flag.d.offending_ie_present) {
                sess_rep->member_flag.d.offending_ie_present = 1;
                sess_rep->offending_ie = obj_type;
            }
            break;
        }
    }

    return res_cause;
}

static int upc_build_f_teid(session_f_teid *fteid,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_len = 0, ie_pos = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_F_TEID);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

        /* flag */
    tlv_encode_uint8_t(resp_buffer, resp_pos, fteid->f_teid_flag.value);

    if (fteid->f_teid_flag.d.ch) {
        if (fteid->f_teid_flag.d.chid) {
            tlv_encode_uint8_t(resp_buffer, resp_pos, fteid->choose_id);
        }
    } else {
            /* TEID */
        tlv_encode_uint32_t(resp_buffer, resp_pos, fteid->teid);
            /* ipv4 */
        if (fteid->f_teid_flag.d.v4) {
            tlv_encode_uint32_t(resp_buffer, resp_pos, fteid->ipv4_addr);
        }
            /* ipv6 */
        if (fteid->f_teid_flag.d.v6) {
            tlv_encode_binary(resp_buffer, resp_pos, IPV6_ALEN,
                fteid->ipv6_addr);
        }
    }

    /* filling local f-teid length */
    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}

static int upc_build_ue_ip(session_ue_ip *ue_ip,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_len_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_UE_IP_ADDRESS);
    ie_len_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* FLAG */
    tlv_encode_uint8_t(resp_buffer, resp_pos, ue_ip->ueip_flag.value);

    /* IPV4 */
    if (ue_ip->ueip_flag.d.v4) {
        tlv_encode_uint32_t(resp_buffer, resp_pos, ue_ip->ipv4_addr);
    }

    /* IPV6 */
    if (ue_ip->ueip_flag.d.v6) {
        tlv_encode_binary(resp_buffer, resp_pos, IPV6_ALEN, ue_ip->ipv6_addr);
    }

    /* IPV6 PREFIX */
    if (ue_ip->ueip_flag.d.ipv6d) {
        tlv_encode_uint8_t(resp_buffer, resp_pos, ue_ip->ipv6_prefix);
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_len_pos, ie_len);

    return ie_len;
}

static int upc_build_volume(session_urr_volume *vol,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_VOLUME_MEASUREMENT);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    tlv_encode_uint8_t(resp_buffer, resp_pos, vol->flag.value);

    if (vol->flag.d.tovol) {
        tlv_encode_uint64_t(resp_buffer, resp_pos, vol->total);
    }

    if (vol->flag.d.ulvol) {
        tlv_encode_uint64_t(resp_buffer, resp_pos, vol->uplink);
    }

    if (vol->flag.d.dlvol) {
        tlv_encode_uint64_t(resp_buffer, resp_pos, vol->downlink);
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    LOG(UPC, RUNNING, "vol_meas.");

    return ie_len;
}

static int upc_build_eth_traffic_info(session_eth_traffic_info *traffic,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    session_mac_address_detected *detectd;
    session_mac_address_removed *removed;
    uint16_t ie_pos = 0, ie_len = 0;
    uint8_t cnt_l1 = 0, cnt_l2 = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_ETHERNET_TRAFFIC_INFORMATION);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* MAC Addresses Detected */
    for (cnt_l1 = 0; cnt_l1 < traffic->mac_addr_detect_num; ++cnt_l1) {
        detectd = &traffic->mac_addr_detect[cnt_l1];

        tlv_encode_type(resp_buffer, resp_pos, UPF_MAC_ADDRESSES_DETECTED);
        tlv_encode_length(resp_buffer, resp_pos,
            sizeof(uint8_t) + ETH_ALEN * detectd->mac_num);
        tlv_encode_uint8_t(resp_buffer, resp_pos, detectd->mac_num);
        for (cnt_l2 = 0; cnt_l2 < detectd->mac_num; ++cnt_l2) {
            tlv_encode_binary(resp_buffer, resp_pos, ETH_ALEN,
                detectd->mac_addr[cnt_l2]);
        }
    }

    /* MAC Addresses Removed */
    for (cnt_l1 = 0; cnt_l1 < traffic->mac_addr_rm_num; ++cnt_l1) {
        removed = &traffic->mac_addr_rm[cnt_l1];

        tlv_encode_type(resp_buffer, resp_pos, UPF_MAC_ADDRESSES_REMOVED);
        tlv_encode_length(resp_buffer, resp_pos,
            sizeof(uint8_t) + ETH_ALEN * removed->mac_num);
        tlv_encode_uint8_t(resp_buffer, resp_pos, removed->mac_num);
        for (cnt_l2 = 0; cnt_l2 < removed->mac_num; ++cnt_l2) {
            tlv_encode_binary(resp_buffer, resp_pos, ETH_ALEN,
                removed->mac_addr[cnt_l2]);
        }
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "Ethernet Traffic Information.");

    return ie_len;
}

static int upc_build_created_pdr(session_created_pdr *cp_arr, uint8_t cp_num,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint8_t cnt = 0, cnt_l2 = 0;
    int ret = 0;
    uint16_t cp_len = 0, cp_len_pos = 0;
    session_created_pdr *cp;

    for (cnt = 0; cnt < cp_num; ++cnt) {
        cp = &cp_arr[cnt];

        tlv_encode_type(resp_buffer, resp_pos, UPF_CREATED_PDR);
        /* Record the current position */
        cp_len_pos = *resp_pos;
        tlv_encode_length(resp_buffer, resp_pos, 0);
        cp_len = *resp_pos;

        /* pdr id */
        tlv_encode_type(resp_buffer, resp_pos, UPF_PDR_ID);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, resp_pos, cp->pdr_id);

        /* local f-teid */
        if (cp->local_fteid_present) {
            ret = upc_build_f_teid(&cp->local_fteid, resp_buffer, resp_pos);
            if (0 > ret) {
                LOG(UPC, ERR, "build f-teid failed.\n");
                return -1;
            }
        }

        /* Local F-TEID for Redundant Transmission */
        if (cp->rt_local_fteid_present) {
            ret = upc_build_f_teid(&cp->rt_local_fteid, resp_buffer, resp_pos);
            if (0 > ret) {
                LOG(UPC, ERR, "build Redundant Transmission f-teid failed.\n");
                return -1;
            }
        }

        /* UE_IP */
        for (cnt_l2 = 0; cnt_l2 < cp->ueip_addr_num; ++cnt_l2) {
            ret = upc_build_ue_ip(&cp->ueip_addr[cnt_l2], resp_buffer, resp_pos);
            if (0 > ret) {
                LOG(UPC, ERR, "build ue ip failed.\n");
                return -1;
            }
        }

        /* filling created pdr length */
        cp_len = *resp_pos - cp_len;
        tlv_encode_length(resp_buffer, &cp_len_pos, cp_len);
        LOG(UPC, RUNNING, "encode traffic endpoint info.");
    }

    return 0;
}

static int upc_build_updated_pdr(session_updated_pdr *cp_arr, uint8_t cp_num,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint8_t cnt = 0;
    int ret = 0;
    uint16_t cp_len = 0, cp_len_pos = 0;
    session_updated_pdr *cp;

    for (cnt = 0; cnt < cp_num; ++cnt) {
        cp = &cp_arr[cnt];

        tlv_encode_type(resp_buffer, resp_pos, UPF_UPDATED_PDR);
        /* Record the current position */
        cp_len_pos = *resp_pos;
        tlv_encode_length(resp_buffer, resp_pos, 0);
        cp_len = *resp_pos;

        /* pdr id */
        tlv_encode_type(resp_buffer, resp_pos, UPF_PDR_ID);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, resp_pos, cp->pdr_id);

        /* Local F-TEID for Redundant Transmission */
        if (cp->rt_local_fteid_present) {
            ret = upc_build_f_teid(&cp->rt_local_fteid, resp_buffer, resp_pos);
            if (0 > ret) {
                LOG(UPC, ERR, "build Redundant Transmission f-teid failed.\n");
                return -1;
            }
        }

        /* filling created pdr length */
        cp_len = *resp_pos - cp_len;
        tlv_encode_length(resp_buffer, &cp_len_pos, cp_len);
        LOG(UPC, RUNNING, "encode traffic endpoint info.");
    }

    return 0;
}

static int upc_build_load_control_info(session_load_contrl_info *ctl_info,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_LOAD_CONTROL_INFORMATION);

    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* sequence number */
    tlv_encode_type(resp_buffer, resp_pos, UPF_SEQUENCE_NUMBER);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
    tlv_encode_uint32_t(resp_buffer, resp_pos, ctl_info->sequence_number);
    /* load metric */
    tlv_encode_type(resp_buffer, resp_pos, UPF_METRIC);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, resp_pos, ctl_info->load_metric);

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "encode load control info.");

    return ie_len;
}

static int upc_build_overload_control_info(
    session_overload_contrl_info *ctl_info,
    uint8_t* resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_OVERLOAD_CONTROL_INFORMATION);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* sequence number */
    tlv_encode_type(resp_buffer, resp_pos, UPF_SEQUENCE_NUMBER);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
    tlv_encode_uint32_t(resp_buffer, resp_pos, ctl_info->sequence_number);

    /* load metric */
    tlv_encode_type(resp_buffer, resp_pos, UPF_METRIC);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, resp_pos, ctl_info->overload_reduc_metric);

    /* timer */
    tlv_encode_type(resp_buffer, resp_pos, UPF_TIMER);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, resp_pos, ctl_info->timer.value);

    /* OCI flags */
    if (ctl_info->oci_flag.d.AOCI) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_OCI_FLAGS);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
        tlv_encode_uint8_t(resp_buffer, resp_pos, ctl_info->oci_flag.value);
    }
    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "encode overload control info.");

    return ie_len;
}

static int upc_build_created_bridge_info(
    session_created_bg_info_within_resp *info,
    uint8_t* resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_CREATED_BRIDGE_INFO_FOR_TSC);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* DS-TT Port Number */
    if (info->ds_tt_port_number_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_DS_TT_PORT_NUMBER);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, info->ds_tt_port_number);
    }

    /* NW-TT Port Number */
    if (info->nw_tt_port_number_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_NW_TT_PORT_NUMBER);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, info->nw_tt_port_number);
    }

    /* TSN Bridge ID */
    if (info->tsn_brige_id_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_TSN_BRIDGE_ID);
        if (info->tsn_brige_id.flag.d.MAC) {
            tlv_encode_length(resp_buffer, resp_pos, 7);
            tlv_encode_uint8_t(resp_buffer, resp_pos, info->tsn_brige_id.flag.value);
            tlv_encode_binary(resp_buffer, resp_pos, ETH_ALEN, info->tsn_brige_id.mac_addr);
        } else {
            tlv_encode_length(resp_buffer, resp_pos, 1);
            tlv_encode_uint8_t(resp_buffer, resp_pos, info->tsn_brige_id.flag.value);
        }
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "encode created bridge info for tsc.");

    return ie_len;
}

static int upc_build_mptcp_para(session_mptcp_param *info,
    uint8_t* resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0, sub_ie_pos = 0, sub_ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_MPTCP_PARAMETERS);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* MPTCP Address Information */
    tlv_encode_type(resp_buffer, resp_pos, UPF_MPTCP_ADDRESS_INFORMATION);
    sub_ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    sub_ie_len = *resp_pos;
    tlv_encode_uint8_t(resp_buffer, resp_pos, info->mptcp_address_info.flag.value);
    tlv_encode_uint8_t(resp_buffer, resp_pos, info->mptcp_address_info.mptcp_proxy_type);
    tlv_encode_uint16_t(resp_buffer, resp_pos, info->mptcp_address_info.mptcp_proxy_port);
    if (info->mptcp_address_info.flag.d.V4) {
        tlv_encode_uint32_t(resp_buffer, resp_pos, info->mptcp_address_info.mptcp_proxy_ipv4);
    }
    if (info->mptcp_address_info.flag.d.V6) {
        tlv_encode_binary(resp_buffer, resp_pos, IPV6_ALEN, info->mptcp_address_info.mptcp_proxy_ipv6);
    }
    sub_ie_len = *resp_pos - sub_ie_len;
    tlv_encode_length(resp_buffer, &sub_ie_pos, sub_ie_len);

    /* UE Link-Specific IP Address */
    tlv_encode_type(resp_buffer, resp_pos, UPF_UE_LINK_SPECIFIC_IP_ADDRESS);
    sub_ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    sub_ie_len = *resp_pos;
    tlv_encode_uint8_t(resp_buffer, resp_pos, info->ue_link_s_ip.flag.value);
    if (info->ue_link_s_ip.flag.d.V4) {
        tlv_encode_uint32_t(resp_buffer, resp_pos, info->ue_link_s_ip.ipv4_3gpp);
    }
    if (info->ue_link_s_ip.flag.d.V6) {
        tlv_encode_binary(resp_buffer, resp_pos, IPV6_ALEN, info->ue_link_s_ip.ipv6_3gpp);
    }
    if (info->ue_link_s_ip.flag.d.NV4) {
        tlv_encode_uint32_t(resp_buffer, resp_pos, info->ue_link_s_ip.ipv4_non_3gpp);
    }
    if (info->ue_link_s_ip.flag.d.NV6) {
        tlv_encode_binary(resp_buffer, resp_pos, IPV6_ALEN, info->ue_link_s_ip.ipv6_non_3gpp);
    }
    sub_ie_len = *resp_pos - sub_ie_len;
    tlv_encode_length(resp_buffer, &sub_ie_pos, sub_ie_len);

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "encode MPTCP Parameters.");

    return ie_len;
}

static int upc_build_atsss_ll(session_atsss_ll_param *info,
    uint8_t* resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_ATSSS_LL_PARAMETERS);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* MPTCP Address Information */
    tlv_encode_type(resp_buffer, resp_pos, UPF_ATSSS_LL_INFORMATION);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, resp_pos, info->atsss_ll_info.value);

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "encode ATSSS-LL Parameters.");

    return ie_len;
}

static int upc_build_pmf_para(session_pmf_param *info,
    uint8_t* resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0, sub_ie_pos = 0, sub_ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_PMF_PARAMETERS);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* MPTCP Address Information */
    tlv_encode_type(resp_buffer, resp_pos, UPF_PMF_ADDRESS_INFORMATION);
    sub_ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    sub_ie_len = *resp_pos;
    tlv_encode_uint8_t(resp_buffer, resp_pos, info->pmf_address_info.flag.value);
    if (info->pmf_address_info.flag.d.V4) {
        tlv_encode_uint32_t(resp_buffer, resp_pos, info->pmf_address_info.pmf_ipv4);
    }
    if (info->pmf_address_info.flag.d.V6) {
        tlv_encode_binary(resp_buffer, resp_pos, IPV6_ALEN, info->pmf_address_info.pmf_ipv6);
    }
    if (info->pmf_address_info.flag.d.V4 || info->pmf_address_info.flag.d.V6) {
        tlv_encode_uint16_t(resp_buffer, resp_pos, info->pmf_address_info.pmf_port_3gpp);
        tlv_encode_uint16_t(resp_buffer, resp_pos, info->pmf_address_info.pmf_port_non_3gpp);
    }
    if (info->pmf_address_info.flag.d.MAC) {
        tlv_encode_binary(resp_buffer, resp_pos, ETH_ALEN, info->pmf_address_info.pmf_mac_3gpp);
        tlv_encode_binary(resp_buffer, resp_pos, ETH_ALEN, info->pmf_address_info.pmf_mac_non_3gpp);
    }
    sub_ie_len = *resp_pos - sub_ie_len;
    tlv_encode_length(resp_buffer, &sub_ie_pos, sub_ie_len);

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "encode PMF Parameters.");

    return ie_len;
}

static int upc_build_atsss_control_para(session_atsss_control_param *info,
    uint8_t* resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_ATSSS_CONTROL_PARAMETERS);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* MPTCP Parameters */
    if (info->mptcp_para_present) {
        upc_build_mptcp_para(&info->mptcp_para, resp_buffer, resp_pos);
    }

    /* ATSSS-LL Parameters */
    if (info->atsss_ll_para_present) {
        upc_build_atsss_ll(&info->atsss_ll_para, resp_buffer, resp_pos);
    }

    /* PMF Parameters */
    if (info->pmf_para_present) {
        upc_build_pmf_para(&info->pmf_para, resp_buffer, resp_pos);
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "encode ATSSS Control Parameters.");

    return ie_len;
}

static int upc_build_md_usage_report(session_md_usage_report *ur_arr,
    uint8_t ur_num, uint8_t *resp_buffer, uint16_t *resp_pos, uint32_t type, int trace_flag)
{
    uint8_t cnt = 0;
    uint16_t ie_pos = 0, ie_len = 0;

    for(cnt = 0; cnt < ur_num; ++cnt) {
        session_md_usage_report *report = &ur_arr[cnt];

        tlv_encode_type(resp_buffer, resp_pos, type);
        ie_pos = *resp_pos;
        tlv_encode_length(resp_buffer, resp_pos, 0);
        ie_len = *resp_pos;

        /* urr id */
        tlv_encode_type(resp_buffer, resp_pos, UPF_URR_ID);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, report->urr_id);
        LOG_TRACE(UPC, DEBUG, trace_flag, "urr id %u.", report->urr_id);

        /* ur seqn */
        tlv_encode_type(resp_buffer, resp_pos, UPF_UR_SEQN);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, report->ur_seqn);
        LOG_TRACE(UPC, DEBUG, trace_flag, "ur seqn %u.", report->ur_seqn);

        /* usage report trigger */
        tlv_encode_type(resp_buffer, resp_pos, UPF_USAGE_REPORT_TRIGGER);
        tlv_encode_length(resp_buffer, resp_pos, 3);
        tlv_encode_int_3b(resp_buffer, resp_pos, report->trigger.value);
        LOG_TRACE(UPC, DEBUG, trace_flag, "trigger %u.", report->trigger.value);

        /* start time */
        if (report->member_flag.d.start_time_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_START_TIME);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, report->start_time);
            LOG_TRACE(UPC, RUNNING, trace_flag, "start time %u.", report->start_time);
        }

        /* end time */
        if (report->member_flag.d.end_time_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_END_TIME);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, report->end_time);
            LOG_TRACE(UPC, RUNNING, trace_flag, "end time %u.", report->end_time);
        }

        /* Volume Measurement */
        if (report->member_flag.d.vol_meas_present) {
            if (0 > upc_build_volume(&report->vol_meas,
                resp_buffer, resp_pos)) {
                LOG(UPC, ERR, "build volume measurement failed.");
                return -1;
            }
        }

        /* Duration Measurement */
        if (report->member_flag.d.duration_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_DURATION_MEASUREMENT);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, report->duration);
            LOG_TRACE(UPC, RUNNING, trace_flag, "duration %u.", report->duration);
        }

        /* Time of First Packet */
        if (report->member_flag.d.first_pkt_time_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_TIME_OF_FIRST_PACKET);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, report->first_pkt_time);
            LOG_TRACE(UPC, RUNNING, trace_flag, "time of first packet %u.",
                report->first_pkt_time);
        }

        /* Time of Last Packet */
        if (report->member_flag.d.last_pkt_time_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_TIME_OF_LAST_PACKET);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, report->last_pkt_time);
            LOG_TRACE(UPC, RUNNING, trace_flag, "time of last packet %u.",
                report->first_pkt_time);
        }

        /* Usage Information */
        if (report->member_flag.d.usage_info_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_USAGE_INFORMATION);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
            tlv_encode_uint8_t(resp_buffer, resp_pos, report->usage_info.value);
            LOG_TRACE(UPC, RUNNING, trace_flag, "usage info %d.", report->usage_info.value);
        }

        /* Query URR Reference */
        if (report->member_flag.d.query_urr_ref_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_QUERY_URR_REFERENCE);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, report->query_urr_ref);
            LOG_TRACE(UPC, RUNNING, trace_flag, "Query URR Reference %u.",
                report->query_urr_ref);
        }

        /* Ethernet Traffic Information */
        if (report->member_flag.d.eth_fraffic_present) {
            if (0 > upc_build_eth_traffic_info(&report->eth_traffic,
                resp_buffer, resp_pos)) {
                LOG(UPC, ERR, "build eth traffic info failed.");
                return -1;
            }
        }

        ie_len = *resp_pos - ie_len;
        tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    }

    return 0;
}

static int upc_build_created_traffic_endpoint(
    session_created_tc_endpoint *tc_arr,
    uint8_t tc_num, uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint8_t cnt = 0, cnt_l2 = 0;
    int ret = 0;

    for (cnt = 0; cnt < tc_num; ++cnt) {
        session_created_tc_endpoint *tc = &tc_arr[cnt];
        uint16_t tc_len = 0, tc_len_pos = 0;

        tlv_encode_type(resp_buffer, resp_pos, UPF_CREATED_TRAFFIC_ENDPOINT);
        /* Record the current position */
        tc_len_pos = *resp_pos;
        tlv_encode_length(resp_buffer, resp_pos, 0);
        tc_len = *resp_pos;

        /* traffic endpoint id */
        tlv_encode_type(resp_buffer, resp_pos, UPF_TRAFFIC_ENDPOINT_ID);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
        tlv_encode_uint8_t(resp_buffer, resp_pos, tc->tc_endpoint_id);

        /* local f-teid */
        if (tc->local_fteid_present) {
            ret = upc_build_f_teid(&tc->local_fteid, resp_buffer, resp_pos);
            if (0 > ret) {
                LOG(UPC, ERR, "build f-teid failed.\n");
                return -1;
            }
        }

        /* Local F-TEID for Redundant Transmission */
        if (tc->rt_local_fteid_present) {
            ret = upc_build_f_teid(&tc->rt_local_fteid, resp_buffer, resp_pos);
            if (0 > ret) {
                LOG(UPC, ERR, "build Redundant Transmission f-teid failed.\n");
                return -1;
            }
        }

        /* UE_IP */
        for (cnt_l2 = 0; cnt_l2 < tc_num; ++cnt_l2) {
            ret = upc_build_ue_ip(&tc->ueip_addr[cnt_l2], resp_buffer, resp_pos);
            if (0 > ret) {
                LOG(UPC, ERR, "build ue ip failed.\n");
                return -1;
            }
        }

        /* filling traffic endpoint length */
        tc_len = *resp_pos - tc_len;
        tlv_encode_length(resp_buffer, &tc_len_pos, tc_len);
        LOG(UPC, RUNNING, "encode traffic endpoint info.");
    }

    return 0;
}

static int upc_build_failed_rule_id(session_failed_rule_id *rule_id,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    tlv_encode_type(resp_buffer, resp_pos, UPF_FAILED_RULE_ID);

    switch (rule_id->rule_type) {
        case SESS_FAILED_PDR:
        case SESS_FAILED_MAR:
            tlv_encode_length(resp_buffer, resp_pos,
                sizeof(uint8_t) + sizeof(uint16_t));
            tlv_encode_uint8_t(resp_buffer, resp_pos, rule_id->rule_type);
            tlv_encode_uint16_t(resp_buffer, resp_pos, rule_id->rule_id);
            break;
        case SESS_FAILED_FAR:
        case SESS_FAILED_QER:
        case SESS_FAILED_URR:
            tlv_encode_length(resp_buffer, resp_pos,
                sizeof(uint8_t) + sizeof(uint32_t));
            tlv_encode_uint8_t(resp_buffer, resp_pos, rule_id->rule_type);
            tlv_encode_uint32_t(resp_buffer, resp_pos, rule_id->rule_id);
            break;
        case SESS_FAILED_BAR:
        case SESS_FAILED_SRR:
            tlv_encode_length(resp_buffer, resp_pos,
                sizeof(uint8_t) + sizeof(uint8_t));
            tlv_encode_uint8_t(resp_buffer, resp_pos, rule_id->rule_type);
            tlv_encode_uint8_t(resp_buffer, resp_pos, rule_id->rule_id);
            break;
        default:
            LOG(UPC, ERR, "encode offending ie failed,"
                " rule type: %d.", rule_id->rule_type);
            break;
    }

    LOG(UPC, RUNNING, "encode failed rule id, type is %d.",
        rule_id->rule_type);

    return 0;
}

static int upc_build_report_dldr(session_dl_data_report *dd_report,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint8_t cnt = 0, max_num = dd_report->pdr_id_num;
    uint16_t ie_pos = 0, ie_len = 0;

    for (cnt = 0; cnt < max_num; ++cnt) {
        session_dl_data_service_info *dd_service =
            &dd_report->dl_data_service[cnt];

        tlv_encode_type(resp_buffer, resp_pos, UPF_DOWNLINK_DATA_REPORT);
        ie_pos = *resp_pos;
        tlv_encode_length(resp_buffer, resp_pos, 0);
        ie_len = *resp_pos;

        /* PDR ID */
        tlv_encode_type(resp_buffer, resp_pos, UPF_PDR_ID);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, resp_pos, dd_report->pdr_id_arr[cnt]);
        LOG(UPC, RUNNING, "encode DLDR[%d] PDR ID: %d.",
            cnt, dd_report->pdr_id_arr[cnt]);

        if (dd_service->ddsi_flag.value & 0x3) {
            /* Downlink Data Service Information */
            tlv_encode_type(resp_buffer, resp_pos,
                UPF_DOWNLINK_DATA_SERVICE_INFORMATION);
            switch (dd_service->ddsi_flag.value) {
                case 1:
                    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint16_t));
                    tlv_encode_uint8_t(resp_buffer, resp_pos,
                        dd_service->ddsi_flag.value);
                    tlv_encode_uint8_t(resp_buffer, resp_pos,
                        dd_service->ppi_value);
                    break;
                case 2:
                    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint16_t));
                    tlv_encode_uint8_t(resp_buffer, resp_pos,
                        dd_service->ddsi_flag.value);
                    tlv_encode_uint8_t(resp_buffer, resp_pos,
                        dd_service->qfi);
                    break;
                case 3:
                    tlv_encode_length(resp_buffer, resp_pos, 3);
                    tlv_encode_uint8_t(resp_buffer, resp_pos,
                        dd_service->ddsi_flag.value);
                    tlv_encode_uint8_t(resp_buffer, resp_pos,
                        dd_service->ppi_value);
                    tlv_encode_uint8_t(resp_buffer, resp_pos,
                        dd_service->qfi);
                    break;
                default:
                    tlv_encode_length(resp_buffer, resp_pos, 1);
                    tlv_encode_uint8_t(resp_buffer, resp_pos,
                        dd_service->ddsi_flag.value);
                    break;
            }
        }
        LOG(UPC, RUNNING, "encode DLDR[%d] flag: %d.",
            cnt, dd_service->ddsi_flag.value);

        ie_len = *resp_pos - ie_len;
        tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    }

    return 0;
}

static int upc_build_remote_gtpu_peer(session_remote_gtpu_peer *gtpu_peer,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    /* Remote GTP-U Peer */
    tlv_encode_type(resp_buffer, resp_pos, UPF_REMOTE_GTP_U_PEER);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    tlv_encode_uint8_t(resp_buffer, resp_pos,
        gtpu_peer->regtpr_flag.value);

    /* IPv4 address */
    if (gtpu_peer->regtpr_flag.d.V4) {
        tlv_encode_uint32_t(resp_buffer, resp_pos, gtpu_peer->ipv4_addr);
    }

    /* IPv6 address */
    if (gtpu_peer->regtpr_flag.d.V6) {
        tlv_encode_binary(resp_buffer, resp_pos,
            IPV6_ALEN, gtpu_peer->ipv6_addr);
    }

    /* Length of Destination Interface field & Destination Interface field */
    if (gtpu_peer->regtpr_flag.d.DI) {
        /* Length of Destination Interface field */
        tlv_encode_uint16_t(resp_buffer, resp_pos, gtpu_peer->des_if_len);

        /* Destination Interface field */
        tlv_encode_uint8_t(resp_buffer, resp_pos, gtpu_peer->dest_if);
    }

    /* Length of Network Instance field & Network Instance field */
    if (gtpu_peer->regtpr_flag.d.NI) {
        /* Length of Network Instance field */
        tlv_encode_uint16_t(resp_buffer, resp_pos, gtpu_peer->net_inst_len);

        /* Network Instance field */
        tlv_encode_binary(resp_buffer, resp_pos, gtpu_peer->net_inst_len,
                            (uint8_t *)gtpu_peer->net_instance);
    }

    /* filling IE total length */
    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}

static int upc_build_report_upfr(session_up_path_failure_report *upfr_report,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;
    uint8_t cnt = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_USER_PLANE_PATH_FAILURE_REPORT);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    for (cnt = 0; cnt < upfr_report->gtpu_peer_num; ++cnt) {
        upc_build_remote_gtpu_peer(&upfr_report->gtpu_peer_arr[cnt], resp_buffer, resp_pos);
    }

    /* filling outer IE total length */
    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}

static int upc_build_report_uprr(session_up_path_recovery_report *uprr_report,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;
    uint8_t cnt = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_USER_PLANE_PATH_RECOVERY_REPORT);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    for (cnt = 0; cnt < uprr_report->gtpu_peer_num; ++cnt) {
        upc_build_remote_gtpu_peer(&uprr_report->gtpu_peer_arr[cnt], resp_buffer, resp_pos);
    }

    /* filling outer IE total length */
    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}


static int upc_build_app_detect_info(session_app_detection_info *app_detect,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos,
        UPF_APPLICATION_DETECTION_INFORMATION);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* APP ID */
    tlv_encode_type(resp_buffer, resp_pos, UPF_APPLICATION_ID);
    tlv_encode_length(resp_buffer, resp_pos, app_detect->app_id.id_len);
    if (app_detect->app_id.id_len) {
        tlv_encode_binary(resp_buffer, resp_pos,
            app_detect->app_id.id_len, app_detect->app_id.value);
    }

    /* APP Instance ID */
    if (app_detect->inst_id.id_len) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_APPLICATION_INSTANCE_ID);
        tlv_encode_length(resp_buffer, resp_pos, app_detect->inst_id.id_len);
        tlv_encode_binary(resp_buffer, resp_pos,
            app_detect->inst_id.id_len, app_detect->inst_id.app_inst_id);
    }

    /* Flow Information */

    /* filling outer IE total length */
    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}

static int upc_build_report_ur(session_report_request_ur *ur_arr,
    uint8_t ur_num, uint8_t* resp_buffer, uint16_t *resp_pos)
{
    uint8_t cnt = 0;
    int ret = 0;
    uint16_t ie_pos = 0, ie_len = 0;

    for (cnt = 0; cnt < ur_num; ++cnt) {
        session_report_request_ur *ur = &ur_arr[cnt];

        tlv_encode_type(resp_buffer, resp_pos,
            UPF_USAGE_REPORT_SESSION_REPORT_REQUEST);
        ie_pos = *resp_pos;
        tlv_encode_length(resp_buffer, resp_pos, 0);
        ie_len = *resp_pos;

        /* urr id */
        tlv_encode_type(resp_buffer, resp_pos, UPF_URR_ID);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, ur->urr_id);
        LOG(UPC, DEBUG, "urr id %u.", ur->urr_id);

        /* ur seqn */
        tlv_encode_type(resp_buffer, resp_pos, UPF_UR_SEQN);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, ur->ur_seqn);
        LOG(UPC, DEBUG, "ur seqn %u.", ur->ur_seqn);

        /* usage report trigger */
        tlv_encode_type(resp_buffer, resp_pos, UPF_USAGE_REPORT_TRIGGER);
        tlv_encode_length(resp_buffer, resp_pos, 3);
        tlv_encode_int_3b(resp_buffer, resp_pos, ur->trigger.value);
        LOG(UPC, DEBUG, "trigger %u.", ur->trigger.value);

        /* start time */
        if (ur->member_flag.d.start_time_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_START_TIME);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, ur->start_time);
            LOG(UPC, RUNNING, "start time %u.", ur->start_time);
        }

        /* end time */
        if (ur->member_flag.d.end_time_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_END_TIME);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, ur->end_time);
            LOG(UPC, RUNNING, "end time %u.", ur->end_time);
        }

        /* Volume Measurement */
        if (ur->member_flag.d.vol_meas_present) {
            if (0 > upc_build_volume(&ur->vol_meas, resp_buffer, resp_pos)) {
                LOG(UPC, ERR, "build volume measurement failed.");
                return -1;
            }
        }

        /* Duration Measurement */
        if (ur->member_flag.d.duration_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_DURATION_MEASUREMENT);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, ur->duration);
            LOG(UPC, RUNNING, "duration %u.", ur->duration);
        }

        /* Application Detection Information */
        if (ur->member_flag.d.app_detect_info_present) {
            ret = upc_build_app_detect_info(&ur->app_detect_info,
                resp_buffer, resp_pos);
            if (0 > ret) {
                LOG(UPC, ERR, "build app detect info failed.");
                return -1;
            }
            LOG(UPC, RUNNING, "app detect info.");
        }

        /* UE IP */
        if (ur->member_flag.d.ue_ip_present) {
            ret = upc_build_ue_ip(&ur->ue_ip, resp_buffer, resp_pos);
            if (0 > ret) {
                LOG(UPC, ERR, "build ue ip failed.");
                return -1;
            }
            LOG(UPC, RUNNING, "ue ip.");
        }

        /* NETWORK INSTANCE */
        if (ur->member_flag.d.network_instance_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_NETWORK_INSTANCE);
            tlv_encode_length(resp_buffer, resp_pos, ur->network_inst_len);
            tlv_encode_binary(resp_buffer, resp_pos, ur->network_inst_len,
                (uint8_t *)ur->network_instance);
            LOG(UPC, RUNNING, "network instance.");
        }

        /* Time of First Packet */
        if (ur->member_flag.d.first_pkt_time_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_TIME_OF_FIRST_PACKET);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, ur->first_pkt_time);
            LOG(UPC, RUNNING, "time of first packet %u.",
                ur->first_pkt_time);
        }

        /* Time of Last Packet */
        if (ur->member_flag.d.last_pkt_time_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_TIME_OF_LAST_PACKET);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, ur->last_pkt_time);
            LOG(UPC, RUNNING, "time of last packet %u.",
                ur->first_pkt_time);
        }

        /* Usage Information */
        if (ur->member_flag.d.usage_info_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_USAGE_INFORMATION);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
            tlv_encode_uint8_t(resp_buffer, resp_pos, ur->usage_info.value);
            LOG(UPC, RUNNING, "usage info %d.", ur->usage_info.value);
        }

        /* Query URR Reference */
        if (ur->member_flag.d.query_urr_ref_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_QUERY_URR_REFERENCE);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, ur->query_urr_ref);
            LOG(UPC, RUNNING, "Query URR Reference %u.",
                ur->query_urr_ref);
        }

        /* Event Time Stamp */
        if (ur->member_flag.d.eve_stamp_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_EVENT_TIME_STAMP_);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
            tlv_encode_uint32_t(resp_buffer, resp_pos, ur->eve_stamp);
            LOG(UPC, RUNNING, "eve stamp %d.", ur->eve_stamp);
        }

        /* Ethernet Traffic Information */
        if (ur->member_flag.d.eth_fraffic_present) {
            if (0 > upc_build_eth_traffic_info(&ur->eth_traffic,
                resp_buffer, resp_pos)) {
                LOG(UPC, ERR, "build eth traffic info failed.");
                return -1;
            }
        }

        /* filling usage report request IE length */
       ie_len = *resp_pos - ie_len;
       tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    }

    return ie_len;
}

static int upc_build_eir(session_error_indication_report *err,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint8_t cnt = 0;
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_ERROR_INDICATION_REPORT);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* Remote f-teid */
    for (cnt = 0; cnt < err->f_teid_num; ++cnt) {
        if (0 > upc_build_f_teid(&err->remote_f_teid_arr[cnt],
            resp_buffer, resp_pos)) {
            LOG(UPC, ERR, "build f-teid failed.\n");
            return -1;
        }
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}

static int upc_build_f_seid(uint64_t seid,
    uint8_t *resp_buffer, uint16_t *resp_pos, uint8_t node_type)
{
    uint16_t ie_pos = 0, ie_len = 0;
    session_ip_addr *local_ip = upc_get_local_ip();

    tlv_encode_type(resp_buffer, resp_pos, UPF_F_SEID);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    switch (node_type) {
        case UPF_NODE_TYPE_IPV4:
            tlv_encode_uint8_t(resp_buffer, resp_pos, 2);
            tlv_encode_uint64_t(resp_buffer, resp_pos, seid);
            tlv_encode_uint32_t(resp_buffer, resp_pos, local_ip->ipv4);
            break;

        case UPF_NODE_TYPE_IPV6:
            tlv_encode_uint8_t(resp_buffer, resp_pos, 1);
            tlv_encode_uint64_t(resp_buffer, resp_pos, seid);
            tlv_encode_binary(resp_buffer, resp_pos, IPV6_ALEN, local_ip->ipv6);
            break;

        default:
            LOG(UPC, RUNNING, "Unsupport node type: %d, use default IPv4", node_type);
            tlv_encode_uint8_t(resp_buffer, resp_pos, 2);
            tlv_encode_uint64_t(resp_buffer, resp_pos, seid);
            tlv_encode_uint32_t(resp_buffer, resp_pos, local_ip->ipv4);
            break;
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}

static int upc_build_clock_drift_report(session_clock_drift_report *cd_report,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_CLOCK_DRIFT_REPORT);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* TSN Time Domain Number */
    tlv_encode_type(resp_buffer, resp_pos, UPF_TSN_TIME_DOMAIN_NUMBER);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, resp_pos, cd_report->tsn_time_domain_number);

    /* Time Offset Measurement */
    if (cd_report->time_offset_measurement_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_TIME_OFFSET_MEASUREMENT);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint64_t));
        tlv_encode_uint64_t(resp_buffer, resp_pos, cd_report->time_offset_measurement);
    }

    /* Cumulative rateRatio Measurement */
    if (cd_report->cumulative_rateratio_measurement_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_CUMULATIVE_RATERATIO_MEASUREMENT);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, cd_report->cumulative_rateratio_measurement);
    }

    /* Time Stamp */
    /*if (cd_report->time_tamp_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_TIME_STAMP);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, cd_report->time_tamp);
    }
*/

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}

static int upc_build_qos_info_in_gpq_report(session_qos_information *qos_info,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_QOS_INFORMATION_IN_GTP_U_PATH_QOS_REPORT);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* Average Packet Delay */
    tlv_encode_type(resp_buffer, resp_pos, UPF_AVERAGE_PACKET_DELAY);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
    tlv_encode_uint32_t(resp_buffer, resp_pos, qos_info->ave_packet_delay);

    /* Minimum Packet Delay */
    if (qos_info->member_flag.d.min_packet_delay_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_MINIMUM_PACKET_DELAY);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, qos_info->min_packet_delay);
    }

    /* Maximum Packet Delay */
    if (qos_info->member_flag.d.max_packet_delay_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_MAXIMUM_PACKET_DELAY);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, qos_info->max_packet_delay);
    }

    /* DSCP */
    if (qos_info->member_flag.d.dscp_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_TRANSPORT_LEVEL_MARKING);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, resp_pos, qos_info->dscp.value);
    }


    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}

static int upc_build_gtpu_path_qos_report(session_gtpu_path_qos_report *gpq_report,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint8_t cnt = 0;
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_GTP_U_PATH_QOS_REPORT);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* Remote GTP-U Peer */
    upc_build_remote_gtpu_peer(&gpq_report->remote_gtpu_peer, resp_buffer, resp_pos);

    /* GTP-U Path Interface Type */
    if (gpq_report->gtpu_path_if_type_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_GTP_U_PATH_INTERFACE_TYPE);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
        tlv_encode_uint8_t(resp_buffer, resp_pos, gpq_report->gtpu_path_if_type.value);
    }

    /* QoS Report Trigger */
    tlv_encode_type(resp_buffer, resp_pos, UPF_QOS_REPORT_TRIGGER);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, resp_pos, gpq_report->qos_report_trigger.value);

    /* Time Stamp */
    tlv_encode_type(resp_buffer, resp_pos, UPF_EVENT_TIME_STAMP_);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
    tlv_encode_uint32_t(resp_buffer, resp_pos, gpq_report->time_stamp);

    /* Start Time */
    if (gpq_report->start_time_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_START_TIME);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, gpq_report->start_time);
    }

    /* QoS Information */
    for (cnt = 0; cnt < gpq_report->qos_info_num; ++cnt) {
        upc_build_qos_info_in_gpq_report(&gpq_report->qos_info[cnt], resp_buffer, resp_pos);
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    return ie_len;
}

static int upc_build_port_mgmt_info_for_tsc(session_port_management_info *info,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos,
        UPF_PORT_MGMT_INFO_FOR_TSC_IE_WITHIN_PFCP_SESSION_MODIFICATION_RESPONSE);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* Port Management Information Container */
    tlv_encode_type(resp_buffer, resp_pos, UPF_PORT_MANAGEMENT_INFORMATION_CONTAINER);
    tlv_encode_length(resp_buffer, resp_pos, strlen(info->port_mgmt_info_container));
    tlv_encode_binary(resp_buffer, resp_pos, strlen(info->port_mgmt_info_container),
        (uint8_t *)info->port_mgmt_info_container);

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "encode Port Management Information for TSC.");

    return ie_len;
}

static int upc_build_qos_monitor_measurement(session_qos_monitor_measurement *info,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_len_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_QOS_MONITORING_MEASUREMENT);
    ie_len_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* FLAG */
    tlv_encode_uint8_t(resp_buffer, resp_pos, info->flag.value);

    /* Downlink packet delay */
    if (info->flag.d.DL) {
        tlv_encode_uint32_t(resp_buffer, resp_pos, info->dl_packet_delay);
    }

    /* Uplink packet delay */
    if (info->flag.d.UL) {
        tlv_encode_uint32_t(resp_buffer, resp_pos, info->ul_packet_delay);
    }

    /* Round trip packet delay */
    if (info->flag.d.RP) {
        tlv_encode_uint32_t(resp_buffer, resp_pos, info->rt_packet_delay);
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_len_pos, ie_len);

    return ie_len;
}

static int upc_build_qoo_monitor_report(session_qos_monitor_report *info_arr, uint8_t info_num,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint8_t cnt = 0;

    for (cnt = 0; cnt < info_num; ++cnt) {
        int cnt = 0;
        uint16_t sr_len = 0, sr_len_pos = 0;
        session_qos_monitor_report *qmr = &info_arr[cnt];

        tlv_encode_type(resp_buffer, resp_pos, UPF_QOS_MONITORING_REPORT);
        /* Record the current position */
        sr_len_pos = *resp_pos;
        tlv_encode_length(resp_buffer, resp_pos, 0);
        sr_len = *resp_pos;

        /* QFI id */
        tlv_encode_type(resp_buffer, resp_pos, UPF_QFI);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
        tlv_encode_uint8_t(resp_buffer, resp_pos, qmr->qfi);

        /* QoS Monitoring Measurement */
        upc_build_qos_monitor_measurement(&qmr->qos_monitor_measurement, resp_buffer, resp_pos);

        /* Time Stamp */
        tlv_encode_type(resp_buffer, resp_pos, UPF_EVENT_TIME_STAMP_);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, qmr->time_stamp);

        /* Start Time */
        tlv_encode_type(resp_buffer, resp_pos, UPF_START_TIME);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
        tlv_encode_uint32_t(resp_buffer, resp_pos, qmr->start_time);

        /* filling created pdr length */
        sr_len = *resp_pos - sr_len;
        tlv_encode_length(resp_buffer, &sr_len_pos, sr_len);
        LOG(UPC, RUNNING, "encode qos monitor report.");
    }

    return 0;
}

static int upc_build_session_report(session_report *info_arr, uint8_t info_num,
    uint8_t *resp_buffer, uint16_t *resp_pos, int trace_flag)
{
    uint8_t cnt = 0;

    for (cnt = 0; cnt < info_num; ++cnt) {
        int cnt = 0;
        uint16_t sr_len = 0, sr_len_pos = 0;
        session_report *sr = &info_arr[cnt];

        tlv_encode_type(resp_buffer, resp_pos, UPF_SESSION_REPORT);
        /* Record the current position */
        sr_len_pos = *resp_pos;
        tlv_encode_length(resp_buffer, resp_pos, 0);
        sr_len = *resp_pos;

        /* SRR id */
        tlv_encode_type(resp_buffer, resp_pos, UPF_SRR_ID);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
        tlv_encode_uint8_t(resp_buffer, resp_pos, sr->srr_id);

        /* Access Availability Report */
        if (sr->access_avail_report_present) {
            tlv_encode_type(resp_buffer, resp_pos, UPF_ACCESS_AVAILABILITY_REPORT);
            tlv_encode_length(resp_buffer, resp_pos, 5);

            tlv_encode_type(resp_buffer, resp_pos, UPF_ACCESS_AVAILABILITY_INFORMATION);
            tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
            tlv_encode_uint8_t(resp_buffer, resp_pos, sr->access_avail_report.access_avail_info.value);
        }

        /* QoS Monitoring Report */
        if (0 > upc_build_qoo_monitor_report(sr->qos_monitor_report,
            sr->qos_monitor_report_num, resp_buffer, resp_pos)) {
            LOG(UPC, ERR, "build QoS Monitoring Report failed.");
        }

        /* filling created pdr length */
        sr_len = *resp_pos - sr_len;
        tlv_encode_length(resp_buffer, &sr_len_pos, sr_len);
        LOG_TRACE(UPC, RUNNING, trace_flag, "encode session report.");
    }

    return 0;
}

static int upc_build_packet_rate_status(session_packet_rate_status *prs,
    uint8_t *resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_PACKET_RATE_STATUS);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    tlv_encode_uint8_t(resp_buffer, resp_pos, prs->flag.value);

    if (prs->flag.d.UL) {
        tlv_encode_uint16_t(resp_buffer, resp_pos, prs->remain_ul_packets);
        if (prs->flag.d.APR) {
            tlv_encode_uint16_t(resp_buffer, resp_pos, prs->addit_remain_ul_packets);
        }
    }

    if (prs->flag.d.DL) {
        tlv_encode_uint16_t(resp_buffer, resp_pos, prs->remain_dl_packets);
        if (prs->flag.d.APR) {
            tlv_encode_uint16_t(resp_buffer, resp_pos, prs->addit_remain_dl_packets);
        }
    }

    if (prs->flag.d.UL || prs->flag.d.DL) {
        tlv_encode_uint64_t(resp_buffer, resp_pos, prs->rate_ctrl_status_time);
    }

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);

    LOG(UPC, RUNNING, "packet rate status.");

    return ie_len;
}

static int upc_build_packet_rate_status_report(session_packet_rate_status_report *info,
    uint8_t* resp_buffer, uint16_t *resp_pos)
{
    uint16_t ie_pos = 0, ie_len = 0;

    tlv_encode_type(resp_buffer, resp_pos, UPF_PACKET_RATE_STATUS_REPORT);
    ie_pos = *resp_pos;
    tlv_encode_length(resp_buffer, resp_pos, 0);
    ie_len = *resp_pos;

    /* QER ID */
    tlv_encode_type(resp_buffer, resp_pos, UPF_QER_ID);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint32_t));
    tlv_encode_uint32_t(resp_buffer, resp_pos, info->qer_id);

    /* load metric */
    upc_build_packet_rate_status(&info->packet_rate_status, resp_buffer, resp_pos);

    ie_len = *resp_pos - ie_len;
    tlv_encode_length(resp_buffer, &ie_pos, ie_len);
    LOG(UPC, RUNNING, "encode Packet Rate Status Report.");

    return ie_len;
}

/* 暂时不考虑UP分配的f-teid和ueip会出现修改的情况 */
static void upc_change_pdr(session_pdr_create *est_pdr,
    session_pdr_update *mdf_pdr)
{
    est_pdr->member_flag.value |= mdf_pdr->member_flag.value;

    if (mdf_pdr->member_flag.d.precedence_present) {
        est_pdr->precedence = mdf_pdr->precedence;
    }

    if (mdf_pdr->member_flag.d.pdi_content_present) {
        session_packet_detection_info *mdf_pdi = &mdf_pdr->pdi_content;
        session_packet_detection_info *est_pdi = &est_pdr->pdi_content;

        est_pdr->member_flag.value |= mdf_pdr->member_flag.value;
        /* local f-teid */
        if (mdf_pdi->member_flag.d.local_fteid_present) {
            memcpy(&est_pdi->local_fteid,
                &mdf_pdi->local_fteid, sizeof(session_f_teid));
        }
        /* network instance */
        if (mdf_pdi->member_flag.d.network_instance_present) {
            strcpy(est_pdi->network_instance, mdf_pdi->network_instance);
        }
        /* ueip */
        if (mdf_pdi->ue_ipaddr_num) {
            memcpy(est_pdi->ue_ipaddr,
                mdf_pdi->ue_ipaddr, sizeof(session_ue_ip) * mdf_pdi->ue_ipaddr_num);
            est_pdi->ue_ipaddr_num = mdf_pdi->ue_ipaddr_num;
        }
        /* traffic endpoint id */
        if (mdf_pdi->traffic_endpoint_num) {
            memcpy(est_pdi->traffic_endpoint_id, mdf_pdi->traffic_endpoint_id,
                sizeof(est_pdi->traffic_endpoint_id[0]) * mdf_pdi->traffic_endpoint_num);
            est_pdi->traffic_endpoint_num = mdf_pdi->traffic_endpoint_num;
        }
        /* sdf filter */
        if (mdf_pdi->sdf_filter_num) {
            memcpy(est_pdi->sdf_filter, mdf_pdi->sdf_filter,
                sizeof(session_sdf_filter) * mdf_pdi->sdf_filter_num);
            est_pdi->sdf_filter_num = mdf_pdi->sdf_filter_num;
        }
        /* application id */
        if (mdf_pdi->member_flag.d.application_id_present) {
            strcpy(est_pdi->application_id, mdf_pdi->application_id);
        }
        /* eth pdu ses info */
        if (mdf_pdi->member_flag.d.eth_pdu_ses_info_present) {
            est_pdi->eth_pdu_ses_info.value =
                mdf_pdi->eth_pdu_ses_info.value;
        }
        /* eth filter */
        if (mdf_pdi->eth_filter_num) {
            memcpy(est_pdi->eth_filter, mdf_pdi->eth_filter,
                sizeof(session_eth_filter) * mdf_pdi->eth_filter_num);
            est_pdi->eth_filter_num = mdf_pdi->eth_filter_num;
        }
        /* qfi */
        if (mdf_pdi->qfi_number) {
            memcpy(est_pdi->qfi_array, mdf_pdi->qfi_array,
                sizeof(est_pdi->qfi_array[0]) * mdf_pdi->qfi_number);
            est_pdi->qfi_number= mdf_pdi->qfi_number;
        }
        /* framed route */
        if (mdf_pdi->framed_route_num) {
            memcpy(est_pdi->framed_route, mdf_pdi->framed_route,
                sizeof(session_framed_route) * mdf_pdi->framed_route_num);
            est_pdi->framed_route_num = mdf_pdi->framed_route_num;
        }
        /* framed routing */
        if (mdf_pdi->member_flag.d.framed_routing_present) {
            est_pdi->framed_routing = mdf_pdi->framed_routing;
        }
        /* framed ipv6 route */
        if (mdf_pdi->framed_ipv6_route_num) {
            memcpy(est_pdi->framed_ipv6_route, mdf_pdi->framed_ipv6_route,
                sizeof(session_framed_route_ipv6) *
                mdf_pdi->framed_ipv6_route_num);
            est_pdi->framed_ipv6_route_num = mdf_pdi->framed_ipv6_route_num;
        }
        /* src interface type */
        if (mdf_pdi->member_flag.d.src_if_type_present) {
            est_pdi->src_if_type.value = mdf_pdi->src_if_type.value;
        }

    }

    if (mdf_pdr->member_flag.d.OHR_present) {
        est_pdr->outer_header_removal.type =
            mdf_pdr->outer_header_removal.type;
        est_pdr->outer_header_removal.gtp_u_exten =
            mdf_pdr->outer_header_removal.gtp_u_exten;
    }

    if (mdf_pdr->member_flag.d.far_id_present) {
        est_pdr->far_id = mdf_pdr->far_id;
    }

    if (mdf_pdr->urr_id_number) {
        memcpy(est_pdr->urr_id_array, mdf_pdr->urr_id_array,
            sizeof(mdf_pdr->urr_id_array[0]) * mdf_pdr->urr_id_number);
        est_pdr->urr_id_number = mdf_pdr->urr_id_number;
    }

    if (mdf_pdr->qer_id_number) {
        memcpy(est_pdr->qer_id_array, mdf_pdr->qer_id_array,
            sizeof(mdf_pdr->qer_id_array[0]) * mdf_pdr->qer_id_number);
        est_pdr->qer_id_number= mdf_pdr->qer_id_number;
    }

    if (mdf_pdr->act_pre_number) {
        memcpy(est_pdr->act_pre_arr, mdf_pdr->act_pre_arr,
            sizeof(mdf_pdr->act_pre_arr[0]) * mdf_pdr->act_pre_number);
        est_pdr->act_pre_number = mdf_pdr->act_pre_number;
    }

    if (mdf_pdr->member_flag.d.act_time_present) {
        est_pdr->activation_time = mdf_pdr->activation_time;
    }

    if (mdf_pdr->member_flag.d.deact_time_present) {
        est_pdr->deactivation_time = mdf_pdr->deactivation_time;
    }
}

static void upc_change_far(session_far_create *est_far,
    session_far_update *mdf_far)
{
    est_far->member_flag.value |= mdf_far->member_flag.value;
    if (mdf_far->member_flag.d.action_present) {
        est_far->action.value = mdf_far->action.value;
    }

    if (mdf_far->member_flag.d.forw_param_present) {
        session_forward_params *est_fp = &est_far->forw_param;
        session_update_forward_params *mdf_fp = &mdf_far->forw_param;

        est_fp->member_flag.value |= mdf_fp->member_flag.value;

        if (mdf_fp->member_flag.d.dest_if_present) {
            est_fp->dest_if = mdf_fp->dest_if;
        }
        if (mdf_fp->member_flag.d.network_instance_present) {
            strcpy(est_fp->network_instance, mdf_fp->network_instance);
        }
        if (mdf_fp->member_flag.d.redirect_present) {
            memcpy(&est_fp->redirect_addr, &mdf_fp->redirect_addr,
                sizeof(session_redirect_info));
        }
        if (mdf_fp->member_flag.d.ohc_present) {
            memcpy(&est_fp->outer_header_creation,
                &mdf_fp->outer_header_creation,
                sizeof(session_outer_header_create));
        }
        if (mdf_fp->member_flag.d.trans_present) {
            est_fp->trans.value = mdf_fp->trans.value;
        }
        if (mdf_fp->member_flag.d.forwarding_policy_present) {
            strcpy(est_fp->forwarding_policy, mdf_fp->forwarding_policy);
        }
        if (mdf_fp->member_flag.d.header_enrichment_present) {
            memcpy(&est_fp->header_enrichment,
                &mdf_fp->header_enrichment,
                sizeof(session_header_enrichment));
        }
        if (mdf_fp->member_flag.d.traffic_endpoint_id_present) {
            est_fp->traffic_endpoint_id = mdf_fp->traffic_endpoint_id;
        }
        if (mdf_fp->member_flag.d.dest_if_type_present) {
            est_fp->dest_if_type.value = mdf_fp->dest_if_type.value;
        }
    }

    if (mdf_far->member_flag.d.bar_id_present) {
        est_far->bar_id = mdf_far->bar_id;
    }
}

static void upc_change_urr(session_usage_report_rule *est_urr,
    session_usage_report_rule *mdf_urr)
{
    est_urr->member_flag.value |= mdf_urr->member_flag.value;
    if (mdf_urr->member_flag.d.method_present) {
        est_urr->method.value = mdf_urr->method.value;
    }
    if (mdf_urr->member_flag.d.trigger_present) {
        est_urr->trigger.value = mdf_urr->trigger.value;
    }
    if (mdf_urr->member_flag.d.period_present) {
        est_urr->period = mdf_urr->period;
    }
    if (mdf_urr->member_flag.d.vol_thres_present) {
        memcpy(&est_urr->vol_thres, &mdf_urr->vol_thres,
            sizeof(session_urr_volume));
    }
    if (mdf_urr->member_flag.d.vol_quota_present) {
        memcpy(&est_urr->vol_quota, &mdf_urr->vol_quota,
            sizeof(session_urr_volume));
    }
    if (mdf_urr->member_flag.d.eve_thres_present) {
        est_urr->eve_thres = mdf_urr->eve_thres;
    }
    if (mdf_urr->member_flag.d.eve_quota_present) {
        est_urr->eve_quota = mdf_urr->eve_quota;
    }
    if (mdf_urr->member_flag.d.tim_thres_present) {
        est_urr->tim_thres = mdf_urr->tim_thres;
    }
    if (mdf_urr->member_flag.d.tim_quota_present) {
        est_urr->tim_quota = mdf_urr->tim_quota;
    }
    if (mdf_urr->member_flag.d.quota_hold_present) {
        est_urr->quota_hold = mdf_urr->quota_hold;
    }
    if (mdf_urr->member_flag.d.drop_thres_present) {
        memcpy(&est_urr->drop_thres, &mdf_urr->drop_thres,
            sizeof(session_urr_drop_thres));
    }
    if (mdf_urr->member_flag.d.mon_time_present) {
        est_urr->mon_time = mdf_urr->mon_time;
    }
    if (mdf_urr->member_flag.d.sub_vol_thres_present) {
        memcpy(&est_urr->sub_vol_thres, &mdf_urr->sub_vol_thres,
            sizeof(session_urr_volume));
    }
    if (mdf_urr->member_flag.d.sub_tim_thres_present) {
        est_urr->sub_tim_thres = mdf_urr->sub_tim_thres;
    }
    if (mdf_urr->member_flag.d.sub_vol_quota_present) {
        memcpy(&est_urr->sub_vol_quota, &mdf_urr->sub_vol_quota,
            sizeof(session_urr_volume));
    }
    if (mdf_urr->member_flag.d.sub_tim_quota_present) {
        est_urr->sub_tim_quota = mdf_urr->sub_tim_quota;
    }
    if (mdf_urr->member_flag.d.sub_eve_thres_present) {
        est_urr->sub_eve_thres = mdf_urr->sub_eve_thres;
    }
    if (mdf_urr->member_flag.d.sub_eve_quota_present) {
        est_urr->sub_eve_quota = mdf_urr->sub_eve_quota;
    }
    if (mdf_urr->member_flag.d.inact_detect_present) {
        est_urr->inact_detect = mdf_urr->inact_detect;
    }
    if (mdf_urr->member_flag.d.measu_info_present) {
        est_urr->measu_info.value = mdf_urr->measu_info.value;
    }
    if (mdf_urr->member_flag.d.quota_far_present) {
        est_urr->quota_far = mdf_urr->quota_far;
    }
    if (mdf_urr->member_flag.d.eth_inact_time_present) {
        est_urr->eth_inact_time = mdf_urr->eth_inact_time;
    }
    if (mdf_urr->linked_urr_number) {
        memcpy(&est_urr->linked_urr, &mdf_urr->linked_urr,
            sizeof(est_urr->linked_urr[0]) * mdf_urr->linked_urr_number);
    }
    if (mdf_urr->add_mon_time_number) {
        memcpy(&est_urr->add_mon_time, &mdf_urr->add_mon_time,
            sizeof(session_urr_add_mon_time) * mdf_urr->add_mon_time_number);
    }
}

static void upc_change_qer(session_qos_enforcement_rule *est_qer,
    session_qos_enforcement_rule *mdf_qer)
{
    est_qer->member_flag.value |= mdf_qer->member_flag.value;
    if (mdf_qer->member_flag.d.qer_corr_id_present) {
        est_qer->qer_corr_id = mdf_qer->qer_corr_id;
    }
    if (mdf_qer->member_flag.d.gate_status_present) {
        est_qer->gate_status.value = mdf_qer->gate_status.value;
    }
    if (mdf_qer->member_flag.d.mbr_value_present) {
        est_qer->mbr_value.ul_mbr = mdf_qer->mbr_value.ul_mbr;
        est_qer->mbr_value.dl_mbr = mdf_qer->mbr_value.dl_mbr;
    }
    if (mdf_qer->member_flag.d.gbr_value_present) {
        est_qer->gbr_value.ul_gbr = mdf_qer->gbr_value.ul_gbr;
        est_qer->gbr_value.dl_gbr = mdf_qer->gbr_value.dl_gbr;
    }
    if (mdf_qer->member_flag.d.packet_rate_status_present) {
        ros_memcpy(&est_qer->pkt_rate_status, &mdf_qer->pkt_rate_status,
            sizeof(session_packet_rate_status));
    }
    if (mdf_qer->member_flag.d.qfi_present) {
        est_qer->qfi = mdf_qer->qfi;
    }
    if (mdf_qer->member_flag.d.ref_qos_present) {
        est_qer->ref_qos = mdf_qer->ref_qos;
    }
    if (mdf_qer->member_flag.d.ppi_present) {
        est_qer->paging_policy_indic = mdf_qer->paging_policy_indic;
    }
    if (mdf_qer->member_flag.d.averaging_window_present) {
        est_qer->averaging_window = mdf_qer->averaging_window;
    }
    if (mdf_qer->qer_ctrl_indic.value) {
        est_qer->qer_ctrl_indic.value = mdf_qer->qer_ctrl_indic.value;
    }
}

static void upc_change_bar(session_buffer_action_rule *est_bar,
    session_buffer_action_rule *mdf_bar)
{
    est_bar->member_flag.value |= mdf_bar->member_flag.value;
    if (mdf_bar->member_flag.d.notify_delay_present) {
        est_bar->notify_delay = mdf_bar->notify_delay;
    }
    if (mdf_bar->member_flag.d.buffer_pkts_cnt_present) {
        est_bar->buffer_pkts_cnt = mdf_bar->buffer_pkts_cnt;
    }
}

static void upc_change_te(session_tc_endpoint *est_te,
    session_tc_endpoint *mdf_te)
{
    est_te->member_flag.value |= mdf_te->member_flag.value;
    /* local f-teid */
    if (mdf_te->member_flag.d.local_fteid_present) {
        memcpy(&est_te->local_fteid,
            &mdf_te->local_fteid, sizeof(session_f_teid));
    }
    /* network instance */
    if (mdf_te->member_flag.d.network_instance_present) {
        strcpy(est_te->network_instance, mdf_te->network_instance);
    }
    /* ueip */
    if (mdf_te->ue_ipaddr_num) {
        memcpy(est_te->ue_ipaddr,
            mdf_te->ue_ipaddr, sizeof(session_ue_ip) * mdf_te->ue_ipaddr_num);
    }
    /* eth pdu ses info */
    if (mdf_te->member_flag.d.eth_pdu_ses_info_present) {
        est_te->eth_pdu_ses_info.value =
            mdf_te->eth_pdu_ses_info.value;
    }
    /* framed route */
    if (mdf_te->framed_route_num) {
        memcpy(est_te->framed_route, mdf_te->framed_route,
            sizeof(session_framed_route) * mdf_te->framed_route_num);
        est_te->framed_route_num = mdf_te->framed_route_num;
    }
    /* framed routing */
    if (mdf_te->member_flag.d.framed_routing_present) {
        est_te->framed_routing = mdf_te->framed_routing;
    }
    /* framed ipv6 route */
    if (mdf_te->framed_ipv6_route_num) {
        memcpy(est_te->framed_ipv6_route, mdf_te->framed_ipv6_route,
            sizeof(session_framed_route_ipv6) *
            mdf_te->framed_ipv6_route_num);
        est_te->framed_ipv6_route_num = mdf_te->framed_ipv6_route_num;
    }
}

inline void upc_change_afai(session_access_forwarding_action *est_afai,
    session_access_forwarding_action *mdf_afai)
{
    if (mdf_afai->member_flag.d.far_id_present) {
        est_afai->far_id = mdf_afai->far_id;
    }
    if (mdf_afai->member_flag.d.weight_present) {
        est_afai->weight = mdf_afai->weight;
    }
    if (mdf_afai->member_flag.d.priority_present) {
        est_afai->priority = mdf_afai->priority;
    }
    if (mdf_afai->urr_num) {
        memcpy(&est_afai->urr_id_arr, &mdf_afai->urr_id_arr,
            sizeof(est_afai->urr_id_arr[0]) * mdf_afai->urr_num);
    }
}

static void upc_change_mar(session_mar_create *est_mar,
    session_mar_update *mdf_mar)
{
    if (mdf_mar->member_flag.d.steer_func_present) {
        est_mar->steer_func = mdf_mar->steer_func;
    }
    if (mdf_mar->member_flag.d.steer_mod_present) {
        est_mar->steer_mod = mdf_mar->steer_mod;
    }
    if (mdf_mar->member_flag.d.update_afai_1_present) {
        upc_change_afai(&est_mar->afai_1, &mdf_mar->update_afai_1);
    }
    if (mdf_mar->member_flag.d.update_afai_2_present) {
        est_mar->member_flag.d.afai_2_present = 1;
        upc_change_afai(&est_mar->afai_2, &mdf_mar->update_afai_2);
    }
    if (mdf_mar->member_flag.d.afai_1_present) {
        memcpy(&est_mar->afai_1, &mdf_mar->afai_1,
            sizeof(session_access_forwarding_action));
    }
    if (mdf_mar->member_flag.d.afai_2_present) {
        est_mar->member_flag.d.afai_2_present = 1;
        memcpy(&est_mar->afai_2, &mdf_mar->afai_2,
            sizeof(session_access_forwarding_action));
    }
}

static int upc_change_data(session_content_create *est, session_content_modify *mdf)
{
    uint8_t cnt = 0;

    /* Rules delete */
    for (cnt = 0; cnt < mdf->remove_pdr_num; ++cnt) {
        uint8_t cnt_l2 = 0, org_num = est->pdr_num;
        uint16_t rm_id = mdf->remove_pdr_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->pdr_num; ++cnt_l2) {
            if (est->pdr_arr[cnt_l2].pdr_id == rm_id) {
                --est->pdr_num;

                if (0 > upc_collect_ueip(&est->pdr_arr[cnt_l2])) {
                    LOG(UPC, ERR, "Free ueip failed.");
                }
                if (0 > upc_collect_teid(&est->pdr_arr[cnt_l2].pdi_content)) {
                    LOG(UPC, ERR, "Free TEID failed.");
                }
                /* If you delete data is not the last, you need to rearrange it. */
                if (cnt_l2 < est->pdr_num) {
                    uint32_t cp_size = sizeof(session_pdr_create) *
                        (est->pdr_num - cnt_l2);
                    memmove(&est->pdr_arr[cnt_l2], &est->pdr_arr[cnt_l2 + 1],
                        cp_size);
                }
                break;
            }
        }

        if (cnt_l2 >= org_num) {
            LOG(UPC, ERR, "Remove pdr(%d) failed, no such rule.", rm_id);
        }
    }

    for (cnt = 0; cnt < mdf->remove_far_num; ++cnt) {
        uint8_t cnt_l2 = 0, org_num = est->far_num;
        uint32_t rm_id = mdf->remove_far_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->far_num; ++cnt_l2) {
            if (est->far_arr[cnt_l2].far_id == rm_id) {
                --est->far_num;
                /* If you delete data is not the last, you need to rearrange it. */
                if (cnt_l2 < est->far_num) {
                    uint32_t cp_size = sizeof(session_far_create) *
                        (est->far_num - cnt_l2);
                    memmove(&est->far_arr[cnt_l2], &est->far_arr[cnt_l2 + 1],
                        cp_size);
                }
                break;
            }
        }

        if (cnt_l2 >= org_num) {
            LOG(UPC, ERR, "Remove far(%u) failed, no such rule.", rm_id);
        }
    }

    for (cnt = 0; cnt < mdf->remove_urr_num; ++cnt) {
        uint8_t cnt_l2 = 0, org_num = est->urr_num;
        uint32_t rm_id = mdf->remove_urr_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->urr_num; ++cnt_l2) {
            if (est->urr_arr[cnt_l2].urr_id == rm_id) {
                --est->urr_num;
                /* If you delete data is not the last, you need to rearrange it. */
                if (cnt_l2 < est->urr_num) {
                    uint32_t cp_size = sizeof(session_usage_report_rule) *
                        (est->urr_num - cnt_l2);
                    memmove((char *)&est->urr_arr[cnt_l2], (char *)&est->urr_arr[cnt_l2 + 1],
                        cp_size);
                }
                break;
            }
        }

        if (cnt_l2 >= org_num) {
            LOG(UPC, ERR, "Remove urr(%u) failed, no such rule.", rm_id);
        }
    }

    for (cnt = 0; cnt < mdf->remove_qer_num; ++cnt) {
        uint8_t cnt_l2 = 0, org_num = est->qer_num;
        uint32_t rm_id = mdf->remove_qer_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->qer_num; ++cnt_l2) {
            if (est->qer_arr[cnt_l2].qer_id == rm_id) {
                --est->qer_num;
                /* If you delete data is not the last, you need to rearrange it. */
                if (cnt_l2 < est->qer_num) {
                    uint32_t cp_size = sizeof(session_qos_enforcement_rule) *
                        (est->qer_num - cnt_l2);
                    memmove(&est->qer_arr[cnt_l2], &est->qer_arr[cnt_l2 + 1],
                        cp_size);
                }
                break;
            }
        }

        if (cnt_l2 >= org_num) {
            LOG(UPC, ERR, "Remove qer(%u) failed, no such rule.", rm_id);
        }
    }

    if (mdf->member_flag.d.remove_bar_present) {
        if (est->bar.bar_id == mdf->remove_bar) {
            est->member_flag.d.bar_present = 0;
        } else {
            LOG(UPC, ERR, "Remove bar(%d) failed, no such rule.", mdf->remove_bar);
        }
    }

    for (cnt = 0; cnt < mdf->remove_tc_endpoint_num; ++cnt) {
        uint8_t cnt_l2 = 0, org_num = est->tc_endpoint_num;
        uint8_t rm_id = mdf->remove_tc_endpoint_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->tc_endpoint_num; ++cnt_l2) {
            if (est->tc_endpoint_arr[cnt_l2].endpoint_id == rm_id) {
                --est->tc_endpoint_num;
                /* If you delete data is not the last, you need to rearrange it. */
                if (cnt_l2 < est->tc_endpoint_num) {
                    uint32_t cp_size = sizeof(session_tc_endpoint) *
                        (est->tc_endpoint_num - cnt_l2);
                    memmove(&est->tc_endpoint_arr[cnt_l2],
                        &est->tc_endpoint_arr[cnt_l2 + 1], cp_size);
                }
                break;
            }
        }

        if (cnt_l2 >= org_num) {
            LOG(UPC, ERR, "Remove tc_endpoint(%d) failed, no such rule.", rm_id);
        }
    }

    for (cnt = 0; cnt < mdf->remove_mar_num; ++cnt) {
        uint8_t cnt_l2 = 0, org_num = est->mar_num;
        uint16_t rm_id = mdf->remove_mar_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->mar_num; ++cnt_l2) {
            if (est->mar_arr[cnt_l2].mar_id == rm_id) {
                --est->mar_num;
                /* If you delete data is not the last, you need to rearrange it. */
                if (cnt_l2 < est->mar_num) {
                    uint32_t cp_size = sizeof(session_mar_create) *
                        (est->mar_num - cnt_l2);
                    memmove(&est->mar_arr[cnt_l2], &est->mar_arr[cnt_l2 + 1],
                        cp_size);
                }
                break;
            }
        }

        if (cnt_l2 >= org_num) {
            LOG(UPC, ERR, "Remove mar(%d) failed, no such rule.", rm_id);
        }
    }

    /* Rules update */
    for (cnt = 0; cnt < mdf->update_pdr_num; ++cnt) {
        uint8_t cnt_l2 = 0;
        session_pdr_create *est_pdr = NULL;
        session_pdr_update *mdf_pdr = &mdf->update_pdr_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->pdr_num; ++cnt_l2) {
            if (est->pdr_arr[cnt_l2].pdr_id == mdf_pdr->pdr_id) {
                break;
            }
        }
        est_pdr = &est->pdr_arr[cnt_l2];

        upc_change_pdr(est_pdr, mdf_pdr);
    }

    for (cnt = 0; cnt < mdf->update_far_num; ++cnt) {
        uint8_t cnt_l2 = 0;
        session_far_create *est_far = NULL;
        session_far_update *mdf_far = &mdf->update_far_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->far_num; ++cnt_l2) {
            if (est->far_arr[cnt_l2].far_id == mdf_far->far_id) {
                break;
            }
        }
        est_far = &est->far_arr[cnt_l2];

        upc_change_far(est_far, mdf_far);
    }

    for (cnt = 0; cnt < mdf->update_urr_num; ++cnt) {
        uint8_t cnt_l2 = 0;
        session_usage_report_rule *est_urr = NULL;
        session_usage_report_rule *mdf_urr = &mdf->update_urr_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->urr_num; ++cnt_l2) {
            if (est->urr_arr[cnt_l2].urr_id == mdf_urr->urr_id) {
                break;
            }
        }
        est_urr = &est->urr_arr[cnt_l2];

        upc_change_urr(est_urr, mdf_urr);
    }

    for (cnt = 0; cnt < mdf->update_qer_num; ++cnt) {
        uint8_t cnt_l2 = 0;
        session_qos_enforcement_rule *est_qer = NULL;
        session_qos_enforcement_rule *mdf_qer = &mdf->update_qer_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->qer_num; ++cnt_l2) {
            if (est->qer_arr[cnt_l2].qer_id == mdf_qer->qer_id) {
                break;
            }
        }
        est_qer = &est->qer_arr[cnt_l2];

        upc_change_qer(est_qer, mdf_qer);
    }

    if (mdf->member_flag.d.update_bar_present) {
        session_buffer_action_rule *est_bar = NULL;
        session_buffer_action_rule *mdf_bar = &mdf->update_bar;

        if (est->bar.bar_id == mdf_bar->bar_id) {
            est_bar = &est->bar;

            upc_change_bar(est_bar, mdf_bar);
        }
    }

    for (cnt = 0; cnt < mdf->update_tc_endpoint_num; ++cnt) {
        uint8_t cnt_l2 = 0;
        session_tc_endpoint *est_te = NULL;
        session_tc_endpoint *mdf_te = &mdf->update_tc_endpoint_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->tc_endpoint_num; ++cnt_l2) {
            if (est->tc_endpoint_arr[cnt_l2].endpoint_id ==
                mdf_te->endpoint_id) {
                break;
            }
        }
        est_te = &est->tc_endpoint_arr[cnt_l2];

        upc_change_te(est_te, mdf_te);
    }

    for (cnt = 0; cnt < mdf->update_mar_num; ++cnt) {
        uint8_t cnt_l2 = 0;
        session_mar_create *est_mar = NULL;
        session_mar_update *mdf_mar = &mdf->update_mar_arr[cnt];

        for (cnt_l2 = 0; cnt_l2 < est->mar_num; ++cnt_l2) {
            if (est->mar_arr[cnt_l2].mar_id == mdf_mar->mar_id) {
                break;
            }
        }
        est_mar = &est->mar_arr[cnt_l2];

        upc_change_mar(est_mar, mdf_mar);
    }

    /* Rules create */
    for (cnt = 0; cnt < mdf->create_pdr_num; ++cnt) {
        if ((mdf->create_pdr_num + est->pdr_num) > MAX_PDR_NUM) {
            LOG(UPC, ERR, "PDR quantity exceeds the maximum.\n");
            return -1;
        }
        ros_memcpy(&est->pdr_arr[est->pdr_num], &mdf->create_pdr_arr[cnt],
            sizeof(session_pdr_create));
        ++est->pdr_num;
    }

    for (cnt = 0; cnt < mdf->create_far_num; ++cnt) {
        if ((mdf->create_far_num + est->far_num) > MAX_FAR_NUM) {
            LOG(UPC, ERR, "FAR quantity exceeds the maximum.\n");
            return -1;
        }
        ros_memcpy(&est->far_arr[est->far_num], &mdf->create_far_arr[cnt],
            sizeof(session_far_create));
        ++est->far_num;
    }

    for (cnt = 0; cnt < mdf->create_urr_num; ++cnt) {
        if ((mdf->create_urr_num + est->urr_num) > MAX_URR_NUM) {
            LOG(UPC, ERR, "URR quantity exceeds the maximum.\n");
            return -1;
        }
        ros_memcpy(&est->urr_arr[est->urr_num], &mdf->create_urr_arr[cnt],
            sizeof(session_usage_report_rule));
        ++est->urr_num;
    }

    for (cnt = 0; cnt < mdf->create_qer_num; ++cnt) {
        if ((mdf->create_qer_num + est->qer_num) > MAX_QER_NUM) {
            LOG(UPC, ERR, "QER quantity exceeds the maximum.\n");
            return -1;
        }
        ros_memcpy(&est->qer_arr[est->qer_num], &mdf->create_qer_arr[cnt],
            sizeof(session_qos_enforcement_rule));
        ++est->qer_num;
    }

    if (mdf->member_flag.d.create_bar_present) {
        if (est->member_flag.d.bar_present) {
            LOG(UPC, ERR, "BAR quantity exceeds the maximum.\n");
            return -1;
        }
        ros_memcpy(&est->bar, &mdf->create_bar,
            sizeof(session_buffer_action_rule));
        est->member_flag.d.bar_present = 1;
    }

    if ((mdf->create_tc_endpoint_num + est->tc_endpoint_num) > MAX_TC_ENDPOINT_NUM) {
        LOG(UPC, ERR, "Traffic Endpoint quantity exceeds the maximum.\n");
        return -1;
    }
    for (cnt = 0; cnt < mdf->create_tc_endpoint_num; ++cnt) {
        ros_memcpy(&est->tc_endpoint_arr[est->tc_endpoint_num],
            &mdf->create_tc_endpoint_arr[cnt], sizeof(session_tc_endpoint));
        ++est->tc_endpoint_num;
    }

    if ((mdf->create_mar_num + est->mar_num) > MAX_MAR_NUM) {
        LOG(UPC, ERR, "MAR quantity exceeds the maximum.\n");
        return -1;
    }
    for (cnt = 0; cnt < mdf->create_mar_num; ++cnt) {
        ros_memcpy(&est->mar_arr[est->mar_num], &mdf->create_mar_arr[cnt],
            sizeof(session_mar_create));
        ++est->mar_num;
    }

    /* Other update */
    if (mdf->member_flag.d.inactivity_timer_present) {
        est->member_flag.d.inactivity_timer_present = 1;
        est->inactivity_timer = mdf->inactivity_timer;
    }

    if (mdf->member_flag.d.trace_info_present) {
        est->member_flag.d.trace_info_present = 1;
        memcpy(&est->trace_info, &mdf->trace_info, sizeof(session_trace_info));
    }

    if (mdf->member_flag.d.update_cp_seid_present) {
        est->cp_f_seid.seid = mdf->update_cp_fseid.seid;
    }

    return 0;
}

static int upc_assign_teid(uint32_t node_index,
    session_packet_detection_info *pdi, struct upc_choose_id_mgmt *choose_mgmt)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.FTUP && pdi->member_flag.d.local_fteid_present) {
        session_ip_addr *ip_addr;

        switch (pdi->si) {
            case EN_COMM_SRC_IF_ACCESS:
                ip_addr = upc_get_n3_local_ip();
                break;

            case EN_COMM_SRC_IF_CP:
                ip_addr = upc_get_local_ip();
                break;

            default:
                ip_addr = upc_get_n3_local_ip();
                break;
        }

        if (pdi->local_fteid.f_teid_flag.d.chid) {
            LOG(UPC, DEBUG, "Choose ID %d, choose array %d", pdi->local_fteid.choose_id,
                choose_mgmt->choose_id[pdi->local_fteid.choose_id]);
            if (choose_mgmt->choose_id[pdi->local_fteid.choose_id]) {
                pdi->local_fteid.teid = choose_mgmt->teid[pdi->local_fteid.choose_id];

            } else {
                pdi->local_fteid.teid = upc_teid_alloc(node_index);
                if ((uint32_t)-1 == pdi->local_fteid.teid) {
                    LOG(UPC, ERR, "alloc teid failed.");
                    return -1;
                }

                /* set choose mgmt */
                choose_mgmt->choose_id[pdi->local_fteid.choose_id] = 1;
                choose_mgmt->teid[pdi->local_fteid.choose_id] = pdi->local_fteid.teid;
            }
        } else {
            pdi->local_fteid.teid = upc_teid_alloc(node_index);
            if ((uint32_t)-1 == pdi->local_fteid.teid) {
                LOG(UPC, ERR, "alloc teid failed.");
                return -1;
            }
        }

        if (pdi->local_fteid.f_teid_flag.d.v4) {
            pdi->local_fteid.ipv4_addr = ip_addr->ipv4;
        }
        if (pdi->local_fteid.f_teid_flag.d.v6) {
            *(uint64_t *)pdi->local_fteid.ipv6_addr =
                *(uint64_t *)ip_addr->ipv6;
            *(uint64_t *)(pdi->local_fteid.ipv6_addr + 8) =
                *(uint64_t *)(ip_addr->ipv6 + 8);
        }

        if (0 > upc_teid_used_add(pdi->local_fteid.teid)) {
            LOG(UPC, ERR, "teid used count add failed, teid: %u.",
                pdi->local_fteid.teid);
            return -1;
        }
    }

    return 0;
}

static int upc_collect_teid(session_packet_detection_info *pdi)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.FTUP && pdi->member_flag.d.local_fteid_present) {

        if (0 > upc_teid_used_sub(pdi->local_fteid.teid)) {
            LOG(UPC, ERR, "teid collect failed, local teid: %u.",
                pdi->local_fteid.teid);
        }
    }

    return 0;
}

static int upc_alloc_teid_from_create(session_content_create *sess, int trace_flag)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.FTUP) {
        uint8_t cnt = 0;
        struct upc_choose_id_mgmt *choose_mgmt = upc_teid_choose_mgmt_get((uint32_t)sess->local_seid);

        LOG_TRACE(UPC, RUNNING, trace_flag, "Ready alloc TEID.");

        for (cnt = 0; cnt < sess->pdr_num; ++cnt) {

            if (0 > upc_assign_teid(sess->node_index,
                &sess->pdr_arr[cnt].pdi_content, choose_mgmt)) {
                LOG(UPC, ERR, "Failure in TEID alloc.");
                return -1;
            }
        }
    }

    return 0;
}

static int upc_alloc_teid_from_modify(session_content_modify *sess)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.FTUP) {
        uint8_t cnt = 0;
        struct upc_choose_id_mgmt *choose_mgmt = upc_teid_choose_mgmt_get((uint32_t)sess->local_seid);

        LOG(UPC, RUNNING, "Ready alloc TEID.");
        for (cnt = 0; cnt < sess->create_pdr_num; ++cnt) {
            if (0 > upc_assign_teid(sess->node_index,
                &sess->create_pdr_arr[cnt].pdi_content, choose_mgmt)) {
                LOG(UPC, ERR, "Failure in TEID alloc.");
                return -1;
            }
        }

        for (cnt = 0; cnt < sess->update_pdr_num; ++cnt) {
            if (0 > upc_assign_teid(sess->node_index,
                &sess->update_pdr_arr[cnt].pdi_content, choose_mgmt)) {
                LOG(UPC, ERR, "Failure in TEID alloc.");
                return -1;
            }
        }
    }

    return 0;
}

static int upc_free_teid_from_create(session_content_create *sess, int trace_flag)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.FTUP) {
        uint8_t cnt = 0;

        LOG_TRACE(UPC, RUNNING, trace_flag, "Ready collection TEID.");

        for (cnt = 0; cnt < sess->pdr_num; ++cnt) {

            if (0 > upc_collect_teid(&sess->pdr_arr[cnt].pdi_content)) {
                LOG(UPC, ERR, "Failure in TEID collection.");
            }
        }
    }

    return 0;
}

static int upc_free_teid_from_modify(session_content_modify *sess)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.FTUP) {
        uint8_t cnt = 0;

        LOG(UPC, RUNNING, "Ready collection TEID.");
        for (cnt = 0; cnt < sess->create_pdr_num; ++cnt) {
            if (0 > upc_collect_teid(&sess->create_pdr_arr[cnt].pdi_content)) {
                LOG(UPC, ERR, "Failure in TEID collection.");
            }
        }

        for (cnt = 0; cnt < sess->update_pdr_num; ++cnt) {
            if (0 > upc_collect_teid(&sess->update_pdr_arr[cnt].pdi_content)) {
                LOG(UPC, ERR, "Failure in TEID collection.");
            }
        }
    }

    return 0;
}

static int upc_assign_ueip(session_pdr_create *pdr)
{
    session_up_features uf = {.value = upc_get_up_features()};
    uint8_t cnt = 0;

    /* The UEIP correctness of the identification and up featrues
    *  has been confirmed when parsing the packet.
    */
    if (uf.d.UEIP && pdr->pdi_content.ue_ipaddr_num) {
        if (pdr->ueip_addr_pool_identity_num &&
            pdr->ueip_addr_pool_identity[0].pool_id_len) {
            uint32_t pool_index = 0;

            if (0 == ueip_pool_index_get(&pool_index,
                pdr->ueip_addr_pool_identity[0].pool_identity)) {
                for (cnt = 0; cnt < pdr->pdi_content.ue_ipaddr_num; ++cnt) {
                    if (0 > ueip_addr_alloc(pool_index, &pdr->pdi_content.ue_ipaddr[cnt])) {
                        LOG(UPC, ERR, "Alloc UEIP address failed.");
                        return -1;
                    }
                }
            } else {
                LOG(UPC, ERR,
                    "Search UEIP pool failed, no such pool name: %s.",
                    pdr->ueip_addr_pool_identity[0].pool_identity);
                return -1;
            }
        } else {
            LOG(UPC, ERR,
                "Lack of network instances when assigning ueip.");
            return -1;
        }
    }

    return 0;
}

int upc_ueip_add_target(session_pdr_create *pdr)
{
    uint32_t sec_key, res_no;
    session_ue_ip *ue_ip = pdr->pdi_content.ue_ipaddr;
    struct ueip_addr_pool *pool = ueip_get_pool_by_name(pdr->ueip_addr_pool_identity[0].pool_identity);
    if (NULL == pool) {
        LOG(UPC, ERR, "Get ueip pool by pool name failed, pool name: %s.",
            pdr->ueip_addr_pool_identity[0].pool_identity);
        return -1;
    }

    if (ue_ip->ueip_flag.d.v4) {
        sec_key = ue_ip->ipv4_addr & UEIP_SECTION_KEY_MASK;
        res_no = ue_ip->ipv4_addr & UEIP_SECTION_RES_MASK;

        if (0 > ueip_res_alloc_target_ip(sec_key, res_no, pool)) {
            LOG(UPC, ERR, "Alloc target ueip failed.");
            return -1;
        }
        ros_atomic32_inc(&pool->use_num);
    } else if (ue_ip->ueip_flag.d.v6) {
        uint32_t suffix_u32 = ntohl(*(uint32_t *)(ue_ip->ipv6_addr + 12));

        sec_key = suffix_u32 & UEIP_SECTION_KEY_MASK;
        res_no = suffix_u32 & UEIP_SECTION_RES_MASK;

        if (0 > ueip_res_alloc_target_ip(sec_key, res_no, pool)) {
            LOG(UPC, ERR, "Alloc target ueip failed.");
            return -1;
        }
        ros_atomic32_inc(&pool->use_num);
    }

    return 0;
}

static int upc_collect_ueip(session_pdr_create *pdr)
{
    session_up_features uf = {.value = upc_get_up_features()};
    uint8_t cnt = 0;

    /* The UEIP correctness of the identification and up featrues
    *  has been confirmed when parsing the packet.
    */
    if (uf.d.UEIP && pdr->pdi_content.ue_ipaddr_num) {
        if (pdr->ueip_addr_pool_identity_num &&
            pdr->ueip_addr_pool_identity[0].pool_id_len) {
            uint32_t pool_index = 0;

            if (0 == ueip_pool_index_get(&pool_index,
                pdr->ueip_addr_pool_identity[0].pool_identity)) {
                for (cnt = 0; cnt < pdr->pdi_content.ue_ipaddr_num; ++cnt) {
                    if (0 > ueip_addr_free(pool_index, &pdr->pdi_content.ue_ipaddr[cnt])) {
                        LOG(UPC, ERR, "Free UEIP address failed.");
                        return -1;
                    }
                }
            } else {
                LOG(UPC, ERR, "Search UEIP pool failed, no such pool name: %s.",
                    pdr->ueip_addr_pool_identity[0].pool_identity);
                return -1;
            }
        } else {
            LOG(UPC, ERR, "Lack of network instances when collecting ueip.");
            return -1;
        }
    }

    return 0;
}

int upc_ueip_del_target(session_pdr_create *pdr)
{
    uint32_t sec_key, res_no;
    session_ue_ip *ue_ip = pdr->pdi_content.ue_ipaddr;
    struct ueip_addr_pool *pool = ueip_get_pool_by_name(pdr->ueip_addr_pool_identity[0].pool_identity);
    if (NULL == pool) {
        LOG(UPC, ERR, "Get ueip pool by pool name failed, pool name: %s.",
            pdr->ueip_addr_pool_identity[0].pool_identity);
        return -1;
    }

    if (ue_ip->ueip_flag.d.v4) {
        sec_key = ue_ip->ipv4_addr & UEIP_SECTION_KEY_MASK;
        res_no = ue_ip->ipv4_addr & UEIP_SECTION_RES_MASK;

        Res_Free(pool->pool_id, sec_key, res_no);
        ros_atomic32_dec(&pool->use_num);
    } else if (ue_ip->ueip_flag.d.v6) {
        uint32_t suffix_u32 = ntohl(*(uint32_t *)(ue_ip->ipv6_addr + 12));

        sec_key = suffix_u32 & UEIP_SECTION_KEY_MASK;
        res_no = suffix_u32 & UEIP_SECTION_RES_MASK;

        Res_Free(pool->pool_id, sec_key, res_no);
        ros_atomic32_dec(&pool->use_num);
    }

    return 0;
}

static int upc_alloc_ueip_from_create(session_content_create *sess, int trace_flag)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.UEIP) {
        uint8_t cnt = 0;

        LOG_TRACE(UPC, RUNNING, trace_flag, "Ready alloc UEIP address.");

        for (cnt = 0; cnt < sess->pdr_num; ++cnt) {
            if (0 > upc_assign_ueip(&sess->pdr_arr[cnt])) {
                LOG(UPC, ERR, "Failure in UEIP alloc.");
                return -1;
            }
        }
    }

    return 0;
}

static int upc_alloc_ueip_from_modify(session_content_modify *sess)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.UEIP) {
        uint8_t cnt = 0;

        LOG(UPC, RUNNING, "Ready alloc UEIP address.");
        for (cnt = 0; cnt < sess->create_pdr_num; ++cnt) {
            if (0 > upc_assign_ueip(&sess->create_pdr_arr[cnt])) {
                LOG(UPC, ERR, "Failure in UEIP alloc.");
                return -1;
            }
        }
    }

    return 0;
}

static int upc_free_ueip_from_create(session_content_create *sess, int trace_flag)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.UEIP) {
        uint8_t cnt = 0;

        LOG_TRACE(UPC, RUNNING, trace_flag, "Ready collection UEIP address.");

        for (cnt = 0; cnt < sess->pdr_num; ++cnt) {
            if (0 > upc_collect_ueip(&sess->pdr_arr[cnt])) {
                LOG(UPC, ERR, "Failure in UEIP collection.");
            }
        }
    }

    return 0;
}

static int upc_free_ueip_from_modify(session_content_modify *sess)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (uf.d.UEIP) {
        uint8_t cnt = 0;

        LOG(UPC, RUNNING, "Ready collection UEIP address.");
        for (cnt = 0; cnt < sess->create_pdr_num; ++cnt) {
            if (0 > upc_collect_ueip(&sess->create_pdr_arr[cnt])) {
                LOG(UPC, ERR, "Failure in UEIP collection.");
            }
        }
    }

    return 0;
}

int upc_free_resources_from_deletion(session_content_create *sess)
{
    session_up_features up_feature = {.value = upc_get_up_features()};

    if (up_feature.d.FTUP || up_feature.d.UEIP) {
        uint8_t cnt = 0;

        LOG(UPC, RUNNING, "Ready collection resources.");
        if (up_feature.d.FTUP) {
            for (cnt = 0; cnt < sess->pdr_num; ++cnt) {
                if (0 > upc_collect_teid(&sess->pdr_arr[cnt].pdi_content)) {
                    LOG(UPC, ERR, "Failure in UEIP collection.");
                }
            }
        }

        if (up_feature.d.UEIP) {
            for (cnt = 0; cnt < sess->pdr_num; ++cnt) {
                if (0 > upc_collect_ueip(&sess->pdr_arr[cnt])) {
                    LOG(UPC, ERR, "Failure in UEIP collection.");
                }
            }
        }
    }

    return 0;
}

static int upc_update_resource_from_create(session_content_create *sess)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (NULL == sess) {
        LOG(UPC, ERR, "Error parameters, sess(%p).", sess);
        return -1;
    }

    if (uf.d.FTUP) {
        uint8_t cnt = 0;
        session_packet_detection_info *pdi = NULL;

        LOG(UPC, RUNNING, "Ready filling teid IE.");
        for (cnt = 0; cnt < sess->pdr_num; ++cnt) {
            pdi = &sess->pdr_arr[cnt].pdi_content;
            if (pdi->member_flag.d.local_fteid_present) {
                if (0 > upc_teid_add_target(pdi->local_fteid.teid)) {
                    LOG(UPC, ERR, "Alloc target teid.");
                    return -1;
                }
            }
        }
    }

    if (uf.d.UEIP) {
        uint8_t cnt = 0;
        session_pdr_create *pdr;
        session_packet_detection_info *pdi = NULL;

        LOG(UPC, RUNNING, "Ready filling ueip IE.");

        for (cnt = 0; cnt < sess->pdr_num; ++cnt) {
            pdr = &sess->pdr_arr[cnt];
            pdi = &sess->pdr_arr[cnt].pdi_content;
            if (pdi->ue_ipaddr_num && pdr->ueip_addr_pool_identity_num) {
                if (0 > upc_ueip_add_target(pdr)) {
                    LOG(UPC, ERR, "Add target UEIP failed.");
                    return -1;
                }
            }
        }
    }

    return 0;
}

static int upc_update_resource_from_modify(session_content_modify *sess)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (NULL == sess) {
        LOG(UPC, ERR, "Error parameters, sess(%p).", sess);
        return -1;
    }

    if (uf.d.FTUP || uf.d.UEIP) {
        upc_seid_entry *seid_entry;
        session_content_create *org_sess;

        seid_entry = upc_seid_entry_search(sess->local_seid);
        if (NULL == seid_entry) {
            LOG(UPC, ERR, "Get seid entry %u failed.", (uint32_t)sess->local_seid);
            return -1;
        }
        org_sess = &seid_entry->session_config;

        if (uf.d.FTUP) {
            uint8_t cnt = 0, cnt_l2 = 0;
            session_packet_detection_info *pdi = NULL;

            LOG(UPC, RUNNING, "Ready filling teid IE.");
            for (cnt = 0; cnt < sess->create_pdr_num; ++cnt) {
                pdi = &sess->create_pdr_arr[cnt].pdi_content;
                if (pdi->member_flag.d.local_fteid_present) {
                    if (0 > upc_teid_add_target(pdi->local_fteid.teid)) {
                        LOG(UPC, ERR, "Alloc target teid.");
                        return -1;
                    }
                }
            }

            for (cnt = 0; cnt < sess->remove_pdr_num; ++cnt) {
                for (cnt_l2 = 0; cnt_l2 < org_sess->pdr_num; ++cnt_l2) {
                    if (org_sess->pdr_arr[cnt_l2].pdr_id == sess->remove_pdr_arr[cnt]) {
                        break;
                    }
                }
                if (cnt_l2 == org_sess->pdr_num) {
                    LOG(UPC, ERR, "Remove pdr id Non-existent.");
                    continue;
                }

                pdi = &org_sess->pdr_arr[cnt_l2].pdi_content;
                if (pdi->member_flag.d.local_fteid_present) {
                    if (0 > upc_teid_used_sub(pdi->local_fteid.teid)) {
                        LOG(UPC, ERR, "teid collect failed, teid: %u.",
                            pdi->local_fteid.teid);
                    }
                }
            }
        }

        if (uf.d.UEIP) {
            uint8_t cnt = 0, cnt_l2 = 0;
            session_pdr_create *pdr;
            session_packet_detection_info *pdi = NULL;

            LOG(UPC, RUNNING, "Ready filling ueip IE.");

            for (cnt = 0; cnt < sess->create_pdr_num; ++cnt) {
                pdr = &sess->create_pdr_arr[cnt];
                pdi = &sess->create_pdr_arr[cnt].pdi_content;
                if (pdi->ue_ipaddr_num && pdr->ueip_addr_pool_identity_num) {
                    if (0 > upc_ueip_add_target(pdr)) {
                        LOG(UPC, ERR, "Add target UEIP failed.");
                        return -1;
                    }
                }
            }

            for (cnt = 0; cnt < sess->remove_pdr_num; ++cnt) {
                for (cnt_l2 = 0; cnt_l2 < org_sess->pdr_num; ++cnt_l2) {
                    if (org_sess->pdr_arr[cnt_l2].pdr_id == sess->remove_pdr_arr[cnt]) {
                        break;
                    }
                }
                if (cnt_l2 == org_sess->pdr_num) {
                    LOG(UPC, ERR, "Remove pdr id Non-existent.");
                    continue;
                }

                pdr = &org_sess->pdr_arr[cnt_l2];
                pdi = &org_sess->pdr_arr[cnt_l2].pdi_content;
                if (pdi->ue_ipaddr_num && pdr->ueip_addr_pool_identity_num) {
                    if (0 > upc_ueip_del_target(pdr)) {
                        LOG(UPC, ERR, "Add target UEIP failed.");
                        return -1;
                    }
                }
            }
        }
    }

    return 0;
}

/* 为会话建立响应报文填充created PDR IE */
void upc_est_fill_created_pdr(session_content_create *sess, session_emd_response *sess_rep)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (NULL == sess || NULL == sess_rep) {
        LOG(UPC, ERR, "Abnormal parameters, sess(%p), sess_rep(%p).",
            sess, sess_rep);
        return;
    }

    if (uf.d.UEIP || uf.d.FTUP) {
        uint8_t cnt, cnt_l2;
        session_pdr_create *pdr = NULL;
        session_created_pdr *crd_pdr = NULL;
        uint8_t fill_flag = 0;

        sess_rep->created_pdr_num = 0;

        LOG(UPC, RUNNING, "Ready fill created PDR.");

        for (cnt = 0; cnt < sess->pdr_num; ++cnt) {
            fill_flag = 0;
            pdr = &sess->pdr_arr[cnt];
            crd_pdr = &sess_rep->created_pdr[sess_rep->created_pdr_num];

            if (uf.d.UEIP && pdr->pdi_content.ue_ipaddr_num) {
                crd_pdr->pdr_id = pdr->pdr_id;
                ros_memcpy(crd_pdr->ueip_addr, pdr->pdi_content.ue_ipaddr,
                    sizeof(session_ue_ip) * pdr->pdi_content.ue_ipaddr_num);
                for (cnt_l2 = 0; cnt_l2 < pdr->pdi_content.ue_ipaddr_num; ++cnt_l2) {
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.v4 = crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.chv4;
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.v6 = crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.chv6;
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.chv4 = 0;
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.chv6 = 0;
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.s_d = 1;
                }
                crd_pdr->ueip_addr_num = pdr->pdi_content.ue_ipaddr_num;
                fill_flag = 1;
            }

            if (uf.d.FTUP && pdr->pdi_content.member_flag.d.local_fteid_present) {
                crd_pdr->local_fteid_present = 1;
                crd_pdr->pdr_id = pdr->pdr_id;
                ros_memcpy(&crd_pdr->local_fteid, &pdr->pdi_content.local_fteid, sizeof(session_f_teid));
                crd_pdr->local_fteid.f_teid_flag.d.ch = 0;
                crd_pdr->local_fteid.f_teid_flag.d.chid = 0;
                fill_flag = 1;
            }

            if (fill_flag)
                ++sess_rep->created_pdr_num;
        }
    }
}

/* 为会话修改响应报文填充created PDR IE */
void upc_mdf_fill_created_pdr(session_content_modify *sess, session_emd_response *sess_rep)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (NULL == sess || NULL == sess_rep) {
        LOG(UPC, ERR, "Abnormal parameters, sess(%p), sess_rep(%p).",
            sess, sess_rep);
        return;
    }

    if (uf.d.UEIP || uf.d.FTUP) {
        uint8_t cnt, cnt_l2;
        session_pdr_create *pdr = NULL;
        session_created_pdr *crd_pdr = NULL;
        uint8_t fill_flag = 0;

        sess_rep->created_pdr_num = 0;

        LOG(UPC, RUNNING, "Ready fill created PDR.");

        for (cnt = 0; cnt < sess->create_pdr_num; ++cnt) {
            fill_flag = 0;
            pdr = &sess->create_pdr_arr[cnt];
            crd_pdr = &sess_rep->created_pdr[sess_rep->created_pdr_num];

            if (uf.d.UEIP && pdr->pdi_content.ue_ipaddr_num) {
                crd_pdr->pdr_id = pdr->pdr_id;
                ros_memcpy(&crd_pdr->ueip_addr, &pdr->pdi_content.ue_ipaddr,
                    sizeof(session_ue_ip) * pdr->pdi_content.ue_ipaddr_num);
                for (cnt_l2 = 0; cnt_l2 < pdr->pdi_content.ue_ipaddr_num; ++cnt_l2) {
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.v4 = crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.chv4;
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.v6 = crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.chv6;
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.chv4 = 0;
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.chv6 = 0;
                    crd_pdr->ueip_addr[cnt_l2].ueip_flag.d.s_d = 1;
                }
                crd_pdr->ueip_addr_num = pdr->pdi_content.ue_ipaddr_num;
                fill_flag = 1;
            }

            if (uf.d.FTUP && pdr->pdi_content.member_flag.d.local_fteid_present) {
                crd_pdr->local_fteid_present = 1;
                crd_pdr->pdr_id = pdr->pdr_id;
                ros_memcpy(&crd_pdr->local_fteid, &pdr->pdi_content.local_fteid, sizeof(session_f_teid));
                crd_pdr->local_fteid.f_teid_flag.d.ch = 0;
                crd_pdr->local_fteid.f_teid_flag.d.chid = 0;
                fill_flag = 1;
            }

            if (fill_flag)
                ++sess_rep->created_pdr_num;
        }
    }
}

void upc_est_fill_created_traffic_endpoint(session_content_create *sess, session_emd_response *sess_rep)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (NULL == sess || NULL == sess_rep) {
        LOG(UPC, ERR, "Abnormal parameters, sess(%p), sess_rep(%p).",
            sess, sess_rep);
        return;
    }

    if (uf.d.UEIP || uf.d.FTUP) {
        uint8_t cnt, cnt_l2;
        session_tc_endpoint *tc = NULL;
        session_created_tc_endpoint *crd_tc = NULL;
        uint8_t fill_flag = 0;

        sess_rep->created_tc_endpoint_num = 0;

        LOG(UPC, RUNNING, "Ready fill created Traffic Endpoint.");

        for (cnt = 0; cnt < sess->tc_endpoint_num; ++cnt) {
            fill_flag = 0;
            tc = &sess->tc_endpoint_arr[cnt];
            crd_tc = &sess_rep->created_tc_endpoint[sess_rep->created_tc_endpoint_num];

            if (uf.d.UEIP && tc->ue_ipaddr_num) {
                crd_tc->tc_endpoint_id = tc->endpoint_id;
                ros_memcpy(crd_tc->ueip_addr, tc->ue_ipaddr,
                    sizeof(session_ue_ip) * tc->ue_ipaddr_num);
                for (cnt_l2 = 0; cnt_l2 < tc->ue_ipaddr_num; ++cnt_l2) {
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.v4 = crd_tc->ueip_addr[cnt_l2].ueip_flag.d.chv4;
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.v6 = crd_tc->ueip_addr[cnt_l2].ueip_flag.d.chv6;
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.chv4 = 0;
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.chv6 = 0;
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.s_d = 1;
                }
                crd_tc->ueip_addr_num = tc->ue_ipaddr_num;
                fill_flag = 1;
            }

            if (uf.d.FTUP && tc->member_flag.d.local_fteid_present) {
                crd_tc->local_fteid_present = 1;
                crd_tc->tc_endpoint_id = tc->endpoint_id;
                ros_memcpy(&crd_tc->local_fteid, &tc->local_fteid, sizeof(session_f_teid));
                crd_tc->local_fteid.f_teid_flag.d.ch = 0;
                crd_tc->local_fteid.f_teid_flag.d.chid = 0;
                fill_flag = 1;
            }

            if (fill_flag)
                ++sess_rep->created_tc_endpoint_num;
        }
    }
}

/* 为会话修改响应报文填充created Traffic Endpoint IE */
void upc_mdf_fill_created_traffic_endpoint(session_content_modify *sess, session_emd_response *sess_rep)
{
    session_up_features uf = {.value = upc_get_up_features()};

    if (NULL == sess || NULL == sess_rep) {
        LOG(UPC, ERR, "Abnormal parameters, sess(%p), sess_rep(%p).",
            sess, sess_rep);
        return;
    }

    if (uf.d.UEIP || uf.d.FTUP) {
        uint8_t cnt, cnt_l2;
        session_tc_endpoint *tc = NULL;
        session_created_tc_endpoint *crd_tc = NULL;
        uint8_t fill_flag = 0;

        sess_rep->created_tc_endpoint_num = 0;

        LOG(UPC, RUNNING, "Ready fill created Traffic Endpoint.");

        for (cnt = 0; cnt < sess->create_tc_endpoint_num; ++cnt) {
            fill_flag = 0;
            tc = &sess->create_tc_endpoint_arr[cnt];
            crd_tc = &sess_rep->created_tc_endpoint[sess_rep->created_tc_endpoint_num];

            if (uf.d.UEIP && tc->ue_ipaddr_num) {
                crd_tc->tc_endpoint_id = tc->endpoint_id;
                ros_memcpy(&crd_tc->ueip_addr, &tc->ue_ipaddr,
                    sizeof(session_ue_ip) * tc->ue_ipaddr_num);
                for (cnt_l2 = 0; cnt_l2 < tc->ue_ipaddr_num; ++cnt_l2) {
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.v4 = crd_tc->ueip_addr[cnt_l2].ueip_flag.d.chv4;
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.v6 = crd_tc->ueip_addr[cnt_l2].ueip_flag.d.chv6;
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.chv4 = 0;
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.chv6 = 0;
                    crd_tc->ueip_addr[cnt_l2].ueip_flag.d.s_d = 1;
                }
                crd_tc->ueip_addr_num = tc->ue_ipaddr_num;
                fill_flag = 1;
            }

            if (uf.d.FTUP && tc->member_flag.d.local_fteid_present) {
                crd_tc->local_fteid_present = 1;
                crd_tc->tc_endpoint_id = tc->endpoint_id;
                ros_memcpy(&crd_tc->local_fteid, &tc->local_fteid, sizeof(session_f_teid));
                crd_tc->local_fteid.f_teid_flag.d.ch = 0;
                crd_tc->local_fteid.f_teid_flag.d.chid = 0;
                fill_flag = 1;
            }

            if (fill_flag)
                ++sess_rep->created_tc_endpoint_num;
        }
    }
}

// 将一个bcd串转换成一个字符串，
// 返回得到的字符串的实际长度
_U32 bcd_to_string(const uint8_t *bcd, uint8_t *str, uint32_t ulBcdLen, uint32_t ulStrBufLen)
{
    static const uint8_t s_ucEndMask[]     = { 0x0f, 0xf0 };
    static const uint8_t  s_ucBitOffset[]   = { 0   , 4   };
    _U8  bcd_value;
    _U32 i;

    if(!bcd || !str) {
        LOG(UPC, ERR, "parameter error, (null)");
        return 0;
    }

    for ( i = 0 ; i < ulBcdLen ; i ++ )
    {
        if( (bcd[i/2]&s_ucEndMask[i%2]) == s_ucEndMask[i%2] )
        {
            break;
        }

        if(i >= ulStrBufLen)
        {
            break;
        }

        bcd_value = (bcd[i/2] >> s_ucBitOffset[i%2]) & 0xf;

        switch(bcd_value)
        {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
                str[i] = bcd_value + '0';
                break;

            case 0x0F:
            default:
                str[i] = 'F';
                break;
        }
    }

    str[i] = '\0';

    return (i);
}

void upc_build_session_establishment_response(
    session_emd_response *sess_rep, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq, uint64_t cp_seid, int trace_flag, uint8_t node_type)
{
    uint16_t msg_hdr_pos = *resp_pos;
    uint16_t buf_pos = *resp_pos;

    if (NULL == sess_rep || NULL == resp_buffer || NULL == resp_pos) {
        LOG(UPC, ERR,
            "Abnormal parameters, sess_rep(%p), resp_buffer(%p), resp_pos(%p).",
            sess_rep, resp_buffer, resp_pos);
        return;
    }

    /* Encode msg header */
    pfcp_client_encode_header(resp_buffer, &buf_pos, 1, cp_seid,
        SESS_SESSION_ESTABLISHMENT_RESPONSE, 0, pkt_seq);

    /* Encode NODE ID */
    pfcp_encode_node_id(resp_buffer, &buf_pos, node_type);

    /* Encode cause */
    tlv_encode_type(resp_buffer, &buf_pos, UPF_CAUSE);
    tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, &buf_pos, sess_rep->cause);
    LOG_TRACE(UPC, RUNNING, trace_flag, "encode cause %d.", sess_rep->cause);

    /* Encode offending ie */
    if (sess_rep->member_flag.d.offending_ie_present) {
        tlv_encode_type(resp_buffer, &buf_pos, UPF_OFFENDING_IE);
        tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, &buf_pos, sess_rep->offending_ie);
        LOG_TRACE(UPC, RUNNING, trace_flag, "encode offending ie %d.",
            sess_rep->offending_ie);
    }

    /* Encode UP F-SEID */
    if (SESS_REQUEST_ACCEPTED == sess_rep->cause) {
        if (0 > upc_build_f_seid(sess_rep->local_seid, resp_buffer, &buf_pos, node_type)) {
            LOG(UPC, ERR, "encode f-seid failed.");
        }
        LOG_TRACE(UPC, RUNNING, trace_flag, "encode f-seid.");
    }

    /* Encode Created PDR */
    if (0 > upc_build_created_pdr(sess_rep->created_pdr,
        sess_rep->created_pdr_num, resp_buffer, &buf_pos)) {
        LOG(UPC, ERR, "build created pdr failed.");
    }

    /* Load Control Information */
    if (sess_rep->member_flag.d.load_ctl_info_present) {
        if (0 > upc_build_load_control_info(&sess_rep->load_ctl_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build load control info failed.");
        }
    }

    /* Overload Control Information */
    if (sess_rep->member_flag.d.overload_ctl_info_present) {
        if (0 > upc_build_overload_control_info(&sess_rep->overload_ctl_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build overload control info failed.");
        }
    }

    /* Encode failed rule id */
    if (sess_rep->member_flag.d.failed_rule_id_present) {
        if (0 > upc_build_failed_rule_id(&sess_rep->failed_rule_id, resp_buffer,
            &buf_pos)) {
            LOG(UPC, ERR, "build failed rule id failed.");
        }
    }

    /* Encode Created Traffic Endpoint */
    if (0 > upc_build_created_traffic_endpoint(sess_rep->created_tc_endpoint,
        sess_rep->created_tc_endpoint_num, resp_buffer, &buf_pos)) {
        LOG(UPC, ERR, "build created traffic endpoint failed.");
    }

    /* Created Bridge Info for TSC */
    if (sess_rep->member_flag.d.created_bg_info_present) {
        if (0 > upc_build_created_bridge_info(&sess_rep->created_bg_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build Created Bridge Info for TSC failed.");
        }
    }

    /* ATSSS Control Parameters */
    if (sess_rep->member_flag.d.atsss_ctrl_para_present) {
        if (0 > upc_build_atsss_control_para(&sess_rep->atsss_ctrl_para,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build ATSSS Control Parameters failed.");
        }
    }

    /* Filling msg header length */
    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, buf_pos);

    *resp_pos = buf_pos;
}

int upc_local_session_establishment(session_content_create *sess_content)
{
    upc_node_cb     *node_cb = NULL;
    session_emd_response sess_rep;

    node_cb = upc_node_get_of_index(sess_content->node_index);
    if (unlikely(NULL == node_cb)) {
        LOG(UPC, ERR, "get node cb failed, index: %u.", sess_content->node_index);

        return -1;
    }

    if (NULL == upc_seid_entry_add_target(node_cb, sess_content)) {
        LOG(UPC, ERR, "Add target seid %u failed.", (uint32_t)sess_content->local_seid);
        return -1;
    }

    if (0 > upc_update_resource_from_create(sess_content)) {
        LOG(UPC, ERR, "Update resource from session create failed.");
    }

    if (0 > session_establish(sess_content, &sess_rep)) {
        LOG(SESSION, ERR, "session establish failed, local_seid: 0x%016lx cp_seid: 0x%016lx.",
            sess_content->local_seid, sess_content->cp_f_seid.seid);
    }

    return 0;
}

void upc_parse_session_establishment_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t resp_pos = 0;
    EN_UPC_HA_SYNC_EVENTS sync_event = HA_SYNC_EVENT_SUCC;
    uint8_t sync_blk_exist = FALSE;
    uint32_t sync_blk_index = 0;
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    upc_establish_m_opt m_opt = {.value = 0};
    uint16_t obj_type, obj_len;
    upc_node_cb     *node_cb = NULL;
    pfcp_node_id    *node_id = NULL;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    upc_seid_entry  *seid_entry = NULL;
    session_content_create sess_content = {{0}};
    session_emd_response sess_rep = {{0}};
    int trace_flag = G_FALSE;

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    LOG(UPC, RUNNING, "Parse session establishment request.");
    /* Parse packet */
    while (buf_pos < buf_max) {
        if (((TLV_TYPE_LEN + TLV_LENGTH_LEN) + buf_pos) <= buf_max) {
            obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
            obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);
        } else {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "buff len abnormal.");
            break;
        }

        if ((obj_len + buf_pos) > buf_max) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING,
                "IE value length error, obj_len: %d, buf_pos: %d, buf_max: %d.",
                obj_len, buf_pos, buf_max);
            break;
        }

        switch (obj_type) {
            case UPF_CREATE_PDR:
                if (sess_content.pdr_num < MAX_PDR_NUM) {
                    m_opt.d.create_pdr = G_TRUE;
                    res_cause = upc_parse_create_pdr(
                        &sess_content.pdr_arr[sess_content.pdr_num], buffer,
                        &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.pdr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of PDR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_FAR:
                if (sess_content.far_num < MAX_FAR_NUM) {
                    m_opt.d.create_far = G_TRUE;
                    res_cause = upc_parse_create_far(
                        &sess_content.far_arr[sess_content.far_num], buffer,
                        &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.far_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of FAR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_URR:
                if (sess_content.urr_num < MAX_URR_NUM) {
                    res_cause = upc_parse_create_urr(
                        &sess_content.urr_arr[sess_content.urr_num], buffer,
                        &buf_pos, buf_pos + obj_len, &sess_rep, 0);
                    ++sess_content.urr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of URR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_QER:
                if (sess_content.qer_num < MAX_QER_NUM) {
                    res_cause = upc_parse_create_qer(
                        &sess_content.qer_arr[sess_content.qer_num], buffer,
                        &buf_pos, buf_pos + obj_len, &sess_rep, 0);
                    ++sess_content.qer_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of QER reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_BAR:
                sess_content.member_flag.d.bar_present = 1;
                res_cause = upc_parse_create_bar(&sess_content.bar, buffer,
                    &buf_pos, buf_pos + obj_len, &sess_rep);
                break;

            case UPF_CREATE_TRAFFIC_ENDPOINT:
                if (sess_content.tc_endpoint_num < MAX_TC_ENDPOINT_NUM) {
                    res_cause = upc_parse_create_traffic_endpoint(
                        &sess_content.tc_endpoint_arr[\
                        sess_content.tc_endpoint_num], buffer,
                        &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.tc_endpoint_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of traffic endpoint"
                        " reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_F_SEID:
                /* Declear supported mandatory option */
                m_opt.d.f_seid = G_TRUE;

                res_cause = upc_parse_f_seid(&sess_content.cp_f_seid, buffer,
                    &buf_pos, buf_max, obj_len);
                break;

            case UPF_NODE_ID:
                /* Declear supported mandatory option */
                m_opt.d.node_id = G_TRUE;

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

            case UPF_PDN_TYPE:
                if (sizeof(uint8_t) == obj_len) {
                    sess_content.pdn_type =
                        tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                LOG(UPC, RUNNING, "decode PDN type: %d.",
                    sess_content.pdn_type);
                break;

            case UPF_USER_PLANE_INACTIVITY_TIMER:
                if (sizeof(uint32_t) == obj_len) {
                    sess_content.member_flag.d.inactivity_timer_present = 1;
                    sess_content.inactivity_timer =
                        tlv_decode_uint32_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_USER_ID:
                sess_content.member_flag.d.user_id_present = 1;
                res_cause = upc_parse_user_id(&sess_content.user_id, buffer,
                    &buf_pos, buf_max, obj_len);
                break;

            case UPF_TRACE_INFORMATION:
                sess_content.member_flag.d.trace_info_present = 1;
                res_cause = upc_parse_trace_info(&sess_content.trace_info,
                    buffer, &buf_pos, buf_max, obj_len);
                break;

            case UPF_APN_DNN:
                if (obj_len && (APN_DNN_LEN > obj_len)) {
                    sess_content.member_flag.d.apn_dnn_present = 1;
                    tlv_decode_binary(buffer, &buf_pos, obj_len,
                        (uint8_t *)sess_content.apn_dnn.value);
                    sess_content.apn_dnn.value[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR,
                        "obj_len: %d abnormal, Should be Less than %d.",
                        obj_len, APN_DNN_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_CREATE_MAR:
                if (sess_content.mar_num < MAX_MAR_NUM) {
                    res_cause = upc_parse_create_mar(
                        &sess_content.mar_arr[sess_content.mar_num], buffer,
                        &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.mar_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of MAR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_PFCPSEREQ_FLAGS:
                if (sizeof(uint8_t) == obj_len) {
                    sess_content.pfcpserq_flags.value = tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_CREATED_BRIDGE_INFO_FOR_TSC:
                if (sizeof(uint8_t) == obj_len) {
                    sess_content.create_bridge.value = tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_CREATE_SRR:
                if (sess_content.srr_num < MAX_SRR_NUM) {
                    res_cause = upc_parse_create_srr(
                        &sess_content.srr_arr[sess_content.srr_num], buffer,
                        &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.srr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of SRR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_PROVIDE_ATSSS_CONTROL_INFORMATION:
                sess_content.member_flag.d.provide_atsss_ctrl_info_present = 1;
                res_cause = upc_parse_provid_atsss_ctrl_info(
                    &sess_content.provide_atsss_ctrl_info, buffer,
                    &buf_pos, buf_pos + obj_len, &sess_rep);
                break;

            case UPF_RECOVERY_TIME_STAMP:
                if (sizeof(uint32_t) == obj_len) {
                    sess_content.recovery_time_stamp = tlv_decode_uint32_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_RAT_TYPE:
                if ((sizeof(uint8_t) + sizeof(uint16_t)) == obj_len) {
                    sess_content.rat_type.enterprise_id = tlv_decode_uint16_t(buffer, &buf_pos);
                    sess_content.rat_type.rat_type = tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, (sizeof(uint8_t) + sizeof(uint16_t)));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_USER_LOCATION_INFO:
                if (3 <= obj_len) {
                    sess_content.user_local_info.enterprise_id = tlv_decode_uint16_t(buffer, &buf_pos);
                    sess_content.user_local_info.geographic_location_type = tlv_decode_uint8_t(buffer, &buf_pos);

                    if ((obj_len - 3) < GEOGRAPHIC_LOCAL_LEN) {
                        tlv_decode_binary(buffer, &buf_pos, obj_len - 3,
                            sess_content.user_local_info.geographic_location);
                    } else {
                        PFCP_MOVE_FORWORD(buf_pos, (obj_len - 3));
                        LOG(UPC, ERR, "UPF_USER_LOCATION_INFO length too long, skip this.");
                    }
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be greater than or equal to %u.",
                        obj_len, 3);
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
        if (unlikely(last_pos == buf_pos)) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "empty ie.");
            break;
        } else {
            last_pos = buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            if (0 == sess_rep.member_flag.d.offending_ie_present) {
                sess_rep.member_flag.d.offending_ie_present = 1;
                sess_rep.offending_ie = obj_type;
            }
            LOG(UPC, RUNNING, "parse abnormal. cause: %d, obj_type: %d.",
                sess_rep.cause, sess_rep.offending_ie);
            break;
        }
    }

    /* Check mandaytory option */
    if ((res_cause == SESS_REQUEST_ACCEPTED) &&
        (m_opt.value ^ UPC_ESTABLISH_M_OPT_MASK)) {
        LOG(UPC, ERR,
            "mandatory option f_seid(%d) node_id(%d)"
            " create_pdr(%d) create_far(%d).",
            m_opt.d.f_seid, m_opt.d.node_id,
            m_opt.d.create_pdr, m_opt.d.create_far);

        res_cause = SESS_MANDATORY_IE_MISSING;
        goto fast_response;
    }

    node_cb = upc_node_get(node_id->type.d.type, node_id->node_id);
    if (unlikely(NULL == node_cb)) {
        LOG(UPC, ERR, "get node cb failed.");

        res_cause = SESS_NO_ESTABLISHED_PFCP_ASSOCIATION;
        goto fast_response;
    }

    if (res_cause != SESS_REQUEST_ACCEPTED) {
        LOG(UPC, ERR, "parse session establishment request failed.");

        goto fast_response;
    }

    sess_content.msg_header.msg_type = SESS_SESSION_ESTABLISHMENT_REQUEST;
    sess_content.msg_header.node_id_index = node_cb->index;
    sess_content.msg_header.seq_num = pkt_seq;

    seid_entry = upc_seid_entry_alloc();
    if (NULL == seid_entry) {
        LOG(UPC, ERR, "Allocate seid failed.");

        res_cause = SESS_NO_RESOURCES_AVAILABLE;
        goto fast_response;
    }
    sess_content.local_seid = seid_entry->index;

    if (0 > upc_alloc_teid_from_create(&sess_content, trace_flag)) {
        LOG(UPC, ERR, "Alloc teid from session create failed.");

        if (0 > upc_free_teid_from_create(&sess_content, trace_flag)) {
            LOG(UPC, ERR, "Free TEID failed.");
        }
        Res_Free(upc_seid_get_pool_id(), 0, seid_entry->index);
        res_cause = SESS_NO_RESOURCES_AVAILABLE;

        goto fast_response;
    }

    if (0 > upc_alloc_ueip_from_create(&sess_content, trace_flag)) {
        LOG(UPC, ERR, "Alloc UEIP from session create failed.");

        if (0 > upc_free_teid_from_create(&sess_content, trace_flag)) {
            LOG(UPC, ERR, "Free TEID failed.");
        }

        if (0 > upc_free_ueip_from_create(&sess_content, trace_flag)) {
            LOG(UPC, ERR, "Free UEIP failed.");
        }
        Res_Free(upc_seid_get_pool_id(), 0, seid_entry->index);
        res_cause = SESS_NO_RESOURCES_AVAILABLE;

        goto fast_response;
    }

    if (0 > upc_seid_entry_add_common(seid_entry, node_cb, &sess_content)) {
        LOG(UPC, ERR, "Add seid entry common failed.");
        Res_Free(upc_seid_get_pool_id(), 0, seid_entry->index);
        res_cause = SESS_NO_RESOURCES_AVAILABLE;

        goto fast_response;
    }

    upc_node_update_peer_sa(node_cb, sa);

    if (sess_content.member_flag.d.user_id_present) {
        seid_entry->sig_trace.user_id_present = 1;
        if (sess_content.user_id.user_id_flag.d.imsif) {
            uint8_t imsi_string[SESSION_MAX_BCD_BYTES << 1] = {0};

            bcd_to_string(sess_content.user_id.imsi, imsi_string, sess_content.user_id.imsi_len << 1,
                SESSION_MAX_BCD_BYTES << 1);
            memcpy(seid_entry->sig_trace.imsi, imsi_string, SESSION_MAX_BCD_BYTES << 1);

            if (user_sig_trace.valid &&
                (USER_SIGNALING_TRACE_IMSI == user_sig_trace.type) &&
                (0 == strcmp((char *)user_sig_trace.imsi, (char *)imsi_string))) {
                seid_entry->sig_trace.type = USER_SIGNALING_TRACE_IMSI;
                seid_entry->sig_trace.valid = 1;
                sess_content.user_id.sig_trace = 1;
            }
        }
        if (sess_content.user_id.user_id_flag.d.msisdnf) {
            uint8_t msisdn_string[SESSION_MAX_BCD_BYTES << 1] = {0};
            bcd_to_string(sess_content.user_id.msisdn, msisdn_string, sess_content.user_id.msisdn_len << 1,
                SESSION_MAX_BCD_BYTES << 1);
            memcpy(seid_entry->sig_trace.msisdn, msisdn_string, SESSION_MAX_BCD_BYTES << 1);

            if (user_sig_trace.valid &&
                (USER_SIGNALING_TRACE_MSISDN == user_sig_trace.type) &&
                (0 == strcmp((char *)user_sig_trace.msisdn, (char *)msisdn_string))) {
                seid_entry->sig_trace.type = USER_SIGNALING_TRACE_MSISDN;
                seid_entry->sig_trace.valid = 1;
                sess_content.user_id.sig_trace = 1;
            }
        }
    }

    trace_flag = seid_entry->sig_trace.valid;
    if (trace_flag) {
        ros_rwlock_write_lock(&user_sig_trace.rwlock);
        upc_write_wireshark((char *)buffer, buf_max, upc_node_get_peer_ipv4(node_cb), 0);
        ros_rwlock_write_unlock(&user_sig_trace.rwlock);
    }
    LOG_TRACE(UPC, RUNNING, trace_flag, "Parse session establishment request finish.");

    seid_entry->session_config.msg_header.seq_num = sess_content.msg_header.seq_num;

    if (0 > session_establish(&sess_content, &sess_rep)) {
        LOG(SESSION, ERR, "session establish failed, local_seid: 0x%016lx cp_seid: 0x%016lx.",
            sess_content.local_seid, sess_content.cp_f_seid.seid);

        res_cause = sess_rep.cause;

        LOG(UPC, ERR, "publish content to sp failed, sequence number: %u.", pkt_seq);
        if (0 > upc_free_teid_from_create(&sess_content, trace_flag)) {
            LOG(UPC, ERR, "Free TEID failed.");
        }

        if (0 > upc_free_ueip_from_create(&sess_content, trace_flag)) {
            LOG(UPC, ERR, "Free UEIP failed.");
        }

        if (0 > upc_seid_entry_remove(seid_entry->index)) {
            LOG(UPC, ERR, "remove seid entry failed.");
        }

        goto fast_response;
    }
    session_fill_load_info(&sess_rep);

    if (upc_hk_build_data_block) {
        sync_blk_index = upc_hk_build_data_block(HA_SYNC_DATA_SESS, HA_CREATE, HA_SYNC_RECV_FROM_CP,
            sync_event, &sess_content);
        if (0 > sync_blk_index) {

            LOG(UPC, ERR, "Build session sync msg failed.");

            res_cause = SESS_CREATE_SYNC_DATA_BLOCK_FAILURE;

            if (0 > upc_free_teid_from_create(&sess_content, trace_flag)) {
                LOG(UPC, ERR, "Free TEID failed.");
            }

            if (0 > upc_free_ueip_from_create(&sess_content, trace_flag)) {
                LOG(UPC, ERR, "Free UEIP failed.");
            }

            if (0 > upc_seid_entry_remove(seid_entry->index)) {
                LOG(UPC, ERR, "remove seid entry failed.");
            }

            goto fast_response;
        }
        sync_blk_exist = TRUE;
    }

    session_establish_to_fp(&sess_content);

    if (upc_hk_change_sync_blk_status) {
        if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_SEND_TO_FPU, sync_event)) {
            LOG(UPC, ERR, "Change session sync msg failed, sess_content.local_seid: %lu.", sess_content.local_seid);
        }
    }

    upc_est_fill_created_pdr(&sess_content, &sess_rep);
    upc_est_fill_created_traffic_endpoint(&sess_content, &sess_rep);

fast_response:
    upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, sa);

    sess_rep.cause = res_cause;
    upc_build_session_establishment_response(&sess_rep, resp_buffer,
        &resp_pos, pkt_seq, sess_content.cp_f_seid.seid, trace_flag,
        sa->sa_family == AF_INET ? UPF_NODE_TYPE_IPV4 : UPF_NODE_TYPE_IPV6);

    if (0 > upc_buff_send2smf(resp_buffer, resp_pos, sa)) {
        LOG_TRACE(UPC, ERR, trace_flag, "Send packet to SMF failed.");
    } else if (trace_flag) {
        ros_rwlock_write_lock(&user_sig_trace.rwlock);
        upc_write_wireshark((char *)resp_buffer, resp_pos, upc_node_get_peer_ipv4(node_cb), 1);
        ros_rwlock_write_unlock(&user_sig_trace.rwlock);
    }

    if (sync_blk_exist) {
        if (upc_hk_change_sync_blk_status) {
            if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_REPLY_TO_CP, sync_event)) {
                LOG(UPC, ERR, "Change session sync msg failed, sess_content.local_seid: %lu.", sess_content.local_seid);
            }
        }
    }
}

void upc_build_session_modification_response(
    session_emd_response *sess_rep, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq, uint64_t cp_seid, int trace_flag)
{
    uint16_t msg_hdr_pos = *resp_pos;
    uint16_t buf_pos = *resp_pos;

    if (NULL == sess_rep || NULL == resp_buffer || NULL == resp_pos) {
        LOG(UPC, ERR,
            "Abnormal parameters, sess_rep(%p), resp_buffer(%p), resp_pos(%p).",
            sess_rep, resp_buffer, resp_pos);
        return;
    }

    /* Encode msg header */
    pfcp_client_encode_header(resp_buffer, &buf_pos, 1, cp_seid,
        SESS_SESSION_MODIFICATION_RESPONSE, 0, pkt_seq);

    /* Encode cause */
    tlv_encode_type(resp_buffer, &buf_pos, UPF_CAUSE);
    tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, &buf_pos, sess_rep->cause);
    LOG_TRACE(UPC, RUNNING, trace_flag, "encode cause %d.", sess_rep->cause);

    /* Encode offending ie */
    if (sess_rep->member_flag.d.offending_ie_present) {
        tlv_encode_type(resp_buffer, &buf_pos, UPF_OFFENDING_IE);
        tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, &buf_pos, sess_rep->offending_ie);
        LOG_TRACE(UPC, RUNNING, trace_flag, "encode offending ie %d.",
            sess_rep->offending_ie);
    }

    /* Encode Created PDR */
    if (0 > upc_build_created_pdr(sess_rep->created_pdr,
        sess_rep->created_pdr_num, resp_buffer, &buf_pos)) {
        LOG(UPC, ERR, "build created pdr failed.");
    }

    /* Load Control Information */
    if (sess_rep->member_flag.d.load_ctl_info_present) {
        if (0 > upc_build_load_control_info(&sess_rep->load_ctl_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build load control info failed.");
        }
    }

    /* Overload Control Information */
    if (sess_rep->member_flag.d.overload_ctl_info_present) {
        if (0 > upc_build_overload_control_info(&sess_rep->overload_ctl_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build overload control info failed.");
        }
    }

    /* Encode usage report */
    if (0 > upc_build_md_usage_report(sess_rep->usage_report,
        sess_rep->usage_report_num, resp_buffer, &buf_pos,
        UPF_USAGE_REPORT_SESSION_MODIFICATION_RESPONSE, trace_flag)) {
        LOG(UPC, ERR, "build usage report failed.");
    }

    /* Encode failed rule id */
    if (sess_rep->member_flag.d.failed_rule_id_present) {
        if (0 > upc_build_failed_rule_id(&sess_rep->failed_rule_id,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build failed rule id failed.");
        }
    }

    /* Encode Additional Usage Reports Information */
    if (sess_rep->member_flag.d.added_usage_report_present) {
        tlv_encode_type(resp_buffer, &buf_pos,
            UPF_ADDITIONAL_USAGE_REPORTS_INFORMATION);
        tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, &buf_pos,
            sess_rep->added_usage_report.value);
        LOG_TRACE(UPC, RUNNING, trace_flag, "encode Additional Usage Reports info %d.",
            sess_rep->added_usage_report.value);
    }

    /* Encode Created Traffic Endpoint */
    if (0 > upc_build_created_traffic_endpoint(sess_rep->created_tc_endpoint,
        sess_rep->created_tc_endpoint_num, resp_buffer, &buf_pos)) {
        LOG(UPC, ERR, "build created traffic endpoint failed.");
    }

    /* Encode Port Management Information for TSC */
    if (sess_rep->member_flag.d.port_mgmt_info_present) {
        if (0 > upc_build_port_mgmt_info_for_tsc(&sess_rep->port_mgmt_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build Port Management Information for TSC failed.");
        }
    }

    /* Encode ATSSS Control Parameters */
    if (sess_rep->member_flag.d.atsss_ctrl_para_present) {
        if (0 > upc_build_atsss_control_para(&sess_rep->atsss_ctrl_para,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build ATSSS Control Parameters failed.");
        }
    }

    /* Encode Updated PDR */
    if (0 > upc_build_updated_pdr(sess_rep->updated_pdr,
        sess_rep->updated_pdr_num, resp_buffer, &buf_pos)) {
        LOG(UPC, ERR, "build updated pdr failed.");
    }

    /* Filling msg header length */
    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, buf_pos);

    *resp_pos = buf_pos;
}

int upc_local_session_modification(session_content_modify *sess_content)
{
    upc_seid_entry  *seid_entry = NULL;
    upc_node_cb     *node_cb = NULL;
    session_emd_response sess_rep;

    seid_entry = upc_seid_entry_search(sess_content->local_seid);
    if (seid_entry == NULL) {
        LOG(UPC, ERR, "search seid entry failed, seid: 0x%lx.", sess_content->local_seid);
        return -1;
    }

    node_cb = upc_node_get_of_index(seid_entry->session_config.node_index);
    if (node_cb == NULL) {
        LOG(UPC, ERR, "search node cb failed.");
        return -1;
    }

    if (0 > upc_update_resource_from_modify(sess_content)) {
        LOG(UPC, ERR, "Update resource from session modify failed.");
    }

    /* publish packed data to sp */
    if (0 > session_modify(sess_content, &sess_rep)) {
        LOG(SESSION, ERR, "session modify failed, local_seid: 0x%016lx cp_seid: 0x%016lx.",
            sess_content->local_seid, sess_content->cp_seid);

        return -1;
    }

    if (0 > upc_change_data(&seid_entry->session_config, sess_content)) {
        LOG(UPC, ERR, "Change redis data failed.");
        return -1;
    }

    return 0;
}

void upc_parse_session_modification_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, uint64_t up_seid, struct sockaddr *sa)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t resp_pos = 0;
    EN_UPC_HA_SYNC_EVENTS sync_event = HA_SYNC_EVENT_SUCC;
    uint8_t sync_blk_exist = FALSE;
    uint32_t sync_blk_index = 0;
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    upc_seid_entry  *seid_entry = NULL;
    upc_node_cb     *node_cb = NULL;
    session_content_modify sess_content = {{0}};
    session_emd_response sess_rep = {{0}};
    pfcp_node_id *node_id = NULL;
    int trace_flag = G_FALSE;

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    LOG(UPC, RUNNING, "Parse session modification request.");
    /* Parse packet */
    while (buf_pos < buf_max) {
        if (((TLV_TYPE_LEN + TLV_LENGTH_LEN) + buf_pos) <= buf_max) {
            obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
            obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);
        } else {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, ERR, "buff len abnormal.");
            break;
        }

        if ((obj_len + buf_pos) > buf_max) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING,
                "IE value length error, obj_len: %d, buf_pos: %d, buf_max: %d.",
                obj_len, buf_pos, buf_max);
            break;
        }

        switch (obj_type) {
            case UPF_UPDATE_PDR:
                if (sess_content.update_pdr_num < MAX_PDR_NUM) {
                    res_cause = upc_parse_update_pdr(
                        &sess_content.update_pdr_arr[sess_content.update_pdr_num
                        ], buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.update_pdr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of PDR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_UPDATE_FAR:
                if (sess_content.update_far_num < MAX_FAR_NUM) {
                    res_cause = upc_parse_update_far(
                        &sess_content.update_far_arr[sess_content.update_far_num
                        ], buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.update_far_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of FAR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_UPDATE_URR:
                if (sess_content.update_urr_num < MAX_URR_NUM) {
                    res_cause = upc_parse_create_urr(
                        &sess_content.update_urr_arr[sess_content.update_urr_num
                        ], buffer, &buf_pos, buf_pos + obj_len, &sess_rep, 1);
                    ++sess_content.update_urr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of URR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_UPDATE_QER:
                if (sess_content.update_qer_num < MAX_QER_NUM) {
                    res_cause = upc_parse_create_qer(
                        &sess_content.update_qer_arr[sess_content.update_qer_num
                        ], buffer, &buf_pos, buf_pos + obj_len, &sess_rep, 1);
                    ++sess_content.update_qer_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of QER reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_UPDATE_BAR_SESSION_MODIFICATION_REQUEST:
                sess_content.member_flag.d.update_bar_present = 1;
                res_cause = upc_parse_create_bar(&sess_content.update_bar,
                    buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                break;

            case UPF_UPDATE_TRAFFIC_ENDPOINT:
                if (sess_content.update_tc_endpoint_num < MAX_TC_ENDPOINT_NUM) {
                    res_cause = upc_parse_create_traffic_endpoint(
                        &sess_content.update_tc_endpoint_arr[\
                        sess_content.update_tc_endpoint_num], buffer,
                        &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.update_tc_endpoint_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of traffic endpoint"
                        " reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_PDR:
                if (sess_content.create_pdr_num < MAX_PDR_NUM) {
                    res_cause = upc_parse_create_pdr(
                        &sess_content.create_pdr_arr[sess_content.create_pdr_num
                        ], buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.create_pdr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of PDR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_FAR:
                if (sess_content.create_far_num < MAX_FAR_NUM) {
                    res_cause = upc_parse_create_far(
                        &sess_content.create_far_arr[sess_content.create_far_num
                        ], buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.create_far_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of FAR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_URR:
                if (sess_content.create_urr_num < MAX_URR_NUM) {
                    res_cause = upc_parse_create_urr(
                        &sess_content.create_urr_arr[sess_content.create_urr_num
                        ], buffer, &buf_pos, buf_pos + obj_len, &sess_rep, 0);
                    ++sess_content.create_urr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of URR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_QER:
                if (sess_content.create_qer_num < MAX_QER_NUM) {
                    res_cause = upc_parse_create_qer(
                        &sess_content.create_qer_arr[sess_content.create_qer_num
                        ], buffer, &buf_pos, buf_pos + obj_len, &sess_rep, 0);
                    ++sess_content.create_qer_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of QER reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_BAR:
                sess_content.member_flag.d.create_bar_present = 1;
                res_cause = upc_parse_create_bar(&sess_content.create_bar,
                    buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                break;

            case UPF_CREATE_TRAFFIC_ENDPOINT:
                if (sess_content.create_tc_endpoint_num < MAX_TC_ENDPOINT_NUM) {
                    res_cause = upc_parse_create_traffic_endpoint(
                        &sess_content.create_tc_endpoint_arr[\
                        sess_content.create_tc_endpoint_num], buffer,
                        &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.create_tc_endpoint_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of traffic endpoint"
                        " reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_REMOVE_PDR:
                if (sess_content.remove_pdr_num < MAX_PDR_NUM) {
                    res_cause = upc_parse_remove_pdr(
                        &sess_content.remove_pdr_arr[sess_content.remove_pdr_num],
                        buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.remove_pdr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of PDR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_REMOVE_FAR:
                if (sess_content.remove_far_num < MAX_FAR_NUM) {
                    res_cause = upc_parse_remove_far(
                        &sess_content.remove_far_arr[sess_content.remove_far_num],
                        buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.remove_far_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of FAR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_REMOVE_URR:
                if (sess_content.remove_urr_num < MAX_URR_NUM) {
                    res_cause = upc_parse_remove_urr(
                        &sess_content.remove_urr_arr[sess_content.remove_urr_num],
                        buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.remove_urr_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of URR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_REMOVE_QER:
                if (sess_content.remove_qer_num < MAX_QER_NUM) {
                    res_cause = upc_parse_remove_qer(
                        &sess_content.remove_qer_arr[sess_content.remove_qer_num],
                        buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.remove_qer_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of QER reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_REMOVE_BAR:
                res_cause = upc_parse_remove_bar(&sess_content.remove_bar,
                    buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                sess_content.member_flag.d.remove_bar_present = 1;
                break;

            case UPF_REMOVE_TRAFFIC_ENDPOINT:
                if (sess_content.remove_tc_endpoint_num < MAX_TC_ENDPOINT_NUM) {
                    res_cause = upc_parse_remove_traffic_endpoint(
                        &sess_content.remove_tc_endpoint_arr[sess_content.remove_tc_endpoint_num],
                        buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.remove_tc_endpoint_num;
                } else {
                    LOG(UPC, ERR, "The number of tarffic endpoint "
                        "reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_F_SEID:
                sess_content.member_flag.d.update_cp_seid_present = 1;
                res_cause = upc_parse_f_seid(&sess_content.update_cp_fseid,
                    buffer, &buf_pos, buf_max, obj_len);
                break;

            case UPF_USER_PLANE_INACTIVITY_TIMER:
                if (sizeof(uint32_t) == obj_len) {
                    sess_content.member_flag.d.inactivity_timer_present = 1;
                    sess_content.inactivity_timer =
                        tlv_decode_uint32_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PFCPSMREQ_FLAGS:
                if (sizeof(uint8_t) == obj_len) {
                    sess_content.pfcpsm_flag.value =
                        tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_QUERY_URR:
                if (sess_content.query_urr_num < MAX_URR_NUM) {
                    if (sizeof(uint32_t) == obj_len) {
                        sess_content.query_urr_arr[sess_content.query_urr_num] =
                            tlv_decode_uint32_t(buffer, &buf_pos);
                        ++sess_content.query_urr_num;
                    } else {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint32_t));
                        res_cause = SESS_INVALID_LENGTH;
                    }
                } else {
                    LOG(UPC, ERR, "The number of URR "
                        "reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_QUERY_URR_REFERENCE:
                if (sizeof(uint32_t) == obj_len) {
                    sess_content.member_flag.d.query_urr_reference_present = 1;
                    sess_content.query_urr_reference =
                        tlv_decode_uint32_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint32_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_TRACE_INFORMATION:
                sess_content.member_flag.d.trace_info_present = 1;
                res_cause = upc_parse_trace_info(&sess_content.trace_info,
                    buffer, &buf_pos, buf_max, obj_len);
                break;

            case UPF_REMOVE_MAR:
                if (sess_content.remove_mar_num < MAX_MAR_NUM) {
                    if (sizeof(uint16_t) == obj_len) {
                        sess_content.remove_mar_arr[sess_content.remove_mar_num]
                            = tlv_decode_uint16_t(buffer, &buf_pos);
                        ++sess_content.remove_mar_num;
                    } else {
                        LOG(UPC, ERR,
                            "obj_len: %d abnormal, Should be %lu.",
                            obj_len, sizeof(uint16_t));
                        res_cause = SESS_INVALID_LENGTH;
                    }
                } else {
                    LOG(UPC, ERR,
                        "The number of FAR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_UPDATE_MAR:
                if (sess_content.update_mar_num < MAX_MAR_NUM) {
                    res_cause = upc_parse_update_mar(
                        &sess_content.update_mar_arr[
                        sess_content.update_mar_num],
                        buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.update_mar_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of MAR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_CREATE_MAR:
                if (sess_content.create_mar_num < MAX_MAR_NUM) {
                    res_cause = upc_parse_create_mar(
                        &sess_content.create_mar_arr[
                        sess_content.create_mar_num],
                        buffer, &buf_pos, buf_pos + obj_len, &sess_rep);
                    ++sess_content.create_mar_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of MAR reaches the upper limit.");
                    res_cause = SESS_NO_RESOURCES_AVAILABLE;
                }
                break;

            case UPF_NODE_ID:
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
                node_cb = upc_node_get(node_id->type.d.type, node_id->node_id);
                if (!node_cb) {
                    LOG(UPC, ERR, "get replace node cb failed, type %d, value %02x%02x%02x%02x",
                        node_id->type.d.type,
                        node_id->node_id[0],
                        node_id->node_id[1],
                        node_id->node_id[2],
                        node_id->node_id[3]);

                    res_cause = SESS_NO_ESTABLISHED_PFCP_ASSOCIATION;
                    break;
                }
                sess_content.member_flag.d.change_node_present = 1;;
                sess_content.change_node_index = node_cb->index;
                break;

            case UPF_RAT_TYPE:
                if ((sizeof(uint8_t) + sizeof(uint16_t)) == obj_len) {
                    sess_content.rat_type.enterprise_id = tlv_decode_uint16_t(buffer, &buf_pos);
                    sess_content.rat_type.rat_type = tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, (sizeof(uint8_t) + sizeof(uint16_t)));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_USER_LOCATION_INFO:
                if (3 <= obj_len) {
                    sess_content.user_local_info.enterprise_id = tlv_decode_uint16_t(buffer, &buf_pos);
                    sess_content.user_local_info.geographic_location_type = tlv_decode_uint8_t(buffer, &buf_pos);

                    if ((obj_len - 3) < GEOGRAPHIC_LOCAL_LEN) {
                        tlv_decode_binary(buffer, &buf_pos, obj_len - 3,
                            sess_content.user_local_info.geographic_location);
                    } else {
                        PFCP_MOVE_FORWORD(buf_pos, (obj_len - 3));
                        LOG(UPC, ERR, "UPF_USER_LOCATION_INFO length too long, skip this.");
                    }
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be greater than or equal to %u.",
                        obj_len, 3);
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
        if (unlikely(last_pos == buf_pos)) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "empty ie.");
            break;
        } else {
            last_pos = buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            LOG(UPC, RUNNING, "parse abnormal.");
            if (0 == sess_rep.member_flag.d.offending_ie_present) {
                sess_rep.member_flag.d.offending_ie_present = 1;
                sess_rep.offending_ie = obj_type;
            }
            break;
        }
    }

    seid_entry = upc_seid_entry_search(up_seid);
    if (seid_entry == NULL) {
        LOG(UPC, ERR, "search seid entry failed, seid: 0x%lx.", up_seid);

        res_cause = SESS_SESSION_CONTEXT_NOT_FOUND;
        goto fast_response;
    }

    ros_rwlock_write_lock(&seid_entry->lock); /* lock */
    if (0 == seid_entry->using) {
        seid_entry->using = 1;
    } else {
        ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */
        res_cause = SESS_PFCP_ENTITY_IN_CONGESTION;
        goto fast_response;
    }
    ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */

    node_cb = upc_node_get_of_index(seid_entry->session_config.node_index);
    if (node_cb == NULL) {
        LOG(UPC, ERR, "search node cb failed.");

        res_cause = SESS_NO_ESTABLISHED_PFCP_ASSOCIATION;
        goto fast_response;
    }
    upc_node_update_peer_sa(node_cb, sa);

    trace_flag = seid_entry->sig_trace.valid;
    if (trace_flag) {
        ros_rwlock_write_lock(&user_sig_trace.rwlock);
        upc_write_wireshark((char *)buffer, buf_max, upc_node_get_peer_ipv4(node_cb), 0);
        ros_rwlock_write_unlock(&user_sig_trace.rwlock);
    }
    LOG_TRACE(UPC, RUNNING, trace_flag, "Parse session modification request finish.");

    if (res_cause != SESS_REQUEST_ACCEPTED) {
        LOG(UPC, ERR, "parse session modification request failed.");

        goto fast_response;
    }

    sess_content.node_index     = node_cb->index;
    sess_content.local_seid     = seid_entry->index;
    sess_content.cp_seid        = seid_entry->session_config.cp_f_seid.seid;

    sess_content.msg_header.msg_type = SESS_SESSION_MODIFICATION_REQUEST;
    sess_content.msg_header.node_id_index = node_cb->index;
    sess_content.msg_header.seq_num = pkt_seq;

    if (0 > upc_alloc_teid_from_modify(&sess_content)) {
        LOG(UPC, ERR, "Alloc teid from session create failed.");

        if (0 > upc_free_teid_from_modify(&sess_content)) {
            LOG(UPC, ERR, "Free TEID failed.");
        }

        res_cause = SESS_NO_RESOURCES_AVAILABLE;

        goto fast_response;
    }

    if (0 > upc_alloc_ueip_from_modify(&sess_content)) {
        LOG(UPC, ERR, "Alloc UEIP from session modify failed.");

        if (0 > upc_free_teid_from_modify(&sess_content)) {
            LOG(UPC, ERR, "Free TEID failed.");
        }

        if (0 > upc_free_ueip_from_modify(&sess_content)) {
            LOG(UPC, ERR, "Free UEIP failed.");
        }

        res_cause = SESS_NO_RESOURCES_AVAILABLE;

        goto fast_response;
    }

    seid_entry->session_config.msg_header.seq_num = sess_content.msg_header.seq_num;

    /* publish packed data to sp */
    if (0 > session_modify(&sess_content, &sess_rep)) {
        LOG(SESSION, ERR, "session modify failed, local_seid: 0x%016lx cp_seid: 0x%016lx.",
            sess_content.local_seid, sess_content.cp_seid);

        res_cause = sess_rep.cause;

        LOG(UPC, ERR, "publish content to sp failed, sequence number: %u.", pkt_seq);

        if (0 > upc_free_teid_from_modify(&sess_content)) {
            LOG(UPC, ERR, "Free TEID failed.");
        }

        if (0 > upc_free_ueip_from_modify(&sess_content)) {
            LOG(UPC, ERR, "Free UEIP failed.");
        }

        goto fast_response;
    }
    session_fill_load_info(&sess_rep);

    if (upc_hk_build_data_block) {
        sync_blk_index = upc_hk_build_data_block(HA_SYNC_DATA_SESS, HA_UPDATE, HA_SYNC_RECV_FROM_CP,
            sync_event, &sess_content);
        if (0 > sync_blk_index) {
            LOG(UPC, ERR, "Build session sync msg failed.");

            res_cause = SESS_CREATE_SYNC_DATA_BLOCK_FAILURE;

            if (0 > upc_free_teid_from_modify(&sess_content)) {
                LOG(UPC, ERR, "Free TEID failed.");
            }

            if (0 > upc_free_ueip_from_modify(&sess_content)) {
                LOG(UPC, ERR, "Free UEIP failed.");
            }

            goto fast_response;
        }
        sync_blk_exist = TRUE;
    }

    session_modify_to_fp(&sess_content);

    if (upc_hk_change_sync_blk_status) {
        if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_SEND_TO_FPU, sync_event)) {
            LOG(UPC, ERR, "Change session sync msg failed.");
        }
    }

    if (0 > upc_change_data(&seid_entry->session_config, &sess_content)) {
        LOG(UPC, ERR, "Change redis data failed.");

        res_cause = SESS_SYSTEM_FAILURE;

        if (0 > upc_free_teid_from_modify(&sess_content)) {
            LOG(UPC, ERR, "Free TEID failed.");
        }

        if (0 > upc_free_ueip_from_modify(&sess_content)) {
            LOG(UPC, ERR, "Free UEIP failed.");
        }
        goto fast_response;
    }

    upc_mdf_fill_created_pdr(&sess_content, &sess_rep);
    upc_mdf_fill_created_traffic_endpoint(&sess_content, &sess_rep);

fast_response:

    upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, sa);

    sess_rep.cause = res_cause;
    upc_build_session_modification_response(&sess_rep, resp_buffer,
        &resp_pos, pkt_seq, sess_content.cp_seid, trace_flag);

    if (seid_entry) {
        ros_rwlock_write_lock(&seid_entry->lock); /* lock */
        seid_entry->using = 0;
        ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */
    }

    if (0 > upc_buff_send2smf(resp_buffer, resp_pos, sa)) {
        LOG_TRACE(UPC, ERR, trace_flag, "Send packet to SMF failed.");
    } else if (trace_flag) {
        ros_rwlock_write_lock(&user_sig_trace.rwlock);
        upc_write_wireshark((char *)resp_buffer, resp_pos, upc_node_get_peer_ipv4(node_cb), 1);
        ros_rwlock_write_unlock(&user_sig_trace.rwlock);
    }

    if (sync_blk_exist) {
        if (upc_hk_change_sync_blk_status) {
            if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_REPLY_TO_CP, sync_event)) {
                LOG(UPC, ERR, "Change session sync msg failed, sess_content.local_seid: %lu.", sess_content.local_seid);
            }
        }
    }
}

void upc_build_session_deletion_response(
    session_emd_response *sess_rep, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq, uint64_t cp_seid, int trace_flag)
{
    uint16_t msg_hdr_pos = *resp_pos;
    uint16_t buf_pos = *resp_pos;

    if (NULL == sess_rep || NULL == resp_buffer || NULL == resp_pos) {
        LOG(UPC, ERR,
            "Abnormal parameters, sess_rep(%p), resp_buffer(%p), resp_pos(%p).",
            sess_rep, resp_buffer, resp_pos);
        return;
    }

    /* Encode msg header */
    pfcp_client_encode_header(resp_buffer, &buf_pos, 1, cp_seid,
        SESS_SESSION_DELETION_RESPONSE, 0, pkt_seq);

    /* Encode cause */
    tlv_encode_type(resp_buffer, &buf_pos, UPF_CAUSE);
    tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, &buf_pos, sess_rep->cause);
    LOG_TRACE(UPC, RUNNING, trace_flag, "encode cause %d.", sess_rep->cause);

    /* Encode offending ie */
    if (sess_rep->member_flag.d.offending_ie_present) {
        tlv_encode_type(resp_buffer, &buf_pos, UPF_OFFENDING_IE);
        tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, &buf_pos, sess_rep->offending_ie);
        LOG_TRACE(UPC, RUNNING, trace_flag, "encode offending ie %d.",
            sess_rep->offending_ie);
    }

    /* Load Control Information */
    if (sess_rep->member_flag.d.load_ctl_info_present) {
        if (0 > upc_build_load_control_info(&sess_rep->load_ctl_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build load control info failed.");
        }
    }

    /* Overload Control Information */
    if (sess_rep->member_flag.d.overload_ctl_info_present) {
        if (0 > upc_build_overload_control_info(&sess_rep->overload_ctl_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build overload control info failed.");
        }
    }

    /* Encode usage report */
    if (0 > upc_build_md_usage_report(sess_rep->usage_report,
        sess_rep->usage_report_num, resp_buffer, &buf_pos,
        UPF_USAGE_REPORT_SESSION_DELETION_RESPONSE, trace_flag)) {
        LOG(UPC, ERR, "build usage report failed.");
    }

    /* Encode Additional Usage Reports Information */
    if (sess_rep->member_flag.d.added_usage_report_present) {
        tlv_encode_type(resp_buffer, &buf_pos,
            UPF_ADDITIONAL_USAGE_REPORTS_INFORMATION);
        tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, &buf_pos,
            sess_rep->added_usage_report.value);
        LOG_TRACE(UPC, RUNNING, trace_flag, "encode Additional Usage Reports info %d.",
            sess_rep->added_usage_report.value);
    }

    /* Packet Rate Status Report */
    if (sess_rep->member_flag.d.pkt_rate_status_report_present) {
        if (0 > upc_build_packet_rate_status_report(&sess_rep->pkt_rate_status_report,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build Packet Rate Status Report failed.");
        }
    }

    /* Encode Session Report */
    if (0 > upc_build_session_report(sess_rep->sess_report,
        sess_rep->sess_report_num, resp_buffer, &buf_pos, trace_flag)) {
        LOG(UPC, ERR, "build Session Report failed.");
    }

    /* Filling msg header length */
    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, buf_pos);

    *resp_pos = buf_pos;
}

int upc_local_session_deletion(session_content_delete *sess_content)
{
    upc_seid_entry   *seid_entry = NULL;
    upc_node_cb     *node_cb = NULL;
    session_emd_response sess_rep;
    struct session_rules_index rules_creator;

    LOG(UPC, RUNNING, "session delete request parse.");

    seid_entry = upc_seid_entry_search(sess_content->local_seid);
    if (seid_entry == NULL) {
        LOG(UPC, ERR, "search seid entry failed.");

        return -1;
    }

    node_cb = upc_node_get_of_index(seid_entry->session_config.node_index);
    if (node_cb == NULL) {
        LOG(UPC, ERR, "search node cb failed.");

        return -1;
    }
    ros_atomic32_dec(&node_cb->session_num);

    /* publish packed data to sp */
    if (0 > session_delete(sess_content->local_seid, sess_content->cp_seid, &sess_rep, FALSE, &rules_creator)) {
        LOG(SESSION, ERR, "session delete failed, local_seid: 0x%016lx cp_seid: 0x%016lx.",
            sess_content->local_seid, sess_content->cp_seid);
    }

    if (0 > upc_free_resources_from_deletion(&seid_entry->session_config)) {
        LOG(UPC, ERR, "Free resources failed.");
    }

    if (0 > upc_seid_entry_remove(sess_content->local_seid)) {
        LOG(UPC, ERR, "remove seid entry failed.");
    }

    return 0;
}

void upc_parse_session_deletion_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, uint64_t up_seid, struct sockaddr *sa)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t resp_pos = 0;
    EN_UPC_HA_SYNC_EVENTS sync_event = HA_SYNC_EVENT_SUCC;
    uint8_t sync_blk_exist = FALSE;
    uint32_t sync_blk_index = 0;
    upc_seid_entry   *seid_entry = NULL;
    upc_node_cb     *node_cb = NULL;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    session_content_delete sess_content = {{0}};
    session_emd_response sess_rep = {{0}};
    int trace_flag = G_FALSE;

    LOG(UPC, RUNNING, "session delete request parse.");

    seid_entry = upc_seid_entry_search(up_seid);
    if (seid_entry == NULL) {
        LOG(UPC, ERR, "search seid entry failed.");

        res_cause = SESS_SESSION_CONTEXT_NOT_FOUND;
        goto fast_response;
    }

    ros_rwlock_write_lock(&seid_entry->lock); /* lock */
    if (0 == seid_entry->using) {
        seid_entry->using = 1;
    } else {
        ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */
        res_cause = SESS_PFCP_ENTITY_IN_CONGESTION;
        goto fast_response;
    }
    ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */

    node_cb = upc_node_get_of_index(seid_entry->session_config.node_index);
    if (node_cb == NULL) {
        LOG(UPC, ERR, "search node cb failed.");

        res_cause = SESS_NO_ESTABLISHED_PFCP_ASSOCIATION;
        goto fast_response;
    }
    upc_node_update_peer_sa(node_cb, sa);

    trace_flag = seid_entry->sig_trace.valid;
    if (trace_flag) {
        ros_rwlock_write_lock(&user_sig_trace.rwlock);
        upc_write_wireshark((char *)buffer, buf_max, upc_node_get_peer_ipv4(node_cb), 0);
        ros_rwlock_write_unlock(&user_sig_trace.rwlock);
    }
    LOG_TRACE(UPC, RUNNING, trace_flag, "Parse session deletion request finish.");

    ros_atomic32_dec(&node_cb->session_num);
    sess_content.node_index     = node_cb->index;
    sess_content.local_seid     = seid_entry->index;
    sess_content.cp_seid        = seid_entry->session_config.cp_f_seid.seid;

    sess_content.msg_header.msg_type = SESS_SESSION_DELETION_REQUEST;
    sess_content.msg_header.node_id_index = node_cb->index;
    sess_content.msg_header.seq_num = pkt_seq;

    seid_entry->session_config.msg_header.seq_num = sess_content.msg_header.seq_num;

    if (upc_hk_build_data_block) {
        sync_blk_index = upc_hk_build_data_block(HA_SYNC_DATA_SESS, HA_REMOVE, HA_SYNC_RECV_FROM_CP,
            sync_event, &sess_content);
        if (0 > sync_blk_index) {
            LOG(UPC, ERR, "Build session sync msg failed.");

            res_cause = SESS_CREATE_SYNC_DATA_BLOCK_FAILURE;

            goto fast_response;
        }
        sync_blk_exist = TRUE;
    }

    /* publish packed data to sp */
    if (0 > session_delete(sess_content.local_seid, sess_content.cp_seid, &sess_rep, 1, NULL)) {
        LOG(SESSION, ERR, "session delete failed, local_seid: 0x%016lx cp_seid: 0x%016lx.",
            sess_content.local_seid, sess_content.cp_seid);

        res_cause = sess_rep.cause;

        sync_event = HA_SYNC_EVENT_FAIL;
        if (upc_hk_change_sync_blk_status) {
            if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_SEND_TO_FPU,
                sync_event)) {
                LOG(UPC, ERR, "Change session sync msg failed.");
            }
        }

        goto fast_response;
    }
    session_fill_load_info(&sess_rep);

    if (upc_hk_change_sync_blk_status) {
        if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_SEND_TO_FPU, sync_event)) {
            LOG(UPC, ERR, "Change session sync msg failed.");
        }
    }

    if (0 > upc_free_resources_from_deletion(&seid_entry->session_config)) {
        LOG(UPC, ERR, "Free resources failed.");
    }

    if (0 > upc_seid_entry_remove(sess_content.local_seid)) {
        LOG(UPC, ERR, "remove seid entry failed.");
    }

fast_response:

    upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, sa);

    sess_rep.cause = res_cause;
    upc_build_session_deletion_response(&sess_rep, resp_buffer,
        &resp_pos, pkt_seq, sess_content.cp_seid, trace_flag);

    if (seid_entry) {
        ros_rwlock_write_lock(&seid_entry->lock); /* lock */
        seid_entry->using = 0;
        ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */
    }

    if (0 > upc_buff_send2smf(resp_buffer, resp_pos, sa)) {
        LOG_TRACE(UPC, ERR, trace_flag, "Send packet to SMF failed.");
    } else if (trace_flag) {
        ros_rwlock_write_lock(&user_sig_trace.rwlock);
        upc_write_wireshark((char *)resp_buffer, resp_pos, upc_node_get_peer_ipv4(node_cb), 1);
        ros_rwlock_write_unlock(&user_sig_trace.rwlock);
    }

    if (sync_blk_exist) {
        if (upc_hk_change_sync_blk_status) {
            if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_REPLY_TO_CP, sync_event)) {
                LOG(UPC, ERR, "Change session sync msg failed, sess_content.local_seid: %lu.", sess_content.local_seid);
            }
        }
    }
}

static int upc_build_session_report_request(
    session_report_request *report_req, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq, uint64_t cp_seid, int trace_flag)
{
    uint16_t msg_hdr_pos = *resp_pos;
    uint16_t buf_pos = *resp_pos;

    /* Encode msg header */
    pfcp_client_encode_header(resp_buffer, &buf_pos, 1, cp_seid,
        SESS_SESSION_REPORT_REQUEST, 0, pkt_seq);

    /* Encode Report Type */
    tlv_encode_type(resp_buffer, &buf_pos, UPF_REPORT_TYPE);
    tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, &buf_pos, report_req->report_type.value);
    LOG_TRACE(UPC, RUNNING, trace_flag, "encode report type %d.",
        report_req->report_type.value);

    /* Encode Downlink Data Report */
    if (report_req->report_type.d.DLDR) {
        if (0 > upc_build_report_dldr(&report_req->dl_data_report,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build report dldr failed.");
        }
    }

    /* Usage Report */
    if (report_req->report_type.d.USAR) {
        if (0 > upc_build_report_ur(report_req->usage_report_arr,
            report_req->usage_report_num, resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build report request usage report failed.");
        }
    }

    /* Remote f-teid */
    if (report_req->report_type.d.ERIR) {
        if (0 > upc_build_eir(&report_req->err_indic_report,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build error indic report failed.");
        }
    }

    /* Load Control Information */
    if (report_req->load_ctrl_present) {
        if (0 > upc_build_load_control_info(&report_req->load_ctrl_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build load control info failed.");
        }
    }

    /* Overload Control Information */
    if (report_req->overload_ctrl_present) {
        if (0 > upc_build_overload_control_info(&report_req->overload_ctrl_info,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build overload control info failed.");
        }
    }

    /* Additional Usage Reports Information */
    if (report_req->added_usage_report_info.d.AURI) {
        tlv_encode_type(resp_buffer, &buf_pos,
            UPF_ADDITIONAL_USAGE_REPORTS_INFORMATION);
        tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, &buf_pos,
            report_req->added_usage_report_info.value);
    }

    /* PFCPSRReq-Flags */
    if (report_req->pfcpsr_flag.d.psdbu) {
        tlv_encode_type(resp_buffer, &buf_pos, UPF_PFCPSRREQ_FLAGS);
        tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint8_t));
        tlv_encode_uint16_t(resp_buffer, &buf_pos,
            report_req->pfcpsr_flag.value);
    }

    /* Filling msg header length */
    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, buf_pos);

    *resp_pos = buf_pos;

    return 0;
}

void upc_parse_session_report_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, uint64_t up_seid, struct sockaddr *sa)
{
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint8_t mandatory_present = 0;
    uint16_t obj_type, obj_len;
    upc_seid_entry   *seid_entry = NULL;
    upc_node_cb     *node_cb = NULL;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    session_f_seid     cp_f_seid = {.seid = 0};
    session_report_response report_resp = {{0}};
    int trace_flag = G_FALSE;

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    LOG(UPC, RUNNING, "Parse session report response.");
    /* Parse packet */
    while (buf_pos < buf_max) {
        if (((TLV_TYPE_LEN + TLV_LENGTH_LEN) + buf_pos) <= buf_max) {
            obj_type = tlv_decode_type(buffer, &buf_pos, buf_max);
            obj_len  = tlv_decode_length(buffer, &buf_pos, buf_max);
        } else {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "buff len abnormal.");
            break;
        }

        if ((obj_len + buf_pos) > buf_max) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING,
                "IE value length error, obj_len: %d, buf_pos: %d, buf_max: %d.",
                obj_len, buf_pos, buf_max);
            break;
        }

        switch (obj_type) {
            case UPF_CAUSE:
                if (sizeof(uint8_t) == obj_len) {
                    mandatory_present = 1;
                    report_resp.cause = tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_OFFENDING_IE:
                if (sizeof(uint16_t) == obj_len) {
                    report_resp.member_flag.d.offending_ie_present = 1;
                    report_resp.offending_ie = tlv_decode_uint16_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint16_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_UPDATE_BAR_PFCP_SESSION_REPORT_RESPONSE:
                report_resp.member_flag.d.update_bar_present = 1;
                res_cause = upc_parse_report_update_bar(&report_resp.update_bar,
                    buffer, &buf_pos, buf_pos + obj_len);
                break;

            case UPF_PFCPSRRSP_FLAGS:
                if (sizeof(uint8_t) == obj_len) {
                    report_resp.member_flag.d.pfcpsp_flag_present = 1;
                    report_resp.pfcpsp_flag.value = tlv_decode_uint8_t(buffer, &buf_pos);
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be %lu.",
                        obj_len, sizeof(uint8_t));
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_F_SEID:
                report_resp.member_flag.d.cp_f_seid_present = 1;
                res_cause = upc_parse_f_seid(&cp_f_seid, buffer,
                    &buf_pos, buf_max, obj_len);
                ros_memcpy(&report_resp.cp_f_seid, &cp_f_seid,
                    sizeof(session_f_seid));
                break;
            case UPF_F_TEID:
                report_resp.member_flag.d.n4_u_f_teid_present = 1;
                res_cause = upc_parse_f_teid(&report_resp.n4_u_f_teid, buffer,
                    &buf_pos, buf_max, obj_len);
                break;

            default:
                LOG(UPC, ERR, "IE type %d, not support, skip it.", obj_type);
                //res_cause = SESS_SERVICE_NOT_SUPPORTED;
                PFCP_MOVE_FORWORD(buf_pos, obj_len);
                /* By manual, these feature UP should not support */
                break;
        }

        /* Must go ahead in each cycle */
        if (unlikely(last_pos == buf_pos)) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "empty ie.");
            break;
        } else {
            last_pos = buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            LOG(UPC, RUNNING, "parse abnormal. cause: %d, obj_type: %d.",
                res_cause, obj_type);
            break;
        }
    }

    if (0 == mandatory_present) {
        LOG(UPC, ERR, "mandatory IE not present.");
        return;
    }

    seid_entry = upc_seid_entry_search(up_seid);
    if (seid_entry == NULL) {
        LOG(UPC, ERR, "search seid entry failed, seid: 0x%lx.", up_seid);
        return;
    }

    if (report_resp.member_flag.d.cp_f_seid_present) {
        ros_rwlock_write_lock(&seid_entry->lock); /* lock */
        memcpy(&seid_entry->session_config.cp_f_seid, &cp_f_seid, sizeof(session_f_seid));
        ros_rwlock_write_unlock(&seid_entry->lock); /* unlock */
    }

    node_cb = upc_node_get_of_index(seid_entry->session_config.node_index);
    if (node_cb == NULL) {
        LOG(UPC, ERR, "search node cb failed.");
        return;
    }
    upc_node_update_peer_sa(node_cb, sa);

    trace_flag = seid_entry->sig_trace.valid;
    if (trace_flag) {
        ros_rwlock_write_lock(&user_sig_trace.rwlock);
        upc_write_wireshark((char *)buffer, buf_max, upc_node_get_peer_ipv4(node_cb), 0);
        ros_rwlock_write_unlock(&user_sig_trace.rwlock);
    }
    LOG_TRACE(UPC, RUNNING, trace_flag, "Parse session report request finish.");

    if (res_cause != SESS_REQUEST_ACCEPTED) {
        LOG(UPC, ERR, "parse session report response failed.");
        return;
    }

    report_resp.local_seid     = seid_entry->index;
    report_resp.cp_seid        = seid_entry->session_config.cp_f_seid.seid;

    report_resp.msg_header.msg_type = SESS_SESSION_REPORT_RESPONSE;
    report_resp.msg_header.node_id_index = node_cb->index;
    report_resp.msg_header.seq_num = pkt_seq;

    /* publish packed data to sp */
    if (0 > session_report_response_proc(&report_resp)) {
        LOG(SESSION, ERR, "session report response process failed, local_seid: 0x%016lx cp_seid: 0x%016lx.",
            report_resp.local_seid, report_resp.cp_seid);
        return;
    }

    if (report_resp.member_flag.d.cp_f_seid_present) {
        if (G_TRUE == upc_get_standby_alive()) {
            session_content_modify sess_content = {{0}};

            /* 这里因为是up主动发，所以收到回复后状态设置为最后一步 */
            sess_content.local_seid = seid_entry->index;
            sess_content.node_index = seid_entry->session_config.node_index;
            memcpy(&sess_content.update_cp_fseid, &report_resp.cp_f_seid, sizeof(session_f_seid));

            if (upc_hk_build_data_block) {
                if (0 > upc_hk_build_data_block(HA_SYNC_DATA_SESS, HA_UPDATE, HA_SYNC_FINAL_STATE,
                    HA_SYNC_EVENT_SUCC, &sess_content)) {
                    LOG(UPC, ERR, "Build session sync msg failed.");
                }
            }
        }
    }
}

static int upc_build_node_report_request(
    session_node_report_request *report_req, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq, uint8_t node_type)
{
    uint16_t msg_hdr_pos = *resp_pos;
    uint16_t buf_pos = *resp_pos;
    uint8_t cnt;

    /* Encode msg header */
    pfcp_client_encode_header(resp_buffer, &buf_pos, 0, 0,
        SESS_NODE_REPORT_REQUEST, 0, pkt_seq);

    /* Encode NODE ID */
    pfcp_encode_node_id(resp_buffer, &buf_pos, node_type);

    /* Encode Node Report Type */
    tlv_encode_type(resp_buffer, &buf_pos, UPF_NODE_REPORT_TYPE);
    tlv_encode_length(resp_buffer, &buf_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, &buf_pos, report_req->node_report_type.value);
    LOG(UPC, RUNNING, "encode node report type %d.",
        report_req->node_report_type.value);

    /* Encode User Plane Path Failure Report */
    if (report_req->node_report_type.d.UPFR) {
        if (0 > upc_build_report_upfr(&report_req->path_fail_report,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build User Plane Path Failure Report failed.");
        }
    }

    /* Encode User Plane Path Recovery Report */
    if (report_req->node_report_type.d.UPRR) {
        if (0 > upc_build_report_uprr(&report_req->up_path_recovery_report,
            resp_buffer, &buf_pos)) {
            LOG(UPC, ERR, "build User Plane Path Recovery Report failed.");
        }
    }

    /* Encode Clock Drift Report */
    for (cnt = 0; cnt < report_req->clock_drift_report_num; ++cnt) {
        upc_build_clock_drift_report(&report_req->clock_drift_report[cnt],
            resp_buffer, &buf_pos);
    }

    /* Encode GTP-U Path QoS Report */
    for (cnt = 0; cnt < report_req->gtpu_path_qos_report_num; ++cnt) {
        upc_build_gtpu_path_qos_report(&report_req->gtpu_path_qos_report[cnt],
            resp_buffer, &buf_pos);
    }

    /* Filling msg header length */
    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, buf_pos);

    *resp_pos = buf_pos;

    return 0;
}

void upc_parse_node_report_response(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, struct sockaddr *sa)
{
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint8_t  m_cause = G_FALSE;
    uint8_t  cause;
    uint16_t offending_ie;
    uint16_t obj_type, obj_len;
    pfcp_node_id *node_id = NULL;
    upc_node_cb *node_cb = NULL;

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    LOG(UPC, RUNNING, "Parse node report response.");
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
                /* Declear supported mandatory option */
                m_cause = G_TRUE;

                /* Parse Cause */
                cause = tlv_decode_uint8_t(buffer, &buf_pos);

                LOG(UPC, RUNNING, "decode cause, value %d", cause);
                break;

            case UPF_OFFENDING_IE:

                /* Parse Offending IE */
                offending_ie = tlv_decode_uint16_t(buffer, &buf_pos);

                LOG(UPC, RUNNING, "decode offending IE, type %d", offending_ie);
                break;

            default:
                LOG(UPC, ERR, "IE type %d, not support, skip it.", obj_type);
                PFCP_MOVE_FORWORD(buf_pos, obj_len);
                break;
        }

        /* Must go ahead in each cycle */
        if (unlikely(last_pos == buf_pos)) {
            LOG(UPC, RUNNING, "empty ie.");
            break;
        } else {
            last_pos = buf_pos;
        }
    }

    /* Check mandaytory option */
    if ((NULL == node_id) ||(m_cause == G_FALSE)) {
        LOG(UPC, RUNNING,
            "no mandatory option node_id(%p) or cause(%d).",
            node_id, m_cause);
        return;
    }

    /* If can't find matched node */
    node_cb = upc_node_get(node_id->type.d.type, node_id->node_id);
    if (NULL == node_cb) {
        LOG(UPC, RUNNING, "no matched node found.");
        return;
    }
    upc_node_update_peer_sa(node_cb, sa);

    return;
}

int gahGetPeerMacbyIp(int ipaddr, char* buf, char* localethname)
{
    int     sockfd;
    unsigned char *ptr;
    struct arpreq arpreq;
    struct sockaddr_in *sin;
    struct sockaddr_storage ss;

    if(NULL == buf) {
        LOG(UPC, ERR, "Parameter error, buf NULL");
        return -1;
    }

    if(NULL == localethname) {
        LOG(UPC, ERR, "Parameter error, localethname NULL");
        return -1;
    }

    memset(&ss, 0, sizeof(ss));
    memset(&arpreq, 0, sizeof(arpreq));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        LOG(UPC, ERR, "socket error");
        return -1;
    }
    sin = (struct sockaddr_in *) &ss;
    sin->sin_family = AF_INET;
    memcpy(&(sin->sin_addr), &ipaddr, sizeof(int));

    sin = (struct sockaddr_in *) &arpreq.arp_pa;
    memcpy(sin, &ss, sizeof(struct sockaddr_in));
    strcpy(arpreq.arp_dev, localethname);
    arpreq.arp_ha.sa_family = AF_UNSPEC;
    if (ioctl(sockfd, SIOCGARP, &arpreq) < 0) {
        LOG(UPC, ERR, "ioctl SIOCGARP: ");
        return -1;
    }
    ptr = (unsigned char *)arpreq.arp_ha.sa_data;
    memcpy(buf, ptr, 6);

    return 0;
}

/*flag: 0 recv, 1 send*/
int upc_write_wireshark(char *buf, int len, uint32_t remote_ip, int flag)
{
    FILE*               fp;
    int                 ret = 0;
    uint16_t            buf_pos = 0;
    struct pcap_pkthdr  *pcap = NULL;
    struct pro_eth_hdr  *eth_hdr = NULL;
    struct pro_ipv4_hdr *ip_hdr = NULL;
    struct pro_udp_hdr  *udp_hdr = NULL;
    struct timeval      tv;
    upc_config_info     *upc_conf = upc_get_config();
    char                send_buf[4096] = {0};
    char                remote_mac[6] = {0};

    if(NULL == buf) {
        LOG(UPC, ERR, "Parameter error, buf NULL");
        return -1;
    }

    if(0 > gahGetPeerMacbyIp(remote_ip, remote_mac, upc_conf->upc2smf_name)) {
        LOG(UPC, ERR, "Get Mac Error. remote_ip %x, ethname %s, remote mac: %02x:%02x:%02x:%02x:%02x:%02x",
        remote_ip, upc_conf->upc2smf_name,
        remote_mac[0], remote_mac[1], remote_mac[2],
        remote_mac[3], remote_mac[4], remote_mac[5]);
    }

    /*如果文件不存在，先填充pcap文件头*/
    if (access(COMM_SIGNALING_TRACE_FILE_NAME, F_OK) != 0) {
        write_wireshark_head(COMM_SIGNALING_TRACE_FILE_NAME);
    }

    /*pcap 数据包头使用主机字节序*/
    gettimeofday(&tv,NULL);
    pcap = (struct pcap_pkthdr *)(send_buf + buf_pos);
    buf_pos += sizeof(struct pcap_pkthdr);
    pcap->caplen = len + sizeof(struct pro_eth_hdr) + sizeof(struct pro_ipv4_hdr) + sizeof(struct pro_udp_hdr);
    pcap->len = pcap->caplen;
    pcap->sec = (uint32_t)tv.tv_sec;
    pcap->usec = (uint32_t)tv.tv_usec;

    eth_hdr = (struct pro_eth_hdr *)(send_buf + buf_pos);
    buf_pos += sizeof(struct pro_eth_hdr);

    if (0 == flag) {
        /* Encode src MAC address */
        *(uint32_t *)eth_hdr->dest = *(uint32_t *)upc_conf->n4_local_mac;
        *(uint16_t *)(eth_hdr->dest + 4) = *(uint16_t *)(upc_conf->n4_local_mac + 4);

        /* Encode dest MAC address */
        *(uint32_t *)eth_hdr->source = *(uint32_t *)remote_mac;
        *(uint16_t *)(eth_hdr->source + 4) = *(uint16_t *)(remote_mac + 4);
    }
    else {
        /* Encode dest MAC address */
        *(uint32_t *)eth_hdr->dest = *(uint32_t *)remote_mac;
        *(uint16_t *)(eth_hdr->dest + 4) = *(uint16_t *)(remote_mac + 4);

        /* Encode src MAC address */
        *(uint32_t *)eth_hdr->source = *(uint32_t *)upc_conf->n4_local_mac;
        *(uint16_t *)(eth_hdr->source + 4) = *(uint16_t *)(upc_conf->n4_local_mac + 4);
    }

    /* Encode type */
    eth_hdr->eth_type = htons(ETH_PRO_IP);

    ip_hdr = (struct pro_ipv4_hdr *)(send_buf + buf_pos);
    buf_pos += sizeof(struct pro_ipv4_hdr);
    /* Encode ip version and header length */
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;

    /* Encode total length */
    ip_hdr->tot_len = htons(len + sizeof(struct pro_ipv4_hdr) + sizeof(struct pro_udp_hdr));

    /* Encode ID */
    ip_hdr->id = (uint16_t)ros_get_tsc_hz();

    /* Encode fragment */
    ip_hdr->frag_off = 0x0040;

    /* Encode TTL */
    ip_hdr->ttl = 0x40;

    /* Encode protocol */
    ip_hdr->protocol = IP_PRO_UDP;

    /* Encode checksum */
    ip_hdr->check = 0;

    if (0 == flag) {
        /* Encode src ip */
        ip_hdr->source = remote_ip;

        /* Encode dest ip */
        ip_hdr->dest = htonl(upc_conf->upf_ip_cfg[EN_PORT_N4].ipv4);
    }
    else {
        /* Encode src ip */
        ip_hdr->source = htonl(upc_conf->upf_ip_cfg[EN_PORT_N4].ipv4);

        /* Encode dest ip */
        ip_hdr->dest = remote_ip;
    }


    udp_hdr = (struct pro_udp_hdr *)(send_buf + buf_pos);
    buf_pos += sizeof(struct pro_udp_hdr);
    /* Encode src port */
    udp_hdr->source = htons(8805);

    /* Encode dest port */
    udp_hdr->dest = htons(8805);

    /* Encode udp length */
    udp_hdr->len = htons(len + sizeof(struct pro_udp_hdr));

    /* Encode checksum */
    udp_hdr->check = 0;

    udp_hdr->check = calc_crc_udp(udp_hdr, ip_hdr);
    ip_hdr->check = calc_crc_ip(ip_hdr);

    memcpy(send_buf + buf_pos, buf, len);
    buf_pos += len;

    if((fp=fopen(COMM_SIGNALING_TRACE_FILE_NAME, "a+"))==NULL) {
        LOG(UPC, ERR, "fopen error");
        return -1;
    }

    ret = fwrite(send_buf, buf_pos, 1, fp);
    if(ret < 0)
    {
        LOG(UPC, ERR, "fwrite error, ret %d", ret);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    return 0;
}

int upc_publish_sess_sig_trace(uint8_t msg_type, uint64_t up_seid, uint64_t cp_seid, uint32_t flag)
{
    session_sig_trace sess_st;

    sess_st.msg_header.msg_type = msg_type;
    sess_st.local_seid = up_seid;
    sess_st.cp_seid = cp_seid;
    sess_st.sigtrace_flag = flag;

    session_sig_trace_proc(&sess_st);
    return 0;
}

void upc_report_proc(void *report, size_t buf_len)
{
    session_msg_header *msg_header = NULL;
    upc_node_cb *node_cb = NULL;

    LOG(UPC, DEBUG, "Process redis queue data length %lu", buf_len);

    if (HA_STATUS_STANDBY < upc_get_work_status()) {

        msg_header = (session_msg_header *)report;

        node_cb = upc_node_get_of_index(msg_header->node_id_index);
        if (node_cb == NULL) {
            LOG(UPC, ERR, "search node cb failed.");
            return;
        }

        switch (msg_header->msg_type) {
            case SESS_SESSION_REPORT_REQUEST:
                {
                    uint8_t send_buf[COMM_MSG_CTRL_BUFF_LEN];
                    uint16_t send_buf_len = 0;
                    session_report_request *report_req = (session_report_request *)report;
                    upc_seid_entry *seid_entry = NULL;
                    int trace_flag = G_FALSE;

                    seid_entry = upc_seid_entry_search(report_req->local_seid);
                    if (NULL == seid_entry) {
                        LOG(UPC, ERR, "search seid entry failed, seid: 0x%lx.", report_req->local_seid);

                        return;
                    }
                    trace_flag = seid_entry->sig_trace.valid;

                    if (buf_len < sizeof(session_report_request)) {
                        LOG(UPC, ERR,
                            "session report request parse failed.\n");
                        return;
                    }

                    upc_fill_ip_udp_hdr(send_buf, &send_buf_len, &node_cb->peer_sa);

                    if (0 > upc_build_session_report_request(report_req, send_buf,
                        &send_buf_len, report_req->msg_header.seq_num, report_req->cp_seid, trace_flag)) {
                        LOG(UPC, ERR,
                            "build session report request failed.");
                        return;
                    }

                    upc_pkt_status_add(UPC_PKT_SESS_REPORT_SEND2SMF);
                    if (0 > upc_buff_send2smf(send_buf, send_buf_len, &node_cb->peer_sa)) {
                        LOG_TRACE(UPC, ERR, trace_flag, "Send packet to fpu failed.");
                        return;
                    } else if (trace_flag) {
                        ros_rwlock_write_lock(&user_sig_trace.rwlock);
                        upc_write_wireshark((char *)send_buf, send_buf_len, upc_node_get_peer_ipv4(node_cb), 1);
                        ros_rwlock_write_unlock(&user_sig_trace.rwlock);
                    }
                }
                break;
            case SESS_NODE_REPORT_REQUEST:
                {
                    uint8_t send_buf[COMM_MSG_CTRL_BUFF_LEN];
                    uint16_t send_buf_len = 0;
                    session_node_report_request *node_report_req = (session_node_report_request *)report;

                    if (buf_len < sizeof(session_node_report_request)) {
                        LOG(UPC, ERR, "node report request parse failed.\n");
                        return;
                    }

                    upc_fill_ip_udp_hdr(send_buf, &send_buf_len, &node_cb->peer_sa);

                    if (0 > upc_build_node_report_request(node_report_req, send_buf,
                        &send_buf_len, node_report_req->msg_header.seq_num, node_cb->peer_id.type.d.type)) {
                        LOG(UPC, ERR, "build node report request failed.");
                        return;
                    }

                    upc_pkt_status_add(UPC_PKT_NODE_REPORT_SEND2SMF);
                    if (0 > upc_buff_send2smf(send_buf, send_buf_len, &node_cb->peer_sa)) {
                        LOG(UPC, ERR, "Send packet to fpu failed.");
                        return;
                    }
                }
                break;
            default:
                LOG(UPC, ERR, "Unsupported message type: %d.", msg_header->msg_type);
                return;
        }
    }

    return;
}

int upc_node_create_pf_rule(char *act, char *pf_rule_name)
{
    session_content_create sess_content = {{0}};
    struct pcf_file *file_value;
    char file_name[128]={0};

    if (!pf_rule_name)
    {
        LOG(UPC, ERR, "pf_rule_name is null.");
        return -1;
    }
    if (!strcmp(act,"add"))
    {
        sprintf(file_name, "%s%s", pf_rule_name, ".ini");
        file_value=pcf_conf_read_from_given_path(PREDEFINE_RULE_PATH, file_name);
        if (!file_value)
        {
            LOG(UPC, ERR, "file_value is null[%s].", pf_rule_name);
            return -1;
        }
        else
        {
            if(upc_parse_session_content(&sess_content,file_value)<0)
            {
                LOG(UPC, ERR, "upc_parse_session_content failed[%s].",pf_rule_name);
                return -1;
            }
        }
        sess_content.msg_header.spare = 1;//创建
    }
    else
    {
        sess_content.msg_header.spare = 0;//删除
    }

    strcpy(sess_content.pdr_arr[0].act_pre_arr[0].rules_name,(char *)pf_rule_name);
    sess_content.msg_header.msg_type = SESS_LOCAL_PREDEFINE_RULE;

    LOG(SESSION, RUNNING, "upc_node_create_pf_rule:%d rules_name:%s",
        sess_content.msg_header.spare,sess_content.pdr_arr[0].act_pre_arr[0].rules_name);

    session_pf_rule_create_proc(&sess_content);

    return 0;
}

