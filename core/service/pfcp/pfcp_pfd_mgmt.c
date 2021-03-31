/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "pfcp_def.h"
#include "pfcp_client.h"
#include "upc_node.h"
#include "upc_session.h"
#include "upc_temp_buffer.h"
#include "pfcp_pfd_mgmt.h"
#include "pfd_mgmt.h"

static pfcp_pfd_table_header pfcp_pfd_mgmt;

static inline pfcp_pfd_table_header *pfcp_pfd_get_table_header(void)
{
    return &pfcp_pfd_mgmt;
}

pfcp_pfd_table_header *pfcp_pfd_get_table_header_public(void)
{
    return &pfcp_pfd_mgmt;
}

static pfcp_pfd_entry *pfcp_pfd_get_entry(uint32_t index)
{
    if (index < pfcp_pfd_mgmt.max_num)
        return &pfcp_pfd_mgmt.entry[index];
    else
        return NULL;
}

pfcp_pfd_entry *pfcp_pfd_entry_alloc(void)
{
    uint32_t index = 0, res_key = 0;
    pfcp_pfd_table_header *pfd_head = pfcp_pfd_get_table_header();

    if (G_FAILURE == Res_Alloc(pfd_head->pool_id, &res_key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(UPC, ERR, "insert seid entry failed, Resource exhaustion, pool id: %d.",
            pfd_head->pool_id);
        return NULL;
    }

    return pfcp_pfd_get_entry(index);
}

void pfcp_pfd_entry_free(uint32_t index)
{
    pfcp_pfd_table_header *pfd_head = pfcp_pfd_get_table_header();

    Res_Free(pfd_head->pool_id, 0, index);
}

static PFCP_CAUSE_TYPE pfcp_parse_pfd_flow_desc(session_pfd_flow_desc *fd,
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

        for (token = strsep(&s, delim); token != NULL;
            token = strsep(&s, delim), ++spil_times) {
            if (*token == 0) {
                continue;
            }

            switch (spil_times) {
                case 0:
                    if (0 == strncmp(token, "permit", 6)) {
                        fd->action = 0;
                    } else if (0 == strncmp(token, "deny", 6)) {
                        fd->action = 1;
                    } else {
                        LOG(UPC, ERR, "parse flow description failed, <action> error: %s.", token);
                        res_cause = SESS_INVALID_LENGTH;
                    }
                    break;

                case 1:
                    if (0 == strncmp(token, "in", 3)) {
                        fd->dir = 0;
                    } else if (0 == strncmp(token, "out", 3)) {
                        fd->dir = 1;
                    } else {
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

                        if (fd->dir == 0) {
                            break;
                        }

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            if (0 == strncmp(tk, "!", 1)) {
                                fd->ip_not = 1;
                            }

                            if (0 == strncmp(tk, "any", 3)) {
                                ros_memset(&fd->ip, 0, IPV6_ALEN);
                                ros_memset(&fd->mask, 0, IPV6_ALEN);
                                fd->ip_type = SESSION_IP_V4V6;
                                break;
                            } else if (strchr(tk, ':')) {
                                /* ipv6 */
                                if (1 != inet_pton(AF_INET6, tk, fd->ip.ipv6)) {
                                    LOG(UPC, ERR,
                                        "parse flow description source failed, ipv6: %s.", tk);
                                    res_cause = SESS_INVALID_LENGTH;
                                }
                                fd->ip_type = SESSION_IP_V6;
                            } else {
                                /* ipv4 */
                                if (1 != inet_pton(AF_INET, tk, &fd->ip.ipv4)) {
                                    LOG(UPC, ERR,
                                        "parse flow description source failed, ipv4: %s.", tk);
                                    res_cause = SESS_INVALID_LENGTH;
                                }
                                fd->ip.ipv4 = ntohl(fd->ip.ipv4);
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
                                fd->mask.ipv4_mask = num_to_mask(prefix);
                            } else {
                                ipv6_prefix_to_mask(fd->mask.ipv6_mask, prefix);
                            }
                        } else {
                            if (fd->ip_type == SESSION_IP_V4) {
                                fd->mask.ipv4_mask = 0xFFFFFFFF;
                            } else {
                                ros_memset(fd->mask.ipv6_mask, 0xFF, IPV6_ALEN);
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
                                fd->no_port = 1;
                                ++spil_times;
                                break;
                            }

                            if (fd->dir == 0) {
                                break;
                            }

                            fd->no_port = 0;
                            fd->port_min = atoi(tk);
                        } else {
                            LOG(UPC, ERR, "parse flow description failed, Incomplete field.");
                            res_cause = SESS_INVALID_LENGTH;
                        }

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            fd->port_max = atoi(tk);
                        } else {
                            fd->port_max = fd->port_min;
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

                        if (fd->dir == 1) {
                            break;
                        }

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            if (0 == strncmp(tk, "!", 1)) {
                                fd->ip_not = 1;
                            }

                            if (0 == strncmp(tk, "assigned", 8) || 0 == strncmp(tk, "any", 3)) {
                                ros_memset(&fd->ip, 0, IPV6_ALEN);
                                ros_memset(&fd->mask, 0, IPV6_ALEN);
                                fd->ip_type = SESSION_IP_V4V6;
                                break;
                            } else if (strchr(tk, ':')) {
                                /* ipv6 */
                                if (1 != inet_pton(AF_INET6, tk, fd->ip.ipv6)) {
                                    LOG(UPC, ERR,
                                        "parse flow description source failed, ipv6: %s.", tk);
                                    res_cause = SESS_INVALID_LENGTH;
                                }
                                fd->ip_type = SESSION_IP_V6;
                            } else {
                                /* ipv4 */
                                if (1 != inet_pton(AF_INET, tk, &fd->ip.ipv4)) {
                                    LOG(UPC, ERR,
                                        "parse flow description source failed, ipv4: %s.", tk);
                                    res_cause = SESS_INVALID_LENGTH;
                                }
                                fd->ip.ipv4 = ntohl(fd->ip.ipv4);
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
                                fd->mask.ipv4_mask = num_to_mask(prefix);
                            } else {
                                ipv6_prefix_to_mask(fd->mask.ipv6_mask, prefix);
                            }
                        } else {
                            if (fd->ip_type == SESSION_IP_V4) {
                                fd->mask.ipv4_mask = 0xFFFFFFFF;
                            } else {
                                ros_memset(fd->mask.ipv6_mask, 0xFF, IPV6_ALEN);
                            }
                        }
                    }
                    break;

                case 8:
                    {
                        /* dest port */
                        char ch[] = "-";
                        char *tk = NULL;

                        if (fd->dir == 1) {
                            break;
                        }

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            fd->no_port = 0;
                            fd->port_min = atoi(tk);
                        } else {
                            fd->no_port = 1;
                            break;
                        }

                        tk = strsep(&token, ch);
                        if (NULL != tk) {
                            fd->port_max = atoi(tk);
                        } else {
                            fd->port_max = fd->port_min;
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

static PFCP_CAUSE_TYPE pfcp_parse_pfd_contents(session_pfd_contents *contents,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max, uint16_t obj_len)
{
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint16_t len_cnt = 0, tmp_len;
    session_up_features uf = {.value = upc_get_up_features()};

    if (obj_len && ((*buf_pos + obj_len) <= buf_max)) {
        /* flag */
        len_cnt += sizeof(uint16_t);
        if (len_cnt <= obj_len) {
            contents->flag.value = tlv_decode_uint16_t(buffer, buf_pos);
        } else {
            LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                obj_len, len_cnt);
            res_cause = SESS_INVALID_LENGTH;
            return res_cause;
        }

        if (contents->flag.d.FD) {
            /* Flow Description */
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                tmp_len = tlv_decode_uint16_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be not greater than %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            if (contents->fd_num < MAX_PFD_FD_NUM) {
                len_cnt += tmp_len;
                if (len_cnt > obj_len) {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be not greater than %d.",
                        obj_len, len_cnt);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }

                res_cause = pfcp_parse_pfd_flow_desc(&contents->fd[contents->fd_num], buffer, buf_pos,
                    buf_max, tmp_len);
                if (res_cause != SESS_REQUEST_ACCEPTED) {
                    LOG(UPC, ERR, "Parse PFD flow description fail.");
                    return res_cause;
                }
                ++contents->fd_num;
            } else {
                LOG(UPC, ERR, "Parse PFD flow description number abnormal, Should be less than %d.",
                    MAX_PFD_FD_NUM);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (contents->flag.d.URL) {
            /* URL */
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                tmp_len = tlv_decode_uint16_t(buffer, buf_pos);
                if (tmp_len >= MAX_PFD_URL_LEN) {
                    LOG(UPC, ERR, "Parse PFD URL length abnormal, Should be less than %d.", MAX_PFD_URL_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            if (contents->url_num < MAX_PFD_FD_NUM) {
                len_cnt += tmp_len;
                if (len_cnt > obj_len) {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be not greater than %d.",
                        obj_len, len_cnt);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }

                tlv_decode_binary(buffer, buf_pos, tmp_len, (uint8_t *)contents->url[contents->url_num]);
                contents->url[contents->url_num][tmp_len] = '\0';
                ++contents->url_num;
            } else {
                LOG(UPC, ERR, "Parse PFD flow description number abnormal, Should be less than %d.",
                    MAX_PFD_FD_NUM);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (contents->flag.d.DN) {
            /* Domain Name */
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                tmp_len = tlv_decode_uint16_t(buffer, buf_pos);
                if (tmp_len >= FQDN_LEN) {
                    LOG(UPC, ERR, "Parse PFD domain name length abnormal, Should be less than %d.", FQDN_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            if (contents->domain_names_num < MAX_PFD_DN_NUM) {
                len_cnt += tmp_len;
                if (len_cnt > obj_len) {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be not greater than %d.",
                        obj_len, len_cnt);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }

                tlv_decode_binary(buffer, buf_pos, tmp_len,
                    (uint8_t *)contents->domain_names[contents->domain_names_num]);
                contents->domain_names[contents->domain_names_num][tmp_len] = '\0';
                ++contents->domain_names_num;
            } else {
                LOG(UPC, ERR, "Parse PFD domain name number abnormal, Should be less than %d.",
                    MAX_PFD_DN_NUM);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (contents->flag.d.CP) {
            /* Custom PFD Content */
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                tmp_len = tlv_decode_uint16_t(buffer, buf_pos);
                if (tmp_len >= MAX_PFD_CUSTOM_PFD_LEN) {
                    LOG(UPC, ERR, "Parse PFD Custom PFD Content length abnormal, Should be less than %d.",
                        MAX_PFD_CUSTOM_PFD_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            len_cnt += tmp_len;
            if (len_cnt > obj_len) {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be not greater than %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            tlv_decode_binary(buffer, buf_pos, tmp_len, (uint8_t *)contents->custom_pfd);
            contents->custom_pfd[tmp_len] = '\0';
        }

        if (contents->flag.d.DNP) {
            /* Domain Name Protocol */
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                tmp_len = tlv_decode_uint16_t(buffer, buf_pos);
                if (tmp_len >= MAX_PFD_DNP_LEN) {
                    LOG(UPC, ERR, "Parse PFD domain name protocol length abnormal, Should be less than %d.",
                        MAX_PFD_DNP_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            if (contents->domain_name_pro_num < MAX_PFD_DN_NUM) {
                len_cnt += tmp_len;
                if (len_cnt > obj_len) {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be not greater than %d.",
                        obj_len, len_cnt);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }

                tlv_decode_binary(buffer, buf_pos, tmp_len,
                    (uint8_t *)contents->domain_name_pro[contents->domain_name_pro_num]);
                contents->domain_name_pro[contents->domain_name_pro_num][tmp_len] = '\0';
                ++contents->domain_name_pro_num;
            } else {
                LOG(UPC, ERR, "Parse PFD domain name protocol number abnormal, Should be less than %d.",
                    MAX_PFD_DN_NUM);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }
        }

        if (contents->flag.d.AFD) {
            uint16_t total_add_len, cur_offset = 0;

            /* Additional Flow Description */
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                total_add_len = tlv_decode_uint16_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            len_cnt += total_add_len;
            if (len_cnt > obj_len) {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be not greater than %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            while (cur_offset < total_add_len) {
                cur_offset += sizeof(uint16_t);
                tmp_len = tlv_decode_uint16_t(buffer, buf_pos);

                if (contents->fd_num < MAX_PFD_FD_NUM) {
                    cur_offset += tmp_len;
                    res_cause = pfcp_parse_pfd_flow_desc(&contents->fd[contents->fd_num], buffer, buf_pos,
                        buf_max, tmp_len);
                    if (res_cause != SESS_REQUEST_ACCEPTED) {
                        LOG(UPC, ERR, "Parse PFD flow description fail.");
                        return res_cause;
                    }
                    ++contents->fd_num;
                } else {
                    LOG(UPC, ERR, "Parse PFD flow description number abnormal, Should be less than %d.",
                        MAX_PFD_FD_NUM);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            }
        }

        if (contents->flag.d.AURL) {
            uint16_t total_add_len, cur_offset = 0;

            /* Additional URL */
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                total_add_len = tlv_decode_uint16_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            len_cnt += total_add_len;
            if (len_cnt > obj_len) {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be not greater than %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            while (cur_offset < total_add_len) {
                cur_offset += sizeof(uint16_t);
                tmp_len = tlv_decode_uint16_t(buffer, buf_pos);

                if (contents->url_num < MAX_PFD_FD_NUM) {
                    cur_offset += tmp_len;
                    tlv_decode_binary(buffer, buf_pos, tmp_len,
                        (uint8_t *)contents->url[contents->url_num]);
                    contents->url[contents->url_num][tmp_len] = '\0';
                    ++contents->url_num;
                } else {
                    LOG(UPC, ERR, "Parse PFD flow description number abnormal, Should be less than %d.",
                        MAX_PFD_FD_NUM);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            }
        }

        if (contents->flag.d.ADNP) {
            uint16_t total_add_len, cur_offset = 0;

            /* Additional Domain Name and Domain Name Protocol */
            len_cnt += sizeof(uint16_t);
            if (len_cnt <= obj_len) {
                total_add_len = tlv_decode_uint16_t(buffer, buf_pos);
            } else {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            len_cnt += total_add_len;
            if (len_cnt > obj_len) {
                LOG(UPC, ERR, "obj_len: %d abnormal, Should be not greater than %d.",
                    obj_len, len_cnt);
                res_cause = SESS_INVALID_LENGTH;
                return res_cause;
            }

            while (cur_offset < total_add_len) {
                cur_offset += sizeof(uint16_t);
                tmp_len = tlv_decode_uint16_t(buffer, buf_pos);

                if (contents->domain_names_num < MAX_PFD_DN_NUM) {
                    cur_offset += tmp_len;
                    tlv_decode_binary(buffer, buf_pos, tmp_len, (uint8_t *)
                        contents->domain_names[contents->domain_names_num]);
                    contents->domain_names[contents->domain_names_num][tmp_len] = '\0';
                    ++contents->domain_names_num;
                } else {
                    LOG(UPC, ERR, "Parse PFD domain name number abnormal, Should be less than %d.",
                        MAX_PFD_DN_NUM);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }

                cur_offset += sizeof(uint16_t);
                tmp_len = tlv_decode_uint16_t(buffer, buf_pos);

                if (contents->domain_name_pro_num < MAX_PFD_DN_NUM) {
                    cur_offset += tmp_len;
                    tlv_decode_binary(buffer, buf_pos, tmp_len,
                        (uint8_t *)contents->domain_name_pro[contents->domain_names_num]);
                    contents->domain_name_pro[contents->domain_names_num][tmp_len] = '\0';
                    ++contents->domain_names_num;
                } else {
                    LOG(UPC, ERR, "Parse PFD domain name protocol number abnormal, Should be less than %d.",
                        MAX_PFD_DN_NUM);
                    res_cause = SESS_INVALID_LENGTH;
                    return res_cause;
                }
            }
        }

        if ((-(int)(contents->flag.value) & contents->flag.value) != contents->flag.value && uf.d.PFDE == 0) {
            LOG(UPC, ERR,
                "Configuration error, PFD set multiple values, but PFDE of UP features not set.");
            res_cause = SESS_SERVICE_NOT_SUPPORTED;
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

static PFCP_CAUSE_TYPE pfcp_parse_pfd_context(session_pfd_context *context,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_pfd_management_response *pfd_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse PFD context.");
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
            case UPF_PFD_CONTENTS:
                if (context->pfd_contents_num < MAX_PFD_NUM_IN_APP) {
                    res_cause = pfcp_parse_pfd_contents(&context->pfd_contents[context->pfd_contents_num], buffer,
                        buf_pos, *buf_pos + obj_len, obj_len);
                    ++context->pfd_contents_num;
                    m_opt = 1;
                } else {
                    LOG(UPC, ERR,
                        "The number of PFD contents reaches the upper limit.");
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
            LOG(UPC, ERR, "parse abnormal.");
            if (0 == pfd_rep->offending_ie_present) {
                pfd_rep->offending_ie_present = 1;
                pfd_rep->offending_ie = obj_type;
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

static PFCP_CAUSE_TYPE pfcp_parse_application_ids_pfds(session_application_ids_pfds *ids,
    uint8_t* buffer, uint16_t *buf_pos, int buf_max,
    session_pfd_management_response *pfd_rep)
{
    uint16_t last_pos = 0;
    uint16_t obj_type = 0, obj_len = 0;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    uint8_t m_opt = 0;

    LOG(UPC, RUNNING, "Parse Application ID's PFDs.");
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
            case UPF_APPLICATION_ID:
                if (obj_len < MAX_APP_ID_LEN) {
                    m_opt = 1;
                    tlv_decode_binary(buffer, buf_pos, obj_len,
                        (uint8_t *)ids->application_id);
                    ids->application_id[obj_len] = '\0';
                } else {
                    LOG(UPC, ERR, "obj_len: %d abnormal, Should be less than %u.",
                        obj_len, MAX_APP_ID_LEN);
                    res_cause = SESS_INVALID_LENGTH;
                }
                break;

            case UPF_PFD_CONTEXT:
                if (ids->pfd_context_num < MAX_PFD_NUM_IN_APP) {
                    res_cause = pfcp_parse_pfd_context(
                        &ids->pfd_context[ids->pfd_context_num], buffer,
                        buf_pos, *buf_pos + obj_len, pfd_rep);
                    ++ids->pfd_context_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of PFD context reaches the upper limit.");
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
            LOG(UPC, ERR, "parse abnormal.");
            if (0 == pfd_rep->offending_ie_present) {
                pfd_rep->offending_ie_present = 1;
                pfd_rep->offending_ie = obj_type;
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

int pfcp_local_pfd_request_proc(session_pfd_mgmt_request *pfd_mgmt_req)
{
    /* publish packed data to sp */
    if (pfd_mgmt_req->app_ids_pfds_num == 0) {
        /* 当Application ID's PFDs IE中的PFD context数量为0意味着要删除该app id关联的所有context */
        pfd_table_clean_all();
    } else {
        int16_t cnt;
        uint8_t err_ret = 0;

        for (cnt = 0; cnt < pfd_mgmt_req->app_ids_pfds_num; ++cnt) {
            if (pfd_mgmt_req->app_ids_pfds[cnt].pfd_context_num == 0) {
                /* 当Application ID's PFDs IE中的PFD context数量为0意味着要删除该app id关联的所有context */
                if (0 > pfd_entry_remove(pfd_mgmt_req->app_ids_pfds[cnt].application_id)) {
                    LOG(SESSION, ERR, "Remove pfd entry fail, no such PFD.");
                }
            } else {
                if (0 > pfd_entry_insert(&pfd_mgmt_req->app_ids_pfds[cnt])) {
                    LOG(SESSION, ERR, "Insert pfd entry fail.");
                    err_ret = 1;
                    break;
                }
            }
        }

        if (err_ret) { /* 异常失败回滚 */
            for (; cnt >= 0; --cnt) {
                if (pfd_mgmt_req->app_ids_pfds[cnt].pfd_context_num > 0) {
                    (void)pfd_entry_remove(pfd_mgmt_req->app_ids_pfds[cnt].application_id);
                }
            }

            return -1;
        }
    }

    return 0;
}

void pfcp_parse_pfd_mgmt_request(uint8_t* buffer,
    uint16_t buf_pos1, int buf_max, uint32_t pkt_seq, struct sockaddr *sa)
{
    uint8_t  resp_buffer[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t resp_pos = 0;
    EN_UPC_HA_SYNC_EVENTS sync_event = HA_SYNC_EVENT_SUCC;
    uint8_t sync_blk_exist = FALSE;
    uint32_t sync_blk_index;
    uint16_t buf_pos = buf_pos1, last_pos = 0;
    uint16_t obj_type, obj_len;
    PFCP_CAUSE_TYPE res_cause = SESS_REQUEST_ACCEPTED;
    upc_node_cb *node_cb;
    session_pfd_mgmt_request pfd_mgmt_req = {{0}};
    session_pfd_management_response pfd_resp = {{0}};
    pfcp_pfd_entry *pfd_entry = NULL;

    LOG(UPC, RUNNING, "buf_pos %d, buf_max %d", buf_pos, buf_max);

    node_cb = upc_get_node_by_sa(sa);
    if (unlikely(NULL == node_cb)) {
        uint16_t msg_hdr_pos;

        upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, sa);

        msg_hdr_pos = resp_pos;
        /* Encode msg header */
        pfcp_client_encode_header(resp_buffer, &resp_pos, 0, 0,
            SESS_PFD_MANAGEMENT_RESPONSE, 0, pkt_seq);

        /* Encode cause */
        tlv_encode_type(resp_buffer, &resp_pos, UPF_CAUSE);
        tlv_encode_length(resp_buffer, &resp_pos, sizeof(uint8_t));
        tlv_encode_uint8_t(resp_buffer, &resp_pos, SESS_NO_ESTABLISHED_PFCP_ASSOCIATION);

        LOG(UPC, ERR, "Process PFD management request fail, no such node.");

        pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, resp_pos);
        upc_buff_send2smf(resp_buffer, resp_pos, sa);
        return;
    }

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
            case UPF_APPLICATION_IDS_PFDS:
                if (pfd_mgmt_req.app_ids_pfds_num < MAX_PFD_APP_IDS_NUM) {
                    res_cause = pfcp_parse_application_ids_pfds(
                        &pfd_mgmt_req.app_ids_pfds[pfd_mgmt_req.app_ids_pfds_num], buffer,
                        &buf_pos, buf_pos + obj_len, &pfd_resp);
                    ++pfd_mgmt_req.app_ids_pfds_num;
                } else {
                    LOG(UPC, ERR,
                        "The number of Application IDs PFDs reaches the upper limit.");
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
        if (unlikely(last_pos == buf_pos)) {
            res_cause = SESS_INVALID_LENGTH;
            LOG(UPC, RUNNING, "empty ie.");
            break;
        } else {
            last_pos = buf_pos;
        }

        if (res_cause != SESS_REQUEST_ACCEPTED) {
            if (0 == pfd_resp.offending_ie_present) {
                pfd_resp.offending_ie_present = 1;
                pfd_resp.offending_ie = obj_type;
            }
            LOG(UPC, ERR, "parse abnormal. cause: %d, obj_type: %d.",
                pfd_resp.cause, pfd_resp.offending_ie);
            break;
        }
    }

    if (res_cause != SESS_REQUEST_ACCEPTED) {
        LOG(UPC, ERR, "parse session establishment request failed.");

        goto fast_response;
    }

    pfd_mgmt_req.msg_header.msg_type = SESS_PFD_MANAGEMENT_REQUEST;
    pfd_mgmt_req.msg_header.node_id_index = node_cb->index;
    pfd_mgmt_req.msg_header.seq_num = pkt_seq;

    pfd_entry = pfcp_pfd_entry_alloc();
    if (NULL == pfd_entry) {
        LOG(UPC, ERR, "Alloc pfd entry failed.");

        res_cause = SESS_NO_RESOURCES_AVAILABLE;
        goto fast_response;
    }

    pfd_mgmt_req.entry_index = pfd_entry->index;

    if (upc_hk_build_data_block) {
        sync_blk_index = upc_hk_build_data_block(HA_SYNC_DATA_PFD, HA_CREATE, HA_SYNC_RECV_FROM_CP,
            sync_event, &pfd_mgmt_req);
        if (0 > sync_blk_index) {

            LOG(UPC, ERR, "Build pfd sync msg failed.");
            res_cause = SESS_CREATE_SYNC_DATA_BLOCK_FAILURE;

            goto fast_response;
        }
        sync_blk_exist = TRUE;
    }

    /* publish packed data to sp */
    if (pfd_mgmt_req.app_ids_pfds_num == 0) {
        /* 当Application ID's PFDs IE中的PFD context数量为0意味着要删除该app id关联的所有context */
        pfd_table_clean_all();
    } else {
        int16_t cnt;
        uint8_t err_ret = 0;

        for (cnt = 0; cnt < pfd_mgmt_req.app_ids_pfds_num; ++cnt) {
            if (pfd_mgmt_req.app_ids_pfds[cnt].pfd_context_num == 0) {
                /* 当Application ID's PFDs IE中的PFD context数量为0意味着要删除该app id关联的所有context */
                if (0 > pfd_entry_remove(pfd_mgmt_req.app_ids_pfds[cnt].application_id)) {
                    LOG(SESSION, ERR, "Remove pfd entry fail, no such PFD.");
                }
            } else {
                if (0 > pfd_entry_insert(&pfd_mgmt_req.app_ids_pfds[cnt])) {
                    LOG(SESSION, ERR, "Insert pfd entry fail.");
                    err_ret = 1;
                    break;
                }
            }
        }

        if (err_ret) { /* 异常失败回滚 */
            for (; cnt >= 0; --cnt) {
                if (pfd_mgmt_req.app_ids_pfds[cnt].pfd_context_num > 0) {
                    (void)pfd_entry_remove(pfd_mgmt_req.app_ids_pfds[cnt].application_id);
                }
            }

            pfd_resp.cause = SESS_REQUEST_REJECTED;
            sync_event = HA_SYNC_EVENT_FAIL;

            goto fast_response;
        }
    }

fast_response:

    upc_fill_ip_udp_hdr(resp_buffer, &resp_pos, sa);

    pfd_resp.cause = res_cause;
    pfcp_build_pfd_management_response(&pfd_resp, resp_buffer, &resp_pos, pkt_seq);

    if (0 > upc_buff_send2smf(resp_buffer, resp_pos, sa)) {
        LOG(UPC, ERR, "Send packet to SMF failed.");
    }

    if (sync_blk_exist) {
        if (upc_hk_change_sync_blk_status) {
            if (0 > upc_hk_change_sync_blk_status(sync_blk_index, HA_SYNC_REPLY_TO_CP, sync_event)) {
                LOG(UPC, ERR, "Change PFD sync msg failed, pfd_entry->index: %u.", pfd_entry ? pfd_entry->index : 0);
            }
        }
    }

	if (pfd_entry)
    	pfcp_pfd_entry_free(pfd_entry->index);
}

void pfcp_build_pfd_management_response(session_pfd_management_response *pfd_rep, uint8_t *resp_buffer,
    uint16_t *resp_pos, uint32_t pkt_seq)
{
    uint16_t msg_hdr_pos = *resp_pos;

    if (NULL == pfd_rep || NULL == resp_buffer || NULL == resp_pos) {
        LOG(UPC, ERR,
            "Abnormal parameters, pfd_rep(%p), resp_buffer(%p), resp_pos(%p).",
            pfd_rep, resp_buffer, resp_pos);
        return;
    }

    /* Encode msg header */
    pfcp_client_encode_header(resp_buffer, resp_pos, 0, 0,
        SESS_PFD_MANAGEMENT_RESPONSE, 0, pkt_seq);

    /* Encode cause */
    tlv_encode_type(resp_buffer, resp_pos, UPF_CAUSE);
    tlv_encode_length(resp_buffer, resp_pos, sizeof(uint8_t));
    tlv_encode_uint8_t(resp_buffer, resp_pos, pfd_rep->cause);
    LOG(UPC, RUNNING, "encode cause %d.", pfd_rep->cause);

    /* Encode offending ie */
    if (pfd_rep->offending_ie_present) {
        tlv_encode_type(resp_buffer, resp_pos, UPF_OFFENDING_IE);
        tlv_encode_length(resp_buffer, resp_pos, sizeof(uint16_t));
        tlv_encode_uint16_t(resp_buffer, resp_pos, pfd_rep->offending_ie);
        LOG(UPC, RUNNING, "encode offending ie %d.", pfd_rep->offending_ie);
    }

    /* Filling msg header length */
    pfcp_client_set_header_length(resp_buffer, msg_hdr_pos, *resp_pos);
}

int64_t pfcp_pfd_table_init(uint32_t pfd_num)
{
    pfcp_pfd_table_header *table_hdr = pfcp_pfd_get_table_header();
    uint32_t index = 0;
    int pool_id = -1;
    pfcp_pfd_entry *entry = NULL;
    int64_t size = 0, total_memory = 0;

    if (0 == pfd_num) {
        LOG(UPC, ERR, "Abnormal parameter, pfd_num: %u.", pfd_num);
        return -1;
    }

    size = sizeof(pfcp_pfd_entry) * pfd_num;
    entry = ros_malloc(size);
    if (NULL == entry) {
        LOG(UPC, ERR, "init PFD table failed, no enough memory, entry number: %u.",
            pfd_num);
        return -1;
    }
    ros_memset(entry, 0, size);

    for (index = 0; index < pfd_num; ++index) {
        entry[index].index = index;
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, pfd_num)) {
        return -1;
    }

    table_hdr->pool_id      = pool_id;
    table_hdr->entry        = entry;
    table_hdr->max_num      = pfd_num;
    ros_rwlock_init(&table_hdr->lock);
    total_memory += size;

    LOG(UPC, RUNNING, "PFD table init success.");

    return total_memory;
}



