/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "cJSON.h"
#include "parse_session_config.h"

static char *read_file(const char *filename)
{
    FILE *file = NULL;
    long length = 0;
    char *content = NULL;
    size_t read_chars = 0;

    /* open in read binary mode */
    file = fopen(filename, "rb");
    if (file == NULL) {
        goto cleanup;
    }

    /* get the length */
    if (fseek(file, 0, SEEK_END) != 0) {
        goto cleanup;
    }
    length = ftell(file);
    if (length < 0) {
        goto cleanup;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        goto cleanup;
    }

    /* allocate content buffer */
    content = (char*)malloc((size_t)length + sizeof(""));
    if (content == NULL) {
        LOG(COMM, ERR, "Failed to apply for memory.");
        goto cleanup;
    }

    /* read the file into memory */
    read_chars = fread(content, sizeof(char), (size_t)length, file);
    if ((long)read_chars != length) {
        free(content);
        content = NULL;
        LOG(COMM, ERR, "Failed to read file into memory.");
        goto cleanup;
    }
    content[read_chars] = '\0';


cleanup:
    if (file != NULL) {
        fclose(file);
    }

    return content;
}

static cJSON *psc_parse_session_file(const char * const filename)
{
    char *file = NULL;
    cJSON *json = NULL;

    file = read_file(filename);
    if (NULL == file) {
        LOG(COMM, ERR, "Failed to read file.");
        return NULL;
    }

    json = cJSON_Parse(file);
    if (NULL == json) {
        LOG(COMM, ERR, "Failed to parse test json file.");
    }
    free(file);

    return json;
}

int psc_parse_f_seid(cJSON *parse, session_f_seid *fseid)
{
    cJSON *parse_tmp = NULL;

    /* SEID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "seid");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        fseid->seid = (uint64_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <seid> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* IPv4 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv4_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ip_addr = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ip_addr, &fseid->ipv4_addr)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            fseid->ipv4_addr = ntohl(fseid->ipv4_addr);
            fseid->ip_version.d.v4 = 1;
        } else {
            /* Maybe you can use the default value(stub IP address) */
            LOG(COMM, ERR, "The type of the keyword <ipv4_address> is not a string.");
            return -1;
        }
    }

    /* IPv6 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv6_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ip_addr = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ip_addr, fseid->ipv6_addr)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            fseid->ip_version.d.v6 = 1;
        } else {
            /* Maybe you can use the default value(stub IP address) */
            LOG(COMM, ERR, "The type of the keyword <ipv6_address> is not a string.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_f_teid(cJSON *parse, session_f_teid *fteid)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        fteid->f_teid_flag.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* TEID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "teid");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            fteid->teid = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <teid> is not numeric.");
            return -1;
        }
    }

    /* IPv4 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv4_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv4_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ipv4_str, &fteid->ipv4_addr)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            fteid->ipv4_addr = ntohl(fteid->ipv4_addr);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv4_address> is not a string.");
            return -1;
        }
    }

    /* IPv6 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv6_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv6_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ipv6_str, fteid->ipv6_addr)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv6_address> is not a string.");
            return -1;
        }
    }

    /* CHOOSE ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "choose_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            fteid->choose_id = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <choose_id> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_ue_ip(cJSON *parse, session_ue_ip *ue_ip)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        ue_ip->ueip_flag.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* IPv4 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv4_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv4_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ipv4_str, &ue_ip->ipv4_addr)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            ue_ip->ipv4_addr = ntohl(ue_ip->ipv4_addr);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv4_address> is not a string.");
            return -1;
        }
    }

    /* IPv6 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv6_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv6_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ipv6_str, ue_ip->ipv6_addr)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv6_address> is not a string.");
            return -1;
        }
    }

    /* IPv6 Prefix Delegation Bits */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv6_prefix_delegation_bits");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            ue_ip->ipv6_prefix = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv6_prefix_delegation_bits> is not numeric.");
            return -1;
        }
    }

    /* IPv6 Prefix Length */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv6_prefix_length");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            ue_ip->ipv6_prefix_len = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv6_prefix_length> is not numeric.");
            return -1;
        }
    }

    return 0;
}

/* Redundant Transmission Detection Parameters IE in PDI */
int psc_parse_redundant_trans_detection_param(cJSON *parse, session_redundant_transmission_detection_param *rtdp)
{
    cJSON *parse_tmp = NULL;

    /* Local F-TEID for Redundant Transmission */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "local_f_teid");
    if (NULL == parse_tmp || !cJSON_IsObject(parse_tmp)) {
        LOG(COMM, ERR, "Missing mandatory keyword <local_f_teid> or The type is not an object.");
        return -1;
    }
    if (0 > psc_parse_f_teid(parse_tmp, &rtdp->fteid)) {
        LOG(COMM, ERR, "Parse Local F-TEID for Redundant Transmission failed.");
        return -1;
    }

    /* Network Instance for Redundant Transmission */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "network_instance");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            if (strlen(cJSON_GetStringValue(parse_tmp)) < NETWORK_INSTANCE_LEN) {
                strcpy(rtdp->network_instance, cJSON_GetStringValue(parse_tmp));
            } else {
                LOG(COMM, ERR, "The length of the <network_instance> value is too long.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <network_instance> is not a string.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_sdf_filter(cJSON *parse, session_sdf_filter *sdf_filter)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        sdf_filter->sdf_flag.value = (uint16_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Flow Description */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flow_description");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char src[512];
            char *s = src;
            char delim[] = " ";
            char *token = NULL;
            uint8_t spil_times = 0;
            session_flow_desc *fd = &sdf_filter->desc;

            strcpy(src, cJSON_GetStringValue(parse_tmp));

            fd->no_sp = fd->no_dp = 1;

            for (token = strsep(&s, delim); token != NULL;
                token = strsep(&s, delim), ++spil_times) {
                if (*token == 0) {
                    continue;
                }

                switch (spil_times) {
                    case 0:
                        if (strncmp(token, "permit", 6)) {
                            LOG(COMM, ERR, "Parse flow description failed, <action> error: %s.", token);
                            return -1;
                        }
                        break;

                    case 1:
                        if (strncmp(token, "out", 3)) {
                            LOG(COMM, ERR, "Parse flow description failed, <dir> error: %s.", token);
                            return -1;
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
                            LOG(COMM, ERR, "Parse flow description failed, <from> error: %s.", token);
                            return -1;
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
                                        LOG(COMM, ERR,
                                            "Parse flow description source failed, ipv6: %s.", tk);
                                        return -1;
                                    }
                                    fd->ip_type = SESSION_IP_V6;
                                } else {
                                    /* ipv4 */
                                    if (1 != inet_pton(AF_INET, tk, &fd->sip.sipv4)) {
                                        LOG(COMM, ERR,
                                            "Parse flow description source failed, ipv4: %s.", tk);
                                        return -1;
                                    }
                                    fd->sip.sipv4 = ntohl(fd->sip.sipv4);
                                    fd->ip_type = SESSION_IP_V4;
                                }
                            } else {
                                LOG(COMM, ERR, "Parse flow description failed, missing source ip.");
                                return -1;
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
                                /* The port may not exist */
                                if (0 == strncmp(tk, "to", 2)) {
                                    fd->no_sp = 1;
                                    ++spil_times;
                                    break;
                                }

                                fd->no_sp = 0;
                                fd->sp_min = atoi(tk);
                            } else {
                                LOG(COMM, ERR, "Parse flow description failed, Incomplete field.");
                                return -1;
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
                            LOG(COMM, ERR, "Parse flow description failed, <to> error: %s.", token);
                            return -1;
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
                                        LOG(COMM, ERR,
                                            "Parse flow description source failed, ipv6: %s.", tk);
                                        return -1;
                                    }
                                    fd->ip_type = SESSION_IP_V6;
                                } else {
                                    /* ipv4 */
                                    if (1 != inet_pton(AF_INET, tk, &fd->dip.dipv4)) {
                                        LOG(COMM, ERR,
                                            "Parse flow description source failed, ipv4: %s.", tk);
                                        return -1;
                                    }
                                    fd->dip.dipv4 = ntohl(fd->dip.dipv4);
                                    fd->ip_type = SESSION_IP_V4;
                                }
                            } else {
                                LOG(COMM, ERR, "Parse flow description failed, missing source ip.");
                                return -1;
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
                        LOG(COMM, ERR,
                            "Parse flow description failed, abnormal spil_times: %d, token: %s.",
                            spil_times, token ? token : "NULL");
                        return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <flow_description> is not a string.");
            return -1;
        }
    }

    /* ToS Traffic Class */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "tos_traffic_class");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            sdf_filter->tos_traffic_class.value = (uint16_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <tos_traffic_class> is not numeric.");
            return -1;
        }
    }

    /* Security Parameter Index */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "security_parameter_index");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            sdf_filter->ipsec_spi = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <security_parameter_index> is not numeric.");
            return -1;
        }
    }

    /* Flow Label */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flow_label");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            sdf_filter->label.value = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <flow_label> is not numeric.");
            return -1;
        }
    }

    /* SDF Filter ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "sdf_filter_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            sdf_filter->sdf_id = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <sdf_filter_id> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_ethernet_pdu_session_info(cJSON *parse, session_eth_pdu_sess_info *epsi)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        epsi->value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    return 0;
}

static int psc_parse_mac(uint8_t *mac, char *str)
{
    int cnt_mac = 0;
    char mac_str[6][PCF_STR_LEN] = {{0,},};
    int ret = -1;

    ret = pcf_str_split(str, ':', mac_str, ETH_ALEN);
    if (ret < ETH_ALEN) {
        LOG(COMM, ERR, "Split string: %s failed, ret: %d.", str, ret);
        return -1;
    }
    for (cnt_mac = 0; cnt_mac < ETH_ALEN; ++cnt_mac) {
        mac[cnt_mac] = strtol(mac_str[cnt_mac], NULL, 16);
    }

    return 0;
}

int psc_parse_mac_address(cJSON *parse, session_mac_addr *mac_addr)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        mac_addr->mac_flag.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Source MAC address value */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "source_mac_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *mac_str = cJSON_GetStringValue(parse_tmp);

            if (0 > psc_parse_mac(mac_addr->src, mac_str)) {
                LOG(COMM, ERR, "Parse MAC address failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <source_mac_address> is not a string.");
            return -1;
        }
    }

    /* Destination MAC address value */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "destination_mac_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *mac_str = cJSON_GetStringValue(parse_tmp);

            if (0 > psc_parse_mac(mac_addr->dst, mac_str)) {
                LOG(COMM, ERR, "Parse MAC address failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <destination_mac_address> is not a string.");
            return -1;
        }
    }

    /* Upper Source MAC address value */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "upper_source_mac_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *mac_str = cJSON_GetStringValue(parse_tmp);

            if (0 > psc_parse_mac(mac_addr->upper_src, mac_str)) {
                LOG(COMM, ERR, "Parse MAC address failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <upper_source_mac_address> is not a string.");
            return -1;
        }
    }

    /* Upper Destination MAC address value */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "upper_destination_mac_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *mac_str = cJSON_GetStringValue(parse_tmp);

            if (0 > psc_parse_mac(mac_addr->upper_dst, mac_str)) {
                LOG(COMM, ERR, "Parse MAC address failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <upper_destination_mac_address> is not a string.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_vlan_tag(cJSON *parse, session_vlan_tag *vlan)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        vlan->flags.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Value */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "value");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        vlan->value.value = (uint16_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <value> is missing or the type of the value is not numeric.");
        return -1;
    }

    return 0;
}

int psc_parse_ethernet_packet_filter(cJSON *parse, session_eth_filter *eth_filter)
{
    cJSON *parse_tmp = NULL;

    /* Ethernet Filter ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ethernet_filter_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            eth_filter->eth_filter_id = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ethernet_filter_id> is not numeric.");
            return -1;
        }
    }

    /* Ethernet Filter Properties */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ethernet_filter_properties");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            eth_filter->eth_filter_prop.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ethernet_filter_properties> is not numeric.");
            return -1;
        }
    }

    /* MAC address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "mac_address");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_mac_address(parse_cnt, &eth_filter->mac_addr[eth_filter->mac_addr_num])) {
                    eth_filter->mac_addr_num++;
                } else {
                    LOG(COMM, ERR, "Parse <mac_address> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <mac_address> is not an array.");
        }
    }

    /* Ethertype */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ethertype");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            eth_filter->eth_type = (uint16_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ethertype> is not numeric.");
            return -1;
        }
    }

    /* C-TAG */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "c_tag");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 > psc_parse_vlan_tag(parse_tmp, &eth_filter->c_tag)) {
                LOG(COMM, ERR, "Parse <c_tag> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <c_tag> is not an object.");
            return -1;
        }
    }

    /* S-TAG */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "s_tag");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 > psc_parse_vlan_tag(parse_tmp, &eth_filter->c_tag)) {
                LOG(COMM, ERR, "Parse <s_tag> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <s_tag> is not an object.");
            return -1;
        }
    }

    /* SDF Filter */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "sdf_filter");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_sdf_filter(parse_cnt, &eth_filter->sdf_arr[eth_filter->sdf_arr_num])) {
                    eth_filter->sdf_arr_num++;
                } else {
                    LOG(COMM, ERR, "Parse <sdf_filter> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <sdf_filter> is not an array.");
        }
    }

    return 0;
}

int psc_parse_framed_route(cJSON *parse, session_framed_route *framed_route)
{
    cJSON *parse_tmp = NULL;

    /* Destination IP address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "destination_ip");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv4_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ipv4_str, &framed_route->dest_ip)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
            framed_route->dest_ip = ntohl(framed_route->dest_ip);
        } else {
            LOG(COMM, ERR, "The type of the keyword <destination_ip> is not a string.");
            return -1;
        }
    }

    /* Destination IP prefix length */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "destination_ip_prefix_length");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            framed_route->ip_mask = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <destination_ip_prefix_length> is not numeric.");
            return -1;
        }
    }

    /* Gateway */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "gateway");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv4_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ipv4_str, &framed_route->gateway)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
            framed_route->gateway = ntohl(framed_route->gateway);
        } else {
            LOG(COMM, ERR, "The type of the keyword <gateway> is not a string.");
            return -1;
        }
    }

    /* Metrics */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "metrics");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            framed_route->metrics = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <metrics> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_framed_ipv6_route(cJSON *parse, session_framed_route_ipv6 *framed_ipv6_route)
{
    cJSON *parse_tmp = NULL;

    /* Destination IP address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "destination_ip");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv6_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ipv6_str, &framed_ipv6_route->dest_ip)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <destination_ip> is not a string.");
            return -1;
        }
    }

    /* Destination IP prefix length */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "destination_ip_prefix_length");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            framed_ipv6_route->ip_mask[0] = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <destination_ip_prefix_length> is not numeric.");
            return -1;
        }
    }

    /* Gateway */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "gateway");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv6_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ipv6_str, &framed_ipv6_route->gateway)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <gateway> is not a string.");
            return -1;
        }
    }

    /* Metrics */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "metrics");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            framed_ipv6_route->metrics = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <metrics> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_ip_multicast_address(cJSON *parse, session_ip_multicast_address *ip_mul_addr)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        ip_mul_addr->flag.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Start IPv4 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "start_ipv4_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv4_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ipv4_str, &ip_mul_addr->start_ip.ipv4)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
            ip_mul_addr->start_ip.ipv4 = ntohl(ip_mul_addr->start_ip.ipv4);
        } else {
            LOG(COMM, ERR, "The type of the keyword <start_ipv4_address> is not a string.");
            return -1;
        }
    }

    /* Start IPv6 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "start_ipv6_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv6_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ipv6_str, ip_mul_addr->start_ip.ipv6)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <start_ipv6_address> is not a string.");
            return -1;
        }
    }

    /* End IPv4 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "end_ipv4_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv4_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ipv4_str, &ip_mul_addr->end_ip.ipv4)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
            ip_mul_addr->end_ip.ipv4 = ntohl(ip_mul_addr->end_ip.ipv4);
        } else {
            LOG(COMM, ERR, "The type of the keyword <end_ipv4_address> is not a string.");
            return -1;
        }
    }

    /* End IPv6 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "end_ipv6_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv6_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ipv6_str, ip_mul_addr->end_ip.ipv6)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <end_ipv6_address> is not a string.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_source_ip_address(cJSON *parse, session_source_ip_address *src_ip)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        src_ip->flag.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* IPv4 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv4_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv4_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ipv4_str, &src_ip->ipv4)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            src_ip->ipv4 = ntohl(src_ip->ipv4);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv4_address> is not a string.");
            return -1;
        }
    }

    /* IPv6 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv6_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv6_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ipv6_str, src_ip->ipv6)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv6_address> is not a string.");
            return -1;
        }
    }

    /* mask/prefix length */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "prefix_length");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            src_ip->prefix_len = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <prefix_length> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_ip_multicast_addressing_info(cJSON *parse, session_ip_multicast_addr_info *imai)
{
    cJSON *parse_tmp = NULL;

    /* IP Multicast Address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ip_multicast_address");
    if (NULL == parse_tmp) {
        LOG(COMM, ERR, "Missing mandatory keyword <ip_multicast_address>");
        return -1;
    }
    if (0 > psc_parse_ip_multicast_address(parse_tmp, &imai->ip_mul_addr)) {
        LOG(COMM, ERR, "Parse <ip_multicast_address> failed.");
        return -1;
    }

    /* Source IP Address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "source_ip_address");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_source_ip_address(parse_cnt, &imai->source_ip[imai->source_ip_num])) {
                    imai->source_ip_num++;
                } else {
                    LOG(COMM, ERR, "Parse <source_ip_address> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <source_ip_address> is not an array.");
        }
    }

    return 0;
}

int psc_parse_pdr_pdi(cJSON *parse, session_packet_detection_info *pdi)
{
    cJSON *parse_tmp = NULL;

    /* Source Interface */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "source_interface");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        pdi->si = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <source_interface> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Local F-TEID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "local_f_teid");
    if (parse_tmp) {
        if (0 == psc_parse_f_teid(parse_tmp, &pdi->local_fteid)) {
            pdi->member_flag.d.local_fteid_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <local_f_teid> failed.");
            return -1;
        }
    }

    /* Network Instance */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "network_instance");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            if (strlen(cJSON_GetStringValue(parse_tmp)) < NETWORK_INSTANCE_LEN) {
                strcpy(pdi->network_instance, cJSON_GetStringValue(parse_tmp));
                pdi->member_flag.d.network_instance_present = 1;
            } else {
                LOG(COMM, ERR, "The length of the <network_instance> value is too long.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <network_instance> is not a string.");
            return -1;
        }
    }

    /* Redundant Transmission Detection Parameters */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "redundant_transmission_detection_parameters");
    if (parse_tmp) {
        if (0 == psc_parse_redundant_trans_detection_param(parse_tmp, &pdi->redundant_transmission_param)) {
            pdi->member_flag.d.redundant_transmission_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <redundant_transmission_detection_parameters> failed.");
            return -1;
        }
    }

    /* UE IP address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ue_ip_address");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_ue_ip(parse_cnt, &pdi->ue_ipaddr[pdi->ue_ipaddr_num])) {
                    pdi->ue_ipaddr_num++;
                } else {
                    LOG(COMM, ERR, "Parse <ue_ip_address> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <ue_ip_address> is not an array.");
        }
    }

    /* Traffic Endpoint ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "traffic_endpoint_id");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                pdi->traffic_endpoint_id[pdi->traffic_endpoint_num++] = (uint8_t)cJSON_GetNumberValue(parse_cnt);
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <traffic_endpoint_id> is not an array.");
        }
    }

    /* SDF Filter */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "sdf_filter");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_sdf_filter(parse_cnt, &pdi->sdf_filter[pdi->sdf_filter_num])) {
                    pdi->sdf_filter_num++;
                } else {
                    LOG(COMM, ERR, "Parse <sdf_filter> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <sdf_filter> is not an array.");
        }
    }

    /* Application ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "application_id");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            if (strlen(cJSON_GetStringValue(parse_tmp)) < MAX_APP_ID_LEN) {
                strcpy(pdi->application_id, cJSON_GetStringValue(parse_tmp));
                pdi->member_flag.d.application_id_present = 1;
            } else {
                LOG(COMM, ERR, "The length of the <application_id> value is too long.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <application_id> is not a string.");
            return -1;
        }
    }

    /* Ethernet PDU Session Information */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ethernet_pdu_session_info");
    if (parse_tmp) {
        if (0 == psc_parse_ethernet_pdu_session_info(parse_tmp, &pdi->eth_pdu_ses_info)) {
            pdi->member_flag.d.eth_pdu_ses_info_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <ethernet_pdu_session_info> failed.");
            return -1;
        }
    }

    /* Ethernet Packet Filter */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ethernet_packet_filter");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_ethernet_packet_filter(parse_cnt, &pdi->eth_filter[pdi->eth_filter_num])) {
                    pdi->eth_filter_num++;
                } else {
                    LOG(COMM, ERR, "Parse <ethernet_packet_filter> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <ethernet_packet_filter> is not an array.");
        }
    }

    /* QFI */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "qfi");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                pdi->qfi_array[pdi->qfi_number++] = (uint8_t)cJSON_GetNumberValue(parse_cnt);
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <qfi> is not an array.");
        }
    }

    /* Framed-Route */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "framed_route");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_framed_route(parse_cnt, &pdi->framed_route[pdi->framed_route_num])) {
                    pdi->framed_route_num++;
                } else {
                    LOG(COMM, ERR, "Parse <framed_route> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <framed_route> is not an array.");
        }
    }

    /* Framed-Routing */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "framed_routing");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            pdi->framed_routing = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <framed_routing> is not numeric.");
            return -1;
        }
    }

    /* Framed-IPv6-Route */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "framed_ipv6_route");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_framed_ipv6_route(parse_cnt, &pdi->framed_ipv6_route[pdi->framed_ipv6_route_num])) {
                    pdi->framed_ipv6_route_num++;
                } else {
                    LOG(COMM, ERR, "Parse <framed_ipv6_route> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <framed_ipv6_route> is not an array.");
        }
    }

    /* Source Interface Type */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "source_interface_type");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            pdi->src_if_type.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <source_interface_type> is not numeric.");
            return -1;
        }
    }

    /* IP Multicast Addressing Info */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ip_multicast_addressing_info");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_ip_multicast_addressing_info(parse_cnt,
                    &pdi->ip_mul_addr_info[pdi->ip_mul_addr_num])) {
                    pdi->ip_mul_addr_num++;
                } else {
                    LOG(COMM, ERR, "Parse <ip_multicast_addressing_info> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <ip_multicast_addressing_info> is not an array.");
        }
    }

    return 0;
}

int psc_parse_outer_header_removal(cJSON *parse, session_outer_header_removal *ohr)
{
    cJSON *parse_tmp = NULL;

    /* Outer Header Removal Description */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "outer_header_removal_description");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        ohr->type = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <outer_header_removal_description> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* GTP-U Extension Header Deletion */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "gtp_u_extension_header_deletion");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        ohr->gtp_u_exten = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <gtp_u_extension_header_deletion> is missing or the type of the value is not numeric.");
        return -1;
    }

    return 0;
}

int psc_parse_remote_gtp_u_peer(cJSON *parse, session_remote_gtpu_peer *rgp)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        rgp->regtpr_flag.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* IPv4 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv4_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv4_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ipv4_str, &rgp->ipv4_addr)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            rgp->ipv4_addr = ntohl(rgp->ipv4_addr);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv4_address> is not a string.");
            return -1;
        }
    }

    /* IPv6 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv6_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv6_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ipv6_str, rgp->ipv6_addr)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv6_address> is not a string.");
            return -1;
        }
    }

    /* Destination Interface field */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "destination_interface");
    if (parse_tmp) {
        if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
            rgp->dest_if = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <destination_interface> is not numeric.");
            return -1;
        }
    }

    /* Network Instance field */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "network_instance");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            if (strlen(cJSON_GetStringValue(parse_tmp)) < NETWORK_INSTANCE_LEN) {
                strcpy(rgp->net_instance, cJSON_GetStringValue(parse_tmp));
            } else {
                LOG(COMM, ERR, "The length of the <network_instance> value is too long.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <network_instance> is not a string.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_transport_delay_reporting(cJSON *parse, session_transport_delay_reporting *tdr)
{
    cJSON *parse_tmp = NULL;

    /* Preceding UL GTP-U Peer */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "preceding_ul_gtp_u_peer");
    if (parse_tmp) {
        if (0 == psc_parse_remote_gtp_u_peer(parse_tmp, &tdr->preceding_ul_gtpu_peer)) {
        } else {
            LOG(COMM, ERR, "Parse <preceding_ul_gtp_u_peer> failed.");
            return -1;
        }
    }

    /* DSCP */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "dscp");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            tdr->dscp.value = (uint16_t)cJSON_GetNumberValue(parse_tmp);
            tdr->dscp_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <dscp> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_redirect_information(cJSON *parse, session_redirect_info *ri)
{
    cJSON *parse_tmp = NULL;

    /* Redirect Address Type */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "address_type");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        ri->addr_type = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <address_type> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Redirect Server Address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "redirect_server_address");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsString(parse_cnt)) {
                    switch (ri->addr_type) {
                        case 0:
                        case 1:
                        case 4:
                            {
                                char *ip_str = cJSON_GetStringValue(parse_tmp);

                                if (strchr(ip_str, ':')) {
                                    if (1 != inet_pton(AF_INET6, ip_str, ri->address.ipv6_addr)) {
                                        LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                                        return -1;
                                    }
                                } else {
                                    if (1 != inet_pton(AF_INET, ip_str, &ri->address.ipv4_addr)) {
                                        LOG(COMM, ERR, "inet_pton failed, error: %s.", strerror(errno));
                                        return -1;
                                    }
                                    ri->address.ipv4_addr = ntohl(ri->address.ipv4_addr);
                                }

                            }
                            break;

                        case 2:
                            if (strlen(cJSON_GetStringValue(parse_cnt)) < REDIRECT_SERVER_ADDR_LEN) {
                                strcpy(ri->address.url, cJSON_GetStringValue(parse_cnt));
                            } else {
                                LOG(COMM, ERR, "The length of the <redirect_server_address> value is too long.");
                                return -1;
                            }
                            break;

                        case 3:
                            if (strlen(cJSON_GetStringValue(parse_cnt)) < REDIRECT_SERVER_ADDR_LEN) {
                                strcpy(ri->address.sip_uri, cJSON_GetStringValue(parse_cnt));
                            } else {
                                LOG(COMM, ERR, "The length of the <redirect_server_address> value is too long.");
                                return -1;
                            }
                            break;

                        default:
                            LOG(COMM, ERR, "Unknown <Redirect Address Type> value.");
                            return -1;
                    }
                } else {
                    LOG(COMM, ERR, "The type of the keyword <redirect_server_address> is not a string.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <redirect_server_address> is not an array.");
        }
    }

    return 0;
}

int psc_parse_outer_header_creation(cJSON *parse, session_outer_header_create *ohc)
{
    cJSON *parse_tmp = NULL;

    /* Outer Header Creation Description */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "outer_header_creation_description");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        ohc->type.value = (uint16_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <outer_header_creation_description> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* TEID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "teid");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            ohc->teid = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <teid> is not numeric.");
            return -1;
        }
    }

    /* IPv4 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv4_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv4_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET, ipv4_str, &ohc->ipv4)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            ohc->ipv4 = ntohl(ohc->ipv4);
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv4_address> is not a string.");
            return -1;
        }
    }

    /* IPv6 address */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ipv6_address");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            char *ipv6_str = cJSON_GetStringValue(parse_tmp);

            if (1 != inet_pton(AF_INET6, ipv6_str, ohc->ipv6)) {
                LOG(COMM, ERR, "inet_pton failed, error: %s.",
                    strerror(errno));
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <ipv6_address> is not a string.");
            return -1;
        }
    }

    /* Port Number */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "port_number");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            ohc->port = (uint16_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <port_number> is not numeric.");
            return -1;
        }
    }

    /* C-TAG */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "c_tag");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 > psc_parse_vlan_tag(parse_tmp, &ohc->ctag)) {
                LOG(COMM, ERR, "Parse <c_tag> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <c_tag> is not an object.");
            return -1;
        }
    }

    /* S-TAG */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "s_tag");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 > psc_parse_vlan_tag(parse_tmp, &ohc->stag)) {
                LOG(COMM, ERR, "Parse <s_tag> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <s_tag> is not an object.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_header_enrichment(cJSON *parse, session_header_enrichment *he)
{
    cJSON *parse_tmp = NULL;

    /* Header Type */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "header_type");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        he->header_type = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <header_type> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Header Field Name */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "header_field_name");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            if (strlen(cJSON_GetStringValue(parse_tmp)) < SESSION_MAX_HEADER_FIELD_LEN) {
                strcpy(he->name, cJSON_GetStringValue(parse_tmp));
                he->name_length = strlen(he->name);
            } else {
                LOG(COMM, ERR, "The length of the <header_field_name> value is too long.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <header_field_name> is not a string.");
            return -1;
        }
    }

    /* Header Field Value */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "header_field_value");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            if (strlen(cJSON_GetStringValue(parse_tmp)) < SESSION_MAX_HEADER_FIELD_LEN) {
                strcpy(he->value, cJSON_GetStringValue(parse_tmp));
                he->value_length = strlen(he->value);
            } else {
                LOG(COMM, ERR, "The length of the <header_field_value> value is too long.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <header_field_value> is not a string.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_far_forwarding_parameters(cJSON *parse, session_forward_params *fp)
{
    cJSON *parse_tmp = NULL;

    /* Destination Interface */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "destination_interface");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        fp->dest_if = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        fp->member_flag.d.dest_if_present = 1;
    } else {
        LOG(COMM, ERR, "The required keyword <destination_interface> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Network Instance */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "network_instance");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            if (strlen(cJSON_GetStringValue(parse_tmp)) < NETWORK_INSTANCE_LEN) {
                strcpy(fp->network_instance, cJSON_GetStringValue(parse_tmp));
                fp->member_flag.d.network_instance_present = 1;
            } else {
                LOG(COMM, ERR, "The length of the <network_instance> value is too long.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <network_instance> is not a string.");
            return -1;
        }
    }

    /* Redirect Information */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "redirect_information");
    if (parse_tmp) {
        if (0 == psc_parse_redirect_information(parse_tmp, &fp->redirect_addr)) {
            fp->member_flag.d.redirect_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <redirect_information> failed.");
            return -1;
        }
    }

    /* Outer Header Creation */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "outer_header_creation");
    if (parse_tmp) {
        if (0 == psc_parse_outer_header_creation(parse_tmp, &fp->outer_header_creation)) {
            fp->member_flag.d.ohc_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <outer_header_creation> failed.");
            return -1;
        }
    }

    /* Transport Level Marking */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "transport_level_marking");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            fp->trans.value = (uint16_t)cJSON_GetNumberValue(parse_tmp);
            fp->member_flag.d.trans_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <transport_level_marking> is not numeric.");
            return -1;
        }
    }

    /* Forwarding Policy */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "forwarding_policy");
    if (parse_tmp) {
        if (cJSON_IsString(parse_tmp)) {
            if (strlen(cJSON_GetStringValue(parse_tmp)) < FORWARDING_POLICY_LEN) {
                strcpy(fp->forwarding_policy, cJSON_GetStringValue(parse_tmp));
                fp->member_flag.d.forwarding_policy_present = 1;
            } else {
                LOG(COMM, ERR, "The length of the <forwarding_policy> value is too long.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <forwarding_policy> is not a string.");
            return -1;
        }
    }

    /* Header Enrichment */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "header_enrichment");
    if (parse_tmp) {
        if (0 == psc_parse_header_enrichment(parse_tmp, &fp->header_enrichment)) {
            fp->member_flag.d.header_enrichment_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <header_enrichment> failed.");
            return -1;
        }
    }

    /* Linked Traffic Endpoint ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "linked_traffic_endpoint_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            fp->traffic_endpoint_id = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            fp->member_flag.d.traffic_endpoint_id_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <linked_traffic_endpoint_id> is not numeric.");
            return -1;
        }
    }

    /* Proxying */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "proxying");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            fp->proxying.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            fp->member_flag.d.proxying_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <proxying> is not numeric.");
            return -1;
        }
    }

    /* Destination Interface Type */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "destination_interface_type");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            fp->dest_if_type.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            fp->member_flag.d.dest_if_type_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <destination_interface_type> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_urr_volume(cJSON *parse, session_urr_volume *vol)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        vol->flag.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Total Volume */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "total_volume");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            vol->total = (uint64_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <total_volume> is not numeric.");
            return -1;
        }
    }

    /* Uplink Volume */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "uplink_volume");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            vol->uplink = (uint64_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <uplink_volume> is not numeric.");
            return -1;
        }
    }

    /* Downlink Volume */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "downlink_volume");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            vol->downlink = (uint64_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <downlink_volume> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_urr_dropped_dl_traffic_threshold(cJSON *parse, session_urr_drop_thres *drop_thres)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        drop_thres->flag.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Downlink Packets */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "downlink_packets");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            drop_thres->packets = (uint64_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <downlink_packets> is not numeric.");
            return -1;
        }
    }

    /* Number of Bytes of Downlink Data */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "downlink_data_bytes");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            drop_thres->bytes = (uint64_t)cJSON_GetNumberValue(parse_tmp);
        } else {
            LOG(COMM, ERR, "The type of the keyword <downlink_data_bytes> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_additional_monitoring_time(cJSON *parse, session_urr_add_mon_time *amt)
{
    cJSON *parse_tmp = NULL;

    /* Monitoring Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "monitoring_time");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            amt->mon_time = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            amt->member_flag.d.mon_time_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <monitoring_time> is not numeric.");
            return -1;
        }
    }

    /* Subsequent Volume Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_volume_threshold");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_urr_volume(parse_tmp, &amt->sub_vol_thres)) {
                amt->member_flag.d.sub_vol_thres_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <subsequent_volume_threshold> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_volume_threshold> is not an object.");
            return -1;
        }
    }

    /* Subsequent Time Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_time_threshold");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            amt->sub_tim_thres = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            amt->member_flag.d.sub_tim_thres_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_time_threshold> is not numeric.");
            return -1;
        }
    }

    /* Subsequent Volume Quota */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_volume_quota");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_urr_volume(parse_tmp, &amt->sub_vol_quota)) {
                amt->member_flag.d.sub_vol_quota_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <subsequent_volume_quota> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_volume_quota> is not an object.");
            return -1;
        }
    }

    /* Subsequent Time Quota */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_time_quota");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            amt->sub_tim_quota = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            amt->member_flag.d.sub_tim_quota_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_time_quota> is not numeric.");
            return -1;
        }
    }

    /* Subsequent Event Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_event_threshold");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            amt->sub_eve_thres = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            amt->member_flag.d.sub_eve_thres_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_event_threshold> is not numeric.");
            return -1;
        }
    }

    /* Subsequent Event Quota */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_event_quota");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            amt->sub_eve_quota = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            amt->member_flag.d.sub_eve_quota_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_event_quota> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_qer_gate_status(cJSON *parse, session_qer_gate_status *gate)
{
    cJSON *parse_tmp = NULL;

    /* UL Gate */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ul_gate");
    if (parse_tmp && cJSON_IsString(parse_tmp)) {
        if (strcasecmp(cJSON_GetStringValue(parse_tmp), "OPEN")) {
            gate->d.ul_gate = 0;
        } else if (strcasecmp(cJSON_GetStringValue(parse_tmp), "CLOSED")) {
            gate->d.ul_gate = 1;
        } else {
            LOG(COMM, ERR, "Abnormal parameter value \"%s\"", cJSON_GetStringValue(parse_tmp));
            return -1;
        }
    } else {
        LOG(COMM, ERR, "The required keyword <ul_mbr> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* DL Gate */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "dl_gate");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        if (strcasecmp(cJSON_GetStringValue(parse_tmp), "OPEN")) {
            gate->d.dl_gate = 0;
        } else if (strcasecmp(cJSON_GetStringValue(parse_tmp), "CLOSED")) {
            gate->d.dl_gate = 1;
        } else {
            LOG(COMM, ERR, "Abnormal parameter value \"%s\"", cJSON_GetStringValue(parse_tmp));
            return -1;
        }
    } else {
        LOG(COMM, ERR, "The required keyword <dl_mbr> is missing or the type of the value is not numeric.");
        return -1;
    }

    return 0;
}

int psc_parse_qer_mbr(cJSON *parse, session_mbr *mbr)
{
    cJSON *parse_tmp = NULL;

    /* UL MBR */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ul_mbr");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        mbr->ul_mbr = (uint64_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <ul_mbr> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* DL MBR */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "dl_mbr");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        mbr->dl_mbr = (uint64_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <dl_mbr> is missing or the type of the value is not numeric.");
        return -1;
    }

    return 0;
}

int psc_parse_qer_gbr(cJSON *parse, session_gbr *gbr)
{
    cJSON *parse_tmp = NULL;

    /* UL GBR */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ul_gbr");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        gbr->ul_gbr = (uint64_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <ul_gbr> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* DL GBR */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "dl_gbr");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        gbr->dl_gbr = (uint64_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <dl_gbr> is missing or the type of the value is not numeric.");
        return -1;
    }

    return 0;
}

int psc_parse_qer_packet_rate_status(cJSON *parse, session_packet_rate_status *pkt_rate_stat)
{
    cJSON *parse_tmp = NULL;

    /* Flags */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "flags");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        pkt_rate_stat->flag.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <flags> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Number of Remaining Uplink Packets Allowed */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "remaining_uplink_packets_allowed");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        pkt_rate_stat->remain_ul_packets = (uint16_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <remaining_uplink_packets_allowed> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Number of Remaining Additional Uplink Packets Allowed */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "remaining_additional_uplink_packets_allowed");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        pkt_rate_stat->addit_remain_ul_packets = (uint16_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <remaining_additional_uplink_packets_allowed> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Number of Remaining Downlink Packets Allowed */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "remaining_downlink_packets_allowed");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        pkt_rate_stat->remain_dl_packets = (uint16_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <remaining_downlink_packets_allowed> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Number of Remaining Additional Downlink Packets Allowed */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "remaining_additional_downlink_packets_allowed");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        pkt_rate_stat->addit_remain_dl_packets = (uint16_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <remaining_additional_downlink_packets_allowed> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Rate Control Status Validity Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "rate_control_status_validity_time");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        pkt_rate_stat->rate_ctrl_status_time = (uint64_t)cJSON_GetNumberValue(parse_tmp);
    } else {
        LOG(COMM, ERR, "The required keyword <rate_control_status_validity_time> is missing or the type of the value is not numeric.");
        return -1;
    }

    return 0;
}

int psc_parse_create_pdr(cJSON *parse, session_pdr_create *create_pdr)
{
    cJSON *parse_tmp = NULL;

    /* PDR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "pdr_id");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        create_pdr->pdr_id = (uint16_t)cJSON_GetNumberValue(parse_tmp);
        create_pdr->member_flag.d.pdr_id_present = 1;
    } else {
        LOG(COMM, ERR, "The required keyword <pdr_id> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Precedence */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "precedence");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        create_pdr->precedence = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        create_pdr->member_flag.d.precedence_present = 1;
    } else {
        LOG(COMM, ERR, "The required keyword <precedence> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* PDI */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "pdi");
    if (parse_tmp && cJSON_IsObject(parse_tmp)) {
        if (0 == psc_parse_pdr_pdi(parse_tmp, &create_pdr->pdi_content)) {
            create_pdr->member_flag.d.pdi_content_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <pdi> failed.");
            return -1;
        }
    } else {
        LOG(COMM, ERR, "The required keyword <pdi> is missing or the type of the value is not an object.");
        return -1;
    }

    /* Outer Header Removal */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "outer_header_removal");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_outer_header_removal(parse_tmp, &create_pdr->outer_header_removal)) {
                create_pdr->member_flag.d.OHR_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <outer_header_removal> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <outer_header_removal> is not an object.");
            return -1;
        }
    }

    /* FAR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "far_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->far_id = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.far_id_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <far_id> is not numeric.");
            return -1;
        }
    }

    /* URR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "urr_id");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsNumber(parse_cnt)) {
                    create_pdr->urr_id_array[create_pdr->urr_id_number++]= (uint32_t)cJSON_GetNumberValue(parse_cnt);
                } else {
                    LOG(COMM, ERR, "The type of the keyword <urr_id> is not numeric.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <urr_id> is not an array.");
        }
    }

    /* QER ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "qer_id");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsNumber(parse_cnt)) {
                    create_pdr->qer_id_array[create_pdr->qer_id_number++]= (uint32_t)cJSON_GetNumberValue(parse_cnt);
                } else {
                    LOG(COMM, ERR, "The type of the keyword <qer_id> is not numeric.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <qer_id> is not an array.");
        }
    }

    /* Activate Predefined Rules */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "activate_predefined_rules");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsString(parse_cnt)) {
                    if (strlen(cJSON_GetStringValue(parse_cnt)) < ACTIVATE_PREDEF_LEN) {
                        strcpy(create_pdr->act_pre_arr[create_pdr->act_pre_number++].rules_name,
                            cJSON_GetStringValue(parse_cnt));
                    } else {
                        LOG(COMM, ERR, "The length of the <activate_predefined_rules> value is too long.");
                        return -1;
                    }
                } else {
                    LOG(COMM, ERR, "The type of the keyword <activate_predefined_rules> is not a string.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <activate_predefined_rules> is not an array.");
        }
    }

    /* Activation Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "activation_time");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->activation_time = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.act_time_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <activation_time> is not numeric.");
            return -1;
        }
    }

    /* Deactivation Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "deactivation_time");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->deactivation_time = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.deact_time_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <deactivation_time> is not numeric.");
            return -1;
        }
    }

    /* MAR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "mar_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->mar_id = (uint16_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.mar_id_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <mar_id> is not numeric.");
            return -1;
        }
    }

    /* Packet Replication and Detection Carry-On Information */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "packet_replication_and_detection_carry_on_info");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->pkt_rd_carry_on_info.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.pkt_rd_carry_on_info_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <packet_replication_and_detection_carry_on_info> is not numeric.");
            return -1;
        }
    }

    /* IP Multicast Addressing Info */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ip_multicast_addressing_info");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_ip_multicast_addressing_info(parse_cnt,
                    &create_pdr->ip_mul_addr_info[create_pdr->ip_mul_addr_num])) {
                    create_pdr->ip_mul_addr_num++;
                } else {
                    LOG(COMM, ERR, "Parse <ip_multicast_addressing_info> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <ip_multicast_addressing_info> is not an array.");
        }
    }

    /* UE IP address Pool Identity */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ue_ip_address_pool_identity");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsString(parse_cnt)) {
                    if (strlen(cJSON_GetStringValue(parse_cnt)) < UE_IP_ADDRESS_POOL_LEN) {
                        strcpy(create_pdr->ueip_addr_pool_identity[create_pdr->ueip_addr_pool_identity_num++].pool_identity,
                            cJSON_GetStringValue(parse_cnt));
                    } else {
                        LOG(COMM, ERR, "The length of the <ue_ip_address_pool_identity> value is too long.");
                        return -1;
                    }
                } else {
                    LOG(COMM, ERR, "The type of the keyword <ue_ip_address_pool_identity> is not a string.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <ue_ip_address_pool_identity> is not an array.");
        }
    }

    /* MPTCP Applicable Indication */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "mptcp_applicable_indication");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->mptcp_app_indication.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.mptcp_app_indication_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <mptcp_applicable_indication> is not numeric.");
            return -1;
        }
    }

    /* Transport Delay Reporting */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "transport_delay_reporting");
    if (parse_tmp) {
        if (0 == psc_parse_transport_delay_reporting(parse_tmp, &create_pdr->transport_delay_rep)) {
            create_pdr->member_flag.d.transport_delay_rep_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <transport_delay_reporting> failed.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_create_predefined_pdr(cJSON *parse, session_pdr_create *create_pdr)
{
    cJSON *parse_tmp = NULL;

    /* Predefined name */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "predefined_name");
    if (parse_tmp && cJSON_IsString(parse_tmp)) {
        if (strlen(cJSON_GetStringValue(parse_tmp)) < ACTIVATE_PREDEF_LEN) {
            strcpy(create_pdr->act_pre_arr[0].rules_name, cJSON_GetStringValue(parse_tmp));
            create_pdr->act_pre_number = 1;
        } else {
            LOG(COMM, ERR, "The length of the <predefined_name> value is too long.");
            return -1;
        }
    } else {
        LOG(COMM, ERR, "The required keyword <predefined_name> is missing or the type of the value is not a string.");
        return -1;
    }

    /* PDI */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "pdi");
    if (parse_tmp && cJSON_IsObject(parse_tmp)) {
        if (0 == psc_parse_pdr_pdi(parse_tmp, &create_pdr->pdi_content)) {
            create_pdr->member_flag.d.pdi_content_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <pdi> failed.");
            return -1;
        }
    } else {
        LOG(COMM, ERR, "The required keyword <pdi> is missing or the type of the value is not an object.");
        return -1;
    }

    /* Outer Header Removal */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "outer_header_removal");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_outer_header_removal(parse_tmp, &create_pdr->outer_header_removal)) {
                create_pdr->member_flag.d.OHR_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <outer_header_removal> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <outer_header_removal> is not an object.");
            return -1;
        }
    }

    /* FAR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "far_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->far_id = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.far_id_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <far_id> is not numeric.");
            return -1;
        }
    }

    /* URR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "urr_id");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsNumber(parse_cnt)) {
                    create_pdr->urr_id_array[create_pdr->urr_id_number++]= (uint32_t)cJSON_GetNumberValue(parse_cnt);
                } else {
                    LOG(COMM, ERR, "The type of the keyword <urr_id> is not numeric.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <urr_id> is not an array.");
        }
    }

    /* QER ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "qer_id");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsNumber(parse_cnt)) {
                    create_pdr->qer_id_array[create_pdr->qer_id_number++]= (uint32_t)cJSON_GetNumberValue(parse_cnt);
                } else {
                    LOG(COMM, ERR, "The type of the keyword <qer_id> is not numeric.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <qer_id> is not an array.");
        }
    }

    /* Activation Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "activation_time");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->activation_time = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.act_time_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <activation_time> is not numeric.");
            return -1;
        }
    }

    /* Deactivation Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "deactivation_time");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->deactivation_time = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.deact_time_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <deactivation_time> is not numeric.");
            return -1;
        }
    }

    /* MAR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "mar_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->mar_id = (uint16_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.mar_id_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <mar_id> is not numeric.");
            return -1;
        }
    }

    /* Packet Replication and Detection Carry-On Information */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "packet_replication_and_detection_carry_on_info");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->pkt_rd_carry_on_info.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.pkt_rd_carry_on_info_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <packet_replication_and_detection_carry_on_info> is not numeric.");
            return -1;
        }
    }

    /* IP Multicast Addressing Info */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ip_multicast_addressing_info");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_ip_multicast_addressing_info(parse_cnt,
                    &create_pdr->ip_mul_addr_info[create_pdr->ip_mul_addr_num])) {
                    create_pdr->ip_mul_addr_num++;
                } else {
                    LOG(COMM, ERR, "Parse <ip_multicast_addressing_info> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <ip_multicast_addressing_info> is not an array.");
        }
    }

    /* UE IP address Pool Identity */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ue_ip_address_pool_identity");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsString(parse_cnt)) {
                    if (strlen(cJSON_GetStringValue(parse_cnt)) < UE_IP_ADDRESS_POOL_LEN) {
                        strcpy(create_pdr->ueip_addr_pool_identity[create_pdr->ueip_addr_pool_identity_num++].pool_identity,
                            cJSON_GetStringValue(parse_cnt));
                    } else {
                        LOG(COMM, ERR, "The length of the <ue_ip_address_pool_identity> value is too long.");
                        return -1;
                    }
                } else {
                    LOG(COMM, ERR, "The type of the keyword <ue_ip_address_pool_identity> is not a string.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <ue_ip_address_pool_identity> is not an array.");
        }
    }

    /* MPTCP Applicable Indication */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "mptcp_applicable_indication");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_pdr->mptcp_app_indication.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            create_pdr->member_flag.d.mptcp_app_indication_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <mptcp_applicable_indication> is not numeric.");
            return -1;
        }
    }

    /* Transport Delay Reporting */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "transport_delay_reporting");
    if (parse_tmp) {
        if (0 == psc_parse_transport_delay_reporting(parse_tmp, &create_pdr->transport_delay_rep)) {
            create_pdr->member_flag.d.transport_delay_rep_present = 1;
        } else {
            LOG(COMM, ERR, "Parse <transport_delay_reporting> failed.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_create_far(cJSON *parse, session_far_create *create_far)
{
    cJSON *parse_tmp = NULL;

    /* FAR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "far_id");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        create_far->far_id = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        create_far->member_flag.d.far_id_present = 1;
    } else {
        LOG(COMM, ERR, "The required keyword <far_id> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Apply Action */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "apply_action");
    if (parse_tmp && cJSON_IsArray(parse_tmp)) {
        cJSON *parse_cnt = NULL;

        cJSON_ArrayForEach(parse_cnt, parse_tmp) {
            if (cJSON_IsString(parse_cnt)) {
                create_far->member_flag.d.action_present = 1;
                if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "DROP")) {
                    create_far->action.d.drop = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "FORW")) {
                    create_far->action.d.forw = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "BUFF")) {
                    create_far->action.d.buff = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "NOCP")) {
                    create_far->action.d.nocp = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "DUPL")) {
                    create_far->action.d.dupl = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "IPMA")) {
                    create_far->action.d.ipma = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "IPMD")) {
                    create_far->action.d.ipmd = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "DFRT")) {
                    create_far->action.d.dfrt = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "EDRT")) {
                    create_far->action.d.edrt = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "BDPN")) {
                    create_far->action.d.bdpn = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "DDPN")) {
                    create_far->action.d.ddpn = 1;
                }
            } else {
                LOG(COMM, ERR, "The type of the keyword <apply_action> is not a string.");
                return -1;
            }
        }
    } else {
        LOG(COMM, ERR, "The required keyword <apply_action> is missing or the type of the value is an array.");
        return -1;
    }

    /* Forwarding Parameters */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "forwarding_parameters");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_far_forwarding_parameters(parse_tmp, &create_far->forw_param)) {
                create_far->member_flag.d.forw_param_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <forwarding_parameters> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <forwarding_parameters> is not an object.");
            return -1;
        }
    }

    /* Duplicating Parameters */

    /* BAR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "bar_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            create_far->bar_id = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            create_far->member_flag.d.bar_id_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <bar_id> is not numeric.");
            return -1;
        }
    }

    /* Redundant Transmission Forwarding Parameters */

    return 0;
}

int psc_parse_create_and_modify_urr(cJSON *parse, session_usage_report_rule *urr)
{
    cJSON *parse_tmp = NULL;

    /* URR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "urr_id");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        urr->urr_id = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        urr->member_flag.d.urr_id_present = 1;
    } else {
        LOG(COMM, ERR, "The required keyword <urr_id> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Measurement Method */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "measurement_method");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        urr->method.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        urr->member_flag.d.method_present = 1;
    } else {
        LOG(COMM, ERR, "The required keyword <measurement_method> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Reporting Triggers */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "reporting_triggers");
    if (parse_tmp && cJSON_IsArray(parse_tmp)) {
        cJSON *parse_cnt = NULL;

        cJSON_ArrayForEach(parse_cnt, parse_tmp) {
            if (cJSON_IsString(parse_cnt)) {
                urr->member_flag.d.trigger_present = 1;
                if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "PERIO")) {
                    urr->trigger.d.perio = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "VOLTH")) {
                    urr->trigger.d.volth = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "TIMTH")) {
                    urr->trigger.d.timth = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "QUHTI")) {
                    urr->trigger.d.quhti = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "START")) {
                    urr->trigger.d.start = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "STOPT")) {
                    urr->trigger.d.stopt = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "DROTH")) {
                    urr->trigger.d.droth = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "LIUSA")) {
                    urr->trigger.d.liusa = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "VOLQU")) {
                    urr->trigger.d.volqu = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "TIMQU")) {
                    urr->trigger.d.timqu = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "ENVCL")) {
                    urr->trigger.d.envcl = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "MACAR")) {
                    urr->trigger.d.macar = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "EVETH")) {
                    urr->trigger.d.eveth = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "EVEQU")) {
                    urr->trigger.d.evequ = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "IPMJL")) {
                    urr->trigger.d.ipmjl = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "QUVTI")) {
                    urr->trigger.d.quvti = 1;
                } else if (0 == strcasecmp(cJSON_GetStringValue(parse_cnt), "REEMR")) {
                    urr->trigger.d.reemr = 1;
                }
            } else {
                LOG(COMM, ERR, "The type of the keyword <reporting_triggers> is not a string.");
                return -1;
            }
        }
    } else {
        LOG(COMM, ERR, "The required keyword <reporting_triggers> is missing or the type of the value is not an array.");
        return -1;
    }

    /* Measurement Period */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "measurement_period");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->period = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.period_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <measurement_period> is not numeric.");
            return -1;
        }
    }

    /* Volume Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "volume_threshold");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_urr_volume(parse_tmp, &urr->vol_thres)) {
                urr->member_flag.d.vol_thres_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <volume_threshold> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <volume_threshold> is not an object.");
            return -1;
        }
    }

    /* Volume Quota */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "volume_quota");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_urr_volume(parse_tmp, &urr->vol_thres)) {
                urr->member_flag.d.vol_thres_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <volume_quota> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <volume_quota> is not an object.");
            return -1;
        }
    }

    /* Event Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "event_threshold");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->eve_thres = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.eve_thres_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <event_threshold> is not numeric.");
            return -1;
        }
    }

    /* Event Quota */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "event_quota");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->eve_quota = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.eve_quota_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <event_quota> is not numeric.");
            return -1;
        }
    }

    /* Time Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "time_threshold");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->tim_thres = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.tim_thres_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <time_threshold> is not numeric.");
            return -1;
        }
    }

    /* Time Quota */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "time_quota");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->tim_quota = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.tim_quota_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <time_quota> is not numeric.");
            return -1;
        }
    }

    /* Quota Holding Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "quota_holding_time");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->quota_hold = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.quota_hold_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <quota_holding_time> is not numeric.");
            return -1;
        }
    }

    /* Dropped DL Traffic Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "dropped_dl_traffic_threshold");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_urr_dropped_dl_traffic_threshold(parse_tmp, &urr->drop_thres)) {
                urr->member_flag.d.drop_thres_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <dropped_dl_traffic_threshold> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <dropped_dl_traffic_threshold> is not an object.");
            return -1;
        }
    }

    /* Quota Validity Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "quota_validity_time");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->quota_validity_time = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.quota_validity_time_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <quota_validity_time> is not numeric.");
            return -1;
        }
    }

    /* Monitoring Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "monitoring_time");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->mon_time = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.mon_time_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <monitoring_time> is not numeric.");
            return -1;
        }
    }

    /* Subsequent Volume Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_volume_threshold");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_urr_volume(parse_tmp, &urr->sub_vol_thres)) {
                urr->member_flag.d.sub_vol_thres_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <subsequent_volume_threshold> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_volume_threshold> is not an object.");
            return -1;
        }
    }

    /* Subsequent Time Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_time_threshold");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->sub_tim_thres = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.sub_tim_thres_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_time_threshold> is not numeric.");
            return -1;
        }
    }

    /* Subsequent Volume Quota */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_volume_quota");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_urr_volume(parse_tmp, &urr->sub_vol_quota)) {
                urr->member_flag.d.sub_vol_quota_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <subsequent_volume_quota> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_volume_quota> is not an object.");
            return -1;
        }
    }

    /* Subsequent Time Quota */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_time_quota");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->sub_tim_quota = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.sub_tim_quota_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_time_quota> is not numeric.");
            return -1;
        }
    }

    /* Subsequent Event Threshold */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_event_threshold");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->sub_eve_thres = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.sub_eve_thres_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_event_threshold> is not numeric.");
            return -1;
        }
    }

    /* Subsequent Event Quota */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "subsequent_event_quota");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->sub_eve_quota = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.sub_eve_quota_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <subsequent_event_quota> is not numeric.");
            return -1;
        }
    }

    /* Inactivity Detection Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "inactivity_detection_time");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->inact_detect = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.inact_detect_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <inactivity_detection_time> is not numeric.");
            return -1;
        }
    }

    /* Linked URR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "linked_urr_id");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsNumber(parse_cnt)) {
                    urr->linked_urr[urr->linked_urr_number++]= (uint32_t)cJSON_GetNumberValue(parse_cnt);
                } else {
                    LOG(COMM, ERR, "The type of the keyword <linked_urr_id> is not numeric.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <linked_urr_id> is not an array.");
        }
    }

    /* Measurement Information */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "measurement_information");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->measu_info.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.measu_info_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <measurement_information> is not numeric.");
            return -1;
        }
    }

    /* Time Quota Mechanism */

    /* Aggregated URRs */

    /* FAR ID for Quota Action */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "quota_action_far_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->quota_far = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.quota_far_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <quota_action_far_id> is not numeric.");
            return -1;
        }
    }

    /* Ethernet Inactivity Timer */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "ethernet_inactivity_timer");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->eth_inact_time = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.eth_inact_time_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <ethernet_inactivity_timer> is not numeric.");
            return -1;
        }
    }

    /* Additional Monitoring Time */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "additional_monitoring_time");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_additional_monitoring_time(parse_cnt,
                    &urr->add_mon_time[urr->add_mon_time_number])) {
                    urr->add_mon_time_number++;
                } else {
                    LOG(COMM, ERR, "Parse <additional_monitoring_time> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <additional_monitoring_time> is not an array.");
        }
    }

    /* Number of Reports */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "number_of_reports");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            urr->number_of_reports = (uint16_t)cJSON_GetNumberValue(parse_tmp);
            urr->member_flag.d.number_of_reports_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <number_of_reports> is not numeric.");
            return -1;
        }
    }

    /* Exempted Application ID for Quota Action */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "exempted_application_id_for_quota_action");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (cJSON_IsString(parse_cnt)) {
                    if (strlen(cJSON_GetStringValue(parse_cnt)) < MAX_APP_ID_LEN) {
                        strcpy(urr->exempted_app_id[urr->exempted_app_id_num++],
                            cJSON_GetStringValue(parse_cnt));
                    } else {
                        LOG(COMM, ERR, "The length of the <exempted_application_id_for_quota_action> value is too long.");
                        return -1;
                    }
                } else {
                    LOG(COMM, ERR, "The type of the keyword <exempted_application_id_for_quota_action> is not a string.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <exempted_application_id_for_quota_action> is not an array.");
        }
    }

    /* Exempted SDF Filter for Quota Action */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "exempted_sdf_filter_for_quota_action");
    if (parse_tmp) {
        if (cJSON_IsArray(parse_tmp)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_tmp) {
                if (0 == psc_parse_sdf_filter(parse_cnt, &urr->exempted_sdf_filter[urr->exempted_sdf_filter_num])) {
                    urr->exempted_sdf_filter_num++;
                } else {
                    LOG(COMM, ERR, "Parse <exempted_sdf_filter_for_quota_action> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <exempted_sdf_filter_for_quota_action> is not an array.");
        }
    }

    return 0;
}

int psc_parse_create_and_modify_qer(cJSON *parse, session_qos_enforcement_rule *qer)
{
    cJSON *parse_tmp = NULL;

    /* QER ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "qer_id");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        qer->qer_id = (uint32_t)cJSON_GetNumberValue(parse_tmp);
        qer->member_flag.d.qer_id_present = 1;
    } else {
        LOG(COMM, ERR, "The required keyword <qer_id> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* QER Correlation ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "qer_correlation_id");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            qer->qer_corr_id = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            qer->member_flag.d.qer_corr_id_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <qer_correlation_id> is not numeric.");
            return -1;
        }
    }

    /* Gate Status */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "gate_status");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_qer_gate_status(parse_tmp, &qer->gate_status)) {
                qer->member_flag.d.gate_status_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <gate_status> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <gate_status> is not an object.");
            return -1;
        }
    }

    /* Maximum Bitrate */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "maximum_bitrate");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_qer_mbr(parse_tmp, &qer->mbr_value)) {
                qer->member_flag.d.mbr_value_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <maximum_bitrate> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <maximum_bitrate> is not an object.");
            return -1;
        }
    }

    /* Guaranteed Bitrate */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "guaranteed_bitrate");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_qer_gbr(parse_tmp, &qer->gbr_value)) {
                qer->member_flag.d.gbr_value_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <guaranteed_bitrate> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <guaranteed_bitrate> is not an object.");
            return -1;
        }
    }

    /* Packet Rate */

    /* Packet Rate Status */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "packet_rate_status");
    if (parse_tmp) {
        if (cJSON_IsObject(parse_tmp)) {
            if (0 == psc_parse_qer_packet_rate_status(parse_tmp, &qer->pkt_rate_status)) {
                qer->member_flag.d.packet_rate_status_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <packet_rate_status> failed.");
                return -1;
            }
        } else {
            LOG(COMM, ERR, "The type of the keyword <packet_rate_status> is not an object.");
            return -1;
        }
    }

    /* DL Flow Level Marking */

    /* QoS flow identifier */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "qfi");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            qer->qfi = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            qer->member_flag.d.qfi_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <qfi> is not numeric.");
            return -1;
        }
    }

    /* Reflective QoS */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "reflective_qos");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            qer->ref_qos = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            qer->member_flag.d.ref_qos_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <reflective_qos> is not numeric.");
            return -1;
        }
    }

    /* Paging Policy Indicator */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "paging_policy_indicator");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            qer->paging_policy_indic = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            qer->member_flag.d.ppi_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <paging_policy_indicator> is not numeric.");
            return -1;
        }
    }

    /* Averaging Window */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "averaging_window");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            qer->averaging_window = (uint32_t)cJSON_GetNumberValue(parse_tmp);
            qer->member_flag.d.averaging_window_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <averaging_window> is not numeric.");
            return -1;
        }
    }

    /* QER Control Indications */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "qer_control_indications");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            qer->qer_ctrl_indic.value = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            qer->member_flag.d.qer_ctrl_indic_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <qer_control_indications> is not numeric.");
            return -1;
        }
    }

    return 0;
}

int psc_parse_create_and_modify_bar(cJSON *parse, session_buffer_action_rule *bar)
{
    cJSON *parse_tmp = NULL;

    /* BAR ID */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "bar_id");
    if (parse_tmp && cJSON_IsNumber(parse_tmp)) {
        bar->bar_id = (uint8_t)cJSON_GetNumberValue(parse_tmp);
        bar->member_flag.d.bar_id_present = 1;
    } else {
        LOG(COMM, ERR, "The required keyword <far_id> is missing or the type of the value is not numeric.");
        return -1;
    }

    /* Downlink Data Notification Delay */

    /* Suggested Buffering Packets Count */
    parse_tmp = cJSON_GetObjectItemCaseSensitive(parse, "suggested_buffering_packets_count");
    if (parse_tmp) {
        if (cJSON_IsNumber(parse_tmp)) {
            bar->buffer_pkts_cnt = (uint8_t)cJSON_GetNumberValue(parse_tmp);
            bar->member_flag.d.buffer_pkts_cnt_present = 1;
        } else {
            LOG(COMM, ERR, "The type of the keyword <suggested_buffering_packets_count> is not numeric.");
            return -1;
        }
    }

    /* MT-EDT Control Information */

    return 0;
}

int psc_parse_session_struct(cJSON *parse, session_content_create *sess)
{
    cJSON *parse_ies = NULL;

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "node_id");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "cp_f_seid");
    if (parse_ies) {
        if (0 > psc_parse_f_seid(parse_ies, &sess->cp_f_seid)) {
            LOG(COMM, ERR, "Parsing error, missing mandatory IE CP F-SEID");
            return -1;
        }
    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "create_pdr");
    if (parse_ies) {
        if (cJSON_IsArray(parse_ies)) {
            cJSON *parse_cnt = NULL;

            cJSON_ArrayForEach(parse_cnt, parse_ies) {
                if (0 == psc_parse_create_pdr(parse_cnt,
                    &sess->pdr_arr[sess->pdr_num])) {
                    sess->pdr_num++;
                } else {
                    LOG(COMM, ERR, "Parse <create_pdr> failed.");
                    return -1;
                }
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <create_pdr> is not an array.");
        }
    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "create_far");
    if (parse_ies) {
        if (cJSON_IsArray(parse_ies)) {

        } else {
            LOG(COMM, ERR, "Parsing error, <create_far> is not an array.");
        }
    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "create_urr");
    if (parse_ies) {
        if (cJSON_IsArray(parse_ies)) {

        } else {
            LOG(COMM, ERR, "Parsing error, <create_urr> is not an array.");
        }
    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "create_qer");
    if (parse_ies) {
        if (cJSON_IsArray(parse_ies)) {

        } else {
            LOG(COMM, ERR, "Parsing error, <create_qer> is not an array.");
        }
    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "create_bar");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "create_traffic_endpoint");
    if (parse_ies) {
        if (cJSON_IsArray(parse_ies)) {

        } else {
            LOG(COMM, ERR, "Parsing error, <create_traffic_endpoint> is not an array.");
        }
    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "pdn_type");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "user_plane_inactivity_timer");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "user_id");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "trace_info");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "apn_dnn");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "create_mar");
    if (parse_ies) {
        if (cJSON_IsArray(parse_ies)) {

        } else {
            LOG(COMM, ERR, "Parsing error, <create_mar> is not an array.");
        }
    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "pfcpsereq_flags");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "create_bridge_info_for_tsc");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "create_srr");
    if (parse_ies) {
        if (cJSON_IsArray(parse_ies)) {

        } else {
            LOG(COMM, ERR, "Parsing error, <create_srr> is not an array.");
        }
    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "provide_atsss_control_info");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "recovery_time_stamp");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "s_nssai");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "provide_rds_configuration_info");
    if (parse_ies) {

    }

    parse_ies = cJSON_GetObjectItemCaseSensitive(parse, "rat_type");
    if (parse_ies) {

    }

    return 0;
}

int psc_parse_predefined_rules(session_content_create *sess, char *filename)
{
    cJSON *parse_arr = NULL, *parse_cnt = NULL;
    cJSON *rules_ies = NULL;

    if (NULL == sess || NULL == filename) {
        LOG(SESSION, ERR, "Abnormal parameters, sess(%p), filename(%p)", sess, filename);
        return -1;
    }

    rules_ies = psc_parse_session_file(filename);
    if (NULL == rules_ies) {
        LOG(COMM, ERR, "Parse json file failed.");
        goto cleanup;
    }

    /* Fill SEID */
    sess->cp_f_seid.seid = PREDEF_SESSION_CP_SEID;
    sess->local_seid     = PREDEF_SESSION_UP_SEID;

    /* Parse PDR */
    parse_arr = cJSON_GetObjectItemCaseSensitive(rules_ies, "create_pdr");
    if (parse_arr && cJSON_IsArray(parse_arr)) {
        cJSON_ArrayForEach(parse_cnt, parse_arr) {
            if (cJSON_IsObject(parse_cnt)) {
                if (0 == psc_parse_create_predefined_pdr(parse_cnt, &sess->pdr_arr[sess->pdr_num])) {
                    sess->pdr_num++;
                } else {
                    LOG(COMM, ERR, "Parse <create_pdr> failed.");
                    goto cleanup;
                }
            } else {
                LOG(COMM, ERR, "Parsing error, <create_pdr> is not an object.");
            }
        }
    }

    /* Parse FAR */
    parse_arr = cJSON_GetObjectItemCaseSensitive(rules_ies, "create_far");
    if (parse_arr && cJSON_IsArray(parse_arr)) {
        cJSON_ArrayForEach(parse_cnt, parse_arr) {
            if (cJSON_IsObject(parse_cnt)) {
                if (0 == psc_parse_create_far(parse_cnt, &sess->far_arr[sess->far_num])) {
                    sess->far_num++;
                } else {
                    LOG(COMM, ERR, "Parse <create_far> failed.");
                    goto cleanup;
                }
            } else {
                LOG(COMM, ERR, "Parsing error, <create_far> is not an object.");
            }
        }
    }

    /* Parse QER */
    parse_arr = cJSON_GetObjectItemCaseSensitive(rules_ies, "create_qer");
    if (parse_arr && cJSON_IsArray(parse_arr)) {
        cJSON_ArrayForEach(parse_cnt, parse_arr) {
            if (cJSON_IsObject(parse_cnt)) {
                if (0 == psc_parse_create_and_modify_qer(parse_cnt, &sess->qer_arr[sess->qer_num])) {
                    sess->qer_num++;
                } else {
                    LOG(COMM, ERR, "Parse <create_qer> failed.");
                    goto cleanup;
                }
            } else {
                LOG(COMM, ERR, "Parsing error, <create_qer> is not an object.");
            }
        }
    }

    /* Parse URR */
    parse_arr = cJSON_GetObjectItemCaseSensitive(rules_ies, "create_urr");
    if (parse_arr && cJSON_IsArray(parse_arr)) {
        cJSON_ArrayForEach(parse_cnt, parse_arr) {
            if (cJSON_IsObject(parse_cnt)) {
                if (0 == psc_parse_create_and_modify_urr(parse_cnt, &sess->urr_arr[sess->urr_num])) {
                    sess->urr_num++;
                } else {
                    LOG(COMM, ERR, "Parse <create_urr> failed.");
                    goto cleanup;
                }
            } else {
                LOG(COMM, ERR, "Parsing error, <create_urr> is not an object.");
            }
        }
    }

    /* Parse BAR */
    parse_arr = cJSON_GetObjectItemCaseSensitive(rules_ies, "create_bar");
    if (parse_arr) {
        if (cJSON_IsObject(parse_cnt)) {
            if (0 == psc_parse_create_and_modify_bar(parse_cnt, &sess->bar)) {
                sess->member_flag.d.bar_present = 1;
            } else {
                LOG(COMM, ERR, "Parse <create_bar> failed.");
                goto cleanup;
            }
        } else {
            LOG(COMM, ERR, "Parsing error, <create_bar> is not an object.");
        }
    }

cleanup:

    if (rules_ies)
        cJSON_Delete(rules_ies);

    return 0;
}

