/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "pfd_mgmt.h"
#include "sp_dns_cache.h"
#include "tuple_table.h"

#define PFD_URL_WILDCARDS       '*'
#define MAX_WC_MATCH_LEN        256

static pfd_table_header g_pfd_mgmt;

static pfd_table_header *pfd_get_table_header(void)
{
    return &g_pfd_mgmt;
}

pfd_table_header *pfd_get_table_header_public(void)
{
    return &g_pfd_mgmt;
}

static pfd_entry *pfd_get_entry(uint32_t index)
{
    return &g_pfd_mgmt.entry[index];
}

pfd_entry *pfd_get_entry_public(uint32_t index)
{
    if (index >= g_pfd_mgmt.max_num) {
        return NULL;
    }
    return &g_pfd_mgmt.entry[index];
}

static int pfd_compare(struct rb_node *node, void *key)
{
    pfd_entry *entry = (pfd_entry *)node;

    return strcmp(entry->pfd.application_id, (char *)key);
}

static inline void pfd_entry_show(session_application_ids_pfds *pfd)
{
    uint8_t cnt, cnt_l2, cnt_l3;
    session_pfd_contents *content;

    LOG(SESSION, DEBUG, "application id: %s", pfd->application_id);
    LOG(SESSION, DEBUG, "pfd context num: %d", pfd->pfd_context_num);

    for (cnt = 0; cnt < pfd->pfd_context_num; ++cnt) {
        LOG(SESSION, DEBUG, "=============PFD Context No %d============", cnt);
        LOG(SESSION, DEBUG, "pfd contents num: %d", pfd->pfd_context[cnt].pfd_contents_num);
        for (cnt_l2 = 0; cnt_l2 < pfd->pfd_context[cnt].pfd_contents_num; ++cnt_l2) {
            content = &pfd->pfd_context[cnt].pfd_contents[cnt_l2];

            LOG(SESSION, DEBUG, "content flag: %d", content->flag.value);
            LOG(SESSION, DEBUG, "content fd_num: %d", content->fd_num);
            LOG(SESSION, DEBUG, "content url_num: %d", content->url_num);
            LOG(SESSION, DEBUG, "content domain_names_num: %d", content->domain_names_num);
            LOG(SESSION, DEBUG, "content domain_name_pro_num: %d", content->domain_name_pro_num);
            for (cnt_l3 = 0; cnt_l3 < content->fd_num; ++cnt_l3) {
                session_pfd_flow_desc *fd = &content->fd[cnt_l3];

                LOG(SESSION, DEBUG, "----------flow description %d------------", cnt_l3);
                LOG(SESSION, DEBUG, "fd ip: 0x%08x %08x %08x %08x", *(uint32_t *)&fd->ip.ipv6[0],
                    *(uint32_t *)&fd->ip.ipv6[4], *(uint32_t *)&fd->ip.ipv6[8], *(uint32_t *)&fd->ip.ipv6[12]);
                LOG(SESSION, DEBUG, "fd ip mask: 0x%08x %08x %08x %08x", *(uint32_t *)&fd->mask.ipv6_mask[0],
                    *(uint32_t *)&fd->mask.ipv6_mask[4], *(uint32_t *)&fd->mask.ipv6_mask[8],
                    *(uint32_t *)&fd->mask.ipv6_mask[12]);
                LOG(SESSION, DEBUG, "fd port: %d-%d", fd->port_min, fd->port_max);
                LOG(SESSION, DEBUG, "fd protocol: %d", fd->protocol);
                LOG(SESSION, DEBUG, "fd action: %d", fd->action);
                LOG(SESSION, DEBUG, "fd ip_type: %d", fd->ip_type);
                LOG(SESSION, DEBUG, "fd dir: %d", fd->dir);
                LOG(SESSION, DEBUG, "fd ip_not: %d", fd->ip_not);
                LOG(SESSION, DEBUG, "fd no_port: %d", fd->no_port);
            }

            for (cnt_l3 = 0; cnt_l3 < content->url_num; ++cnt_l3) {
                LOG(SESSION, DEBUG, "----------URL %d------------", cnt_l3);
                LOG(SESSION, DEBUG, "url: %s", content->url[cnt_l3]);
            }
            if (content->flag.d.CP) {
                LOG(SESSION, DEBUG, "----------Custom pfd------------");
                LOG(SESSION, DEBUG, "cp: %s", content->custom_pfd);
            }
            for (cnt_l3 = 0; cnt_l3 < content->domain_names_num; ++cnt_l3) {
                LOG(SESSION, DEBUG, "----------DN %d------------", cnt_l3);
                LOG(SESSION, DEBUG, "dn: %s", content->domain_names[cnt_l3]);
            }
            for (cnt_l3 = 0; cnt_l3 < content->domain_name_pro_num; ++cnt_l3) {
                LOG(SESSION, DEBUG, "----------DNP %d------------", cnt_l3);
                LOG(SESSION, DEBUG, "dnp: %s", content->domain_name_pro[cnt_l3]);
            }
        }
    }
}

static inline void pfd_entry_show_cli(struct cli_def *cli, session_application_ids_pfds *pfd)
{
    uint8_t cnt, cnt_l2, cnt_l3;
    session_pfd_contents *content;
    char ip_str[256];

    cli_print(cli, "application id: %s\n", pfd->application_id);
    cli_print(cli, "pfd context num: %d\n", pfd->pfd_context_num);

    for (cnt = 0; cnt < pfd->pfd_context_num; ++cnt) {
        cli_print(cli, "=============PFD Context No %d============\n", cnt);
        cli_print(cli, "pfd contents num: %d\n", pfd->pfd_context[cnt].pfd_contents_num);
        for (cnt_l2 = 0; cnt_l2 < pfd->pfd_context[cnt].pfd_contents_num; ++cnt_l2) {
            content = &pfd->pfd_context[cnt].pfd_contents[cnt_l2];

            cli_print(cli, "content flag: %d\n", content->flag.value);
            cli_print(cli, "content fd_num: %d\n", content->fd_num);
            cli_print(cli, "content url_num: %d\n", content->url_num);
            cli_print(cli, "content domain_names_num: %d\n", content->domain_names_num);
            cli_print(cli, "content domain_name_pro_num: %d\n", content->domain_name_pro_num);
            for (cnt_l3 = 0; cnt_l3 < content->fd_num; ++cnt_l3) {
                session_pfd_flow_desc *fd = &content->fd[cnt_l3];

                cli_print(cli, "----------flow description %d------------\n", cnt_l3);
                if (fd->ip_type == SESSION_IP_V4) {
                    uint32_t tmp_addr = htonl(fd->ip.ipv4);
                    if (NULL == inet_ntop(AF_INET, &tmp_addr, ip_str, sizeof(ip_str))) {
                        cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                        continue;
                    }
                    cli_print(cli, "FD IP       : %s", ip_str);

                    tmp_addr = htonl(fd->mask.ipv4_mask);
                    if (NULL == inet_ntop(AF_INET, &tmp_addr, ip_str, sizeof(ip_str))) {
                        cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                        continue;
                    }
                    cli_print(cli, "FD IP Mask  : %s", ip_str);
                } else {
                    if (NULL == inet_ntop(AF_INET6, fd->ip.ipv6, ip_str, sizeof(ip_str))) {
                        cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                        continue;
                    }
                    cli_print(cli, "FD IP       : %s", ip_str);

                    if (NULL == inet_ntop(AF_INET6, fd->mask.ipv6_mask, ip_str, sizeof(ip_str))) {
                        cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                        continue;
                    }
                    cli_print(cli, "FD IP Mask  : %s", ip_str);
                }
                cli_print(cli, "FD Port     : %d-%d\n", fd->port_min, fd->port_max);
                cli_print(cli, "FD Protocol : %d\n", fd->protocol);
                cli_print(cli, "FD Action   : %d\n", fd->action);
                cli_print(cli, "FD IP Type  : %d\n", fd->ip_type);
                cli_print(cli, "FD Dir      : %d\n", fd->dir);
                cli_print(cli, "FD IP Not   : %d\n", fd->ip_not);
                cli_print(cli, "FD No Port  : %d\n", fd->no_port);
            }

            for (cnt_l3 = 0; cnt_l3 < content->url_num; ++cnt_l3) {
                cli_print(cli, "----------URL %d------------\n", cnt_l3);
                cli_print(cli, "URL: %s", content->url[cnt_l3]);
            }
            if (content->flag.d.CP) {
                cli_print(cli, "----------Custom pfd------------\n");
                cli_print(cli, "CP: %s\n", content->custom_pfd);
            }
            for (cnt_l3 = 0; cnt_l3 < content->domain_names_num; ++cnt_l3) {
                cli_print(cli, "----------DN %d------------\n", cnt_l3);
                cli_print(cli, "DN: %s\n", content->domain_names[cnt_l3]);
            }
            for (cnt_l3 = 0; cnt_l3 < content->domain_name_pro_num; ++cnt_l3) {
                cli_print(cli, "----------DNP %d------------\n", cnt_l3);
                cli_print(cli, "DNP: %s\n", content->domain_name_pro[cnt_l3]);
            }
        }
    }
}

int pfd_entry_insert(session_application_ids_pfds *pfd)
{
    uint32_t index = 0, res_key = 0;
    pfd_entry *entry = NULL;
    pfd_table_header *pfd_head = pfd_get_table_header();

    if (NULL == pfd) {
        LOG(SESSION, ERR, "Abnormal parameter, pfd(%p).", pfd);
        return -1;
    }

    pfd_entry_show(pfd);

    ros_rwlock_write_lock(&pfd_head->lock); /* lock */
    entry = (pfd_entry *)rbtree_search(&pfd_head->pfd_root, pfd->application_id, pfd_compare);
    ros_rwlock_write_unlock(&pfd_head->lock); /* unlock */
    if (NULL != entry) {
        LOG(SESSION, RUNNING, "pfd application id: %s existence, Modify it.",
            pfd->application_id);
        ros_rwlock_write_lock(&entry->lock); /* lock */
        ros_memcpy(&entry->pfd, pfd, sizeof(*pfd));
        ros_rwlock_write_unlock(&entry->lock); /* unlock */

        return 0;
    } else {
        if (G_FAILURE == Res_Alloc(pfd_head->pool_id, &res_key, &index,
            EN_RES_ALLOC_MODE_OC)) {
            LOG(SESSION, ERR, "insert seid entry failed, Resource exhaustion, pool id: %d.",
                pfd_head->pool_id);
            return -1;
        }

        entry = pfd_get_entry(index);

        memcpy(&entry->pfd, pfd, sizeof(session_application_ids_pfds));

        ros_rwlock_write_lock(&pfd_head->lock); /* lock */
        /* insert seid tree */
        if (0 > rbtree_insert(&pfd_head->pfd_root, &entry->node, entry->pfd.application_id,
            pfd_compare)) {
            ros_rwlock_write_unlock(&pfd_head->lock); /* unlock */

            Res_Free(pfd_head->pool_id, 0, entry->index);
            LOG(SESSION, ERR, "pfd entry insert failed, key: %s.",
                pfd->application_id);
            return -1;
        }
        ros_rwlock_write_unlock(&pfd_head->lock); /* unlock */
    }

    return 0;
}

int pfd_entry_remove(char *application_id)
{
    pfd_entry *entry = NULL;
    pfd_table_header *pfd_head = pfd_get_table_header();

    ros_rwlock_write_lock(&pfd_head->lock); /* lock */
    entry = (pfd_entry *)rbtree_delete(&pfd_head->pfd_root,
        application_id, pfd_compare);
    if (NULL == entry) {
        ros_rwlock_write_unlock(&pfd_head->lock); /* unlock */
        LOG(SESSION, ERR, "pfd entry remove failed, application id: %s.",
            application_id);
        return -1;
    }
    Res_Free(pfd_head->pool_id, 0, entry->index);
    ros_rwlock_write_unlock(&pfd_head->lock); /* unlock */

    return 0;
}

pfd_entry *pfd_entry_search(char *application_id)
{
    pfd_entry *entry = NULL;
    pfd_table_header *pfd_head = pfd_get_table_header();

    ros_rwlock_write_lock(&pfd_head->lock); /* lock */
    entry = (pfd_entry *)rbtree_search(&pfd_head->pfd_root,
        application_id, pfd_compare);
    ros_rwlock_write_unlock(&pfd_head->lock); /* unlock */
    if (NULL == entry) {
        LOG(SESSION, ERR, "pfd entry search failed, application id: %s.",
            application_id);
        return NULL;
    }

    return entry;
}

void pfd_table_clean_all(void)
{
    pfd_table_header *table_hdr = pfd_get_table_header();
    pfd_entry *entry = NULL;
    int32_t cur_index = -1;

    cur_index = Res_GetAvailableInBand(table_hdr->pool_id, cur_index + 1, table_hdr->max_num);
    for (; -1 != cur_index;) {
        entry = pfd_get_entry(cur_index);

        pfd_entry_remove(entry->pfd.application_id);

        cur_index = Res_GetAvailableInBand(table_hdr->pool_id, cur_index + 1, table_hdr->max_num);
    }

    LOG(SESSION, RUNNING, "PFD table clean success.");
}

int64_t pfd_table_init(uint32_t pfd_num)
{
    pfd_table_header *table_hdr = pfd_get_table_header();
    uint32_t index = 0;
    int pool_id = -1;
    pfd_entry *entry = NULL;
    int64_t size = 0, total_memory = 0;

    if (0 == pfd_num) {
        LOG(SESSION, ERR, "Abnormal parameter, pfd_num: %u.", pfd_num);
        return -1;
    }

    size = sizeof(pfd_entry) * pfd_num;
    entry = ros_malloc(size);
    if (NULL == entry) {
        LOG(SESSION, ERR, "init PFD table failed, no enough memory, entry number: %u.",
            pfd_num);
        return -1;
    }
    ros_memset(entry, 0, size);

    for (index = 0; index < pfd_num; ++index) {
        entry[index].index = index;
        ros_rwlock_init(&entry[index].lock);
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

    LOG(SESSION, RUNNING, "PFD table init success.");

    return total_memory;
}

static inline void pfd_calc_url_depth(char *url, int *depth)
{
    uint32_t cnt, url_len = strlen(url), depth_cnt = 0;

    for (cnt = 0; cnt < url_len; ++cnt) {
        if (url[cnt] == '/')
            ++depth_cnt;
    }
    *depth = depth_cnt;
}

static inline const char *pfd_strstr_greedy(const char hay[], const char needle[])
{
	const char *next, *prev;

	next = strstr(hay, needle);
	if (!next)
        return NULL;

	for (;;) {
		prev = next;
		next = strstr(next + 1, needle);
		if (!next)
            return prev;
	}
}

static int __pfd_url_prefix_match(const char find[], const char hay[])
{
	uint32_t wilds = 0;
    const char *tmp_ptr;
    const uint32_t find_len = strlen(find);
	uint32_t find_cnt, hay_cnt = 0;

    for (tmp_ptr = find; *tmp_ptr; ++tmp_ptr) {
		if (*tmp_ptr == PFD_URL_WILDCARDS)
            ++wilds;
	}

	/* no wildcards */
	if (0 == wilds) {
        /* Match prefix */
		return strncmp(find, hay, find_len) == 0;
	}

	for (find_cnt = 0; find_cnt < find_len; ++find_cnt) {
		if (find[find_cnt] != PFD_URL_WILDCARDS) {
			if (find[find_cnt] != hay[hay_cnt])
				return 0;
			++hay_cnt;
		} else {
			// If multiple wildcards in a row, skip to the last
			while (find[find_cnt + 1] == PFD_URL_WILDCARDS)
                ++find_cnt;

			if (find_cnt >= (find_len - 1))
				return 1;

			// Wildcard, not last
			const char * const ender = strchrnul(&find[find_cnt + 1], PFD_URL_WILDCARDS);
			const uint32_t dist = ender - &find[find_cnt + 1];

			char piece[dist + 1];
			memcpy(piece, &find[find_cnt + 1], dist);
			piece[dist] = '\0';

			const char * const lastmatch = pfd_strstr_greedy(&hay[hay_cnt], piece);
			if (!lastmatch)
				return 0;

			// Is backtracking required?
			const char * const firstmatch = strstr(&hay[hay_cnt], piece);

			// The dist check is to make sure this is not a suffix search
			if (firstmatch != lastmatch && dist != find_len - find_cnt - 1) {
				const uint32_t move = firstmatch - &hay[hay_cnt];
				hay_cnt += move;
			} else {
				const uint32_t move = lastmatch - &hay[hay_cnt];
				hay_cnt += move;
			}
		}
	}
    /* Don't care if it's a perfect match */

	return 1;
}

int strstarmatch(const char *pattern, const char *filename) {
    if (!pattern || !filename)
        return -1;

    while (pattern && *filename) {
        int star = *pattern == '*';
        const char *chunk = pattern + star;
        pattern = strchr(chunk, '*');
        size_t n = pattern ? pattern - chunk : strlen(chunk);

        if (star && !n)
            return 0;

        while (memcmp(chunk, filename, n))
            if (!star || *filename++ == '\0')
                return -1;
        filename += n;
    }

    return !(pattern == NULL && *filename == '\0');
}

/* 返回值 大于1 :匹配成功 | 0:匹配失败 */
int pfd_url_prefix_match(const char find[], const char hay[])
{
    char *find_sep, *hay_sep;
    char find_host[MAX_WC_MATCH_LEN];
    uint32_t find_host_len;
    char hay_host[MAX_WC_MATCH_LEN];
    uint32_t hay_host_len;

    /* 需要将host和path分开匹配, 目前以/作为边界区分 */
    find_sep = strchrnul(find, '/');
	find_host_len = find_sep - find;

    hay_sep = strchrnul(hay, '/');
	hay_host_len = hay_sep - hay;

	memcpy(find_host, find, find_host_len);
	find_host[find_host_len] = '\0';

	memcpy(hay_host, hay, hay_host_len);
	hay_host[hay_host_len] = '\0';

    /* match host */
    if (0 == __pfd_url_prefix_match(find_host, hay_host)) {
        return 0;
    }

    /* match path */
    if (*find_sep == '\0') {
        return 1;
    } else {
        if (*hay_sep != '\0') {
            if (0 == __pfd_url_prefix_match(find_sep, hay_sep)) {
                return 0;
            }
        } else {
            return 0;
        }
    }

    return 1;
}

/* 返回值 大于1 :匹配成功 | 0:匹配失败 */
int pfd_match_process(struct filter_key *key, uint8_t *field_offset,
    char *app_id, int *url_depth)
{
    pfd_entry *entry;
    session_application_ids_pfds *pfd;
    struct pro_udp_hdr  *udp_hdr = NULL;
    struct pro_tcp_hdr  *tcp_hdr = NULL;
    uint16_t src_port, dst_port;
    uint8_t cnt_l1, cnt_l2;
    tuple_key _5_tuple = {{0}};
    char http_url[MAX_BUFFER_URL_LEN], url_present = 0;
    int ret = 0;

    if (NULL == key || NULL == field_offset || NULL == app_id) {
        LOG(SESSION, ERR, "Abnormal parameters, key(%p), field_offset(%p), app_id(%p).",
            key, field_offset, app_id);
        return EN_PFD_MATCH_FAIL;
    }

    entry = pfd_entry_search(app_id);
    if (NULL == entry) {
        LOG(SESSION, ERR, "Search PFD entry failed, application id: %s", app_id);
        return EN_PFD_MATCH_FAIL;
    }

    pfd = &entry->pfd;
    /* match with pfd */
    if (likely(FLOW_MASK_FIELD_ISSET(field_offset, FLOW_FIELD_L1_IPV4))) {
        struct pro_ipv4_hdr *ip_hdr = FlowGetIpv4Header(key, field_offset);
        if (unlikely(NULL == ip_hdr)) {
            LOG(SESSION, ERR, "get ipv4 header failed.");
            return EN_PFD_MATCH_FAIL;
        }

        _5_tuple.sipv4 = ntohl(ip_hdr->source);
        _5_tuple.dipv4 = ntohl(ip_hdr->dest);
        _5_tuple.protocol = ip_hdr->protocol;

        switch(ip_hdr->protocol)
        {
            case IP_PRO_UDP:
                udp_hdr = FlowGetUdpHeader(key, field_offset);
                if (unlikely(NULL == udp_hdr)) {
                    return EN_PFD_MATCH_FAIL;
                }
                _5_tuple.sport = src_port = htons(udp_hdr->source);
                _5_tuple.dport = dst_port = htons(udp_hdr->dest);
                break;

            case IP_PRO_TCP:
                tcp_hdr = FlowGetTcpHeader(key, field_offset);
                if (unlikely(NULL == tcp_hdr)) {
                    return EN_PFD_MATCH_FAIL;
                }
                _5_tuple.sport = src_port = htons(tcp_hdr->source);
                _5_tuple.dport = dst_port = htons(tcp_hdr->dest);
                break;

            default:
                _5_tuple.sport = src_port = 0;
                _5_tuple.dport = dst_port = 0;
                break;
        }

        if (IP_PRO_TCP == ip_hdr->protocol && tcp_hdr->psh) {
            if (0 == layer7_url_extract(tcp_hdr, ntohs(ip_hdr->tot_len), http_url, NULL, sizeof(http_url))) {
                url_present = 1;
                if (0 > tuple_table_update(&_5_tuple, http_url)) {
                    LOG(SESSION, ERR, "Tuple table update failed.");
                    /* Don't return */
                }
            } else {
                /* The source and destination of the 5 tuple need to be swapped */
                uint32_t swap;

                swap = _5_tuple.sipv4;
                _5_tuple.sipv4 = _5_tuple.dipv4;
                _5_tuple.dipv4 = swap;
                swap = _5_tuple.sport;
                _5_tuple.sport = _5_tuple.dport;
                _5_tuple.dport = swap;

                if (0 == tuple_table_search_url(&_5_tuple, http_url)) {
                    url_present = 1;
                    LOG(SESSION, DEBUG, "Search URL: %s", http_url);
                } else {
                    LOG(SESSION, ERR, "Search Tuple table URL failed.");
                }
            }
        }

        LOG(SESSION, DEBUG, "PFD context number: %d.", pfd->pfd_context_num);
        ros_rwlock_read_lock(&entry->lock); /* lock */
        for (cnt_l1 = 0; cnt_l1 < pfd->pfd_context_num; ++cnt_l1) {
            session_pfd_context *pfd_context = &pfd->pfd_context[cnt_l1];

            ret = 0;
            LOG(SESSION, DEBUG, "PFD contents number: %d.", pfd_context->pfd_contents_num);
            for (cnt_l2 = 0; cnt_l2 < pfd_context->pfd_contents_num; ++cnt_l2) {
                session_pfd_contents *pfd_contents = &pfd_context->pfd_contents[cnt_l2];

                LOG(SESSION, RUNNING, "ipv4 packet matching pfd contents.");

                /* Match Flow Description and Additional Flow Description */
                if (pfd_contents->flag.d.FD) {
                    uint8_t cnt_fd, diff_num;
                    uint32_t match_ip;
					uint16_t match_port;

                    for (cnt_fd = 0; cnt_fd < pfd_contents->fd_num; ++cnt_fd) {
                        session_pfd_flow_desc *fd = &pfd_contents->fd[cnt_fd];
                        diff_num = 0;

                        if (0 == (fd->ip_type & SESSION_IP_V4)) {
                            continue;
                        }

                        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_GTP_T_PDU)) {
                            match_ip = htonl(ip_hdr->dest);
							match_port = dst_port;
                        } else {
                            match_ip = htonl(ip_hdr->source);
							match_port = src_port;
                        }

                        LOG(SESSION, DEBUG,
                            "packet info::match_ip:0x%08x, match_port:%u, proto:%u.",
                            match_ip,  match_port, ip_hdr->protocol);

                        LOG(SESSION, DEBUG,
                            "pfd contents::action:%d, dir:%d ip:0x%08x/0x%08x, port:%d-%d, protocol: %d, ip_not: %d.",
                            fd->action, fd->dir, fd->ip.ipv4, fd->mask.ipv4_mask, fd->port_min, fd->port_max,
                            fd->protocol, fd->ip_not);

                        if (fd->protocol && (ip_hdr->protocol != fd->protocol)) {
                            ++diff_num;
                        }
                        if (fd->ip.ipv4) {
                            if (fd->ip_not) {
                                if ((match_ip & fd->mask.ipv4_mask) == (fd->ip.ipv4 & fd->mask.ipv4_mask)) {
                                    ++diff_num;
                                }
                            } else {
                                if ((match_ip & fd->mask.ipv4_mask) != (fd->ip.ipv4 & fd->mask.ipv4_mask)) {
                                    ++diff_num;
                                }
                            }
                        }
                        if (fd->no_port == 0 && ((match_port < fd->port_min) || (match_port > fd->port_max))) {
                            ++diff_num;
                        }

                        if (0 == fd->action) {
                            /* permit */
                            if (diff_num > 0) {
                                continue;
                            }
                        } else {
                            /* deny */
                            if (diff_num == 0) {
                                continue;
                            }
                        }

                        LOG(SESSION, DEBUG, "flow description match success.");
                        ret |= EN_PFD_MATCH_FD;
                        break;
                    }

                    if (cnt_fd >= pfd_contents->fd_num) {
                        LOG(SESSION, DEBUG, "PFD FD mismatch.");
                        continue;
                    }
                }

                /* Match URL and Additional URL */
                if (pfd_contents->flag.d.URL) {
                    uint8_t cnt_url;

                    if (url_present) {
                        LOG(SESSION, DEBUG, "Tcp header length: %d, sizeof(http_url): %lu",
                            ntohs(ip_hdr->tot_len), sizeof(http_url));

                        for (cnt_url = 0; cnt_url < pfd_contents->url_num; ++cnt_url) {
                            LOG(SESSION, DEBUG, "packet_URL: %s <=> PFD_URL: %s",
                                http_url, pfd_contents->url[cnt_url]);
                            if (pfd_url_prefix_match(pfd_contents->url[cnt_url], http_url)) {
                                pfd_calc_url_depth(pfd_contents->url[cnt_url], url_depth);
                                LOG(SESSION, DEBUG, "Match URL success.");
                                ret |= EN_PFD_MATCH_URL;
                                break;
                            }
                            LOG(SESSION, DEBUG, "URL mismatch.");
                        }

                        if (cnt_url >= pfd_contents->url_num) {
                            LOG(SESSION, DEBUG, "PFD URL mismatch.");
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                /* Match Domain Name */
                if (pfd_contents->flag.d.DN) {
                }

                /* Match Custom PFD Content */
                if (pfd_contents->flag.d.CP) {
                }

                /* Match Domain Name Protocol */
                if (pfd_contents->flag.d.DNP) {
                }

                /* Match Additional Domain Name and Domain Name Protocol */
                if (pfd_contents->flag.d.ADNP) {
                }
                ros_rwlock_read_unlock(&entry->lock); /* unlock */

                /* DNS sniffer filter */
                if (ret & EN_PFD_MATCH_FD) {
                    /* Do not turn on DNS sniffer */
                } else if (ret & EN_PFD_MATCH_URL) {
                    char dn[COMM_MSG_DNS_NAME_LENG];
                    uint32_t dn_len = strchr(http_url, '/') - http_url;

                    if (dn_len >= COMM_MSG_DNS_NAME_LENG) {
                        LOG(SESSION, MUST, "The system predefined length is too short,"
                            " COMM_MSG_DNS_NAME_LENG: %d, current length: %u",
                            COMM_MSG_DNS_NAME_LENG, dn_len);
                        return EN_PFD_MATCH_FAIL;
                    }
                    ros_memcpy(dn, http_url, dn_len);
                    dn[dn_len] = '\0';
                    if (sdc_sniffer_master_switch() || 0 == sdc_sniffer_match(dn)) {
                        if (0 > sdc_check_dns(dn, (void *)&_5_tuple.dipv4, EN_DNS_IPV4)) {
                            LOG(SESSION, DEBUG, "DNS inspection failed, DN: %s", dn);
                            return EN_PFD_MATCH_FAIL;
                        }
                        LOG(SESSION, DEBUG, "DNS inspection passed, DN: %s", dn);
                    }
                }

                return EN_PFD_MATCH_ALL;
            }
        }
        ros_rwlock_read_unlock(&entry->lock); /* unlock */

        LOG(SESSION, DEBUG, "PFD mismatch.");
        return EN_PFD_MATCH_FAIL;
    }
    else if (likely(FLOW_MASK_FIELD_ISSET(field_offset,FLOW_FIELD_L1_IPV6))) {
		LOG(SESSION, DEBUG, "ipv6 packet matching pfd contents.");
        struct pro_ipv6_hdr *ip_hdr = FlowGetIpv6Header(key, field_offset);
        if (unlikely(!ip_hdr)) {
            return EN_PFD_MATCH_FAIL;
        }

        switch(ip_hdr->nexthdr)
        {
            case IP_PRO_UDP:
                udp_hdr = FlowGetUdpHeader(key, field_offset);
                if (unlikely(!udp_hdr)) {
                    return EN_PFD_MATCH_FAIL;
                }
                src_port = htons(udp_hdr->source);
                dst_port = htons(udp_hdr->dest);
                break;

            case IP_PRO_TCP:
                tcp_hdr = FlowGetTcpHeader(key, field_offset);
                if (unlikely(!tcp_hdr)) {
                    return EN_PFD_MATCH_FAIL;
                }
                src_port = htons(tcp_hdr->source);
                dst_port = htons(tcp_hdr->dest);
                break;

            default:
                src_port = 0;
                dst_port = 0;
                break;
        }

        ros_rwlock_read_lock(&entry->lock); /* lock */
        for (cnt_l1 = 0; cnt_l1 < pfd->pfd_context_num; ++cnt_l1) {
            session_pfd_context *pfd_context = &pfd->pfd_context[cnt_l1];

            for (cnt_l2 = 0; cnt_l2 < pfd_context->pfd_contents_num; ++cnt_l2) {
                session_pfd_contents *pfd_contents = &pfd_context->pfd_contents[cnt_l2];

                if (pfd_contents->flag.d.FD) {
                    uint8_t cnt_fd, diff_num;
                    uint8_t match_ip[IPV6_ALEN];
					uint16_t match_port;

                    for (cnt_fd = 0; cnt_fd < pfd_contents->fd_num; ++cnt_fd) {
                        session_pfd_flow_desc *fd = &pfd_contents->fd[cnt_fd];
                        diff_num = 0;

                        if (0 == (fd->ip_type & SESSION_IP_V6)) {
                            continue;
                        }
                        if (FLOW_MASK_FIELD_ISSET(key->field_offset, FLOW_FIELD_GTP_T_PDU)) {
                            /* N3 rule */
                            memcpy(match_ip, ip_hdr->daddr, IPV6_ALEN);
							match_port = dst_port;
                        } else {
                            /* N6 rule */
                            memcpy(match_ip, ip_hdr->saddr, IPV6_ALEN);
							match_port = src_port;
                        }

                        LOG(SESSION, RUNNING,
					      "packet info::(dip:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)"
					      "(sip:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)"
					      " sp:%u, dp:%u, proto:%u.",
						    ip_hdr->daddr[0],ip_hdr->daddr[1],ip_hdr->daddr[2],ip_hdr->daddr[3],
				            ip_hdr->daddr[4],ip_hdr->daddr[5],ip_hdr->daddr[6],ip_hdr->daddr[7],
				            ip_hdr->daddr[8],ip_hdr->daddr[9],ip_hdr->daddr[10],ip_hdr->daddr[11],
				            ip_hdr->daddr[12],ip_hdr->daddr[13],ip_hdr->daddr[14],ip_hdr->daddr[15],
				            ip_hdr->saddr[0],ip_hdr->saddr[1],ip_hdr->saddr[2],ip_hdr->saddr[3],
				            ip_hdr->saddr[4],ip_hdr->saddr[5],ip_hdr->saddr[6],ip_hdr->saddr[7],
				            ip_hdr->saddr[8],ip_hdr->saddr[9],ip_hdr->saddr[10],ip_hdr->saddr[11],
				            ip_hdr->saddr[12],ip_hdr->saddr[13],ip_hdr->saddr[14],ip_hdr->saddr[15],
						    src_port,dst_port, ip_hdr->nexthdr);

                        LOG(SESSION, RUNNING,
                            "pfd contents::action:%d, dir:%d ip:0x%08x/0x%08x, port:%d-%d, protocol: %d, ip_not: %d.",
                            fd->action, fd->dir, fd->ip.ipv4, fd->mask.ipv4_mask, fd->port_min, fd->port_max,
                            fd->protocol, fd->ip_not);

						LOG(SESSION, RUNNING,
					      "pfd contents::(keyip:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)"
					      "(keymask:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x)"
					      "action:%d, dir:%d  port:%d-%d, protocol: %d, ip_not: %d.",
					      fd->ip.ipv6[0],fd->ip.ipv6[1],fd->ip.ipv6[2],fd->ip.ipv6[3],
					      fd->ip.ipv6[4],fd->ip.ipv6[5],fd->ip.ipv6[6],fd->ip.ipv6[7],
					      fd->ip.ipv6[8],fd->ip.ipv6[9],fd->ip.ipv6[10],fd->ip.ipv6[11],
					      fd->ip.ipv6[12],fd->ip.ipv6[13],fd->ip.ipv6[14],fd->ip.ipv6[15],
					      fd->mask.ipv6_mask[0],fd->mask.ipv6_mask[1],fd->mask.ipv6_mask[2],fd->mask.ipv6_mask[3],
					      fd->mask.ipv6_mask[4],fd->mask.ipv6_mask[5],fd->mask.ipv6_mask[6],fd->mask.ipv6_mask[7],
					      fd->mask.ipv6_mask[8],fd->mask.ipv6_mask[9],fd->mask.ipv6_mask[10],fd->mask.ipv6_mask[11],
					      fd->mask.ipv6_mask[12],fd->mask.ipv6_mask[13],fd->mask.ipv6_mask[14],fd->mask.ipv6_mask[15],
					      fd->action, fd->dir,fd->port_min, fd->port_max,fd->protocol, fd->ip_not);

                        if (fd->protocol && (ip_hdr->nexthdr != fd->protocol)) {
                            ++diff_num;
                        }
                        if (*(uint64_t *)fd->ip.ipv6) {
                            if (fd->ip_not) {
                                if ((((*(uint64_t *)match_ip & *(uint64_t *)fd->mask.ipv6_mask) ==
                                    (*(uint64_t *)fd->ip.ipv6 & *(uint64_t *)fd->mask.ipv6_mask)) &&
                                    ((*(uint64_t *)&match_ip[8] & *(uint64_t *)&fd->mask.ipv6_mask[8]) ==
                                    (*(uint64_t *)&fd->ip.ipv6[8] & *(uint64_t *)&fd->mask.ipv6_mask[8])))) {
                                    ++diff_num;
                                }
                            } else {
                                if ((((*(uint64_t *)match_ip & *(uint64_t *)fd->mask.ipv6_mask) !=
                                    (*(uint64_t *)fd->ip.ipv6 & *(uint64_t *)fd->mask.ipv6_mask)) ||
                                    ((*(uint64_t *)&match_ip[8] & *(uint64_t *)&fd->mask.ipv6_mask[8]) !=
                                    (*(uint64_t *)&fd->ip.ipv6[8] & *(uint64_t *)&fd->mask.ipv6_mask[8])))) {
                                    ++diff_num;
                                }
                            }
                        }
                        if (fd->no_port == 0 && ((match_port < fd->port_min) || (match_port > fd->port_max))) {
                            ++diff_num;
                        }
                        ros_rwlock_read_unlock(&entry->lock); /* unlock */

                        if (0 == fd->action) {
                            /* permit */
                            if (diff_num == 0) {
                                return EN_PFD_MATCH_FD;
                            } else {
                                continue;
                            }
                        } else {
                            /* deny */
                            if (diff_num > 0) {
                                return EN_PFD_MATCH_FD;
                            } else {
                                continue;
                            }
                        }
                    }
                }
            }
        }
        ros_rwlock_read_unlock(&entry->lock); /* unlock */

        LOG(SESSION, DEBUG, "pfd match fail.");
        return EN_PFD_MATCH_FAIL;
    }
    else {
        LOG(SESSION, DEBUG, "Not ipv4 and ipv6 packet.");
        return EN_PFD_MATCH_FAIL;
    }
}

int pfd_parse_pfd_contents(session_pfd_contents *pfd_contents, struct pcf_file *conf)
{
	int index = 0;
	uint8_t cnt = 0;
	char buf_name[128] = {0};
	session_pfd_flow_desc *fd_ptr = NULL;
    /* the key pair and value get must be in order */
	struct kv_pair flow_desc_key_pair[] = {
        { "fd_iptype", NULL },
		{ "fd_ip", NULL },
		{ "fd_mask", NULL },
		{ "fd_pmin", NULL },
		{ "fd_pmax", NULL },
		{ "fd_protocol", NULL },
		{ "fd_action", NULL },
		{ "fd_dir", NULL },
		{ "fd_ip_not", NULL },
		{ "fd_no_port", NULL },
        { NULL, NULL, }
    };
	struct kv_pair url_key_pair[] = {
        { "pfd_contents_url", NULL },
        { NULL, NULL, }
    };
	struct kv_pair custom_pfd_key_pair[] = {
        { "pfd_contents_custom_pfd", NULL },
        { NULL, NULL, }
    };
	struct kv_pair domain_names_key_pair[] = {
        { "pfd_contents_domain_names", NULL },
        { NULL, NULL, }
    };
	struct kv_pair domain_names_pro_key_pair[] = {
        { "pfd_contents_domain_name_pro", NULL },
        { NULL, NULL, }
    };

	if((pfd_contents == NULL) || (conf == NULL))
	{
        LOG(SESSION, ERR, "pfd_contents[%p] conf[%p] is NULL\n",pfd_contents,conf);
        return -1;
    }

	/*flow desc*/
	if(pfd_contents->flag.d.FD)
	{
		for (cnt = 0; cnt < pfd_contents->fd_num && cnt < MAX_PFD_FD_NUM; ++cnt) {
			ros_memset(buf_name,0,128);
	        sprintf(buf_name, "%s_%d", "flow_desc", cnt + 1);
	        fd_ptr = &pfd_contents->fd[cnt];
	        index = 0;

			ros_memset(fd_ptr, 0, sizeof(session_pfd_flow_desc));
			while (flow_desc_key_pair[index].key != NULL) {
		        flow_desc_key_pair[index].val = pcf_get_key_value(conf,
		                     buf_name, flow_desc_key_pair[index].key);
		        if (!flow_desc_key_pair[index].val) {
		            LOG(SESSION, ERR, "Can't get key[%s] in section[%s].\n",
		                flow_desc_key_pair[index].key, buf_name);
		            return -1;
		        }
		        ++index;
		    }
			index = 0;

			/* fd_iptype */
		    if (strlen(flow_desc_key_pair[index].val) > 0) {
				fd_ptr->ip_type = strtol(flow_desc_key_pair[index].val, NULL, 10);
		        ++index;
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		        return -1;
		    }

			/* fd_iptype */
			if(fd_ptr->ip_type == 2)
			{
				/* ipv6 */
				if (strlen(flow_desc_key_pair[index].val) > 0) {
			        if (1 != inet_pton(AF_INET6, flow_desc_key_pair[index].val,
			            fd_ptr->ip.ipv6)) {
			            LOG(SESSION, ERR, "parse ipv6 address failed.");
			            return -1;
			        }
			        ++index;
			    } else {
			        LOG(SESSION, ERR, "Invalid %s:%s config.\n", flow_desc_key_pair[index].key,
			            flow_desc_key_pair[index].val);
			        return -1;
			    }

				/* ipv6 mask */
		        if (strlen(flow_desc_key_pair[index].val) > 0) {
		            fd_ptr->mask.ipv6_mask[0] =
		                strtol(flow_desc_key_pair[index].val, NULL, 10);
		            ++index;
		        } else {
		            LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		                flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		            return -1;
		        }
			}
			else
			{
				/* ipv4 */
			    if (strlen(flow_desc_key_pair[index].val) > 0) {
			        if (1 != inet_pton(AF_INET, flow_desc_key_pair[index].val,
			            &fd_ptr->ip.ipv4)) {
			            LOG(SESSION, ERR, "parse ipv4 address failed.");
			            return -1;
			        }
			        fd_ptr->ip.ipv4 = ntohl(fd_ptr->ip.ipv4);
			        ++index;
			    } else {
			        LOG(SESSION, ERR, "Invalid %s:%s config.\n", flow_desc_key_pair[index].key,
			            flow_desc_key_pair[index].val);
			        return -1;
			    }

				/* ipv4 mask */
				if (strlen(flow_desc_key_pair[index].val) > 0) {
		            fd_ptr->mask.ipv4_mask = strtol(flow_desc_key_pair[index].val, NULL, 10);
		            ++index;
		        } else {
		            LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		                flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		            return -1;
	        	}
			}

			/* fd_pmin */
		    if (strlen(flow_desc_key_pair[index].val) > 0) {
				fd_ptr->port_min = strtol(flow_desc_key_pair[index].val, NULL, 10);
		        ++index;
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		        return -1;
		    }

			/* fd_pmax */
		    if (strlen(flow_desc_key_pair[index].val) > 0) {
				fd_ptr->port_max = strtol(flow_desc_key_pair[index].val, NULL, 10);
		        ++index;
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		        return -1;
		    }

			/* fd_protocol */
		    if (strlen(flow_desc_key_pair[index].val) > 0) {
				fd_ptr->protocol = strtol(flow_desc_key_pair[index].val, NULL, 10);
		        ++index;
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		        return -1;
		    }

			/* fd_action */
		    if (strlen(flow_desc_key_pair[index].val) > 0) {
				fd_ptr->action = strtol(flow_desc_key_pair[index].val, NULL, 10);
		        ++index;
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		        return -1;
		    }

			/* fd_dir */
		    if (strlen(flow_desc_key_pair[index].val) > 0) {
				fd_ptr->dir = strtol(flow_desc_key_pair[index].val, NULL, 10);
		        ++index;
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		        return -1;
		    }

			/* fd_ip_not */
		    if (strlen(flow_desc_key_pair[index].val) > 0) {
				fd_ptr->ip_not = strtol(flow_desc_key_pair[index].val, NULL, 10);
		        ++index;
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		        return -1;
		    }

			/* fd_no_port */
		    if (strlen(flow_desc_key_pair[index].val) > 0) {
				fd_ptr->no_port = strtol(flow_desc_key_pair[index].val, NULL, 10);
		        ++index;
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            flow_desc_key_pair[index].key, flow_desc_key_pair[index].val);
		        return -1;
		    }
		}
	}

	/* url */
	if(pfd_contents->flag.d.URL)
	{
		for (cnt = 0; cnt < pfd_contents->url_num && cnt < MAX_PFD_URL_NUM; ++cnt) {
			ros_memset(buf_name,0,128);
	        sprintf(buf_name, "%s_%d", "url", cnt + 1);

	        url_key_pair[0].val = pcf_get_key_value(conf,
	                     buf_name, url_key_pair[0].key);
	        if (!url_key_pair[0].val) {
	            LOG(SESSION, ERR, "Can't get key[%s] in section[%s].\n",
	                url_key_pair[0].key, buf_name);
	            return -1;
	        }

			ros_memset(pfd_contents->url[cnt], 0, MAX_PFD_URL_LEN);
		    if (strlen(url_key_pair[0].val) > 0) {
		        strcpy(pfd_contents->url[cnt],url_key_pair[0].val);
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            url_key_pair[0].key, url_key_pair[0].val);
		        return -1;
		    }
		}
	}

	/* custom_pfd */
	if(pfd_contents->flag.d.CP)
	{
	    custom_pfd_key_pair[0].val = pcf_get_key_value(conf,
	                 "custom_pfd_1", custom_pfd_key_pair[0].key);
	    if (!custom_pfd_key_pair[0].val) {
	        LOG(SESSION, ERR, "Can't get key[%s] in section[%s].\n",
	            custom_pfd_key_pair[0].key, "custom_pfd_1");
	        return -1;
	    }

		ros_memset(pfd_contents->custom_pfd, 0, MAX_PFD_CUSTOM_PFD_LEN);
	    if (strlen(custom_pfd_key_pair[0].val) > 0) {
	        strcpy(pfd_contents->custom_pfd,custom_pfd_key_pair[0].val);
	    } else {
	        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
	            custom_pfd_key_pair[0].key, custom_pfd_key_pair[0].val);
	        return -1;
	    }
	}

	/* domain_names */
	if(pfd_contents->flag.d.DN)
	{
		for (cnt = 0; cnt < pfd_contents->domain_names_num && cnt < MAX_PFD_DN_NUM; ++cnt) {
			ros_memset(buf_name,0,128);
	        sprintf(buf_name, "%s_%d", "domain_names", cnt + 1);

	        domain_names_key_pair[0].val = pcf_get_key_value(conf,
	                     buf_name, domain_names_key_pair[0].key);
	        if (!domain_names_key_pair[0].val) {
	            LOG(SESSION, ERR, "Can't get key[%s] in section[%s].\n",
	                domain_names_key_pair[0].key, buf_name);
	            return -1;
	        }

			ros_memset(pfd_contents->domain_names[cnt], 0, FQDN_LEN);
		    if (strlen(domain_names_key_pair[0].val) > 0) {
		        strcpy(pfd_contents->domain_names[cnt],domain_names_key_pair[0].val);
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            domain_names_key_pair[0].key, domain_names_key_pair[0].val);
		        return -1;
		    }
		}
	}

	/* domain_names_pro */
	if(pfd_contents->flag.d.DNP)
	{
		for (cnt = 0; cnt < pfd_contents->domain_name_pro_num && cnt < MAX_PFD_DN_NUM; ++cnt) {
			ros_memset(buf_name,0,128);
	        sprintf(buf_name, "%s_%d", "domain_names_pro", cnt + 1);

	        domain_names_pro_key_pair[0].val = pcf_get_key_value(conf,
	                     buf_name, domain_names_pro_key_pair[0].key);
	        if (!domain_names_pro_key_pair[0].val) {
	            LOG(SESSION, ERR, "Can't get key[%s] in section[%s].\n",
	                domain_names_pro_key_pair[0].key, buf_name);
	            return -1;
	        }

			ros_memset(pfd_contents->domain_name_pro[cnt], 0, FQDN_LEN);
		    if (strlen(domain_names_pro_key_pair[0].val) > 0) {
		        strcpy(pfd_contents->domain_name_pro[cnt],domain_names_pro_key_pair[0].val);
		    } else {
		        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
		            domain_names_pro_key_pair[0].key, domain_names_pro_key_pair[0].val);
		        return -1;
		    }
		}
	}
	return 0;
}

int pfd_parse_pfd_contents_num(session_pfd_contents *pfd_contents, uint8_t pfd_cont_num, struct pcf_file *conf)
{
	int index = 0;
	uint8_t cnt = 0;
	char buf_name[128] = {0};
	session_pfd_contents *pfd_contents_ptr = NULL;
    /* the key pair and value get must be in order */
	struct kv_pair pfd_contents_key_pair[] = {
        { "pfd_contents_flag", NULL },
		{ "pfd_contents_fd_num", NULL },
		{ "pfd_contents_url_num", NULL },
		{ "domain_names_num", NULL },
		{ "domain_name_pro_num", NULL },
        { NULL, NULL, }
    };

	if((pfd_contents == NULL) || (conf == NULL))
	{
        LOG(SESSION, ERR, "pfd_contents[%p] conf[%p] is NULL\n",pfd_contents,conf);
        return -1;
    }

	for (cnt = 0; cnt < pfd_cont_num && cnt < MAX_PFD_NUM_IN_APP; ++cnt) {
		ros_memset(buf_name,0,128);
        sprintf(buf_name, "%s_%d", "pfd_contents", cnt + 1);
        pfd_contents_ptr = &pfd_contents[cnt];
        index = 0;

		ros_memset(pfd_contents_ptr, 0, sizeof(session_pfd_contents));
		while (pfd_contents_key_pair[index].key != NULL) {
	        pfd_contents_key_pair[index].val = pcf_get_key_value(conf,
	                     buf_name, pfd_contents_key_pair[index].key);
	        if (!pfd_contents_key_pair[index].val) {
	            LOG(SESSION, ERR, "Can't get key[%s] in section[%s].\n",
	                pfd_contents_key_pair[index].key, buf_name);
	            return -1;
	        }
	        ++index;
	    }
		index = 0;

		/* pfd_contents_flag */
	    if (strlen(pfd_contents_key_pair[index].val) > 0) {
			pfd_contents_ptr->flag.value = strtol(pfd_contents_key_pair[index].val, NULL, 10);
	        ++index;
	    } else {
	        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
	            pfd_contents_key_pair[index].key, pfd_contents_key_pair[index].val);
	        return -1;
	    }

		/* pfd_contents_fd_num */
	    if (strlen(pfd_contents_key_pair[index].val) > 0) {
			pfd_contents_ptr->fd_num = strtol(pfd_contents_key_pair[index].val, NULL, 10);
	        ++index;
	    } else {
	        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
	            pfd_contents_key_pair[index].key, pfd_contents_key_pair[index].val);
	        return -1;
	    }

		/* pfd_contents_url_num */
	    if (strlen(pfd_contents_key_pair[index].val) > 0) {
			pfd_contents_ptr->url_num = strtol(pfd_contents_key_pair[index].val, NULL, 10);
	        ++index;
	    } else {
	        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
	            pfd_contents_key_pair[index].key, pfd_contents_key_pair[index].val);
	        return -1;
	    }

		/* domain_names_num */
	    if (strlen(pfd_contents_key_pair[index].val) > 0) {
			pfd_contents_ptr->domain_names_num = strtol(pfd_contents_key_pair[index].val, NULL, 10);
	        ++index;
	    } else {
	        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
	            pfd_contents_key_pair[index].key, pfd_contents_key_pair[index].val);
	        return -1;
	    }

		/* domain_name_pro_num */
	    if (strlen(pfd_contents_key_pair[index].val) > 0) {
			pfd_contents_ptr->domain_name_pro_num = strtol(pfd_contents_key_pair[index].val, NULL, 10);
	        ++index;
	    } else {
	        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
	            pfd_contents_key_pair[index].key, pfd_contents_key_pair[index].val);
	        return -1;
	    }

		if((pfd_contents_ptr->fd_num > MAX_PFD_FD_NUM) || (pfd_contents_ptr->url_num > MAX_PFD_URL_NUM) ||
			(pfd_contents_ptr->domain_names_num > MAX_PFD_DN_NUM) || (pfd_contents_ptr->url_num > MAX_PFD_DN_NUM))
		{
	        LOG(SESSION, ERR, "fd_num[%d] url_num[%d] domain_names_num[%d] url_num[%d] can't > 4\n",
	            pfd_contents_ptr->fd_num,pfd_contents_ptr->url_num,pfd_contents_ptr->domain_names_num,pfd_contents_ptr->url_num);
	        return -1;
	    }

		if(pfd_parse_pfd_contents(pfd_contents,conf) < 0)
		{
	        LOG(SESSION, ERR, "pfd_parse_pfd_contents parse failed!\n");
	        return -1;
	    }
	}

	return 0;
}

int pfd_parse_pfd_mgmt(session_application_ids_pfds *app_ids_pfds_ptr, struct pcf_file *conf)
{
	int index = 0;
    /* the key pair and value get must be in order */
	struct kv_pair app_id_key_pair[] = {
        { "application_id", NULL },
		{ "pfd_context_num", NULL },
        { NULL, NULL, }
    };
	struct kv_pair pfd_context_key_pair[] = {
		{ "pfd_contents_num", NULL },
        { NULL, NULL, }
    };

	if((app_ids_pfds_ptr == NULL) || (conf == NULL))
	{
        LOG(SESSION, ERR, "app_ids_pfds_ptr[%p] conf[%p] is NULL\n",app_ids_pfds_ptr,conf);
        return -1;
    }

	ros_memset(app_ids_pfds_ptr, 0, sizeof(session_application_ids_pfds));
	while (app_id_key_pair[index].key != NULL) {
        app_id_key_pair[index].val = pcf_get_key_value(conf,
                     "app_create", app_id_key_pair[index].key);
        if (!app_id_key_pair[index].val) {
            LOG(SESSION, ERR, "Can't get key[%s] in section[%s].\n",
                app_id_key_pair[index].key, "app_create");
            return -1;
        }
        ++index;
    }
	index = 0;

	/* application_id */
    if (strlen(app_id_key_pair[index].val) > 0) {
        strcpy(app_ids_pfds_ptr->application_id,app_id_key_pair[index].val);
        ++index;
    } else {
        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
            app_id_key_pair[index].key, app_id_key_pair[index].val);
        return -1;
    }

	/* pfd_context_num */
    if (strlen(app_id_key_pair[index].val) > 0) {
        app_ids_pfds_ptr->pfd_context_num = strtol(app_id_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
            app_id_key_pair[index].key, app_id_key_pair[index].val);
        return -1;
    }

	if(app_ids_pfds_ptr->pfd_context_num > 1)
	{
        LOG(SESSION, ERR, "pfd_context_num [%d] can't > %d.\n",
            app_ids_pfds_ptr->pfd_context_num,1);
        return -1;
    }

	/* pfd_contents_num */
	pfd_context_key_pair[0].val = pcf_get_key_value(conf,"pfd_context_1", pfd_context_key_pair[0].key);
    if (!pfd_context_key_pair[0].val) {
        LOG(SESSION, ERR, "Can't get key[%s] in section[%s].\n",
            pfd_context_key_pair[0].key, "pfd_context_1");
        return -1;
    }

	if (strlen(pfd_context_key_pair[0].val) > 0) {
        app_ids_pfds_ptr->pfd_context[0].pfd_contents_num = strtol(pfd_context_key_pair[0].val, NULL, 10);
    } else {
        LOG(SESSION, ERR, "Invalid %s:%s config.\n",
            pfd_context_key_pair[0].key, pfd_context_key_pair[0].val);
        return -1;
    }

	if(app_ids_pfds_ptr->pfd_context[0].pfd_contents_num > 1)
	{
        LOG(SESSION, ERR, "pfd_contents_num [%d] can't > %d.\n",
            app_ids_pfds_ptr->pfd_context[0].pfd_contents_num,1);
        return -1;
    }

	if(pfd_parse_pfd_contents_num(&app_ids_pfds_ptr->pfd_context[0].pfd_contents[0], 1, conf) < 0)
	{
        LOG(SESSION, ERR, "pfd_parse_pfd_contents parse failed!\n");
        return -1;
    }

	return 0;
}

int pfd_cli_process(struct cli_def *cli, int argc, char **argv)
{
    pfd_table_header *pfd_mgmt = pfd_get_table_header_public();
    pfd_entry *entry;
	session_application_ids_pfds app_ids_pfds_ptr;
	struct pcf_file * file_value;
	char file_name[128]={0};


    if (argc < 1 || 0 == strncmp(argv[0], "help", 4)) {
        goto help;
    }

	if(0 == strncmp(argv[0], "show", 4))
	{
		if(argc < 2 || argv[1] == NULL)
			goto help;

	    if (0 == strncmp(argv[1], "all", 3)) {
	        entry = (pfd_entry *)rbtree_first(&pfd_mgmt->pfd_root);
	        while (entry) {
	            cli_print(cli, "APP-No              APP-ID.\n", argv[1]);
	            cli_print(cli, "%-8u            %s\n", entry->index, entry->pfd.application_id);

	            entry = (pfd_entry *)rbtree_next(&entry->node);
	        }
	    } else {
	        entry = pfd_entry_search(argv[1]);
	        if (NULL == entry) {
	            cli_print(cli, "No such pfd(%s) entry.\n", argv[1]);
	            goto help;
	        }
	        pfd_entry_show_cli(cli, &entry->pfd);
	    }
	}
	else if(0 == strncmp(argv[0], "add", 3))
	{
		if(argc < 2 || argv[1] == NULL)
			goto help;

		sprintf(file_name,"%s%s",argv[1],".ini");
		file_value=pcf_conf_read_from_given_path(PFD_RULE_PATH,(char *)file_name);
		if(!file_value)
		{
	        cli_print(cli, "can't find file[%s]",file_name);
	        return -1;
	    }
		if(pfd_parse_pfd_mgmt(&app_ids_pfds_ptr,file_value) < 0)
		{
			cli_print(cli, "parse pfd[%s] failed\n",argv[1]);
			return -1;
		}

		if(pfd_entry_insert(&app_ids_pfds_ptr) < 0)
		{
			cli_print(cli, "add pfd[%s] failed\n",argv[1]);
			return -1;
		}
		else
		{
			cli_print(cli, "add pfd[%s] success\n",argv[1]);
		}
	}
	else if(0 == strncmp(argv[0], "del", 3))
	{
		if(argc < 2 || argv[1] == NULL)
			goto help;

		if(pfd_entry_remove(argv[1])<0)
		{
			cli_print(cli, "remove pfd[%s] failed\n",argv[1]);
			return -1;
		}
		else
		{
			cli_print(cli, "remove pfd[%s] success\n",argv[1]);
		}
	}
	else if(0 == strncmp(argv[0], "clear", 5))
	{
		pfd_table_clean_all();
	}
	else
	{
		cli_print(cli, "unknown type[%s], please input show/add/del/clear.\n",argv[0]);
		return 0;
	}

	return 0;

help:

    cli_print(cli, "pfd show <app id>|<all> /add <app id> /del <app id> /clear\n");

    return 0;
}

