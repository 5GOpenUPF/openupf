/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_audit.h"
#include "session_msg.h"
#include "predefine_rule_mgmt.h"
#include "sp_backend_mgmt.h"
#include "sp_dns_cache.h"

sp_dns_cache_table g_sdc_table;
struct fsm_audit sdc_audit_4am;
struct fsm_audit sdc_audit_simple;

static int sdc_fp_amd(uint32_t *index_arr, uint32_t index_num, uint32_t cmd, int fd);


#ifdef SDC_SNIFFER_ENABLE
sp_dns_sniffer_table g_sdc_sniffer_table;

static inline sp_dns_sniffer_table *sdc_sniffer_get_table(void)
{
    return &g_sdc_sniffer_table;
}

sp_dns_sniffer_table *sdc_sniffer_get_table_public(void)
{
    return &g_sdc_sniffer_table;
}

static inline sp_dns_sniffer_entry *sdc_sniffer_get_entry(uint32_t index)
{
    return &g_sdc_sniffer_table.entry[index];
}

static int64_t sdc_sniffer_init(uint32_t dns_num)
{
    int32_t             pool_id;
    sp_dns_sniffer_entry *sniffer_entry = NULL;
    sp_dns_sniffer_table *sniffer_table = sdc_sniffer_get_table();
    int64_t             total_mem = 0, size = 0;
    uint32_t            loop;

    /* create DNS sniffer table */
    size = dns_num * sizeof(sp_dns_sniffer_entry);
    total_mem += size;
    sniffer_entry = ros_malloc(size);
    if (NULL == sniffer_entry) {
        LOG(SESSION, ERR, "Malloc fail.");
        return -1;
    }
    ros_memset(sniffer_entry, 0, size);

    for (loop = 0; loop < dns_num; loop++) {
        sniffer_entry[loop].index = loop;
        ros_rwlock_init(&sniffer_entry[loop].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Create pool fail.");
        return -1;
    }

    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, dns_num)) {
        LOG(SESSION, ERR, "Add section fail.");
        return -1;
    }

    sniffer_table->pool_id      = pool_id;
    sniffer_table->max_num      = dns_num;
    sniffer_table->entry        = sniffer_entry;
    sniffer_table->snf_root     = RB_ROOT_INIT_VALUE;
    sniffer_table->master_switch= 0; /* default disable */
    ros_rwlock_init(&sniffer_table->lock);

    return total_mem;
}

static int sdc_sniffer_key_compare(struct rb_node *node, void *key)
{
    sp_dns_sniffer_entry *entry = (sp_dns_sniffer_entry *)node;
    char *name = (char *)key;

    return strcmp(entry->dname, name);
}

int sdc_sniffer_update(char *url)
{
    sp_dns_sniffer_entry  *entry = NULL;
    sp_dns_sniffer_table  *table = sdc_sniffer_get_table();
    uint32_t index, key;

    if (strlen(url) >= COMM_MSG_DNS_NAME_LENG) {
        LOG(SESSION, ERR, "DNS sniffer domain name too long, Cannot exceed %u",
            COMM_MSG_DNS_NAME_LENG);
        return -1;
    }

    LOG(SESSION, RUNNING, "create DNS sniffer.");
    ros_rwlock_write_lock(&table->lock); /* lock */
    entry = (sp_dns_sniffer_entry *)rbtree_search(&table->snf_root,
        url, sdc_sniffer_key_compare);
    ros_rwlock_write_unlock(&table->lock); /* unlock */
    if (NULL == entry) {
        if (G_FAILURE == Res_Alloc(table->pool_id, &key, &index, EN_RES_ALLOC_MODE_OC)) {
            LOG(SESSION, ERR, "The resources are exhausted.");
            return -1;
        }
        entry = sdc_sniffer_get_entry(index);
        ros_rwlock_write_lock(&entry->lock); /* lock */
        strcpy(entry->dname, url);
        ros_rwlock_write_unlock(&entry->lock); /* unlock */

        ros_rwlock_write_lock(&table->lock);/* lock */
        if (0 > rbtree_insert(&table->snf_root, &entry->snf_node,
            entry->dname, sdc_sniffer_key_compare)) {
            ros_rwlock_write_unlock(&table->lock);/* unlock */
            Res_Free(table->pool_id, key, index);
            LOG(SESSION, ERR, "insert dns sniffer to root failed, name: %s.",
                entry->dname);
            return -1;
        }
        ros_rwlock_write_unlock(&table->lock);/* unlock */
    } else {
        LOG(SESSION, RUNNING, "This DNS sniffer already exists.");
    }

    return 0;
}

int sdc_sniffer_del(char *url)
{
    sp_dns_sniffer_entry  *entry = NULL;
    sp_dns_sniffer_table  *table = sdc_sniffer_get_table();

    if (strlen(url) >= COMM_MSG_DNS_NAME_LENG) {
        LOG(SESSION, ERR, "DNS sniffer domain name too long, Cannot exceed %u",
            COMM_MSG_DNS_NAME_LENG);
        return -1;
    }

    LOG(SESSION, RUNNING, "Remove DNS sniffer.");
    ros_rwlock_write_lock(&table->lock); /* lock */
    entry = (sp_dns_sniffer_entry *)rbtree_delete(&table->snf_root,
        url, sdc_sniffer_key_compare);
    ros_rwlock_write_unlock(&table->lock); /* unlock */
    if (NULL == entry) {
        LOG(SESSION, RUNNING, "No such DNS sniffer, %s.", url);
        return -1;
    }
    Res_Free(table->pool_id, 0, entry->index);

    return 0;
}

int sdc_sniffer_match(char *url)
{
    sp_dns_sniffer_entry  *entry = NULL;
    sp_dns_sniffer_table  *table = sdc_sniffer_get_table();

    if (strlen(url) >= COMM_MSG_DNS_NAME_LENG) {
        LOG(SESSION, ERR, "DNS sniffer domain name too long, Cannot exceed %u",
            COMM_MSG_DNS_NAME_LENG);
        return -1;
    }

    LOG(SESSION, RUNNING, "Search DNS sniffer.");
    ros_rwlock_write_lock(&table->lock); /* lock */
    entry = (sp_dns_sniffer_entry *)rbtree_search(&table->snf_root,
        url, sdc_sniffer_key_compare);
    ros_rwlock_write_unlock(&table->lock); /* unlock */

    return entry == NULL ? -1 : 0;
}

int sdc_sniffer_master_switch(void)
{
    sp_dns_sniffer_table *table = sdc_sniffer_get_table();

    return table->master_switch;
}

int sdc_sniffer_cmd(struct cli_def *cli, int argc, char **argv)
{
    sp_dns_sniffer_table *table = sdc_sniffer_get_table();

    if (argc < 1 || 0 == strncmp(argv[0], "help", 4) || 0 == strncmp(argv[0], "hlep", 4)) {
        goto hlep;
    }

    if (argc > 0 && 0 == strncmp(argv[0], "show", 4)) {
        sp_dns_sniffer_entry *entry = NULL;
        uint32_t cnt = 0;

        cli_print(cli, "DNS sniffer master switch: %s",
            table->master_switch ? "enabled" : "disabled");
        cli_print(cli, "--------------DNS sniffer enabled list--------------");
        entry = (sp_dns_sniffer_entry *)rbtree_first(&table->snf_root);
        while (entry) {
            cli_print(cli, "domain name[%u]: %s", ++cnt, entry->dname);

            entry = (sp_dns_sniffer_entry *)rbtree_next(&entry->snf_node);
        }
    } else if (argc > 1 && 0 == strncmp(argv[0], "add", 3)) {

        if (strlen(argv[1]) >= COMM_MSG_DNS_NAME_LENG) {
            cli_print(cli, "Domain name length too long, Less than %u is required.",
                COMM_MSG_DNS_NAME_LENG);
            return -1;
        }

        if (0 > sdc_sniffer_update(argv[1])) {
            cli_print(cli, "Add dns sniffer failed.");
            return -1;
        }
        cli_print(cli, "Add dns sniffer success.");
    } else if (argc > 1 && 0 == strncmp(argv[0], "del", 3)) {

        if (strlen(argv[1]) >= COMM_MSG_DNS_NAME_LENG) {
            cli_print(cli, "Domain name length too long, Less than %u is required.",
                COMM_MSG_DNS_NAME_LENG);
            return -1;
        }

        if (0 > sdc_sniffer_del(argv[1])) {
            cli_print(cli, "Del dns sniffer failed.");
            return -1;
        }
        cli_print(cli, "Del dns sniffer success.");
    } else if (argc > 0 && 0 == strncmp(argv[0], "enable", 6)) {
        table->master_switch = 1;
    } else if (argc > 0 && 0 == strncmp(argv[0], "disable", 7)) {
        table->master_switch = 0;
    } else {
        goto hlep;
    }

    return 0;

hlep:

    cli_print(cli, "usage: dns_snf <add|del|show|enable|disable> [domain name]");
    cli_print(cli, "  e.g. dns_snf add www.10086.com");
    cli_print(cli, "  e.g. dns_snf show");
    cli_print(cli, "  e.g. dns_snf enable");
    cli_print(cli, "  e.g. dns_snf disable");
    cli_print(cli, "  \"enable\" Global enabled, all rules will enable DNS sniffer.");

    return -1;
}
#else
int sdc_sniffer_match(char *url)
{
    return 0;
}

int sdc_sniffer_master_switch(void)
{
    return 1;
}

int sdc_sniffer_cmd(struct cli_def *cli, int argc, char **argv)
{
    return 0;
}
#endif

static inline sp_dns_cache_table *sdc_get_table(void)
{
    return &g_sdc_table;
}

sp_dns_cache_table *sdc_get_table_public(void)
{
    return &g_sdc_table;
}

static inline sp_dns_cache_entry *sdc_get_entry(uint32_t index)
{
    if (index < g_sdc_table.max_num)
        return &g_sdc_table.entry[index];
    else
        return NULL;
}

inline struct fsm_audit *sdc_get_audit_simple(void)
{
    return &sdc_audit_simple;
}

inline struct fsm_audit *sdc_get_audit_4am(void)
{
    return &sdc_audit_4am;
}

void sdc_entry_show(sp_dns_cache_entry *entry)
{
    uint8_t cnt = 0;

    LOG(SESSION, DEBUG, "--------------DNS--------------");
    LOG(SESSION, DEBUG, "index: %u", entry->index);
    LOG(SESSION, DEBUG, "name: %s", entry->dns_cfg.name);
    LOG(SESSION, DEBUG, "expire: %u", entry->dns_cfg.expire);
    LOG(SESSION, DEBUG, "ipaddr_num: %u", entry->dns_cfg.ipaddr_num);
    for (cnt = 0; cnt < entry->dns_cfg.ipaddr_num; ++cnt) {
        if (entry->dns_cfg.ipaddr[cnt].ip_ver == EN_DNS_IPV4) {
            LOG(SESSION, DEBUG, "IPv4: 0x%08x", entry->dns_cfg.ipaddr[cnt].ip.ipv4);
        } else {
            LOG(SESSION, DEBUG, "IPv6: 0x%08x %08x %08x %08x",
                *(uint32_t *)&entry->dns_cfg.ipaddr[cnt].ip.ipv6[0],
                *(uint32_t *)&entry->dns_cfg.ipaddr[cnt].ip.ipv6[4],
                *(uint32_t *)&entry->dns_cfg.ipaddr[cnt].ip.ipv6[8],
                *(uint32_t *)&entry->dns_cfg.ipaddr[cnt].ip.ipv6[12]);
        }
    }
}

static void *sdc_ageing_task(void *arg)
{
    sp_dns_cache_entry  *entry = NULL;
    sp_dns_cache_table  *table = sdc_get_table();
    int32_t cur_index = -1;
    uint32_t cur_time;

    for (;;) {
        cur_time = ros_getime();

        cur_index = Res_GetAvailableInBand(table->pool_id, cur_index + 1, table->max_num);
        for (; -1 != cur_index;) {
            entry = sdc_get_entry(cur_index);

            if (entry->dns_cfg.expire < cur_time) {
                sdc_del(&entry->index, 1);
                sdc_fp_amd(&entry->index, 1, EN_COMM_MSG_UPU_DNS_DEL, MB_SEND2BE_BROADCAST_FD);
            }

            cur_index = Res_GetAvailableInBand(table->pool_id, cur_index + 1, table->max_num);
        }

        sleep(SDC_DNS_CACHE_AGEING_PERIOD);
    }

    return NULL;
}

int64_t sdc_init(uint32_t dns_num)
{
    int32_t             pool_id;
    sp_dns_cache_entry  *entry = NULL;
    sp_dns_cache_table  *table = sdc_get_table();
    int64_t             total_mem = 0, size = 0;
    uint32_t            loop;
    pthread_t           pthr_id;

    /* create DNS cache table */
    size = dns_num * sizeof(sp_dns_cache_entry);
    total_mem += size;
    entry = ros_malloc(size);
    if (NULL == entry) {
        LOG(SESSION, ERR, "Malloc fail.");
        return -1;
    }
    ros_memset(entry, 0, size);

    for (loop = 0; loop < dns_num; loop++) {
        entry[loop].index = loop;
        ros_rwlock_init(&entry[loop].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(SESSION, ERR, "Create pool fail.");
        return -1;
    }

    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, dns_num)) {
        LOG(SESSION, ERR, "Add section fail.");
        return -1;
    }

    table->pool_id      = pool_id;
    table->max_num      = dns_num;
    table->entry        = entry;
    ros_rwlock_init(&table->lock);
    table->dns_root     = RB_ROOT_INIT_VALUE;
    table->aging_time   = 86400;

    /* create DNS sniffer table */
    size = sdc_sniffer_init(dns_num);
    if (0L > size) {
        LOG(SESSION, ERR, "DNS sniffer init failed.");
        return -1;
    }
    total_mem += size;

    if (0 != pthread_create(&pthr_id, NULL, sdc_ageing_task, NULL)) {
        LOG(SESSION, ERR, "create dns ageing task pthread failed.");
        return -1;
    }

    /* init 4am audit */
    if (0 > audit_4am_init(&sdc_audit_4am, EN_DNS_AUDIT)) {
        LOG(SESSION, ERR, "audit_4am_init failed.");
        return -1;
    }

    /* init sample audit */
    if (0 > audit_simple_init(&sdc_audit_simple, EN_DNS_AUDIT)) {
        LOG(SESSION, ERR, "Simple audit init failed.");
        return -1;
    }

    return total_mem;
}

static int sdc_key_compare(struct rb_node *node, void *key)
{
    sp_dns_cache_entry *entry = (sp_dns_cache_entry *)node;
    char *name = (char *)key;

    return strcmp(entry->dns_cfg.name, name);
}

static inline void sdc_dns_config_hton(comm_msg_dns_config *cfg)
{
    uint16_t cnt;

    if (cfg->ipaddr_num > COMM_MSG_DNS_IP_NUM) {
        /* 防止非法调用引起内存越界 */
        LOG(SESSION, ERR, "ERROR: Illegal function call.");
        return;
    }
    for (cnt = 0; cnt < cfg->ipaddr_num; ++cnt) {
        if (EN_DNS_IPV4 == cfg->ipaddr[cnt].ip_ver) {
            cfg->ipaddr[cnt].ip.ipv4 = htonl(cfg->ipaddr[cnt].ip.ipv4);
        }
    }
    cfg->expire     = htonl(cfg->expire);
    cfg->ipaddr_num = htons(cfg->ipaddr_num);
}

/* 只能网络序转主机序才能调用，否则会引起不必要的循环异常 */
static inline void sdc_dns_config_ntoh(comm_msg_dns_config *cfg)
{
    uint16_t cnt;

    cfg->expire     = ntohl(cfg->expire);
    cfg->ipaddr_num = ntohs(cfg->ipaddr_num);
    if (cfg->ipaddr_num > COMM_MSG_DNS_IP_NUM) {
        /* 防止非法调用引起内存越界 */
        LOG(SESSION, ERR, "ERROR: Illegal function call.");
        return;
    }
    for (cnt = 0; cnt < cfg->ipaddr_num; ++cnt) {
        if (EN_DNS_IPV4 == cfg->ipaddr[cnt].ip_ver) {
            cfg->ipaddr[cnt].ip.ipv4 = ntohl(cfg->ipaddr[cnt].ip.ipv4);
        }
    }
}

int sdc_add(uint32_t index, comm_msg_dns_config *cfg, uint8_t dns_tag)
{
    sp_dns_cache_entry  *entry = NULL;
    sp_dns_cache_table  *table = sdc_get_table();

    LOG(SESSION, RUNNING, "Add new DNS cache entry[%u]", index);
    if (G_FAILURE == Res_AllocTarget(table->pool_id, 0, index)) {
        LOG(SESSION, ERR, "Resource alloc fail.");
        return -1;
    }
    entry = sdc_get_entry(index);

    LOG(SESSION, DEBUG, "Add new DNS cache, name: %s", cfg->name);
    ros_rwlock_write_lock(&entry->lock); /* lock */
    ros_memcpy(&entry->dns_cfg, cfg, sizeof(comm_msg_dns_config));
    entry->dns_tag = dns_tag;
    if (entry->dns_tag == SDC_DNS_WHITE_LIST) {
        /* 白名单的DNS设置配置超时时间 */
        entry->dns_cfg.expire = ros_getime() + table->aging_time;
    }
    ros_rwlock_write_unlock(&entry->lock); /* unlock */

    ros_rwlock_write_lock(&table->lock);/* lock */
    if (0 > rbtree_insert(&table->dns_root, &entry->dns_node,
        entry->dns_cfg.name, sdc_key_compare)) {
        ros_rwlock_write_unlock(&table->lock);/* unlock */
        Res_Free(table->pool_id, 0, index);
        LOG(SESSION, ERR, "insert dns cache to root failed, name: %s.",
            entry->dns_cfg.name);
        return -1;
    }
    ros_rwlock_write_unlock(&table->lock);/* unlock */

    return 0;
}

int sdc_update(uint32_t index, comm_msg_dns_config *cfg)
{
    sp_dns_cache_entry  *entry = NULL;
    sp_dns_cache_table  *table = sdc_get_table();
    uint8_t dns_tag = SDC_DNS_OTHER;

    /* 验证是否是白名单的DNS */
    if (NULL != white_list_entry_search(cfg->name, 0, 1)) {
        dns_tag = SDC_DNS_WHITE_LIST;
        LOG(SESSION, RUNNING, "DNS match white-list success, %s.", cfg->name);
    }

    if (G_TRUE == Res_IsAlloced(table->pool_id, 0, index)) {
        entry = sdc_get_entry(index);
        ros_rwlock_write_lock(&entry->lock); /* lock */
        if (0 == strcmp(entry->dns_cfg.name, cfg->name)) {
            ros_memcpy(&entry->dns_cfg, cfg, sizeof(comm_msg_dns_config));
            entry->dns_tag = dns_tag;
            if (entry->dns_tag == SDC_DNS_WHITE_LIST) {
                /* 白名单的DNS设置配置超时时间 */
                entry->dns_cfg.expire = ros_getime() + table->aging_time;
            }
            ros_rwlock_write_unlock(&entry->lock); /* unlock */
        } else {
            ros_memcpy(&entry->dns_cfg, cfg, sizeof(comm_msg_dns_config));
            entry->dns_tag = dns_tag;
            if (entry->dns_tag == SDC_DNS_WHITE_LIST) {
                /* 白名单的DNS设置配置超时时间 */
                entry->dns_cfg.expire = ros_getime() + table->aging_time;
            }
            ros_rwlock_write_unlock(&entry->lock); /* unlock */

            /* 域名改变但entry没变, 先从二叉树上删除再插入 */
            ros_rwlock_write_lock(&table->lock);/* lock */
            rbtree_erase(&entry->dns_node, &table->dns_root);

            if (0 > rbtree_insert(&table->dns_root, &entry->dns_node,
                entry->dns_cfg.name, sdc_key_compare)) {
                ros_rwlock_write_unlock(&table->lock);/* unlock */
                Res_Free(table->pool_id, 0, index);
                LOG(SESSION, ERR, "reinsert dns cache to root failed, name: %s.",
                    entry->dns_cfg.name);
                return -1;
            }
            ros_rwlock_write_unlock(&table->lock);/* unlock */
        }

        return 0;
    } else {
        if (0 > sdc_add(index, cfg, dns_tag)) {
            LOG(SESSION, ERR, "Add dns cache failed.");
            return -1;
        }
    }

    return 0;
}

void sdc_del(uint32_t *index_arr, uint32_t index_num)
{
    sp_dns_cache_entry  *entry = NULL;
    sp_dns_cache_table  *table = sdc_get_table();
    uint32_t cnt;

    for (cnt = 0; cnt < index_num; ++cnt) {
        entry = sdc_get_entry(index_arr[cnt]);

        ros_rwlock_write_lock(&table->lock); /* lock */
        rbtree_erase(&entry->dns_node, &table->dns_root);
        ros_rwlock_write_unlock(&table->lock); /* unlock */
        Res_Free(table->pool_id, 0, entry->index);
    }
}

int sdc_check_dns(char *d_name, void *ip_addr, uint8_t ip_ver)
{
    sp_dns_cache_entry  *entry = NULL;
    sp_dns_cache_table  *table = sdc_get_table();
    comm_msg_dns_ip     *dns_ip;
    uint32_t cnt;
    uint32_t target_ipv4 = *(uint32_t *)ip_addr;
    uint8_t *target_ipv6 = (uint8_t *)ip_addr;

    ros_rwlock_write_lock(&table->lock);/* lock */
    entry = (sp_dns_cache_entry *)rbtree_search(&table->dns_root,
        d_name, sdc_key_compare);
    ros_rwlock_write_unlock(&table->lock);/* unlock */
    if (NULL == entry) {
        LOG(SESSION, ERR, "No such dns cache(%s), default match success.",
            d_name);
        /* 本地没有DNS cache 默认匹配成功 */
        return 0;
    }

    dns_ip = entry->dns_cfg.ipaddr;
    for (cnt = 0; cnt < entry->dns_cfg.ipaddr_num; ++cnt) {
        switch (ip_ver) {
            case EN_DNS_IPV4:
                LOG(SESSION, DEBUG, "Compare IP: 0x%08x <> 0x%08x",
                    dns_ip[cnt].ip.ipv4, target_ipv4);
                if (EN_DNS_IPV4 == dns_ip[cnt].ip_ver &&
                    dns_ip[cnt].ip.ipv4 == target_ipv4) {
                    return 0;
                }
                break;

            case EN_DNS_IPV6:
                LOG(SESSION, DEBUG, "Compare IP: 0x%08x %08x %08x %08x <> 0x%08x %08x %08x %08x",
                    *(uint32_t *)&dns_ip[cnt].ip.ipv6[0],
                    *(uint32_t *)&dns_ip[cnt].ip.ipv6[4],
                    *(uint32_t *)&dns_ip[cnt].ip.ipv6[8],
                    *(uint32_t *)&dns_ip[cnt].ip.ipv6[12],
                    *(uint32_t *)&target_ipv6[0],
                    *(uint32_t *)&target_ipv6[4],
                    *(uint32_t *)&target_ipv6[8],
                    *(uint32_t *)&target_ipv6[12]);
                if (EN_DNS_IPV6 == dns_ip[cnt].ip_ver &&
                    0 == ros_memcmp(dns_ip[cnt].ip.ipv6, target_ipv6, IPV6_ALEN)) {
                    return 0;
                }
                break;

            default:
                LOG(SESSION, ERR, "Unsupport IP version: %d", ip_ver);
                return -1;
        }
    }

    return -1;
}

int sdc_update_ie_proc(comm_msg_ie_t *ie)
{
    uint32_t cnt;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    comm_msg_dns_ie_data *ie_data = NULL;

    if (NULL == ie) {
        LOG(SESSION, ERR, "Parameter abnormal, ie(%p).",
            ie);
        return -1;
    }

    ie_data = (comm_msg_dns_ie_data *)rule_ie->data;
    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        ie_data[cnt].index = ntohl(ie_data[cnt].index);
        sdc_dns_config_ntoh(&ie_data[cnt].cfg);
        if (0 > sdc_update(ie_data[cnt].index, &ie_data[cnt].cfg)) {
            LOG(SESSION, ERR, "Update dns cache failed, index: %u.",
                ie_data[cnt].index);
        }
    }

    return 0;
}

/* 请求fpu往spu下发指定index的(添加/修改/删除)请求 */
static int sdc_fp_amd(uint32_t *index_arr, uint32_t index_num, uint32_t cmd, int fd)
{
    uint8_t                     buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                    buf_len = 0;
    comm_msg_header_t           *msg;
    comm_msg_rules_ie_t         *ie = NULL;
    uint32_t                    cnt = 0, data_cnt = 0;
    uint32_t                    *ie_data = NULL;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(uint32_t);

    if (unlikely(0 == index_num)) {
        LOG(SESSION, ERR, "parameter is invalid, index number: %u.",
            index_num);
        return -1;
    }

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd     = htons(cmd);
    ie_data     = (uint32_t *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        ie_data[data_cnt] = htonl(index_arr[cnt]);
        ++data_cnt;

        if (data_cnt >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(uint32_t) * data_cnt;
            ie->rules_num = htonl(data_cnt);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > session_msg_send_to_fp((char *)buf, buf_len, fd)) {
                LOG(UPC, ERR, "Send buffer to backend failed.");
                return -1;
            }
            data_cnt = 0;
        }
    }

    if (data_cnt > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(uint32_t) * data_cnt;
        ie->rules_num = htonl(data_cnt);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > session_msg_send_to_fp((char *)buf, buf_len, fd)) {
            LOG(UPC, ERR, "Send buffer to backend failed.");
            return -1;
        }
        data_cnt = 0;
    }

    return 0;
}

inline uint32_t sdc_sum(void)
{
    sp_dns_cache_table *table = sdc_get_table();

    return Res_GetAlloced(table->pool_id);
}

uint32_t sdc_check_all(comm_msg_ie_t *ie, int fd)
{
    sp_dns_cache_table  *table = sdc_get_table();
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    sp_dns_cache_entry *entry = NULL;
    comm_msg_dns_ie_data *ie_data = NULL;
    uint32_t cnt = 0;
    uint32_t mod_arr[ONCE_CHANGE_NUMBER_MAX], mod_num = 0;

    if (NULL == ie) {
        LOG(SESSION, ERR, "parameter is invalid, ie(%p).", ie);
        return -1;
    }

    ie_data = (comm_msg_dns_ie_data *)rule_ie->data;
    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t index = ntohl(ie_data[cnt].index);

        if (G_FALSE == Res_IsAlloced(table->pool_id, 0, index)) {
            LOG(SESSION, ERR, "entry is invalid, index: %u.",
                index);
            continue;
        }

        sdc_dns_config_ntoh(&ie_data[cnt].cfg);
        entry = sdc_get_entry(index);
        if (NULL == entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", index);
            continue;
        }

        ros_rwlock_read_lock(&entry->lock);// lock
        if (ros_memcmp(&ie_data[cnt].cfg, &entry->dns_cfg, sizeof(comm_msg_dns_config))) {
            ros_rwlock_read_unlock(&entry->lock);// unlock
            if (mod_num == ONCE_CHANGE_NUMBER_MAX) {
                if (0 > sdc_fp_amd(mod_arr, mod_num, EN_COMM_MSG_UPU_DNS_ADD, fd)) {
                    LOG(SESSION, ERR, "Modify fpu entry failed.");
                    return -1;
                }
                mod_num = 0;
            }
            mod_arr[mod_num] = index;
            ++mod_num;
        } else {
            ros_rwlock_read_unlock(&entry->lock);// unlock
        }
    }

    if (mod_num > 0) {
        if (0 > sdc_fp_amd(mod_arr, mod_num, EN_COMM_MSG_UPU_DNS_ADD, fd)) {
            LOG(SESSION, ERR, "Modify fpu entry failed.");
            return -1;
        }
    }

    return 0;
}

int sdc_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd)
{
    sp_dns_cache_table *table = sdc_get_table();
    uint32_t field_num = 0, cnt = 0, sp_del = 0, fp_add2sp = 0, diff = 0;
    uint32_t remainder = 0;
    uint32_t del_arr[ONCE_CHANGE_NUMBER_MAX], del_num = 0;
    uint32_t add_arr[ONCE_CHANGE_NUMBER_MAX], add_num = 0;
    uint8_t val_data[SERVICE_BUF_TOTAL_LEN];
    comm_msg_entry_val_config_t *sp_val_cfg = (comm_msg_entry_val_config_t *)val_data;

    LOG(SESSION, RUNNING, "validity action start.");

    if (NULL == fp_val_cfg) {
        LOG(SESSION, ERR, "Abnormal parameter, fp_val_cfg(%p).", fp_val_cfg);
        return -1;
    }

    if (0 > session_val_ntoh(fp_val_cfg)) {
        LOG(SESSION, ERR, "Abnormal parameters, invalid 'val config'.");
        return -1;
    }

    if (G_SUCCESS != Res_GetRangeField(table->pool_id, 0,
        fp_val_cfg->start, fp_val_cfg->entry_num, sp_val_cfg->data)) {
        LOG(SESSION, ERR, "Get range field failed, start: %u, entry_num: %u.",
            fp_val_cfg->start, fp_val_cfg->entry_num);
        return -1;
    }

    field_num = fp_val_cfg->entry_num >> RES_PART_LEN_BIT;
    for (cnt = 0; cnt < field_num; ++cnt) {
        diff = sp_val_cfg->data[cnt] ^ fp_val_cfg->data[cnt];
        if (diff) {
            uint32_t start_bit = fp_val_cfg->start + (cnt << RES_PART_LEN_BIT);

            sp_del = (sp_val_cfg->data[cnt] & diff) ^ diff;
            fp_add2sp = (fp_val_cfg->data[cnt] & diff) ^ diff;

            if (sp_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    sdc_del(del_arr, del_num);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, sp_del,
                    del_arr, &del_num);
            }
            if (fp_add2sp) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    sdc_fp_amd(add_arr, add_num, EN_COMM_MSG_UPU_DNS_ADD, fd);
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_add2sp,
                    add_arr, &add_num);
            }
        }
    }

    remainder = fp_val_cfg->entry_num & RES_PART_LEN_MASK;
    if (remainder) {
        diff = sp_val_cfg->data[cnt] ^ fp_val_cfg->data[cnt];
        diff &= ~((1 << (RES_PART_LEN - remainder)) - 1);
        if (diff) {
            uint32_t start_bit = fp_val_cfg->start + (cnt << RES_PART_LEN_BIT);

            sp_del = (sp_val_cfg->data[cnt] & diff) ^ diff;
            fp_add2sp = (fp_val_cfg->data[cnt] & diff) ^ diff;

            if (sp_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    sdc_del(del_arr, del_num);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, sp_del,
                    del_arr, &del_num);
            }
            if (fp_add2sp) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    sdc_fp_amd(add_arr, add_num, EN_COMM_MSG_UPU_DNS_ADD, fd);
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_add2sp,
                    add_arr, &add_num);
            }
        }
    }

    if (del_num > 0) {
        sdc_del(del_arr, del_num);
    }
    if (add_num > 0) {
        sdc_fp_amd(add_arr, add_num, EN_COMM_MSG_UPU_DNS_ADD, fd);
    }

    return 0;
}

int sdc_aging_time_set(struct cli_def *cli, int argc, char **argv)
{
    sp_dns_cache_table *dns_tbl = sdc_get_table_public();
    uint32_t time = 0, cnt;

    if (argc < 1 || 0 == strncmp(argv[0], "help", 4)) {
        cli_print(cli, "dns_aging [<Dec>d] [<Dec>h] [<Dec>m] [<Dec>s]");
        cli_print(cli, "Examples: dns_aging 1d 2h 3m 4s");
        cli_print(cli, "d: day  h: hour  m: minute  s: second");
        return -1;
    }

    for (cnt = 0; cnt < argc; ++cnt) {
        if (strchr(argv[cnt], 'd')) {
            time += atoi(argv[cnt]) * 86400;
        } else if (strchr(argv[cnt], 'h')) {
            time += atoi(argv[cnt]) * 3600;
        } else if (strchr(argv[cnt], 'm')) {
            time += atoi(argv[cnt]) * 60;
        } else if (strchr(argv[cnt], 's')) {
            time += atoi(argv[cnt]);
        }
    }

    if (0 == time) {
        cli_print(cli, "Set aging time fail, invaild parameter.");
        return -1;
    }

    dns_tbl->aging_time = time;

    return 0;
}

int sdc_table_show(struct cli_def *cli, int argc, char **argv)
{
    sp_dns_cache_table *dns_tbl = sdc_get_table();
    sp_dns_cache_entry *entry = NULL;
    uint32_t cnt, cur_time = ros_getime(), total_num = 0, tmp_addr;
    char ip_str[512];

    cli_print(cli, "--------------DNS cache list--------------");
    entry = (sp_dns_cache_entry *)rbtree_first(&dns_tbl->dns_root);
    while (entry) {
        cli_print(cli, "name[%u]: %s", ++total_num, entry->dns_cfg.name);
        cli_print(cli, "TTL: %u", entry->dns_cfg.expire > cur_time ? entry->dns_cfg.expire - cur_time : 0);
        cli_print(cli, "ipaddr_num: %u", entry->dns_cfg.ipaddr_num);
        for (cnt = 0; cnt < entry->dns_cfg.ipaddr_num; ++cnt) {
            if (entry->dns_cfg.ipaddr[cnt].ip_ver == EN_DNS_IPV4) {
                tmp_addr = htonl(entry->dns_cfg.ipaddr[cnt].ip.ipv4);
                if (NULL == inet_ntop(AF_INET, &tmp_addr, ip_str, sizeof(ip_str))) {
                    cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                    continue;
                }
                cli_print(cli, "IPv4: %s", ip_str);
            } else {
                if (NULL == inet_ntop(AF_INET6, entry->dns_cfg.ipaddr[cnt].ip.ipv6, ip_str, sizeof(ip_str))) {
                    cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                    continue;
                }
                cli_print(cli, "IPv6: %s", ip_str);
            }
        }
        cli_print(cli, "");

        entry = (sp_dns_cache_entry *)rbtree_next(&entry->dns_node);
    }

    if (argc > 0 && 0 == strncmp(argv[0], "add", 3)) {
        comm_msg_dns_config cfg = {.name = "www.baidu.com", .expire = ros_getime() + 10};
        if (0 > sdc_add(1, &cfg, SDC_DNS_OTHER)) {
            cli_print(cli, "Add dns cache failed.");
        }

    }

    return 0;
}

