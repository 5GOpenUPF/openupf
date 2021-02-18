/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SP_DNS_CACHE__H__
#define __SP_DNS_CACHE__H__

/* DNS老化检查周期 */
#define SDC_DNS_CACHE_AGEING_PERIOD     (5)

#define SDC_SNIFFER_ENABLE

enum EN_SDC_DNS_TAG {
    SDC_DNS_WHITE_LIST = 1,
    SDC_DNS_OTHER,
};

typedef struct tag_sp_dns_cache_entry {
    struct rb_node          dns_node;
    uint32_t                index;
    ros_rwlock_t            lock;
    comm_msg_dns_config     dns_cfg;
    uint8_t                 dns_tag; /* EN_SDC_DNS_TAG */
    uint8_t                 spare[7];
} sp_dns_cache_entry;

typedef struct tag_sp_dns_cache_table {
    sp_dns_cache_entry      *entry;
    struct rb_root          dns_root;
    uint32_t                max_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
    uint16_t                spare;
    uint32_t                aging_time; /* default 24 hours == 86400 seconds */
} sp_dns_cache_table;

#ifdef SDC_SNIFFER_ENABLE
typedef struct tag_sp_dns_sniffer_entry {
    struct rb_node          snf_node;
    char                    dname[COMM_MSG_DNS_NAME_LENG];
    uint32_t                index;
    ros_rwlock_t            lock;
} sp_dns_sniffer_entry;

typedef struct tag_sp_dns_sniffer_table {
    sp_dns_sniffer_entry    *entry;
    struct rb_root          snf_root;
    uint32_t                max_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
    uint8_t                 master_switch; /* 0:disable   1:enable */
    uint8_t                 spare[5];
} sp_dns_sniffer_table;

sp_dns_sniffer_table *sdc_sniffer_get_table_public(void);
#endif

int sdc_sniffer_match(char *url);
int sdc_sniffer_master_switch(void);



sp_dns_cache_table *sdc_get_table_public(void);
int sdc_check_dns(char *d_name, void *ip_addr, uint8_t ip_ver);
struct fsm_audit *sdc_get_audit_simple(void);
struct fsm_audit *sdc_get_audit_4am(void);

int64_t sdc_init(uint32_t dns_num);
uint32_t sdc_sum(void);
void sdc_del(uint32_t *index_arr, uint32_t index_num);
int sdc_update_ie_proc(comm_msg_ie_t *ie);
uint32_t sdc_check_all(comm_msg_ie_t *ie, int fd);
int sdc_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd);

#endif

