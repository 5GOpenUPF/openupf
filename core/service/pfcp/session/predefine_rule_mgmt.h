/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __PFRULE_MGMT_H
#define __PFRULE_MGMT_H

//预定义规则表宏
#define MAX_PF_RULE_TABLE 1000
#define MAX_PF_RULE_NAME_LEN 64
#define MAX_PF_RULE_PDR_TABLE 2
#define MAX_PF_RULE_FAR_TABLE 6
#define MAX_PF_RULE_QER_TABLE 6
#define MAX_PF_RULE_URR_TABLE 6
#define MAX_PF_RULE_QUOTE_PDR_TABLE 100

//白名单表宏
#define MAX_WHITE_LIST_TABLE 1000
#define MAX_WHITE_LIST_HOST_LEN 256

//预定义规则表
struct predefine_table {
	uint32_t	index;
	uint8_t		predefine_name[MAX_PF_RULE_NAME_LEN];
	uint32_t	pdr_id[MAX_PF_RULE_PDR_TABLE];
	uint32_t	pdr_index[MAX_PF_RULE_PDR_TABLE];
	uint32_t	pdr_num;
	uint32_t	bar_id;
	uint32_t	bar_index;
	uint32_t	bar_num;
	uint32_t	far_id[MAX_PF_RULE_FAR_TABLE];
	uint32_t	far_index[MAX_PF_RULE_FAR_TABLE];
	uint32_t	far_num;
	uint32_t	qer_id[MAX_PF_RULE_QER_TABLE];
	uint32_t	qer_index[MAX_PF_RULE_QER_TABLE];
	uint32_t	qer_num;
	uint32_t	urr_id[MAX_PF_RULE_URR_TABLE];
	uint32_t	urr_index[MAX_PF_RULE_URR_TABLE];
	uint32_t	urr_num;
	uint32_t	quote_pdr_index[MAX_PF_RULE_QUOTE_PDR_TABLE];
	uint32_t	quote_pdr_num;
	ros_rwlock_t lock;
	uint8_t		inuse;
	uint8_t		activate;
};

struct pf_rule_table_head {
    struct predefine_table *pf_table;
    uint32_t                max_num;
    ros_atomic32_t          use_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
};

//白名单表
struct white_list_table {
	struct rb_node         node;
	uint32_t                index;
	char					host[MAX_WHITE_LIST_HOST_LEN];
	uint32_t                ip;
	ros_rwlock_t            lock;
	uint32_t                head_enrich_flag;//头增强时要增加哪些字段
	uint8_t					flag;//1代表host，0代表iP
};

struct white_list_table_head {
    struct white_list_table *wl_table;
	struct rb_root      	ip_root;
    struct rb_root      	host_root;
    uint32_t                max_num;
    ros_atomic32_t          use_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
};

extern int64_t pf_rule_table_init(uint32_t pf_rule_num);
extern struct predefine_table *pf_rule_table_get(uint32_t index);
extern uint32_t pf_rule_table_create(void);
extern struct predefine_table *pf_rule_table_search(uint8_t *rule_name);
extern int pf_rule_table_show(struct cli_def *cli, int argc, char **argv);
extern uint32_t pf_rule_table_delete(uint32_t index);
extern uint32_t pf_rule_table_clear(void);

extern int64_t white_list_table_init(uint32_t pf_rule_num);
extern struct white_list_table *white_list_table_get(uint32_t index);
extern int cli_white_list(struct cli_def *cli, int argc, char **argv);
extern struct white_list_table *white_list_entry_search(char *host,uint32_t ipaddr,uint8_t flag);


#endif