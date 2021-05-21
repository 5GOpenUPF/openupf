/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __WHITE_LIST_H
#define __WHITE_LIST_H

#define MAX_WHITE_LIST_TABLE 1000
#define MAX_WHITE_LIST_HOST_LEN 256

struct white_list_table {
	struct rb_node         node;
	uint32_t                index;
	char					host[MAX_WHITE_LIST_HOST_LEN];
	uint32_t                ip;
	ros_rwlock_t            lock;
	uint32_t                head_enrich_flag;
	uint8_t					flag; /* 1: host  0: IP */
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


int64_t white_list_table_init(uint32_t pf_rule_num);
struct white_list_table *white_list_table_get(uint32_t index);
int cli_white_list(struct cli_def *cli, int argc, char **argv);
struct white_list_table *white_list_entry_search(char *host,uint32_t ipaddr,uint8_t flag);

#endif

