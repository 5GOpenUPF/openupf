/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _TUPLE_TABLE_H__
#define _TUPLE_TABLE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BUFFER_URL_LEN      1024

/* Tuple table recycling cycle time, Unit second */
#define TUPLE_TABLE_RECOVERY_CYCLE      20

/*
*   五元组中的信息都以Access为参考方向
*   Core方向来的报文需要将源和目的信息对换
*/
#pragma pack(1)
typedef struct tag_tuple_key {
    union {
        uint32_t    sipv4;
        uint8_t     sipv6[IPV6_ALEN];
    };
    union {
        uint32_t    dipv4;
        uint8_t     dipv6[IPV6_ALEN];
    };
    uint16_t        sport;
    uint16_t        dport;
    uint8_t         protocol;
} tuple_key;
#pragma pack()

typedef struct tag_tuple_table_entry {
    struct rb_node          tuple_node;
    struct dl_list          tuple_list; /* Priority recycling of linked list by time */

    tuple_key               key;
    uint8_t                 resv[2];
    uint8_t                 url_present;
    char                    url[MAX_BUFFER_URL_LEN];

    uint32_t                index;
    ros_rwlock_t            lock;
    uint32_t                create_time; /* Entry create time */
} tuple_table_entry;

typedef struct tag_tuple_table_head {
    tuple_table_entry       *tuple_entry;
    struct rb_root          tuple_root;
    struct dl_list       recov_list; /* Priority recycling of linked list by time */
    uint32_t                max_num;
    ros_rwlock_t            lock;
    uint16_t                pool_id;
} tuple_table_head;

tuple_table_head *tuple_head_get_public(void);

int64_t tuple_table_init(uint32_t fast_num);
int tuple_table_update(tuple_key *_5_tuple, char *url);
int tuple_table_search_url(tuple_key *_5_tuple, char *out_url);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _TUPLE_TABLE_H__ */





