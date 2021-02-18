/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_ETHERNET_H
#define __SESSION_ETHERNET_H


struct session_ethernet_entry {
    struct rb_node          eth_node;   /* Global UE MAC tree node */
    struct dl_list          sess_node;  /* Session UE MAC list node */
    struct session_t        *session;  /* Associated session */
    ros_rwlock_t            lock;
    uint32_t                index;
    uint8_t                 ue_mac[ETH_ALEN]; /* UE MAC key */
    uint8_t                 spare[2];
};

struct session_ethernet_table {
    struct session_ethernet_entry   *eth_entry;
    struct rb_root                  eth_root;
    uint32_t                        max_num;
    ros_rwlock_t                    lock;
    uint16_t                        pool_id;
    uint8_t                         spare[6];
};

int se_entry_insert(struct session_t *sess, uint8_t *ue_mac);
int se_entry_delete(struct session_t *sess);
struct session_ethernet_entry *se_entry_search(uint8_t *ue_mac);

int64_t se_table_init(uint32_t session_num);

#endif

