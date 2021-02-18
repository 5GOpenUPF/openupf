/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_ORPHAN_H__
#define __SESSION_ORPHAN_H__


enum EN_PACKET_TYPE {
    EN_PKT_TYPE_IPV4    = 1,
    EN_PKT_TYPE_IPV6    = 2,
    EN_PKT_TYPE_ETH     = 3,
};

struct sp_fast_entry {
    struct rb_node      oph_node;       /* node on orphan tree */
    struct dl_list      list_node;      /* tree node queue */
    struct pdr_key      key;            /* match pdr rules key */
    uint8_t             ue_mac[ETH_ALEN]; /* Only Ethernet bearer */
    uint8_t             pdr_si;
    uint8_t             pkt_type;       /* EN_PACKET_TYPE */
    uint32_t            fast_id;        /* fast table index */
    uint32_t            index;          /* orphan entry index */
};

struct sp_orphan_table_head {
    struct sp_fast_entry        *fast_entry;
    struct rb_root              oph_fteid_v4_root; /* packet have GTP header */
    struct rb_root              oph_ueip_v4_root;
    struct rb_root              oph_fteid_v6_root; /* packet have GTP header */
    struct rb_root              oph_ueip_v6_root;
    struct rb_root              oph_ue_mac_root; /* Ethernet 802.3 */
    uint32_t                    max_num;
    ros_atomic32_t              use_num;
    ros_rwlock_t                lock;
    uint16_t                    pool_id;
};


int session_orphan_insert(uint32_t fast_id,
    uint8_t is_gtpu, uint8_t pkt_type, void *p_key);
int session_orphan_modify(uint32_t *index_arr, uint32_t index_num);
int64_t session_orphan_table_init(uint32_t orphan_num);

#endif
