/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __PDR_MGMT_H
#define __PDR_MGMT_H


typedef enum {
    NON_FILTER,
    FILTER_SDF,
    FILTER_ETH
} filter_type;

union pdr_ipv6_key {
    struct {
        uint64_t    key1;
        uint64_t    key2;
    } d;
    uint8_t     value[IPV6_ALEN];
};

struct pdr_key {
    union {
        uint32_t            ipv4;
        union pdr_ipv6_key  ipv6;
    } ip_addr;
    uint32_t teid;
};

struct sdf_filter_entry {
    struct dl_list      sdf_filter_node;
    session_sdf_filter  sdf_cfg;
    uint32_t            index;
};

struct sdf_filter_table {
    struct sdf_filter_entry     *sdf_filter_entry;
    uint32_t                    max_num;
    ros_atomic32_t              use_num;
    ros_rwlock_t                lock;
    uint16_t                    pool_id;
};

struct eth_filter {
    uint32_t                    eth_filter_id;
    uint16_t                    eth_type;
    session_eth_filter_prop     eth_filter_prop;
    uint8_t                     mac_addr_num;
    session_mac_addr            mac_addr[MAX_MAC_ADDRESS_NUM];
    session_vlan_tag            c_tag;
    session_vlan_tag            s_tag;
    struct dl_list              sdf_list;
};

struct ul_pdu_sess_info
{
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t                 ext_len:5; /* extention header length, by bytes */
    uint8_t                 ts_ofs :3; /* Offset of time stamp field in optional[8] */
#else
    uint8_t                 ts_ofs :3;
    uint8_t                 ext_len:5;
#endif

    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint8_t                 pdu_type:4; /* 0 */
        uint8_t                 qmp     :1; /* if 1, need take time stamp */
        uint8_t                 ddi     :1; /*DL Delay Ind*/
        uint8_t                 udi     :1; /*UL Delay Ind*/
        uint8_t                 spare1  :1;
#else
        uint8_t                 spare1  :1;
        uint8_t                 udi     :1; /*UL Delay Ind*/
        uint8_t                 ddi     :1; /*DL Delay Ind*/
        uint8_t                 qmp     :1; /* if 1, need take time stamp */
        uint8_t                 pdu_type:4; /* 0 */
#endif

#if BYTE_ORDER == BIG_ENDIAN
        uint8_t                 spare2  :2;
        uint8_t                 qfi     :6;
#else
        uint8_t                 qfi     :6;
        uint8_t                 spare2  :2;
#endif

        uint8_t                 optional[24]; /**
                                              * PPI field: 0 or 1 octets
                                              * time_stamp: 0 or 4 octets,second number from 0 h 1 January 1900 UTC
                                              * Padding: 0~3 octets
                                              **/
    }s;
};

struct eth_filter_entry {
    struct dl_list      eth_filter_node;
    struct eth_filter   eth_cfg;
    uint32_t            index;
};

struct eth_filter_table {
    struct eth_filter_entry     *eth_filter_entry;
    uint32_t                    max_num;
    ros_atomic32_t              use_num;
    ros_rwlock_t                lock;
    uint16_t                    pool_id;
};

struct pdr_framed_route {
    struct rb_node              route_node;
    struct dl_list              pq_node;
    session_framed_route        route;
    struct pdr_table            *pdr_tbl;
};

struct pdr_framed_route_ipv6 {
    struct rb_node              route_node;
    struct dl_list              pq_node;
    session_framed_route_ipv6   route;
    struct pdr_table            *pdr_tbl;
};

struct pdr_ue_ipaddress {
    struct rb_node              v4_node; /* IPv4 RB node */
    struct rb_node              v6_node; /* IPv6 RB node */
    struct dl_list              v4_pq_node; /* IPv4 precedence queue */
    struct dl_list              v6_pq_node; /* IPv6 precedence queue */
    session_ue_ip               ueip;
    struct pdr_table            *pdr_tbl; /* Link PDR */
};

struct pdr_local_fteid {
    struct rb_node              v4_node; /* IPv4 */
    struct rb_node              v6_node; /* IPv6 */
    struct dl_list              v4_pq_node; /* IPv4 precedence queue */
    struct dl_list              v6_pq_node; /* IPv6 precedence queue */
    session_f_teid              local_fteid;
    struct pdr_table            *pdr_tbl; /* Link PDR */
};

struct pkt_detection_info {
    struct pdr_local_fteid          local_fteid[2]; /* Only when PDIU is supported can there be two local f-teid */
    char                            network_instance[NETWORK_INSTANCE_LEN];
    struct pdr_ue_ipaddress         ue_ipaddr[MAX_UE_IP_NUM];
    struct dl_list                  filter_list;

    filter_type                     filter_type;
    uint8_t                         si;
    uint8_t                         traffic_endpoint_num;
    session_eth_pdu_sess_info       eth_pdu_ses_info;
    uint8_t                         qfi_number;

    struct pdr_framed_route         framed_ipv4_route[MAX_FRAMED_ROUTE_NUM];
    struct pdr_framed_route_ipv6    framed_ipv6_route[MAX_FRAMED_ROUTE_NUM];
    char                            application_id[MAX_APP_ID_LEN];
    uint8_t                         qfi_array[MAX_QFI_NUM];
    uint8_t                         traffic_endpoint_id[MAX_TC_ENDPOINT_NUM];
    uint8_t                         framed_ipv4_route_num;
    uint8_t                         framed_ipv6_route_num;
    uint8_t                         ue_ipaddr_num;
    session_3gpp_interface_type     src_if_type;

    uint8_t                         local_fteid_num;
    uint8_t                         application_id_present;
    uint8_t                         src_if_type_present;
    uint8_t                         spare;
    uint32_t                        framed_routing;
    uint32_t                		head_enrich_flag;
};

struct pkt_detection_rule {
    uint16_t                        pdr_id;
    uint8_t                         far_present;
    uint8_t                         mar_present;
    uint32_t                        precedence;
    struct pkt_detection_info       pdi_content;
    comm_msg_outh_rm_t              outer_header_removal;
    uint32_t                        far_id;
    uint32_t                        urr_list_number;
    uint32_t                        qer_list_number;
    uint32_t                        urr_id_array[MAX_URR_NUM];
    uint32_t                        qer_id_array[MAX_QER_NUM];
    uint16_t                        mar_id;
    uint8_t                         act_pre_number;
    session_act_predef_rules        act_pre_arr[ACTIVATE_PREDEF_RULE_NUM];
    uint32_t                        activation_time;
    uint32_t                        deactivation_time;
};

struct pdr_private {
    uint32_t                        far_index;
    uint32_t                        mar_index;
};

struct pdr_table {
    struct rb_node              pdr_node;   /* key is pdr id */
    struct pkt_detection_rule   pdr;
    struct pdr_private          pdr_pri;
    struct dl_list              eth_dl_node; /* Only use downlink PDR of ethernet PDN */
    struct rb_root              predef_root; /* Predefined root node of binary tree */
    uint32_t                    index;      /* also instance index */
    ros_rwlock_t                lock;
    struct session_t            *session_link;  /* PDR associated session */
    struct ros_timer            *timer_id;  /* timerID of active and deactive */
    struct ros_timer            *nocp_report_timer;  /* NOCP report request timer */
    ros_atomic16_t              nocp_flag;  /* 1:not report, 0:already report */
    uint8_t                     is_active;  /* 1:pdr active 0: pdr deactive */
};

struct pdr_table_head {
    struct pdr_table    *pdr_table;
    struct rb_root      fteid_v4_root;
    struct rb_root      fteid_v6_root;
    struct rb_root      ueip_dv4_root; /* The S-D field of the UE IP address is set to 1 */
    struct rb_root      ueip_dv6_root; /* The S-D field of the UE IP address is set to 1 */
    struct rb_root      ueip_sv4_root; /* The S-D field of the UE IP address is set to 0 */
    struct rb_root      ueip_sv6_root; /* The S-D field of the UE IP address is set to 0 */
    struct rb_root      fr_v4_root;
    struct rb_root      fr_v6_root;
    uint32_t            max_num;
    ros_atomic32_t      use_num;
    ros_rwlock_t        teid_v4_lock;
    ros_rwlock_t        teid_v6_lock;
    ros_rwlock_t        ueip_v4_lock;
    ros_rwlock_t        ueip_v6_lock;
    ros_rwlock_t        fr_v4_lock;
    ros_rwlock_t        fr_v6_lock;
    uint16_t            pool_id;
};

struct pdr_table_head *pdr_get_head(void);
inline uint32_t pdr_get_max_num(void);

void pdr_table_show(struct pdr_table *pdr_tbl);
struct pdr_table *pdr_get_table(uint32_t index);
struct pdr_table *pdr_get_table_public(uint32_t index);
uint16_t pdr_get_pool_id(void);
int64_t pdr_table_init(uint32_t session_num);
struct pdr_table *pdr_table_create(struct session_t *sess, uint16_t id);
/* Create a predefined PDR rule group associated with a PDR table */
struct pdr_table *pdr_table_create_to_pdr_table(struct session_t *sess,
    struct pdr_table *root_pdr, char *predef_name);
int pdr_remove(struct session_t *sess, uint16_t *id_arr, uint8_t id_num,
    uint32_t *rm_pdr_index_arr, uint32_t *rm_pdr_num, uint32_t *fail_id);
int pdr_remove_predefined_pdr(struct session_t *sess, struct pdr_table *root_pdr, char *predef_name);
struct pdr_table *pdr_table_search(struct session_t *sess, uint16_t id);
struct pdr_table *pdr_map_lookup(struct filter_key *key);
int pdr_fraud_identify(struct filter_key *key, struct pdr_table *pdr_tbl);
void pdr_set_deactive_timer_cb(void *timer, uint64_t para);
int pdr_set_active(struct pdr_table *pdr_tbl);
int pdr_insert(struct session_t *sess, void *parse_pdr_arr,
    uint32_t pdr_num, uint32_t *fail_id);
int pdr_modify(struct session_t *sess, void *parse_pdr_arr,
    uint32_t pdr_num, uint32_t *fail_id);
int pdr_clear(struct session_t *sess,
    uint8_t fp_sync, struct session_rules_index * rules);
int pdr_sum(void);
int sdf_filter_create(struct dl_list *sdf_list_head,
    session_sdf_filter *sdf_cfg);
struct eth_filter_entry *eth_filter_create(struct dl_list *eth_list_head,
    void *eth_cfg);
int pdr_show_activate_table(struct cli_def *cli, int argc, char **argv);
int pdr_arp_match_ueip(struct pdr_key *rb_key, uint8_t is_v4);
struct pdr_table *pdr_ueip_match(struct pdr_key *rb_key, uint8_t is_v4);

#endif

