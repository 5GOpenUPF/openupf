/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef _FP_MSG_H__
#define _FP_MSG_H__

#ifdef __cplusplus
extern "C" {
#endif


#define ACTION_DROP         0x01
#define ACTION_FORW         0x02
#define ACTION_BUFF         0x04
#define ACTION_NOCP         0x08
#define ACTION_DUPL         0x10
#define ACTION_TEMP         0x80        /* Add by user, not from standard */

#define FP_TIMER_BUFF_SIZE  1400


/*---------------------------------fast table---------------------------------*/

/* Hash bucket, contains hash tree, the index is hash value of filter entry */
#pragma pack(1)
typedef struct  tag_fp_fast_bucket
{
    AVLU_TREE           hash_tree;      /* AVL tree node */
    ros_rwlock_t        rwlock;         /* rw lock */
    uint32_t            node_count;     /* Number of node in the tree */
}fp_fast_bucket;
#pragma pack()

/* Fast table */
#pragma pack(1)
typedef struct  tag_fp_fast_entry
{
    struct avlu_node    *left;          /* pointer to the left subtree */
    struct avlu_node    *right;         /* pointer to the right subtree */
    int32_t             height;         /* height of the subtree */
    uint32_t            aux_info;       /* to resolve hash collision */
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t            valid :1;       /* valid bit */
    uint32_t            count :3;       /* recycle count */
    uint32_t            index :28;      /* index bits */
#else
    uint32_t            index :28;      /* index bits */
    uint32_t            count :3;       /* recycle count */
    uint32_t            valid :1;       /* valid bit */
#endif
    void                *tcp_seg_mgmt;	 /*use for tcp segment*/
    uint8_t             cfg_data[0];    /* configuration data from sp */
}fp_fast_entry;
#pragma pack()
#define FP_TABLE_ENTRY_COMMON_LEN           (sizeof(fp_fast_entry))

#pragma pack(1)
typedef struct tag_fp_fast_shadow
{
    NODE                lstnode;
    uint32_t            index;          /* index */
    uint32_t            key;            /* key for hash search */
    ros_rwlock_t        rwlock;         /* rw lock */
    LIST                list;           /* buff list when temp or buff action */
    uint8_t             resv[4];        /* align to 8 bytes */
    fp_fast_entry       *entry;         /* point to entry */
    struct  tag_fp_fast_table *head;    /* point to head */
}fp_fast_shadow;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_fast_table
{
    fp_fast_entry       *entry;         /* point to entry pool */
    fp_fast_shadow      *shadow;        /* point to shadow pool */
    fp_fast_bucket      *bucket;        /* pointer to first bucket */
    fp_fast_bucket      *frag;          /* pointer to first frag */
    uint32_t            entry_max;      /* Max number */
    uint32_t            bucket_mask;    /* Bucket distribute mask */
    uint16_t            res_no;
    uint8_t             port_no;        /* Port No. */
    uint8_t             port_type;      /* Port type */
}fp_fast_table;
#pragma pack()




/*---------------------------------far table----------------------------------*/
#pragma pack(1)
typedef struct  tag_fp_far_entry
{
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t            valid :1;       /* valid bit */
    uint32_t            resv  :3;       /* resv */
    uint32_t            index :28;      /* index bits */
#else
    uint32_t            index :28;      /* index bits */
    uint32_t            resv  :3;       /* resv */
    uint32_t            valid :1;       /* valid bit */
#endif
    ros_rwlock_t        rwlock;         /* this node rw lock */
    comm_msg_far_config config;         /* configuration */
    struct dl_list      inst_lst;       /* link back when use */
    struct dl_list      inst2_lst;      /* link back when use */
}fp_far_entry;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_far_table
{
    fp_far_entry        *entry;         /* point to entry pool */
    uint32_t            entry_max;      /* max number */
    uint16_t            res_no;
}fp_far_table;
#pragma pack()




/*---------------------------------bar table----------------------------------*/
/* Buffering configuration */
#pragma pack(1)
typedef struct  tag_fp_bar_container
{
    ros_atomic32_t      time_start;     /* timer start time */
    ros_atomic32_t      pkts_count;     /* current buffer packets */
}fp_bar_container;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_bar_entry
{
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t            valid :1;       /* valid bit */
    uint32_t            resv  :3;       /* resv */
    uint32_t            index :28;      /* index bits */
#else
    uint32_t            index :28;      /* index bits */
    uint32_t            resv  :3;       /* resv */
    uint32_t            valid :1;       /* valid bit */
#endif
    ros_rwlock_t        rwlock;         /* this node rw lock */
    comm_msg_bar_config config;
    fp_bar_container    container;
}fp_bar_entry;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_bar_table
{
    fp_bar_entry        *entry;         /* point to entry pool */
    uint32_t            entry_max;      /* max number */
    uint16_t            res_no;
}fp_bar_table;
#pragma pack()




/*---------------------------------urr table----------------------------------*/
#pragma pack(1)
typedef struct tag_fp_urr_mac_entry {
    struct avluint64_node   *left;      /* pointer to the left subtree */
    struct avluint64_node   *right;     /* pointer to the right subtree */
    int32_t             height;         /* height of the subtree */
    uint64_t            mac;            /* mac address, work as key */
    ros_atomic32_t      last_pkt;       /* UTC time, last packet time */
}fp_urr_mac_entry;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_urr_mac_bucket
{
    AVLU64_TREE         tree;           /* AVL tree node */
    comm_msg_urr_mac_t  *new_mac;       /* new mac address list */
    comm_msg_urr_mac_t  *obs_mac;       /* obsolescent mac address list */
    ros_rwlock_t        rwlock;         /* rw lock */
    ros_atomic32_t      entry_cnt;      /* how many node in table */
}fp_urr_mac_bucket;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_urr_mac_table
{
    fp_urr_mac_entry    *entry;         /* point to entry pool */
    uint32_t            entry_max;      /* max number */
    uint16_t            res_no;
}fp_urr_mac_table;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_urr_container
{
    uint8_t             vol_status;
    uint8_t             tim_status;
    uint8_t             eve_status;
    comm_msg_urr_vol_flag_t flag;       /* volume flag */
    ros_atomic64_t      vol_total;      /* remainder total volume number */
    ros_atomic64_t      vol_dlink;      /* remainder downlink volume number */
    ros_atomic64_t      vol_ulink;      /* remainder uplink volume number */
    ros_atomic32_t      time;           /* remainder time in second */
    ros_atomic32_t      event;          /* remainder event number */
    ros_atomic32_t      droppkts;       /* remainder dropped packets number */
    ros_atomic32_t      dropbyte;       /* remainder dropped bytes number */
    ros_atomic32_t      first_pkt;      /* first packet reach time */
    ros_atomic32_t      last_pkt;       /* last packet reach time */
    ros_atomic32_t      start_hold;     /* quota holding timer start time */
    ros_atomic32_t      start_time;     /* monitoring start time */
    struct ros_timer    *idt_timer;     /* inactivity detection timer */
    struct ros_timer    *mon_timer;     /* monitoring timer */
    struct ros_timer    *qht_timer;     /* quota holding timer */
    struct ros_timer    *per_timer;     /* quota holding timer */
    struct ros_timer    *eit_timer;     /* ethernet inactivity timer */
    comm_msg_urr_mon_time_t mon_cfg;    /* current effective configuration */
}fp_urr_container;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_urr_entry
{
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t            valid :1;       /* valid bit */
    uint32_t            resv  :3;       /* resv */
    uint32_t            index :28;      /* index bits */
#else
    uint32_t            index :28;      /* index bits */
    uint32_t            resv  :3;       /* resv */
    uint32_t            valid :1;       /* valid bit */
#endif
    ros_rwlock_t        rwlock;         /* this node rw lock */
    fp_urr_mac_bucket   mac_bucket;     /* if trace mac, for save mac info */
    fp_urr_container    container;      /* resource container */
    comm_msg_urr_config config;         /* core configuration */
}fp_urr_entry;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_urr_table
{
    fp_urr_entry        *entry;         /* point to entry pool */
    uint32_t            entry_max;      /* max number */
    uint16_t            res_no;
}fp_urr_table;
#pragma pack()




/*---------------------------------qer table----------------------------------*/
#pragma pack(1)
typedef struct tag_fp_qos_meter
{
    ros_atomic64_t      tokenc_num;      /* how many bytes left till now */
    uint64_t            tokenc_grow;     /* mbr * FP_QER_KBR_TO_BYTE */
	ros_atomic64_t      tokenp_num;      /* how many bytes left till now */
    uint64_t            tokenp_grow;     /* mbr * FP_QER_KBR_TO_BYTE */
    ros_atomic64_t      last_cycles;
    ros_atomic32_t      pkt_num;
	ros_atomic64_t 		debt;
    uint32_t            valid_cycle;
	uint32_t			color;
}fp_qos_meter;
#pragma pack()


#pragma pack(1)
typedef struct  tag_fp_qer_entry
{
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t            valid :1;       /* valid bit */
    uint32_t            resv  :3;       /* resv */
    uint32_t            index :28;      /* index bits */
#else
    uint32_t            index :28;      /* index bits */
    uint32_t            resv  :3;       /* resv */
    uint32_t            valid :1;       /* valid bit */
#endif
    ros_rwlock_t                qos_lock;       /* qer spin lock    */
    comm_msg_qer_config         qer_cfg;        /* qer config */
    fp_qos_meter                ul_meter;       /* uplink meter */
    fp_qos_meter                dl_meter;       /* downlink meter */
}fp_qer_entry;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_qer_table
{
    fp_qer_entry        *entry;         /* point to entry pool */
    uint32_t            entry_max;      /* max number */
    uint16_t            res_no;
}fp_qer_table;
#pragma pack()




/*---------------------------------inst table---------------------------------*/
#pragma pack(1)
typedef struct  tag_fp_inst_control
{
    uint8_t             light;          /* 0: green; 1: yellow; 2: red */
    uint8_t             urr_bnum;       /* urr_bqos number */
    uint8_t             urr_anum;       /* urr_aqos number */
    uint8_t             urr_dnum;       /* urr_dqos number */
    uint32_t            urr_bqos[MAX_URR_NUM];  /* urr list before qos */
    uint32_t            urr_aqos[MAX_URR_NUM];  /* urr list after qos */
    uint32_t            urr_drop[MAX_URR_NUM];  /* urr list of drop pkt */
}fp_inst_control;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_inst_entry
{
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t            valid :1;       /* valid bit */
    uint32_t            active:1;       /* Whether the flag is active */
    uint32_t            resv  :2;       /* resv */
    uint32_t            index :28;      /* index bits */
#else
    uint32_t            index :28;      /* index bits */
    uint32_t            resv  :2;       /* resv */
    uint32_t            active:1;       /* Whether the flag is active */
    uint32_t            valid :1;       /* valid bit */
#endif
    ros_rwlock_t        lstlock;        /* fast link rw lock */
    LIST                lstfast;        /* fast link list */
    ros_rwlock_t        rwlock;         /* this node rw lock */
    struct dl_list      far_node;      /* Link to far */
    struct dl_list      far2_node;     /* Link to far */
    comm_msg_inst_config config;
    comm_msg_urr_stat_t  stat;          /* stat of this instance */
    fp_inst_control     control;        /* local control block */
    uint32_t            inact;          /* inactivity count */
    uint32_t            max_act;        /* Maximum activation count */
}fp_inst_entry;
#pragma pack()

#define FP_MSG_MAX_STAT_BUF_SIZE        9000
#pragma pack(1)
typedef struct  tag_fp_inst_table
{
    fp_inst_entry       *entry;
    uint32_t            entry_max;      /* Max number */
    uint16_t            res_no;
    uint16_t            res_stat;       /* stat entry mark */
    int32_t             cur_stat_entry; /* current stat entry */
    uint8_t             resv[4];        /* keep aligning to 8 bytes */
    struct ros_timer    *stat_timer;    /* to handle stat entry */
}fp_inst_table;
#pragma pack()

static inline void fp_print_action_str(session_far_action *action, int trace_flag)
{
    LOG_TRACE(FASTPASS, RUNNING, trace_flag, "action: %s%s%s%s%s%s%s%s%s%s%s",
        action->d.drop ? "drop ":"",
        action->d.forw ? "forw ":"",
        action->d.buff ? "buff ":"",
        action->d.nocp ? "nocp ":"",
        action->d.dupl ? "dupl ":"",
        action->d.ipma ? "ipma ":"",
        action->d.ipmd ? "ipmd ":"",
        action->d.dfrt ? "dfrt ":"",
        action->d.edrt ? "edrt ":"",
        action->d.bdpn ? "bdpn ":"",
        action->d.ddpn ? "ddpn ":"");
}

uint32_t fp_fast_clear(uint32_t type);

inline void *fp_fast_entry_get(fp_fast_table *head, uint32_t index);
inline void *fp_fast_shadow_get(fp_fast_table *head, uint32_t index);
inline fp_inst_entry *fp_inst_entry_get(uint32_t index);
inline fp_far_entry *fp_far_entry_get(uint32_t index);
inline fp_bar_entry *fp_bar_entry_get(uint32_t index);
inline fp_qer_entry *fp_qer_entry_get(uint32_t index);


void fp_msg_copy_volume(comm_msg_urr_volume_t *dst, comm_msg_urr_volume_t *src);

inline comm_msg_header_t *fp_msg_header_fill(void *buf);
inline void fp_msg_entry_val_hton(comm_msg_entry_val_config_t *val_cfg);
uint32_t fp_msg_proc(void *trans_mng, comm_msg_ie_t *ie);
fp_fast_entry *fp_fast_table_add(fp_fast_table *head, fp_fast_entry *entry,
    uint32_t hash_key, uint32_t aux_info);
fp_fast_entry *fp_fast_alloc(fp_fast_table *head);
uint32_t fp_fast_free(fp_fast_table *head, uint32_t index);

int fp_msg_send(char *buf, uint32_t len);
void fp_msg_fast_copy(comm_msg_fast_cfg *entry_cfg, comm_msg_fast_cfg *input_cfg);
uint32_t fp_fast_link_add(uint32_t inst_index, fp_fast_shadow *shadow);
void fp_msg_inst_second_timer(void *timer, uint64_t para);
int fp_write_wireshark(char *buf, int len);

#ifdef __cplusplus
}
#endif

#endif /* _FP_MSG_H__ */

