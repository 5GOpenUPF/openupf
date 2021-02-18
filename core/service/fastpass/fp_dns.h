/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __FP_DNS__H__
#define __FP_DNS__H__

#define FP_DNS_BUCKET_NUM               256
#define FP_DNS_CLASS_IN                 1
#define FP_DNS_ANS_TTL                  55

/**
 * DNS error codes in the flags.rcode field of the parsed response. These match
 * external definitions found in RFCs. Values below 16 are found in the original
 * DNS header, while larger values are constructed from the EDNS0 field.
 */
enum {
    FP_DNS_R_NOERROR        = 0,
    FP_DNS_R_FORMERR        = 1,  /* Format Error                     [RFC1035] */
    FP_DNS_R_SERVFAIL       = 2,  /* Server Failure                   [RFC1035] */
    FP_DNS_R_NXDOMAIN       = 3,  /* Non-Existent Domain              [RFC1035] */
    FP_DNS_R_NOTIMP         = 4,  /* Not Implemented                  [RFC1035] */
    FP_DNS_R_REFUSED        = 5,  /* Query Refused                    [RFC1035] */
    FP_DNS_R_YXDOMAIN       = 6,  /* Name Exists when it should't     [RFC2136] */
    FP_DNS_R_YXRRSET        = 7,  /* RR Set Exists when it should't   [RFC2136] */
    FP_DNS_R_NXRRSET        = 8,  /* RR Set that should exist does't  [RFC2136] */
    FP_DNS_R_NOTAUTH        = 9,  /* Not Authorized                   [RFC2845] */
    FP_DNS_R_NOTZONE        = 10, /* Name not contained in zone       [RFC2136] */
    FP_DNS_R_BADSIG         = 16, /* TSIG Signature Failure           [RFC2845] */
    FP_DNS_R_BADKEY         = 17, /* Key not recognized               [RFC2845] */
    FP_DNS_R_BADTIME        = 18, /* Signature out of time window     [RFC2845] */
    FP_DNS_R_BADMODE        = 19, /* Bad TKEY Mode                    [RFC2930] */
    FP_DNS_R_BADNAME        = 20, /* Duplicate key name               [RFC2930] */
    FP_DNS_R_BADALG         = 21, /* Algorithm not supported          [RFC2930] */
    FP_DNS_R_BADTRUNC       = 22, /* Bad Truncation                   [RFC4635] */
};

enum {
    FP_DNS_TYPE_A           = 1,
    FP_DNS_TYPE_NS          = 2,
    FP_DNS_TYPE_CNAME       = 5,
    FP_DNS_TYPE_SOA         = 6,
    FP_DNS_TYPE_PTR         = 12,
    FP_DNS_TYPE_HINFO       = 13,
    FP_DNS_TYPE_MX          = 15,
    FP_DNS_TYPE_TXT         = 16,
    FP_DNS_TYPE_RP          = 17,
    //FP_DNS_TYPE_SIG         = 24,
    //FP_DNS_TYPE_KEY         = 25,
    FP_DNS_TYPE_AAAA        = 28,
    FP_DNS_TYPE_SRV         = 33,
    FP_DNS_TYPE_NAPTR       = 35,
    FP_DNS_TYPE_CERT        = 37,
    FP_DNS_TYPE_OPT         = 41,
    FP_DNS_TYPE_DS          = 43,
    FP_DNS_TYPE_SSHFP       = 44,
    FP_DNS_TYPE_RRSIG       = 46,
    FP_DNS_TYPE_NSEC        = 47,
    FP_DNS_TYPE_DNSKEY      = 48,
    FP_DNS_TYPE_NSEC3       = 50,
    FP_DNS_TYPE_NSEC3PARAM  = 51,
    FP_DNS_TYPE_TLSA        = 52,
    FP_DNS_TYPE_CDS         = 59,
    FP_DNS_TYPE_CDNSKEY     = 60,
    FP_DNS_TYPE_SPF         = 99,
    //FP_DNS_TYPE_AXFR        = 252,
    //FP_DNS_TYPE_ANY         = 255,
    FP_DNS_TYPE_CAA         = 257,
};

/**
 * The value of the flags.opcode field. These are externally defined in RFCs and
 * match the values found in the packet.
 */
enum {
    FP_DNS_OP_QUERY         = 0,
    FP_DNS_OP_IQUERY        = 1,
    FP_DNS_OP_STATUS        = 2,
    FP_DNS_OP_NOTIFY        = 4, /* NS_NOTIFY_OP */
    FP_DNS_OP_UPDATE        = 5, /* NS_UPDATE_OP */
};

#pragma pack(1)
typedef union tag_fp_dns_ans_name {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t                h   :2;
        uint16_t                l   :14;
#else
        uint16_t                l   :14;
        uint16_t                h   :2;
#endif
    }d;
    uint16_t value;
} fp_dns_rr_name_point;
#pragma pack()

#pragma pack(1)
typedef struct tag_fp_dns_rr{
    uint16_t            dnstype;
    uint16_t            dnsclass;
    uint32_t            ttl;
    uint16_t            length;
    uint8_t             rrdata[0];
}fp_dns_rr;
#pragma pack()
#define FP_DNS_RR_DATA_OFFSIZE          sizeof(fp_dns_rr)

#pragma pack(1)
typedef union tag_fp_dns_flags {
    struct {
#if BYTE_ORDER == BIG_ENDIAN
        uint16_t                qr          :1;
        uint16_t                opcode      :4;
        uint16_t                aa          :1;
        uint16_t                tc          :1;
        uint16_t                rd          :1;
        uint16_t                ra          :1;
        uint16_t                z           :1;
        uint16_t                ans_auth    :1;
        uint16_t                non_auth    :1;
        uint16_t                reply_code  :4;
#else
        uint16_t                reply_code  :4;
        uint16_t                non_auth    :1;
        uint16_t                ans_auth    :1;
        uint16_t                z           :1;
        uint16_t                ra          :1;
        uint16_t                rd          :1;
        uint16_t                tc          :1;
        uint16_t                aa          :1;
        uint16_t                opcode      :4;
        uint16_t                qr          :1;
#endif
    }d;
    uint16_t value;
} fp_dns_flags;
#pragma pack()

#pragma pack(1)
typedef struct tag_fp_dns_header {
    uint16_t            id;             /* ID:长度为16位，是一个用户发送查询的时候定义的随机数 */
    fp_dns_flags        flags;          /* Flags:长度16位 */
    uint16_t            ques;           /* QDCount:长度16位，报文请求段中的问题记录数。 */
    uint16_t            answ;           /* ANCount:长度16位，报文回答段中的回答记录数。 */
    uint16_t            auth;           /* NSCOUNT :长度16位，报文授权段中的授权记录数。 */
    uint16_t            addrrs;         /* ARCOUNT :长度16位，报文附加段中的附加记录数。 */
} fp_dns_header;
#pragma pack()

#pragma pack(1)
typedef struct tag_fp_dns_tail_query {
    uint16_t            type;
    uint16_t            classtype;
} fp_dns_tail_query;
#pragma pack()

#pragma pack(1)
typedef struct tag_fp_dns_tail_response {
    fp_dns_rr_name_point    name;           /* C0 0C 域名指针  */
    uint16_t                type;           /* 查询类型 */
    uint16_t                classtype;      /* 分类 */
} fp_dns_tail_response;
#pragma pack()

#pragma pack(1)
typedef struct tag_fp_dns_cache_node {
    struct rb_node      dns_node;
    uint32_t            index;
    uint16_t            aux_info;
    uint16_t            spare;
    comm_msg_dns_config dns_cfg;
}fp_dns_cache_node;
#pragma pack()

/* Hash bucket, contains hash tree, the index is hash value of filter entry */
#pragma pack(1)
typedef struct  tag_fp_dns_bucket {
    struct rb_root      dns_root;       /* rb_tree root */
    ros_rwlock_t        rwlock;         /* rw lock */
    uint32_t            node_count;     /* Number of node in the tree */
}fp_dns_bucket;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_dns_table
{
    fp_dns_cache_node   *entry;         /* entry address */
    fp_dns_bucket       *bucket;        /* pointer to first bucket */
    uint32_t            entry_max;      /* max number */
    uint32_t            bucket_mask;    /* bucket distribute mask */
    uint16_t            res_no;
    uint8_t             resv[2];        /* reserve */
}fp_dns_table;
#pragma pack()


/* 保存信任的DNS服务器地址 */
#pragma pack(1)
typedef struct tag_fp_dns_credible_entry {
    struct rb_node          cdb_node;
    comm_msg_dns_ip         ipaddr; /* 存放网络序地址 */
    uint32_t                index;
    uint32_t                spare;
} fp_dns_credible_entry;
#pragma pack()

#pragma pack(1)
typedef struct tag_fp_dns_credible_table {
    fp_dns_credible_entry   *entry;
    struct rb_root          cdb_root;
    ros_rwlock_t            lock;
    uint32_t                max_num;
    uint16_t                pool_id;
    uint8_t                 master_switch; /* 0:disable   1:enable */
    uint8_t                 spare[5];
} fp_dns_credible_table;
#pragma pack()

fp_dns_table *fp_dns_table_get_public(void);
fp_dns_cache_node *fp_dns_node_get_public(uint32_t index);

int64_t fp_dns_node_init(uint32_t node_num);
void fp_dns_deinit(void);
int32_t fp_dns_handle_query(uint8_t *dns_pl, uint32_t dns_len);
int32_t fp_dns_handle_response(uint8_t *dns_pl, uint32_t dns_len);

uint32_t fp_dns_update2sp(uint32_t *index_arr, uint32_t index_num);
uint32_t fp_dns_table_del(uint32_t index);
void fp_dns_config_hton(comm_msg_dns_config *cfg);

int fp_dns_credible_match(comm_msg_dns_ip *ipaddr);
int fp_dns_credible_master_switch(void);

#endif

