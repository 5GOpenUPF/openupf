/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __KEY_EXTRACT_H
#define __KEY_EXTRACT_H

#define URL_EXTRACT_MAX             512

/* Parse packet by net order, be carefully when you call it */
#if ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )           /* Intel type */
#define FLOW_PFCP_PORT            25890     /* 0x6522 */
#define FLOW_BGP_PORT             45824     /* 0xb300 */
#define FLOW_UDP_PORT_GTPU        26632     /* 0x6808 */
#define FLOW_DNS_PORT             13568     /* 0x3500 */

#define FLOW_ETH_PRO_IP           0x0008	/* Internet Protocol packet     */
#define FLOW_ETH_PRO_ARP          0x0608	/* Address Resolution packet    */
#define FLOW_ETH_PRO_8021Q        0x0081	/* 802.1Q VLAN Extended Header  */
#define FLOW_ETH_PRO_IPV6         0xDD86	/* IPv6 over bluebook           */
#define FLOW_ETH_PRO_PPP_DISC     0x6388	/* PPPoE discovery messages     */
#define FLOW_ETH_PRO_PPP_SES      0x6488	/* PPPoE session messages       */
#define FLOW_ETH_PRO_MPLS_UC      0x4788	/* MPLS Unicast traffic         */
#define FLOW_ETH_PRO_MPLS_MC      0x4888	/* MPLS Multicast traffic       */
#define FLOW_ETH_PRO_8021AD       0xA888	/* 802.1ad Service VLAN         */
#else
#define FLOW_PFCP_PORT            8805      /* 0x2265 */
#define FLOW_BGP_PORT             179       /* 0x00b3 */
#define FLOW_UDP_PORT_GTPU        2152      /* 0x0868 */
#define FLOW_DNS_PORT             53        /* 0x0035 */

#define FLOW_ETH_PRO_IP           0x0800	/* Internet Protocol packet     */
#define FLOW_ETH_PRO_ARP          0x0806	/* Address Resolution packet    */
#define FLOW_ETH_PRO_8021Q        0x8100	/* 802.1Q VLAN Extended Header  */
#define FLOW_ETH_PRO_IPV6         0x86DD	/* IPv6 over bluebook           */
#define FLOW_ETH_PRO_PPP_DISC     0x8863	/* PPPoE discovery messages     */
#define FLOW_ETH_PRO_PPP_SES      0x8864	/* PPPoE session messages       */
#define FLOW_ETH_PRO_MPLS_UC      0x8847	/* MPLS Unicast traffic         */
#define FLOW_ETH_PRO_MPLS_MC      0x8848	/* MPLS Multicast traffic       */
#define FLOW_ETH_PRO_8021AD       0x88A8	/* 802.1ad Service VLAN         */
#endif

#define TLS_NOT_HEAD_ENRICH					 	0x80000000
#define TLS_CONTENT_TYPE_HANDSHAKE       		22
#define TLS_CONTENT_TYPE_APPLICATION       		23
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO    		1
#define TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE	16

#define TLS_SUB_EXTENSION_TYPE_PHONENUM    	 1
#define TLS_SUB_EXTENSION_TYPE_UEIP    		(1<<1)
#define TLS_SUB_EXTENSION_TYPE_SUPI    		(1<<2)
#define TLS_SUB_EXTENSION_TYPE_PEI    		(1<<3)
#define TLS_SUB_EXTENSION_TYPE_ULI    		(1<<4)
#define TLS_SUB_EXTENSION_TYPE_UPFIP    		(1<<6)
#define TLS_SUB_EXTENSION_TYPE_TIMESTAMP   	(1<<7)
#define TLS_SUB_EXTENSION_TYPE_RATTYPE    	(1<<8)
#define TLS_SUB_EXTENSION_TYPE_DNN    		(1<<9)

/* LLC contorl field */
#define XDLC_S_U_MASK   0x03	/**< Mask to test for S or U */
#define XDLC_S          0x01	/**< Supervisory frames */
#define XDLC_U          0x03	/**< Unnumbered frames */

enum EN_GTP_EXTERNSION_HEADER {
    /* No more extension headers */
    EN_GTP_EH_NO_MORE               = 0x00,
    /* Service Class Indicator */
    EN_GTP_EH_SCI                   = 0x20,
    /* UDP Port. Provides the UDP Source Port of the triggering message. */
    EN_GTP_EH_UDP_PORT              = 0x40,
    /* RAN Container */
    EN_GTP_EH_RAN_CT                = 0x81,
    /* Xw RAN Container */
    EN_GTP_EH_XW_RAN_CT             = 0x83,
    /* NR RAN Container */
    EN_GTP_EH_NR_RAN_CT             = 0x84,
    /* PDU Session Container. */
    EN_GTP_EH_PDU_SESS_CT           = 0x85,
};

#if (defined(PRODUCT_IS_fpu) || defined(PRODUCT_IS_stub) || defined(PRODUCT_IS_lbu))
#define PACKET_LEN_CHECK(off, s, l) \
            do { \
               } while((0))

#else
/* use for packet length check */
#define PACKET_LEN_CHECK(off, s, l) \
    do { \
        if (((off) + (s)) > (l)) { \
            LOG(CM, ERR, \
                 "len error:off:%d, s:%u, l:%d", off, (uint32_t)s, l); \
            return -1; \
        }\
    } while(0)
#endif


struct ipv4_key {
    uint32_t sip;               /* IP source address. */
    uint32_t dip;               /* IP destination address. */
    uint16_t sport;             /* TCP/UDP/SCTP source port. */
    uint16_t dport;             /* TCP/UDP/SCTP destination port. */
    uint8_t  proto;             /* IP protocol or lower 8 bits of ARP opcode. */
    uint8_t  resv1;             /* reserved */
    uint16_t resv2;             /* reserved */
};

struct ipv6_key {
    uint8_t  src[IPV6_ALEN];    /* IPv6 source address. */
	uint8_t  dst[IPV6_ALEN];    /* IPv6 destination address. */
    uint16_t sport;             /* TCP/UDP/SCTP source port. */
    uint16_t dport;             /* TCP/UDP/SCTP destination port. */
    uint32_t label;	            /* IPv6 flow label. */
    uint8_t  proto;             /* IP protocol or lower 8 bits of ARP opcode. */
    uint8_t  resv1;             /* reserved */
    uint16_t resv2;             /* reserved */
};

struct tp_port {
    uint16_t source;            /* TCP/UDP/SCTP source port. */
    uint16_t dest;              /* TCP/UDP/SCTP destination port. */
};

/* enum of pdn type */
typedef enum {
    PDN_TYPE_IPV4 = 1,
    PDN_TYPE_IPV6,
    PDN_TYPE_IPV4V6,
    PDN_TYPE_NON_IP,
    PDN_TYPE_ETHERNET,
    PDN_TYPE_BUTT
}PDN_TYPE;

struct packet_desc {
    char   *buf;
    int     len;
    int     offset;
    uint8_t pdn_type;
};

typedef PDN_TYPE (*PDN_TYPE_GET)(void *);

/* Used for get or set fast table id with desc.
   The caller must make sure desc and desc->buf are not null.
*/
#define GET_FAST_TID(buff) \
        (htonl(*(uint32_t *)buff))

#define SET_FAST_TID(buff, tid) \
        ((*(uint32_t *)(buff))=ntohl((uint32_t)tid))

/* Used for get or set fast table id with desc.
   The caller must make sure desc and desc->buf are not null.
*/
#define GET_FAST_TYPE(buff) \
        (*(uint8_t *)(buff + sizeof(uint32_t)))

#define SET_FAST_TYPE(buff, type) \
        ((*(uint8_t *)((char *)buff + sizeof(uint32_t)))=(uint8_t)type)

/* Record fast ID and fast type length == sizeof(uint32_t) + sizeof(uint8_t) */
#define RECORD_FAST_INFO_LEN        5

enum FAST_TABLE_TYPE {
    FAST_TBL_IPV4       = 0,
    FAST_TBL_IPV6       = 1,
    FAST_TBL_MAC        = 2,
};

/********************flow field releated define*************************/
/* Field types */
enum flow_field_type {
	FLOW_FIELD_MIN = 0,

	/* Basic Field Types */

	/* First byte for outer header, order must be same with L2 */
	FLOW_FIELD_L1_ETH   = FLOW_FIELD_MIN,   /* 0--Ethernet */
	FLOW_FIELD_L1_CVLAN,                    /* 1--Custom vlan */
	FLOW_FIELD_L1_SVLAN,                    /* 2--Service vlan */
	FLOW_FIELD_L1_TCP,                      /* 3--TCP */
	FLOW_FIELD_L1_UDP,                      /* 4--UDP */
	FLOW_FIELD_L1_SCTP,                     /* 5--SCTP */
	FLOW_FIELD_L1_IPV4,                     /* 6--IPv4 address */
	FLOW_FIELD_L1_IPV6,                     /* 7--IPv6 address. */
    FLOW_FIELD_L1_RESV1,                    /* 8--RESERVE */
    FLOW_FIELD_L1_RESV2,                    /* 9--RESERVE */

    /* Second byte for inner header, order must be same with L1 */
    FLOW_FIELD_L2_ETH,                      /* 10--Ethernet */
    FLOW_FIELD_L2_CVLAN,                    /* 11--Custom vlan */
    FLOW_FIELD_L2_SVLAN,                    /* 12--Service vlan */
    FLOW_FIELD_L2_TCP,                      /* 13--TCP */
    FLOW_FIELD_L2_UDP,                      /* 14--UDP */
    FLOW_FIELD_L2_SCTP,                     /* 15--SCTP */
    FLOW_FIELD_L2_IPV4,                     /* 16--IPv4 */
    FLOW_FIELD_L2_IPV6,                     /* 17--IPv6 */
    FLOW_FIELD_L2_RESV1,                    /* 18--RESERVE */
    FLOW_FIELD_L2_RESV2,                    /* 19--RESERVE */

    /* Other bytes for others */
    FLOW_FIELD_ARP,                         /* 20--ARP */
    FLOW_FIELD_GTP_U,                       /* 21--GTP U */
    FLOW_FIELD_GTP_CONTENT,                 /* 22--GTP Content Start Point */
    FLOW_FIELD_GTP_ECHO,                    /* 23--GTP ECHO    */
    FLOW_FIELD_GTP_EXT,                     /* 24--GTP Extention */
    FLOW_FIELD_GTP_ERR_INDI,          		/* 25--GTP Error Indication */
    FLOW_FIELD_GTP_END_MARKER,              /* 26--GTP End Marker */
    FLOW_FIELD_GTP_T_PDU,                   /* 27--GTP T PDU */

    /* Ethernet(IEEE 802.3) */
    FLOW_FIELD_ETHERNET_LLC,                /* 28--LLC */
    FLOW_FIELD_ETHERNET_DATA,               /* 29--data */
    FLOW_FIELD_ETHERNET_DL,                 /* 30--Ethernet 802.3 downlink packet */

    /* Don't exceed it */
    FLOW_FIELD_MAX,                         /* Maximum field value */
};

struct filter_key {
    uint8_t     *pPkt;
    uint8_t     field_offset[FLOW_FIELD_MAX];
    uint8_t     field_length[FLOW_FIELD_MAX];
};

#define FLOW_MASK_FIELD_ISSET(offset, field)    (offset[field])

typedef struct extensions_key_t {
    uint16_t   	extensions_type;
    uint16_t   	extensions_len;
	uint8_t    	*value_ptr;
	uint32_t	is_vaild;
} extensions_key;

static inline struct pro_eth_hdr *
FlowGetL1MACHeader(struct filter_key *field)
{
    return ((struct pro_eth_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L1_ETH]));
}

static inline struct pro_arp_hdr *
FlowGetARPHeader(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_ARP])) ?
        ((struct pro_arp_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_ARP])) : (NULL);
}

static inline struct pro_vlan_hdr *
FlowGetL1CVlan(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L1_CVLAN])) ?
        ((struct pro_vlan_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L1_CVLAN])) : (NULL);
}

static inline struct pro_vlan_hdr *
FlowGetL1SVlan(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L1_SVLAN])) ?
        ((struct pro_vlan_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L1_SVLAN])) : (NULL);
}

static inline struct pro_ipv4_hdr *
FlowGetL1Ipv4Header(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L1_IPV4])) ?
        ((struct pro_ipv4_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L1_IPV4])) : (NULL);
}

static inline unsigned long
FlowGetL1Ipv4Long(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L1_IPV4])) ?
        (*(unsigned long *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L1_IPV4] + 12)) : (0);
}

static inline struct pro_ipv6_hdr *
FlowGetL1Ipv6Header(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L1_IPV6])) ?
        ((struct pro_ipv6_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L1_IPV6])) : (NULL);
}

static inline uint8_t
FlowGetL1IpVersion(struct filter_key *field)
{
    if (field->field_offset[FLOW_FIELD_L1_IPV4]) {
        return 4;
    }
    else if (field->field_offset[FLOW_FIELD_L1_IPV6]) {
        return 6;
    }
    else
    {
        return 0;
    }
}

static inline struct pro_udp_hdr *
FlowGetL1UdpHeader(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L1_UDP])) ?
        ((struct pro_udp_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L1_UDP])) : (NULL);
}

static inline struct pro_tcp_hdr *
FlowGetL1TcpHeader(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L1_TCP])) ?
        ((struct pro_tcp_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L1_TCP])) : (NULL);
}

static inline struct pro_eth_hdr *
FlowGetL2MACHeader(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L2_ETH])) ?
        ((struct pro_eth_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L2_ETH])) : (NULL);
}

static inline struct pro_vlan_hdr *
FlowGetL2CustomVlan(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L2_CVLAN])) ?
        ((struct pro_vlan_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L2_CVLAN])) : (NULL);
}

static inline struct pro_vlan_hdr *
FlowGetL2ServiceVlan(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L2_SVLAN])) ?
        ((struct pro_vlan_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L2_SVLAN])) : (NULL);
}

static inline struct pro_ipv4_hdr *
FlowGetL2Ipv4Header(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L2_IPV4])) ?
        ((struct pro_ipv4_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L2_IPV4])) : (NULL);
}

static inline unsigned long
FlowGetL2Ipv4Long(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L2_IPV4])) ?
        (*(unsigned long *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L2_IPV4] + 12)) : (0);
}

static inline struct pro_ipv6_hdr *
FlowGetL2Ipv6Header(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L2_IPV6])) ?
        ((struct pro_ipv6_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L2_IPV6])) : (NULL);
}

static inline struct pro_udp_hdr *
FlowGetL2UdpHeader(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L2_UDP])) ?
        ((struct pro_udp_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L2_UDP])) : (NULL);
}

static inline struct pro_tcp_hdr *
FlowGetL2TcpHeader(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_L2_TCP])) ?
        ((struct pro_tcp_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_L2_TCP])) : (NULL);
}

static inline uint8_t
FlowGetL2IpVersion(struct filter_key *field)
{
    if (field->field_offset[FLOW_FIELD_L2_IPV4]) {
        return 4;
    }
    else if (field->field_offset[FLOW_FIELD_L2_IPV6]) {
        return 6;
    }
    else
    {
        return 0;
    }
}

static inline struct pro_eth_hdr *
FlowGetMACHeader(struct filter_key *key, uint8_t *field_offset)
{
    if (field_offset == key->field_offset) {
        return FlowGetL1MACHeader(key);
    }
    else {
        return FlowGetL2MACHeader(key);
    }
}

static inline struct pro_ipv4_hdr *
FlowGetIpv4Header(struct filter_key *key, uint8_t *field_offset)
{
    if (field_offset == key->field_offset) {
        return FlowGetL1Ipv4Header(key);
    }
    else {
        return FlowGetL2Ipv4Header(key);
    }
}
static inline struct pro_ipv6_hdr *
FlowGetIpv6Header(struct filter_key *key, uint8_t *field_offset)
{
    if (field_offset == key->field_offset) {
        return FlowGetL1Ipv6Header(key);
    }
    else {
        return FlowGetL2Ipv6Header(key);
    }
}

static inline struct pro_udp_hdr *
FlowGetUdpHeader(struct filter_key *key, uint8_t *field_offset)
{
    if (field_offset == key->field_offset) {
        return FlowGetL1UdpHeader(key);
    }
    else {
        return FlowGetL2UdpHeader(key);
    }
}

static inline struct pro_tcp_hdr *
FlowGetTcpHeader(struct filter_key *key, uint8_t *field_offset)
{
    if (field_offset == key->field_offset) {
        return FlowGetL1TcpHeader(key);
    }
    else {
        return FlowGetL2TcpHeader(key);
    }
}

static inline struct pro_gtp_hdr *
FlowGetGtpuHeader(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_GTP_U])) ?
        ((struct pro_gtp_hdr *)(field->pPkt +
        field->field_offset[FLOW_FIELD_GTP_U])) : (NULL);
}

static inline uint8_t *
FlowGetGtpuInner(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_GTP_CONTENT])) ?
        ((uint8_t *)(field->pPkt +
        field->field_offset[FLOW_FIELD_GTP_CONTENT])) : (NULL);
}

static inline uint8_t *
FlowGetGtpuExt(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_GTP_EXT])) ?
        ((uint8_t *)(field->pPkt +
        field->field_offset[FLOW_FIELD_GTP_EXT])) : (NULL);
}

static inline uint8_t *
FlowGetGtpuInnerContext(struct filter_key *field)
{
    return (likely(field->field_offset[FLOW_FIELD_GTP_CONTENT])) ?
        ((uint8_t *)(field->pPkt +
        field->field_offset[FLOW_FIELD_GTP_CONTENT])) : (NULL);
}

void key_field_dump(struct filter_key *key);
int packet_dissect(struct packet_desc *desc, struct filter_key *key);

static inline unsigned long
PktGetIpv4Long(struct pro_ipv4_hdr *ipv4_hdr)
{
    unsigned long *tmp;

    tmp = (unsigned long *)(&ipv4_hdr->source);
    return (*tmp);
}

static inline unsigned long
PktGetIpv6Long(struct pro_ipv6_hdr *ipv6_hdr)
{
    uint64_t *tmp_s, *tmp_d;

    tmp_s = (uint64_t *)(ipv6_hdr->saddr);
    tmp_d = (uint64_t *)(ipv6_hdr->daddr);
    return (tmp_s[0] ^ tmp_d[0] ^ tmp_s[1] ^ tmp_d[1]);
}

static inline unsigned int
PktGetPortInt(struct tp_port *tp)
{
    return (*(unsigned int *)(tp));
}

struct pro_ipv4_hdr *pkt_get_l3_header(char *buf, int len);
struct pro_ipv6_hdr *pkt_get_l3_ipv6_header(char *buf, int len);
struct pro_arp_hdr  *pkt_get_arp_header(char *buf, int len);
int pkt_get_inner_ip_header(struct pro_gtp_hdr *gtp_hdr, void **ip_hdr);
struct pro_ipv6_hdr *pkt_get_inner_ipv6_header(struct pro_gtp_hdr *gtp_hdr);
int layer7_url_extract(struct pro_tcp_hdr *tcp_hdr, uint32_t total_len, char *out_url, char *out_host, uint32_t max_len);
int pkt_parse_https_client_hello(char *tcp_payload, uint16_t tls_total_len, uint16_t *in_offset,
	extensions_key *e_key, uint8_t decode_exten_flag, uint8_t *exist_17516);
int pkt_parse_https(struct pro_tcp_hdr *tcp_hdr, extensions_key *e_key, uint8_t decode_exten_flag, uint8_t *exist_17516);
uint64_t bcd_to_int64(uint8_t *bcd, uint8_t len, uint8_t flag);

#endif
