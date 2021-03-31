/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "key_extract.h"

static inline int bufis(const char *s, size_t l, const char *t)
{
    return strlen(t) == l && memcmp(s, t, l) == 0;
}

void ipv4_addr_dump(struct pro_ipv4_hdr *ipv4_hdr)
{
    char sip[32] = {0};
    char dip[32] = {0};

    if (!inet_ntop(AF_INET, &ipv4_hdr->source, sip, sizeof(sip)))
    {
        return;
    }

    if (!inet_ntop(AF_INET, &ipv4_hdr->dest, dip, sizeof(dip)))
    {
        return;
    }
    LOG(SERVER, DEBUG, "sip:%s, dip:%s", sip, dip);
}

void ipv6_addr_dump(struct pro_ipv6_hdr *ipv6_hdr)
{
    char sip[64] = {0};
    char dip[64] = {0};

    if (!inet_ntop(AF_INET6, ipv6_hdr->saddr, sip, sizeof(sip)))
    {
        return;
    }

    if (!inet_ntop(AF_INET6, ipv6_hdr->daddr, dip, sizeof(dip)))
    {
        return;
    }

    LOG(SERVER, DEBUG, "sip:%s, dip:%s", sip, dip);
}

/* if need check key field, call this function after packet_dissect */
void key_field_dump(struct filter_key *key)
{
    int i;

    for (i = FLOW_FIELD_L1_ETH; i < FLOW_FIELD_MAX; ++i) {
        LOG(SERVER, DEBUG, "field:%d, exist:%s, offset:%d.",
           i, (key->field_offset[i] ? ("YES") : ("NO")),
           key->field_offset[i]);
    }

    if (key->field_offset[FLOW_FIELD_L1_IPV4]) {
        struct pro_ipv4_hdr *iphdr;
        struct tp_port *tp;

        iphdr = FlowGetL1Ipv4Header(key);
        if (NULL != iphdr) {
            LOG(SERVER, DEBUG, "Outer: ip src:%x, udp dst:%x",
                ntohl(iphdr->source), ntohl(iphdr->dest));
        }

        switch (iphdr->protocol) {
            case IP_PRO_UDP:
            case IP_PRO_TCP:
            case IP_PRO_SCTP:
                tp = (struct tp_port *)(iphdr + 1);
                LOG(SERVER, DEBUG, "Outer: tp sport:%u, tp dport:%u",
                    ntohs(tp->source), ntohs(tp->dest));
                break;

            default:
                break;
        }
    }

    if (key->field_offset[FLOW_FIELD_L2_IPV4]) {
        struct pro_ipv4_hdr *iphdr;
        struct tp_port *tp;

        iphdr = FlowGetL2Ipv4Header(key);
        if (NULL != iphdr) {
            LOG(SERVER, DEBUG, "Inner: ip src:%x, udp dst:%x",
                ntohl(iphdr->source), ntohl(iphdr->dest));
        }

        switch (iphdr->protocol) {
            case IP_PRO_UDP:
            case IP_PRO_TCP:
            case IP_PRO_SCTP:
                tp = (struct tp_port *)(iphdr + 1);
                LOG(SERVER, DEBUG, "Inner: tp sport:%u, tp dport:%u",
                    ntohs(tp->source), ntohs(tp->dest));
                break;

            default:
                break;
        }
    }

    if (key->field_offset[FLOW_FIELD_GTP_U]) {
        struct pro_gtp_hdr *gtphdr;
        uint8_t *inner;

        gtphdr = FlowGetGtpuHeader(key);
        inner = FlowGetGtpuInner(key);

        if (NULL != gtphdr) {
            LOG(SERVER, DEBUG, "Gtpu: flags:%02x, teid:0x%08x",
                gtphdr->flags.data, ntohl(gtphdr->teid));
        }

        if (NULL != inner) {
            LOG(SERVER, DEBUG, "Gtpu: inner[%02x %02x %02x %02x]",
                inner[0], inner[1], inner[2], inner[3]);
        }
    }
}

static inline PDN_TYPE pdn_type_get(struct filter_key *key)
{
    uint8_t byte = key->pPkt[key->field_offset[FLOW_FIELD_GTP_CONTENT]];

    switch (byte >> 4) {
        case 4:
            return PDN_TYPE_IPV4;

        case 6:
            return PDN_TYPE_IPV6;

        default:
            /* is Non-IP or Ethernet */;
            {
                uint16_t ethtype = ntohs(*(uint16_t *)&key->pPkt[
                    key->field_offset[FLOW_FIELD_GTP_CONTENT] + 12]);

                switch (ethtype) {
                    case FLOW_ETH_PRO_8021Q:
                    case FLOW_ETH_PRO_8021AD:
                        return PDN_TYPE_ETHERNET;

                    default:
                        if (ethtype <= 1500) {
                            return PDN_TYPE_ETHERNET;
                        } else {
                            return PDN_TYPE_NON_IP;
                        }
                }
            }
    }
}

static inline int ethernet_802_3_extract(struct packet_desc *desc,
    struct filter_key *key)
{
    uint8_t llc_ctrl;

    PACKET_LEN_CHECK(desc->offset, 4, desc->len);

    key->field_offset[FLOW_FIELD_ETHERNET_LLC] = desc->offset;
    desc->offset += 2;

    llc_ctrl = *(uint8_t *)&desc->buf[desc->offset];
    switch (llc_ctrl & XDLC_S_U_MASK) {
        case XDLC_S:
            desc->offset += 2;
            key->field_offset[FLOW_FIELD_ETHERNET_DATA] = desc->offset;
            break;

        case XDLC_U:
            desc->offset++;
            key->field_offset[FLOW_FIELD_ETHERNET_DATA] = desc->offset;
            break;

        default:
            desc->offset += 2;
            key->field_offset[FLOW_FIELD_ETHERNET_DATA] = desc->offset;
            break;
    }
    key->field_length[FLOW_FIELD_ETHERNET_LLC] =
        key->field_offset[FLOW_FIELD_ETHERNET_DATA] - key->field_offset[FLOW_FIELD_ETHERNET_LLC];

    return 0;
}

/* extract mac, eth type, c-vlan, s-vlan */
static inline int layer2_extract(struct packet_desc *desc,
    uint8_t *field_offset, uint8_t *field_length)
{
    struct pro_eth_hdr *eth;
    uint16_t eth_type;

    /* dissect from ethernet */
    /* eth header */
    PACKET_LEN_CHECK(desc->offset, ETH_HLEN, desc->len);
    eth = (struct pro_eth_hdr *)(desc->buf + desc->offset);
    field_offset[FLOW_FIELD_L1_ETH] = desc->offset;
    field_length[FLOW_FIELD_L1_ETH] = ETH_HLEN;
    desc->offset += ETH_HLEN;
    eth_type = (eth->eth_type);

    LOG(SERVER, PERIOD, "offset:%d, eth_type:%04x.",
             desc->offset, eth_type);

    /* if vlan exsit, max two vlan header supported */
    if (unlikely((FLOW_ETH_PRO_8021Q == eth_type)
      ||(FLOW_ETH_PRO_8021AD == eth_type)))
    {
        /* outer vlan */
        struct pro_vlan_hdr *outer_vlan;

        PACKET_LEN_CHECK(desc->offset, VLAN_HLEN, desc->len);
        outer_vlan = (struct pro_vlan_hdr *)(desc->buf + desc->offset);

        LOG(SERVER, PERIOD,
               "offset:%d, outer vlan detected, tci:0x%04x.",
               desc->offset, outer_vlan->tci.data);

        field_offset[FLOW_FIELD_L1_SVLAN] = desc->offset;
        field_length[FLOW_FIELD_L1_SVLAN] = VLAN_HLEN;
        desc->offset += VLAN_HLEN;
        eth_type = outer_vlan->eth_type;

        /* inner vlan */
        if ((FLOW_ETH_PRO_8021Q == eth_type)
          ||(FLOW_ETH_PRO_8021AD == eth_type))
        {
#ifdef LOG_MODE_DEBUG
            struct pro_vlan_hdr *inner_vlan;

            PACKET_LEN_CHECK(desc->offset, VLAN_HLEN, desc->len);
            inner_vlan = (struct pro_vlan_hdr *)(desc->buf + desc->offset);
            LOG(SERVER, PERIOD,
                   "offset:%d, inner vlan detected, tci:0x%04x.",
                   desc->offset, inner_vlan->tci.data);
#endif
            field_offset[FLOW_FIELD_L1_CVLAN] = desc->offset;
            field_length[FLOW_FIELD_L1_CVLAN] = VLAN_HLEN;
            desc->offset += VLAN_HLEN;
        }
    }

    return eth_type;
}

/* extract ipv4 */
static inline int layer3_ipv4_extract(struct packet_desc *desc,
    uint8_t *field_offset, uint8_t *field_length)
{
    struct pro_ipv4_hdr *ipHdr;

    PACKET_LEN_CHECK(desc->offset, sizeof(struct pro_ipv4_hdr), desc->len);
    ipHdr = (struct pro_ipv4_hdr *)(desc->buf + desc->offset);
    LOG(SERVER, PERIOD,
           "offset:%d, ipv4 detected, dest:0x%08x, src:0x%08x, tos:%u, protocol:%u, len:%u.",
           desc->offset, ipHdr->dest, ipHdr->source, ipHdr->tos,
           ipHdr->protocol, ntohs(ipHdr->tot_len));
    PACKET_LEN_CHECK(desc->offset, ntohs(ipHdr->tot_len), desc->len);

    field_offset[FLOW_FIELD_L1_IPV4] = desc->offset;
    field_length[FLOW_FIELD_L1_IPV4] = ipHdr->ihl << 2;
    desc->offset += (ipHdr->ihl << 2);

    return ipHdr->protocol;
}

/* extract ipv6 */
static inline int layer3_ipv6_extract(struct packet_desc *desc,
    uint8_t *field_offset, uint8_t *field_length)
{
    struct pro_ipv6_hdr *ipv6Hdr;
    uint8_t nexthdr;

    PACKET_LEN_CHECK(desc->offset,
           sizeof(struct pro_ipv6_hdr), desc->len);
    ipv6Hdr = (struct pro_ipv6_hdr *)(desc->buf + desc->offset);
    LOG(SERVER, PERIOD,
               "offset:%d, ipv6 detected, nexthdr:%u, payload_len:%u.",
               desc->offset, ipv6Hdr->nexthdr, ntohs(ipv6Hdr->payload_len));

    field_offset[FLOW_FIELD_L1_IPV6] = desc->offset;
    desc->offset += sizeof(struct pro_ipv6_hdr);
    PACKET_LEN_CHECK(desc->offset, ntohs(ipv6Hdr->payload_len), desc->len);
    nexthdr    = ipv6Hdr->nexthdr;

    /* need skip ext header, found finally protocol */
    while (pro_is_ipv6_exthdr(nexthdr))
    {
        struct pro_ipv6_opt_hdr *hp = NULL;
        int hdrlen;

        if (nexthdr == IPV6_NEXTHDR_NONE) {
            LOG(SERVER, ERR, "IPv6 next header none detected.");
            return -1;
        }

        PACKET_LEN_CHECK(desc->offset,
           sizeof(struct pro_ipv6_opt_hdr), desc->len);
        hp = (struct pro_ipv6_opt_hdr *)(desc->buf + desc->offset);
        if (IPV6_NEXTHDR_FRAGMENT == nexthdr) {
            hdrlen = 8;
        }
        else if (nexthdr == IPV6_NEXTHDR_AUTH) {
            hdrlen = (hp->hdrlen + 2)<<2;
        }
        else {
            hdrlen = (hp->hdrlen + 1)<<3;
        }
        PACKET_LEN_CHECK(desc->offset, hdrlen, desc->len);
        nexthdr = hp->nexthdr;
        desc->offset += hdrlen;
    }
    field_length[FLOW_FIELD_L1_IPV6] = desc->offset - field_offset[FLOW_FIELD_L1_IPV6];

    return nexthdr;
}

/* extract layer 4 */
static inline int layer4_extract(struct packet_desc *desc,
    uint8_t *field_offset, uint8_t *field_length, uint8_t proto)
{
    switch(proto)
    {
        case IP_PRO_UDP:
        {
#ifdef LOG_MODE_DEBUG
            struct pro_udp_hdr *udp_hdr =
                (struct pro_udp_hdr *)(desc->buf + desc->offset);
            LOG(SERVER, PERIOD,
                       "offset:%d, udp detected, sport:%u, dport:%u",
                       desc->offset,
                       ntohs(udp_hdr->source),
                       ntohs(udp_hdr->dest));
#endif
            field_offset[FLOW_FIELD_L1_UDP] = desc->offset;
            field_length[FLOW_FIELD_L1_UDP] = UDP_HLEN;
            desc->offset += UDP_HLEN;
        }
        break;

        case IP_PRO_TCP:
        {
            struct pro_tcp_hdr *tcp_hdr =
                (struct pro_tcp_hdr *)(desc->buf + desc->offset);
            LOG(SERVER, PERIOD,
                       "offset:%d, tcp detected, sport:%u, dport:%u",
                       desc->offset,
                       ntohs(tcp_hdr->source),
                       ntohs(tcp_hdr->dest));
            field_offset[FLOW_FIELD_L1_TCP] = desc->offset;
            field_length[FLOW_FIELD_L1_TCP] = (tcp_hdr->doff << 2);
            desc->offset += (tcp_hdr->doff << 2);
        }
        break;

        case IP_PRO_SCTP:
        {
#ifdef LOG_MODE_DEBUG
            struct pro_sctp_hdr *sctp_hdr =
                (struct pro_sctp_hdr *)(desc->buf + desc->offset);
            LOG(SERVER, PERIOD,
                       "offset:%d, sctp detected, sport:%u, dport:%u",
                       desc->offset,
                       ntohs(sctp_hdr->source),
                       ntohs(sctp_hdr->dest));
#endif
            field_offset[FLOW_FIELD_L1_SCTP] = desc->offset;
            field_length[FLOW_FIELD_L1_SCTP] = sizeof(struct pro_sctp_hdr);
            desc->offset += sizeof(struct pro_sctp_hdr);
        }
        break;

#if 0
        case IP_PRO_AH:
        {
#ifdef LOG_MODE_DEBUG
            struct pro_ah_hdr *ah_hdr =
                (struct pro_ah_hdr *)(desc->buf + desc->offset);
            LOG(SERVER, PERIOD,
                       "offset:%d, ipsec ah detected, spi:0x%08x",
                       desc->offset, ntohl(ah_hdr->spi));
#endif
            FLOW_MASK_FIELD_SET(key_field, FLOW_FIELD_L1_IPSEC_SPI);
            desc->offset += sizeof(struct pro_ah_hdr);
        }
        break;

        case IP_PRO_ESP:
        {
#ifdef LOG_MODE_DEBUG
            struct pro_esp_hdr *esp_hdr =
                (struct pro_esp_hdr *)(desc->buf + desc->offset);
            LOG(SERVER, PERIOD,
                       "offset:%d, ipsec esp detected, spi:0x%08x",
                       desc->offset, ntohl(esp_hdr->spi));
#endif
            FLOW_MASK_FIELD_SET(key_field, FLOW_FIELD_L1_IPSEC_SPI);
            desc->offset += sizeof(struct pro_esp_hdr);
        }
        break;
#endif

        default:
            break;
    }
    return 0;
}

/* ul_key_extract, use pdn type to dissect different type gtpu T-PDU */
static inline int layer5_gtpu_inner_extract(struct packet_desc *desc,
    struct filter_key *key)
{
    int proto;

    LOG(SERVER, PERIOD, "buf:%p, offset:%d, len:%d, pdn_type:%d.",
        desc->buf, desc->offset, desc->len, desc->pdn_type);

    switch (desc->pdn_type) {
        case PDN_TYPE_IPV4V6:
        case PDN_TYPE_IPV4:
            proto = layer3_ipv4_extract(desc, &(key->field_offset[FLOW_FIELD_L2_ETH]),
                &(key->field_length[FLOW_FIELD_L2_ETH]));
            break;

        case PDN_TYPE_IPV6:
            proto = layer3_ipv6_extract(desc, &(key->field_offset[FLOW_FIELD_L2_ETH]),
                &(key->field_length[FLOW_FIELD_L2_ETH]));
            if (unlikely(-1 == proto)) {
                return -1;
            }
            break;

        case PDN_TYPE_NON_IP:
            return 0;

        case PDN_TYPE_ETHERNET:
            if (unlikely(-1 == layer2_extract(desc, &key->field_offset[FLOW_FIELD_L2_ETH],
                &key->field_length[FLOW_FIELD_L2_ETH]))) {
                LOG(SERVER, ERR, "Extract Ethernet 802.3 packet failed.");
                return -1;
            }
            return ethernet_802_3_extract(desc, key);

        default:
            LOG(SERVER, ERR, "Invalid pdn type %u!", desc->pdn_type);
            return -1;
    }

    return layer4_extract(desc, &(key->field_offset[FLOW_FIELD_L2_ETH]),
        &(key->field_length[FLOW_FIELD_L2_ETH]), (uint8_t)proto);
}

/* extract layer 4 */
static inline int layer5_gtpu_extract(struct packet_desc *desc, struct filter_key *key)
{
    struct pro_gtp_hdr  *gtp_hdr = NULL;
    union pro_gtp_flags *gtp_flags = NULL;

    key->field_offset[FLOW_FIELD_GTP_U] = desc->offset;
    key->field_length[FLOW_FIELD_GTP_U] = GTP_HDR_LEN_MIN;

    PACKET_LEN_CHECK(desc->offset, GTP_HDR_LEN_MIN, desc->len);
    gtp_hdr  = (struct pro_gtp_hdr *)(desc->buf + desc->offset);

    LOG(SERVER, PERIOD,
                 "offset:%d, gtpu detected, flags:0x%02x, teid:0x%08x, msg-type:0x%02x, len:%u",
                 desc->offset, gtp_hdr->flags.data, ntohl(gtp_hdr->teid),
                 gtp_hdr->msg_type, ntohs(gtp_hdr->length));

    /* check gtp version and type */
    gtp_flags = &gtp_hdr->flags;
    /* version == 1 && type == 1 */
    if (unlikely((gtp_flags->data & 0x30) != 0x30)) {
        LOG(SERVER, ERR, "gtpu version error or type error: %d.", gtp_flags->data);
        return -1;
    }

    switch (gtp_hdr->msg_type) {
        case MSG_TYPE_T_ECHO_REQ:
        case MSG_TYPE_T_ECHO_RESP:
            /* GTP-U ECHO */
            key->field_offset[FLOW_FIELD_GTP_ECHO] = desc->offset;
            LOG(SERVER, PERIOD, "GTP-U echo packet!");
            break;

        case MSG_TYPE_T_ERR_INDI:
            /* GTP-U ERROR INDICATION */
            key->field_offset[FLOW_FIELD_GTP_ERR_INDI] = desc->offset;
            LOG(SERVER, PERIOD, "GTP-U error indication packet!");
            break;

        case MSG_TYPE_T_END_MARKER:
            /* GTP-U End Marker */
            key->field_offset[FLOW_FIELD_GTP_END_MARKER] = desc->offset;
            LOG(SERVER, PERIOD, "GTP-U end marker packet!");
            break;

        case MSG_TYPE_T_PDU:
            /* GTP-U T-PDU */
            key->field_offset[FLOW_FIELD_GTP_T_PDU] = desc->offset;
            //LOG(SERVER, PERIOD, "GTP-U T-PDU packet!");
            PACKET_LEN_CHECK(desc->offset, ntohs(gtp_hdr->length), desc->len);
            break;

        default:
            LOG(SERVER, ERR, "Not GTP-U PDU!");
            return -1;
    }
    desc->offset += GTP_HDR_LEN_MIN;

    /* extension header or sequence or N-PDU present
    *  sequence              : 2 octets
    *  N-PDU                 : 1 octet
    *  extension header type : 1 byte
    *  S, E, PN任意一个出现，则extension header都至少是4个字节，
    *  三个字段都会存在，只是是否解释的问题
    */
    //if (gtp_flags->s.e || gtp_flags->s.s || gtp_flags->s.pn) {
    if (gtp_flags->data & 0x7) {
        uint8_t  nextHdr;
        /* extension header length 定义为4字节，
           因为其长度实际是4字节为单位的，算偏移时要乘法，以防溢出 */
        uint32_t extHeaderLen;

#if 0
        /* sequence */
        if (gtp_flags->s.s) {
            /* do nothing now */
        }
        desc->offset += 2;

        /* N-PDU */
        if (gtp_flags->s.pn) {
            /* do nothing now */
        }
        desc->offset++;
#else
        desc->offset += 3;
#endif

        if (gtp_flags->s.e) {
            key->field_offset[FLOW_FIELD_GTP_EXT] = desc->offset;

            /* parse extension type */
            nextHdr = *(uint8_t *)(desc->buf + desc->offset);
            desc->offset++;
            while (nextHdr && desc->offset < desc->len) {
                extHeaderLen = *(uint8_t *)(desc->buf + desc->offset);
                desc->offset++;

                /* do next header parse, then calcuate head offset */
                desc->offset += ((extHeaderLen << 2) - 2);

                LOG(SERVER, PERIOD, "type:0x%02x, length:%d.",
                    nextHdr, extHeaderLen);
                nextHdr = *(uint8_t *)(desc->buf + desc->offset);
                desc->offset++;
            }
            key->field_length[FLOW_FIELD_GTP_EXT] =
                desc->offset - key->field_offset[FLOW_FIELD_GTP_U] - GTP_HDR_LEN_MIN;
        }
        else {
            desc->offset++;
        }
    }

    /* record gtp field */
    key->field_offset[FLOW_FIELD_GTP_CONTENT] = desc->offset;
    //key->field_length[FLOW_FIELD_GTP_CONTENT] = desc->len - desc->offset;

    switch (gtp_hdr->msg_type) {
        case MSG_TYPE_T_PDU:
            /* Only G-PDU can continue parsing */
            break;

        default:
            return 0;
    }

    /* Get PDN type */
    desc->pdn_type = pdn_type_get(key);

    return layer5_gtpu_inner_extract(desc, key);
}

/* dissect packets, extract packets infomation, caller must be provider
   pdn_type_get function for get pdn type by gtpu teid and ip */
int packet_dissect(struct packet_desc *desc, struct filter_key *key)
{
    struct tp_port          *tp;
    uint16_t                eth_type, eth_len;
    uint8_t                 ip_proto;
    int                     ret;

    if (unlikely((!desc) || (!key))) {
        LOG(SERVER, ERR, "desc or key is null!");
        return -1;
    }

    /* init set key */
    memset(key->field_offset, 0, FLOW_FIELD_MAX);
    memset(key->field_length, 0, FLOW_FIELD_MAX);
    key->pPkt = (uint8_t *)desc->buf;

    LOG(SERVER, PERIOD, "buf:%p, offset:%d, len:%d",
        desc->buf, desc->offset, desc->len);

    /* parse first l2 header */
    eth_type = layer2_extract(desc, key->field_offset, key->field_length);
    eth_len = ntohs(eth_type);

    /* Ethernet II or IEEE 802.3 */
    if (likely((eth_len >= 0x0600))) {
        /* Ethernet II should be >= 1536(0x0600) */

        /* if vlan exsit, max two vlan header supported */
        switch (eth_type) {
            case FLOW_ETH_PRO_IP:
                ip_proto = layer3_ipv4_extract(desc, key->field_offset, key->field_length);
                break;

            case FLOW_ETH_PRO_IPV6:
                ip_proto = layer3_ipv6_extract(desc, key->field_offset, key->field_length);
                break;

            case FLOW_ETH_PRO_ARP:
                key->field_offset[FLOW_FIELD_ARP] = desc->offset;
                return 0;

            default:
                LOG(SERVER, PERIOD, "Unsupport ether type %x.", (eth_type));
                return -1;
        }

        /* check gtpu packet or not */
        tp = (struct tp_port *)(desc->buf + desc->offset);

        /* do non-gtpu packet parse */
        ret = layer4_extract(desc, key->field_offset, key->field_length, ip_proto);

        /* Gtpu packet */
        if ((IP_PRO_UDP == ip_proto) && (FLOW_UDP_PORT_GTPU == (tp->dest))) {
            ret = layer5_gtpu_extract(desc, key);
        }
    }
    else if (eth_len <= 0x05DC) {
        LOG(SERVER, PERIOD, "eth_len: 0x%hx", eth_len);
        /* 802.3 should be <= 1500 */
        key->field_offset[FLOW_FIELD_ETHERNET_DL] = desc->offset;
        ret = ethernet_802_3_extract(desc, key);
    }
    else {
        ret = -1;
    }

    return ret;
}

/* dissect ipv4 packets ip header */
struct pro_ipv4_hdr *pkt_get_l3_header(char *buf, int len)
{
    struct pro_eth_hdr *eth;
    uint16_t eth_type;

    /* dissect from ethernet */
    /* eth header */
    eth = (struct pro_eth_hdr *)buf;
    eth_type = (eth->eth_type);

    LOG(SERVER, PERIOD, "offset:%d, eth_type:%04x.", ETH_HLEN, ntohs(eth_type));

    if (likely(FLOW_ETH_PRO_IP == eth_type)) {
        return (struct pro_ipv4_hdr *)(eth + 1);
    }
    /* if vlan exsit, max two vlan header supported */
    /* we don't need save vlan info, it will be found in PDR */
    else if (unlikely((FLOW_ETH_PRO_8021Q == eth_type)
      ||(FLOW_ETH_PRO_8021AD == eth_type)))
    {
        /* outer vlan */
        struct pro_vlan_hdr *outer_vlan;

        outer_vlan = (struct pro_vlan_hdr *)(buf + ETH_HLEN);
        eth_type = outer_vlan->eth_type;

        LOG(SERVER, PERIOD,
               "offset:%d, outer vlan detected, tci:0x%04x.",
               VLAN_HLEN + ETH_HLEN, outer_vlan->tci.data);

        if (FLOW_ETH_PRO_IP == eth_type) {
            return (struct pro_ipv4_hdr *)(outer_vlan + 1);
        }
        /* inner vlan */
        else if ((FLOW_ETH_PRO_8021Q == eth_type)
          ||(FLOW_ETH_PRO_8021AD == eth_type))
        {
            struct pro_vlan_hdr *inner_vlan;

            inner_vlan = (struct pro_vlan_hdr *)(buf + ETH_HLEN + ETH_HLEN);

            LOG(SERVER, PERIOD,
                   "offset:%d, inner vlan detected, tci:0x%04x.",
                   ETH_HLEN + VLAN_HLEN + VLAN_HLEN, inner_vlan->tci.data);

            if (FLOW_ETH_PRO_IP == inner_vlan->eth_type) {
                return (struct pro_ipv4_hdr *)(inner_vlan + 1);
            }
        }
    }

    return NULL;
}

struct pro_ipv6_hdr *pkt_get_l3_ipv6_header(char *buf, int len)
{
    struct pro_eth_hdr *eth;
    uint16_t eth_type;

    /* dissect from ethernet */
    /* eth header */
    eth = (struct pro_eth_hdr *)buf;
    eth_type = (eth->eth_type);

    LOG(SERVER, PERIOD, "offset:%d, eth_type:%04x.", ETH_HLEN, ntohs(eth_type));

    if (likely(FLOW_ETH_PRO_IPV6 == eth_type)) {
        return (struct pro_ipv6_hdr *)(eth + 1);
    }
    /* if vlan exsit, max two vlan header supported */
    /* we don't need save vlan info, it will be found in PDR */
    else if (unlikely((FLOW_ETH_PRO_8021Q == eth_type)
      ||(FLOW_ETH_PRO_8021AD == eth_type)))
    {
        /* outer vlan */
        struct pro_vlan_hdr *outer_vlan;

        outer_vlan = (struct pro_vlan_hdr *)(buf + ETH_HLEN);
        eth_type = outer_vlan->eth_type;

        LOG(SERVER, PERIOD,
               "offset:%d, outer vlan detected, tci:0x%04x.",
               VLAN_HLEN + ETH_HLEN, outer_vlan->tci.data);

        if (FLOW_ETH_PRO_IPV6 == eth_type) {
            return (struct pro_ipv6_hdr *)(outer_vlan + 1);
        }
        /* inner vlan */
        else if ((FLOW_ETH_PRO_8021Q == eth_type)
          ||(FLOW_ETH_PRO_8021AD == eth_type))
        {
            struct pro_vlan_hdr *inner_vlan;

            inner_vlan = (struct pro_vlan_hdr *)(buf + ETH_HLEN + ETH_HLEN);

            LOG(SERVER, PERIOD,
                   "offset:%d, inner vlan detected, tci:0x%04x.",
                   ETH_HLEN + VLAN_HLEN + VLAN_HLEN, inner_vlan->tci.data);

            if (FLOW_ETH_PRO_IPV6 == inner_vlan->eth_type) {
                return (struct pro_ipv6_hdr *)(inner_vlan + 1);
            }
        }
    }

    return NULL;
}

/* dissect arp header */
struct pro_arp_hdr *pkt_get_arp_header(char *buf, int len)
{
    struct pro_eth_hdr *eth;
    uint16_t eth_type;

    /* dissect from ethernet */
    /* eth header */
    eth = (struct pro_eth_hdr *)buf;
    eth_type = (eth->eth_type);

    LOG(SERVER, PERIOD, "offset:%d, eth_type:%04x.", ETH_HLEN, ntohs(eth_type));

    if (likely(FLOW_ETH_PRO_ARP == eth_type)) {
        return (struct pro_arp_hdr *)(eth + 1);
    }
    /* if vlan exsit, max two vlan header supported */
    /* we don't need save vlan info, it will be found in PDR */
    else if (unlikely((FLOW_ETH_PRO_8021Q == eth_type)
      ||(FLOW_ETH_PRO_8021AD == eth_type)))
    {
        /* outer vlan */
        struct pro_vlan_hdr *outer_vlan;

        outer_vlan = (struct pro_vlan_hdr *)(buf + ETH_HLEN);
        eth_type = outer_vlan->eth_type;

        LOG(SERVER, PERIOD,
               "offset:%d, outer vlan detected, tci:0x%04x.",
               VLAN_HLEN + ETH_HLEN, outer_vlan->tci.data);

        if (FLOW_ETH_PRO_ARP == eth_type) {
            return (struct pro_arp_hdr *)(outer_vlan + 1);
        }
        /* inner vlan */
        else if ((FLOW_ETH_PRO_8021Q == eth_type)
          ||(FLOW_ETH_PRO_8021AD == eth_type))
        {
            struct pro_vlan_hdr *inner_vlan;

            inner_vlan = (struct pro_vlan_hdr *)(buf + ETH_HLEN + ETH_HLEN);

            LOG(SERVER, PERIOD,
                   "offset:%d, inner vlan detected, tci:0x%04x.",
                   ETH_HLEN + VLAN_HLEN + VLAN_HLEN, inner_vlan->tci.data);

            if (FLOW_ETH_PRO_ARP == inner_vlan->eth_type) {
                return (struct pro_arp_hdr *)(inner_vlan + 1);
            }
        }
    }

    return NULL;
}

/* dissect GTP-U packet inner IP header(v4/v6) */
int pkt_get_inner_ip_header(struct pro_gtp_hdr *gtp_hdr, void **ip_hdr)
{
    union pro_gtp_flags *gtp_flags = &gtp_hdr->flags;
    char *cur_pos = (char *)gtp_hdr;
    uint8_t offset = GTP_HDR_LEN_MIN, byte;

    if (gtp_flags->s.e || gtp_flags->s.s || gtp_flags->s.pn) {
        /* extension header length 定义为4字节，
           因为其长度实际是4字节为单位的，算偏移时要乘法，以防溢出 */

#if 0
        /* sequence */
        if (gtp_flags->s.s) {
            /* do nothing now */
        }
        offset += 2;

        /* N-PDU */
        if (gtp_flags->s.pn) {
            /* do nothing now */
        }
        ++offset;
#else
        offset += 3;
#endif

        if (gtp_flags->s.e) {
            uint32_t extHeaderLen;
            uint16_t extIdx = 0;
            /* parse extension type */
            uint8_t nextHdr = *(uint8_t *)(cur_pos + offset);

            ++offset;
            while (nextHdr) {
                extHeaderLen = *(uint8_t *)(cur_pos + offset);
                ++offset;

                /* do next header parse, then calcuate head offset */
                offset += ((extHeaderLen << 2) - 2);

                LOG(SERVER, PERIOD,
                    "extIdx:%d, type:0x%02x, length:%d.\n",
                    extIdx, nextHdr, extHeaderLen);
                ++extIdx;
                nextHdr = *(uint8_t *)(cur_pos + offset);
                ++offset;
            }
        }
        else {
            ++offset;
        }
    }

    /* Get PDN type */
    byte = *((uint8_t *)cur_pos + offset);
    *ip_hdr = (void *)(cur_pos + offset);

    switch (byte >> 4) {
        case 4:
            return 4;

        case 6:
            return 6;

        default:
            return -1;
    }
}

/* dissect ipv6 packets ip header */
struct pro_ipv6_hdr *pkt_get_inner_ipv6_header(struct pro_gtp_hdr *gtp_hdr)
{
    union pro_gtp_flags *gtp_flags = &gtp_hdr->flags;
    char *cur_pos = (char *)gtp_hdr;
    uint8_t offset = GTP_HDR_LEN_MIN, byte;

    if (gtp_flags->s.e || gtp_flags->s.s || gtp_flags->s.pn) {
        /* extension header length 定义为4字节，
           因为其长度实际是4字节为单位的，算偏移时要乘法，以防溢出 */

#if 0
        /* sequence */
        if (gtp_flags->s.s) {
            /* do nothing now */
        }
        offset += 2;

        /* N-PDU */
        if (gtp_flags->s.pn) {
            /* do nothing now */
        }
        ++offset;
#else
        offset += 3;
#endif

        if (gtp_flags->s.e) {
            uint32_t extHeaderLen;
            uint16_t extIdx = 0;
            /* parse extension type */
            uint8_t nextHdr = *(uint8_t *)(cur_pos + offset);

            ++offset;
            while (nextHdr) {
                extHeaderLen = *(uint8_t *)(cur_pos + offset);
                ++offset;

                /* do next header parse, then calcuate head offset */
                offset += ((extHeaderLen << 2) - 2);

                LOG(SERVER, PERIOD,
                    "extIdx:%d, type:0x%02x, length:%d.\n",
                    extIdx, nextHdr, extHeaderLen);
                ++extIdx;
                nextHdr = *(uint8_t *)(cur_pos + offset);
                ++offset;
            }
        }
        else {
            ++offset;
        }
    }

    /* Get PDN type */
    byte = *((uint8_t *)cur_pos + offset);

    if ((byte >> 4) == 6) {
        return (struct pro_ipv6_hdr *)(cur_pos + offset);
    }

    return NULL;
}

int layer7_url_extract(struct pro_tcp_hdr *tcp_hdr, uint32_t total_len, char *out_url, char *out_host, uint32_t max_len)
{
    uint16_t tcp_hdr_len;
    char *payload;
    struct phr_request_info req_info;
    uint32_t cnt, url_offset = 0;
    struct phr_header *head;

    if (NULL == tcp_hdr || NULL == out_url || 0 == max_len) {
        LOG(SERVER, ERR, "Parameters abnormal, tcp_hdr(%p), out_url(%p), max_len: %u.\n",
            tcp_hdr, out_url, max_len);
        return -1;
    }

    tcp_hdr_len = tcp_hdr->doff << 2;
    total_len -= tcp_hdr_len;
    payload = ((char *)tcp_hdr) + tcp_hdr_len;

    if (0 > phr_parse_request(payload, total_len, &req_info, 0)) {
        LOG(SERVER, DEBUG, "Parse http request fail.");
        return -1;
    }

    for (cnt = 0; cnt < PHR_HEADER_NUM; ++cnt) {
        head = &req_info.headers[cnt];
        if (bufis(head->name, head->name_len, "Host")) {
            url_offset += head->value_len;
            if (unlikely(url_offset >= max_len)) {
                LOG(SERVER, ERR, "ERROR: Actual URL length %u greater than %u.", url_offset, max_len);
                return -1;
            }
            memcpy(out_url, head->value, head->value_len);
            if(out_host)
                memcpy(out_host, head->value, head->value_len);

            url_offset += req_info.path_len;
            if (unlikely(url_offset >= max_len)) {
                LOG(SERVER, ERR, "ERROR: Actual URL length %u greater than %u.", url_offset, max_len);
                return -1;
            }
            memcpy(&out_url[head->value_len], req_info.path, req_info.path_len);
            out_url[url_offset] = '\0';
            LOG(SERVER, DEBUG, "Parse URL: %s", out_url);

            return 0;
        }
    }
    LOG(SERVER, ERR, "Parse http success, but not found 'host' tag");

    return -1;
}

int pkt_parse_https_client_hello(char *tcp_payload, uint16_t tls_total_len, uint16_t *in_offset,
	extensions_key *e_key, uint8_t decode_exten_flag, uint8_t *exist_17516)
{
	uint16_t				offset = 0,sub_offset = 0,len_offset=0;
	uint8_t					session_id_len = 0;
	uint16_t				cipher_suites_len = 0;
	uint8_t					compres_method_len = 0;
	uint16_t				extensions_total_len = 0;
	char                   	*extensions = NULL,*sub_extensions = NULL;
	uint16_t				extensions_type=0,extensions_len=0,sub_extensions_total_len=0;
	uint16_t				sub_extensions_len=0;
	uint8_t					sub_extensions_type=0;
	uint16_t				i,j;

	offset = *in_offset;

	offset += 38;	//handshake type和length、verison、random固定占38个字节
	len_offset += 38;
	session_id_len = tcp_payload[offset];
	offset += 1;	//session_id_len自身占一个字节
	len_offset += 1;
	offset += session_id_len;	//session_id_len
	len_offset += session_id_len;
	cipher_suites_len = ntohs(*((uint16_t *)(tcp_payload+offset)));
	offset += 2;	//cipher_suites_len自身占两个字节
	len_offset += 2;
	offset += cipher_suites_len;	//cipher_suites_len
	len_offset += cipher_suites_len;

	compres_method_len = tcp_payload[offset];
	offset += 1;	//compres_method_len自身占一个字节
	len_offset += 1;
	offset += compres_method_len;	//compres_method_len
	len_offset += compres_method_len;
	extensions_total_len = ntohs(*((uint16_t *)(tcp_payload+offset)));
	offset += 2;	//extensions_len自身占两个字节
	len_offset += 2;
	extensions = tcp_payload+offset;
	offset += extensions_total_len;	//extensions_len
	len_offset += extensions_total_len;

	if(len_offset != tls_total_len)
	{
        LOG(SERVER, ERR,"pkt_parse_https_client_hello tls_total_len[%d] != len_offset[%d], decode failed!",
			tls_total_len,len_offset);
        return -1;
    }
	*in_offset = offset;

	if(decode_exten_flag)
	{
		offset = 0;
		i=0;
		//寻找SNI和17516扩展头
		while((extensions_total_len>0) && (i<40))
		{
			extensions_type = ntohs(*((uint16_t *)(extensions+offset)));
			offset+=2;
			extensions_len = ntohs(*((uint16_t *)(extensions+offset)));
			offset+=2;
			if(e_key)
			{
				//type=0表示SNI(server name indication)
				if(extensions_type == 0)
				{
					e_key[0].is_vaild = 1;
					e_key[0].extensions_type = 0;
					e_key[0].extensions_len = extensions_len;
					e_key[0].value_ptr = (uint8_t *)(extensions+offset);
				}
				else if(extensions_type == 17516)
				{
					if(exist_17516)
						*exist_17516 = 1;
					sub_extensions = (extensions+offset);
					sub_extensions_total_len = extensions_len;
					sub_offset = 0;
					j=0;
					while((sub_extensions_total_len>0) && (j<20))
					{
						sub_extensions_type = sub_extensions[sub_offset];
						sub_offset+=1;//17516中的子扩展类型为1个字节
						sub_extensions_len = ntohs(*((uint16_t *)(sub_extensions+sub_offset)));
						sub_offset+=2;
						if((sub_extensions_type >= 1) && (sub_extensions_type <= 10))
						{
							e_key[sub_extensions_type].is_vaild = 1;
							e_key[sub_extensions_type].extensions_type = sub_extensions_type;
							e_key[sub_extensions_type].extensions_len = sub_extensions_len;
							e_key[sub_extensions_type].value_ptr = (uint8_t *)(sub_extensions+sub_offset);
						}
						sub_offset+=sub_extensions_len;
						sub_extensions_total_len -= (sub_extensions_len+3);
						j++;
					}
				}
			}
			offset+=extensions_len;
			extensions_total_len -= (extensions_len+4);
			i++;
		}
	}
	return 0;
}

int pkt_parse_https(struct pro_tcp_hdr *tcp_hdr, extensions_key *e_key,
	uint8_t decode_exten_flag, uint8_t *exist_17516)
{
	char                   	*tcp_payload = NULL;
	char                   	*total_len_ptr = NULL, *hello_ptr = NULL;
	uint16_t				offset = 0;
	uint8_t					tls_pro_type;
	uint16_t				tls_total_len;
	uint32_t				handshake_type;

	tcp_payload = (char *)tcp_hdr + (tcp_hdr->doff << 2);
	tls_pro_type = tcp_payload[offset];
	offset += 3;	//tls content type和version
	if(tls_pro_type == TLS_CONTENT_TYPE_HANDSHAKE)
	{
		total_len_ptr = tcp_payload+offset;
		tls_total_len = ntohs(*((uint16_t *)total_len_ptr));
		offset += 2;	//length
		hello_ptr = tcp_payload+offset;
		handshake_type = ntohl(*((uint32_t *)hello_ptr));
		if(((handshake_type>>24)&0xff) == TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
		{
			if(pkt_parse_https_client_hello(tcp_payload,tls_total_len,&offset,
				e_key,decode_exten_flag,exist_17516)<0)
			{
		        LOG(SERVER, ERR,"pkt_parse_https_client_hello decode failed!");
		        return -1;
		    }
			return 0;
		}
	}
	else
	{
        LOG(SERVER, ERR,"pkt_parse_https_client_hello unknown type:%d",tls_pro_type);
    }
	return -1;
}

uint64_t bcd_to_int64(uint8_t *bcd, uint8_t len, uint8_t flag)
{
	int i=0;
	uint64_t result=0;

	if(len > 8)
	{
		LOG(SERVER, ERR,"bcd_to_int64 len[%d] > 8, failed!",len);
		return -1;
	}


	//flag==1: 16进制的0x0008618867101079转换为10进制的8618867101079
	if(flag)
	{
		for(i=0;i<len;i++)
		{
			result = result * 100;
			result += ((bcd[i]>>4)*10 + (bcd[i]&0x0f));
		}
	}
	else
	{
		//flag==0: 16进制的0x7910106788610800转换为10进制的8618867101079
		for(i=len;i>=0;i--)
		{
			result = result * 100;
			result += ((bcd[i]>>4)*10 + (bcd[i]&0x0f));
		}
	}

	return result;
}

