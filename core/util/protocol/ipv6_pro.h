/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __IPV6_PRO_H
#define __IPV6_PRO_H

#define IPV6_FLOWINFO_FLOWLABEL		0x000fffff
#define IPV6_FLOWINFO_PRIORITY		0x0ff00000

#ifndef IPV6_ALEN
#define IPV6_ALEN               (16)
#endif
/*
 *	NextHeader field of IPv6 header
 */

#define IPV6_NEXTHDR_HOP		  0	    /* Hop-by-hop option header. */
#define IPV6_NEXTHDR_TCP		  6	    /* TCP segment. */
#define IPV6_NEXTHDR_UDP		  17	/* UDP message. */
#define IPV6_NEXTHDR_IPV6		  41	/* IPv6 in IPv6 */
#define IPV6_NEXTHDR_ROUTING	  43	/* Routing header. */
#define IPV6_NEXTHDR_FRAGMENT	  44	/* Fragmentation/reassembly header. */
#define IPV6_NEXTHDR_GRE		  47	/* GRE header. */
#define IPV6_NEXTHDR_ESP		  50	/* Encapsulating security payload. */
#define IPV6_NEXTHDR_AUTH		  51	/* Authentication header. */
#define IPV6_NEXTHDR_ICMP		  58	/* ICMP for IPv6. */
#define IPV6_NEXTHDR_NONE		  59	/* No next header */
#define IPV6_NEXTHDR_DEST		  60	/* Destination options header. */
#define IPV6_NEXTHDR_SCTP		  132	/* SCTP message. */
#define IPV6_NEXTHDR_MOBILITY	  135	/* Mobility header. */

#define IPV6_NEXTHDR_MAX		  255

/*
 *	IPv6 fixed header
 *
 *	BEWARE, it is incorrect. The first 4 bits of flow_lbl
 *	are glued to priority now, forming "class".
 */

struct pro_ipv6_hdr {
    union {
        struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            unsigned int		flow_lbl : 20;
        	unsigned int		priority : 8;
        	unsigned int		version  : 4;
#else
        	unsigned int		version  : 4;
        	unsigned int		priority : 8;
            unsigned int		flow_lbl : 20;
#endif
        } d;
        unsigned int value;
    } vtc_flow;

	unsigned short      payload_len;
	unsigned char		nexthdr;
	unsigned char		hop_limit;

	unsigned char       saddr[IPV6_ALEN];
	unsigned char       daddr[IPV6_ALEN];
}__packed;

struct pro_ipv6_opt_hdr {
    unsigned char		nexthdr;
    unsigned char		hdrlen;
}__packed;

/*
 * fragmentation header
 */
struct pro_ipv6_frag_hdr {
	unsigned char		nexthdr;
	unsigned char		reserved;
	unsigned short		frag_off;
	unsigned int		identification;
}__packed;

static inline int pro_is_ipv6_exthdr(unsigned char nexthdr)
{
    /*
     * find out if nexthdr is an extension header or a protocol
     */
    switch (nexthdr) {
        case IPV6_NEXTHDR_HOP:
        case IPV6_NEXTHDR_ROUTING:
        case IPV6_NEXTHDR_FRAGMENT:
        case IPV6_NEXTHDR_AUTH:
        case IPV6_NEXTHDR_NONE:
        case IPV6_NEXTHDR_DEST:
            return G_TRUE;

        default:
            return G_FALSE;
    }
}

struct pro_icmpv6_hdr {
	uint8_t type; /**< ICMPv6 type, normally 135. */
	uint8_t code; /**< ICMPv6 code, normally 0. */
	uint16_t checksum; /**< ICMPv6 checksum. */
	uint32_t reserved; /**< Reserved, normally 0. */
	uint8_t target_addr[IPV6_ALEN]; /**< Target address. */
}__packed;

struct icmp6_option {
	uint8_t type; /**< 1 source 2 target */
	uint8_t lenth;
	uint8_t link_addr[ETH_ALEN];
}__packed;

#endif

