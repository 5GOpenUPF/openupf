/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __ETH_PRO_H
#define __ETH_PRO_H

/*
 *	IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
 *	and FCS/CRC (frame check sequence).
 */
#ifndef ETH_ALEN
#define ETH_ALEN               6	/* Octets in one ethernet addr   */
#endif

#ifndef ETH_HLEN
#define ETH_HLEN               14	/* Total octets in header.       */
#endif

/*
 *	These are the defined Ethernet Protocol ID's.
 */

#define ETH_PRO_IP             0x0800	  /* Internet Protocol packet     */
#define ETH_PRO_ARP            0x0806	  /* Address Resolution packet    */
#define ETH_PRO_8021Q          0x8100	  /* 802.1Q VLAN Extended Header  */
#define ETH_PRO_IPV6           0x86DD	  /* IPv6 over bluebook           */
#define ETH_PRO_PPP_DISC       0x8863	  /* PPPoE discovery messages     */
#define ETH_PRO_PPP_SES        0x8864	  /* PPPoE session messages       */
#define ETH_PRO_MPLS_UC        0x8847	  /* MPLS Unicast traffic         */
#define ETH_PRO_MPLS_MC        0x8848	  /* MPLS Multicast traffic       */
#define ETH_PRO_8021AD         0x88A8	  /* 802.1ad Service VLAN         */

struct pro_eth_hdr {
    unsigned char   dest[ETH_ALEN];
    unsigned char   source[ETH_ALEN];
    unsigned short  eth_type;
}__packed;

#endif
