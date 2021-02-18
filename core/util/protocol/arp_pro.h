/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __ARP_PRO_H
#define __ARP_PRO_H

/*
 *	This structure defines an ethernet arp header.
 */
struct pro_arp_hdr {
	unsigned short      ar_hrd;	/* format of hardware address   */
	unsigned short      ar_pro;	/* format of protocol address   */
	unsigned char       ar_hln;	/* length of hardware address   */
	unsigned char       ar_pln;	/* length of protocol address   */
	unsigned short      ar_op;	/* ARP opcode (command)     */

	/* Ethernet+IPv4 specific members. */
	unsigned char       ar_sha[ETH_ALEN];	/* sender hardware address  */
	unsigned char       ar_sip[4];		/* sender IP address        */
	unsigned char       ar_tha[ETH_ALEN];	/* target hardware address  */
	unsigned char       ar_tip[4];		/* target IP address        */
} __packed;

#endif

