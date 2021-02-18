/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef __CRC_H__
#define __CRC_H__

#ifdef __cplusplus
extern "C" {
#endif
typedef struct udp_check_subhdr {
    int check_srcIp;
    int check_dstIp;
    char check_rsv;
    char checkprotocol;
    short check_udp_len;
}pro_udp_subhdr;

typedef struct ipv4_psd_header {
	uint32_t src_addr; /* IP address of source host. */
	uint32_t dst_addr; /* IP address of destination host. */
	uint8_t  zero;     /* zero. */
	uint8_t  proto;    /* L4 protocol type. */
	uint16_t len;      /* L4 length. */
} psd_hdr;

uint16_t calc_crc_tcp(struct pro_tcp_hdr *tcp_hdr, struct pro_ipv4_hdr *ip_hdr);
uint16_t calc_crc_tcp6(struct pro_tcp_hdr *tcp_hdr,
    struct pro_ipv6_hdr *ip_hdr);
uint16_t calc_crc_udp(struct pro_udp_hdr *udp_hdr, struct pro_ipv4_hdr *ip_hdr);
uint16_t calc_crc_udp6(struct pro_udp_hdr *udp_hdr,
    struct pro_ipv6_hdr *ip_hdr);
uint16_t calc_crc_ip(struct pro_ipv4_hdr *ip_hdr);
uint16_t calc_crc_icmp(uint16_t *buffer, int size);
void calc_fix_sum (uint8_t *pCheckSum, uint8_t *pOldData, uint16_t usOldLen,
    uint8_t *pNewData, uint16_t usNewLen);

#ifdef __cplusplus
}
#endif

#endif /* __CRC_H__ */

