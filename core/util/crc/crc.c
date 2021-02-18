/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#include "common.h"
#include "util.h"

#define CSUM_MANGLED_0 (0xffff)

uint32_t check_sum(uint8_t *buf, uint32_t len, uint32_t sum)
{
	uint32_t i;

	for (i = 0; i < (len & ~1U); i += 2) {
		sum += (uint16_t)ntohs(*((uint16_t *)(buf + i)));
		if (sum > 0xffff)
			sum -= 0xffff;
	}

	if (i < len) {
		sum += buf[i] << 8;
		if (sum > 0xffff)
			sum -= 0xffff;
	}

	return sum;
}

uint16_t calc_crc_tcp(struct pro_tcp_hdr *tcp_hdr, struct pro_ipv4_hdr *ip_hdr)
{
    uint32_t ip_payload_len = ntohs(ip_hdr->tot_len) -
        sizeof(struct pro_ipv4_hdr);
	uint32_t sum = 0;
	uint16_t res;

	sum = check_sum((uint8_t *)&ip_hdr->source, 2 * sizeof(ip_hdr->source),
				IP_PRO_TCP + ip_payload_len);
	sum = check_sum((uint8_t *)tcp_hdr, ip_payload_len, sum);
	res = 0xffff & ~sum;
	if (res)
		return htons(res);
	else
		return CSUM_MANGLED_0;
}

uint16_t calc_crc_tcp6(struct pro_tcp_hdr *tcp_hdr, struct pro_ipv6_hdr *ip_hdr)
{
	uint32_t sum = 0;
	uint16_t res;

	sum = check_sum((uint8_t *)ip_hdr->saddr, 2 * sizeof(ip_hdr->saddr),
				IP_PRO_TCP + ntohs(ip_hdr->payload_len));
	sum = check_sum((uint8_t *)tcp_hdr, ntohs(ip_hdr->payload_len), sum);
	res = 0xffff & ~sum;
	if (res)
		return htons(res);
	else
		return CSUM_MANGLED_0;
}

uint16_t calc_crc_udp(struct pro_udp_hdr *udp_hdr, struct pro_ipv4_hdr *ip_hdr)
{
	uint32_t sum = 0;
	uint16_t res;

	sum = check_sum((uint8_t *)&ip_hdr->source, 2 * sizeof(ip_hdr->source),
				IP_PRO_UDP + ntohs(udp_hdr->len));
	sum = check_sum((uint8_t *)udp_hdr, ntohs(udp_hdr->len), sum);
	res = 0xffff & ~sum;
	if (res)
		return htons(res);
	else
		return CSUM_MANGLED_0;
}

uint16_t calc_crc_udp6(struct pro_udp_hdr *udp_hdr, struct pro_ipv6_hdr *ip_hdr)
{
	uint32_t sum = 0;
	uint16_t res;

	sum = check_sum((uint8_t *)ip_hdr->saddr, 2 * sizeof(ip_hdr->saddr),
				IP_PRO_UDP + ntohs(udp_hdr->len));
	sum = check_sum((uint8_t *)udp_hdr, ntohs(udp_hdr->len), sum);
	res = 0xffff & ~sum;
	if (res)
		return htons(res);
	else
		return CSUM_MANGLED_0;
}

uint16_t calc_crc_ip(struct pro_ipv4_hdr *ip_hdr)
{
    uint16_t  *ptr_data = (uint16_t *)ip_hdr;
    uint32_t  sum = 0;
    uint32_t  i, lenmax = ip_hdr->ihl << 1;
    uint16_t  checksum;

    for (i = 0; i < lenmax; i++) {
        sum += ptr_data[i];
    }

    checksum = (sum >> 16) + (sum & 0x0000FFFF);

    return ~checksum;
}

uint16_t calc_crc_icmp(uint16_t *buffer, int size)
{
	unsigned long cksum=0;

	while(size > 1)
	{
	 cksum += *buffer++;
	 size -= sizeof(uint16_t);
	}

	if(size)
	{
	 cksum += *(uint8_t *)buffer;
	}

	cksum=(cksum >> 16) + (cksum & 0xffff);
	cksum+=(cksum >> 16);
	return(uint16_t) (~cksum);
}

void calc_fix_sum (uint8_t *pCheckSum, uint8_t *pOldData, uint16_t usOldLen,
    uint8_t *pNewData, uint16_t usNewLen)
{
	long working_checksum;
	long old_data_word;
	long new_data_word;

	working_checksum = (uint32_t) ((pCheckSum[0] << 8) + pCheckSum[1]);
	working_checksum = (~working_checksum & 0x0000FFFF);

	while (usOldLen > 0x0000)
	{
		if (usOldLen == 0x00000001)
		{
			old_data_word = (uint32_t) ((pOldData[0] << 8) + pOldData[1]);

			working_checksum = working_checksum - (old_data_word & 0x0000FF00);

			if ((long) working_checksum <= 0x00000000L)
			{
				--working_checksum;

				working_checksum = working_checksum & 0x0000FFFF;
			}

			break;
		}
		else
		{
			old_data_word = (uint32_t) ((pOldData[0] << 8) + pOldData[1]);

			pOldData = pOldData + 2;

			working_checksum = working_checksum - (old_data_word & 0x0000FFFF);

			if ((long) working_checksum <= 0x00000000L)
			{
				--working_checksum;

				working_checksum = working_checksum & 0x0000FFFF;
			}

			usOldLen = (uint16_t) (usOldLen - 2);
		}
	}

	while (usNewLen > 0x0000)
	{
		if (usNewLen == 0x00000001)
		{
			new_data_word = (uint32_t) ((pNewData[0] << 8) + pNewData[1]);

			working_checksum = working_checksum + (new_data_word & 0x0000FF00);

			if (working_checksum & 0x00010000)
			{
				++working_checksum;

				working_checksum = working_checksum & 0x0000FFFF;
			}

			break;
		}
		else
		{
			new_data_word = (uint32_t) ((pNewData[0] << 8) + pNewData[1]);

			pNewData = pNewData + 2;

			working_checksum = working_checksum + (new_data_word & 0x0000FFFF);

			if (working_checksum & 0x00010000)
			{
				++working_checksum;

				working_checksum = working_checksum & 0x0000FFFF;
			}

			usNewLen = (uint16_t) (usNewLen - 2);
		}
	}

	working_checksum = ~working_checksum;
	pCheckSum[0] = (uint8_t) (working_checksum >> 8);
	pCheckSum[1] = (uint8_t) (working_checksum & 0x000000FF);
}

