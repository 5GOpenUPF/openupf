/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __HASH16_H__
#define __HASH16_H__

#ifdef __cplusplus
extern "C" {
#endif

uint16_t hash16_by_short(uint16_t iv, uint16_t datum);
uint16_t hash16_by_int(uint16_t iv, uint32_t datum);
uint16_t hash16_by_long(uint16_t iv, uint64_t datum);
uint16_t hash16_calc_ipv4(uint64_t ipv4, uint32_t port, uint16_t  proto, uint32_t *aux_info);
uint16_t hash16_calc_ipv6(uint64_t *ip, uint32_t port, uint32_t label, uint16_t  proto, uint32_t *aux_info);
uint16_t hash16_calc_mac(uint8_t *mac, uint32_t *aux_info);
uint16_t hash16_calc_ethernet(uint8_t *mac, uint32_t llc, uint32_t *aux_info);
uint16_t hash16_calc_uint32(uint32_t input);

#ifdef __cplusplus
}
#endif

#endif /* __HASH16_H__ */

