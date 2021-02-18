/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __LIBUTIL_H__
#define __LIBUTIL_H__

#ifndef ENABLE_OCTEON_III
int ros_system(const char *cmdstring);
#endif
int mask_to_num(unsigned int mask_in);
unsigned int num_to_mask(int mask_num);
int num_to_power(unsigned int num, unsigned char *power);
unsigned int power_to_num(unsigned char power);
void ipv6_prefix_to_mask(uint8_t *mask_num, uint8_t prefix);

#endif

