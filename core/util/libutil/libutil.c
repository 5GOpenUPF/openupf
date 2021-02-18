/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "libutil.h"

#ifndef ENABLE_OCTEON_III
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

int ros_system(const char *cmdstring)
{
    pid_t   pid;
	int     status;

	if(cmdstring == NULL)
	    return (1);

	if((pid = vfork()) < 0)
	{
	    status = -1;
	}
	else if(pid == 0)
	{
	    execl("/bin/sh", "sh", "-c", cmdstring, (char *)0);
		_exit(127);
	}
	else
	{
	    while(waitpid(pid, &status, 0) < 0)
	    {
	        if(errno != EINTR)
	        {
	            status = -1;
				break;
	        }
	    }
	}

	return (status);
}

#endif

int mask_to_num(unsigned int mask_in)
{
    int iloop;
    unsigned int mask[33] = {
        0x00000000, 0x80000000, 0xc0000000, 0xe0000000,
        0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000,
        0xff000000, 0xff800000, 0xffc00000, 0xffe00000,
        0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000,
        0xffff0000, 0xffff8000, 0xffffc000, 0xffffe000,
        0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00,
        0xffffff00, 0xffffff80, 0xffffffc0, 0xffffffe0,
        0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe,
        0xffffffff,
    };

    for (iloop = 0; iloop <= 32; iloop++) {
        if (mask_in == mask[iloop]) {
            return iloop;
        }
    }

    return 32;
}

unsigned int num_to_mask(int mask_num)
{
    unsigned int mask[33] = {
        0x00000000, 0x80000000, 0xc0000000, 0xe0000000,
        0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000,
        0xff000000, 0xff800000, 0xffc00000, 0xffe00000,
        0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000,
        0xffff0000, 0xffff8000, 0xffffc000, 0xffffe000,
        0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00,
        0xffffff00, 0xffffff80, 0xffffffc0, 0xffffffe0,
        0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe,
        0xffffffff,
    };

    if (mask_num <= 32) {
        return mask[mask_num];
    }
    else {
        return mask[32];
    }
}

int num_to_power(unsigned int num, unsigned char *power)
{
    unsigned char  bit_no;

    for (bit_no = 0; bit_no < 32; bit_no++) {
        if (num == (unsigned int)(1 << bit_no))
        {
            *power = bit_no;

            return 0;
        }
    }

    return -1;
}

unsigned int power_to_num(unsigned char power)
{
    return (1 << power);
}

void ipv6_prefix_to_mask(uint8_t *mask_num, uint8_t prefix)
{
    uint8_t cnt = 0;
    uint8_t valid_byte = prefix >> 3;
    uint8_t valid_bit = prefix & 0x7;

    for (cnt = 0; cnt < valid_byte; ++cnt) {
        mask_num[cnt] = 0xFF;
    }

    switch (valid_bit) {
        case 0:
            break;
        case 1:
            mask_num[valid_byte] = 0x80;
            break;
        case 2:
            mask_num[valid_byte] = 0xC0;
            break;
        case 3:
            mask_num[valid_byte] = 0xE0;
            break;
        case 4:
            mask_num[valid_byte] = 0xF0;
            break;
        case 5:
            mask_num[valid_byte] = 0xF8;
            break;
        case 6:
            mask_num[valid_byte] = 0xFC;
            break;
        case 7:
            mask_num[valid_byte] = 0xFE;
            break;
    }
}

