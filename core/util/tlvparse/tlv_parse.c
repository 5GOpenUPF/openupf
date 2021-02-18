/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "tlv_parse.h"

int tlv_decode_length(uint8_t* buffer, uint16_t *buf_pos1, int buf_max)
{
    uint16_t len1;
    uint16_t buf_pos = *buf_pos1;

    if (buf_pos + TLV_LENGTH_LEN > buf_max)
        return -1;

    len1 = (buffer[buf_pos] << 8) + buffer[buf_pos + 1];

    if (len1 + buf_pos + TLV_LENGTH_LEN <= buf_max) {
        *buf_pos1 = buf_pos + TLV_LENGTH_LEN;
        return len1;
    }
    else {
        return -1;
    }
}

int tlv_decode_type(uint8_t* buffer, uint16_t *buf_pos1, int buf_max)
{
    uint16_t type1;
    uint16_t buf_pos = *buf_pos1;

    if (buf_pos + TLV_TYPE_LEN > buf_max)
        return -1;

    type1 = (buffer[buf_pos] << 8) + buffer[buf_pos + 1];
    *buf_pos1 = buf_pos + TLV_TYPE_LEN;

    return type1;
}

uint8_t tlv_decode_uint8_t(uint8_t* buffer, uint16_t *buf_pos1)
{
    uint16_t buf_pos = *buf_pos1;

    *buf_pos1 = buf_pos + sizeof(uint8_t);

    return buffer[buf_pos];
}

uint16_t tlv_decode_uint16_t(uint8_t* buffer, uint16_t *buf_pos1)
{
    uint16_t ret_val;
    uint8_t  byteloop;
    uint16_t buf_pos = *buf_pos1;

    ret_val = 0;
    for (byteloop = 0; byteloop < sizeof(uint16_t); byteloop++) {
        ret_val = (ret_val << 8);
        ret_val += buffer[buf_pos + byteloop];
    }

    *buf_pos1 = buf_pos + sizeof(uint16_t);

    return ret_val;
}

uint32_t tlv_decode_uint32_t(uint8_t* buffer, uint16_t *buf_pos1)
{
    uint32_t ret_val;
    uint8_t  byteloop;
    uint16_t buf_pos = *buf_pos1;

    ret_val = 0;
    for (byteloop = 0; byteloop < sizeof(uint32_t); byteloop++) {
        ret_val = (ret_val << 8);
        ret_val += buffer[buf_pos + byteloop];
    }

    *buf_pos1 = buf_pos + sizeof(uint32_t);

    return ret_val;
}

uint64_t tlv_decode_uint64_t(uint8_t* buffer, uint16_t *buf_pos1)
{
    uint64_t ret_val;
    uint8_t  byteloop;
    uint16_t buf_pos = *buf_pos1;

    ret_val = 0;
    for (byteloop = 0; byteloop < sizeof(uint64_t); byteloop++) {
        ret_val = (ret_val << 8);
        ret_val += buffer[buf_pos + byteloop];
    }

    *buf_pos1 = buf_pos + sizeof(uint64_t);

    return ret_val;
}

uint32_t tlv_decode_int_3b(uint8_t* buffer, uint16_t *buf_pos1)
{
    uint32_t ret_val;
    uint8_t  byteloop;
    uint16_t buf_pos = *buf_pos1;

    ret_val = 0;
    for (byteloop = 0; byteloop < 3; byteloop++) {
        ret_val = (ret_val << 8);
        ret_val += buffer[buf_pos + byteloop];
    }

    *buf_pos1 = buf_pos + 3;

    return ret_val;
}

uint64_t tlv_decode_int_5b(uint8_t* buffer, uint16_t *buf_pos1)
{
    uint64_t ret_val;
    uint8_t  byteloop;
    uint16_t buf_pos = *buf_pos1;

    ret_val = 0;
    for (byteloop = 0; byteloop < 5; byteloop++) {
        ret_val = (ret_val << 8);
        ret_val += buffer[buf_pos + byteloop];
    }

    *buf_pos1 = buf_pos + 5;

    return ret_val;
}

void tlv_decode_binary(uint8_t* buffer, uint16_t *buf_pos1,
    uint32_t length, uint8_t *out)
{
    uint16_t buf_pos = *buf_pos1;

    memcpy(out, buffer + buf_pos, length);

    *buf_pos1 = buf_pos + length;
    return;
}


void tlv_encode_length(uint8_t* buffer, uint16_t *buf_pos1, uint16_t length)
{
    uint16_t buf_pos = *buf_pos1;
    buffer[buf_pos] = (uint8_t)((length & 0xFF00) >> 8);
    buffer[buf_pos + 1] = (uint8_t)(length & 0xFF);

    *buf_pos1 = buf_pos + TLV_LENGTH_LEN;
}

void tlv_encode_type(uint8_t* buffer, uint16_t *buf_pos1, uint16_t type)
{
    uint16_t buf_pos = *buf_pos1;
    buffer[buf_pos] = (uint8_t)((type & 0xFF00) >> 8);
    buffer[buf_pos + 1] = (uint8_t)(type & 0xFF);

    *buf_pos1 = buf_pos + TLV_TYPE_LEN;
}

void tlv_encode_uint8_t(uint8_t* buffer, uint16_t *buf_pos1, uint8_t value)
{
    uint16_t buf_pos = *buf_pos1;
    buffer[buf_pos] = value;

    *buf_pos1 = buf_pos + sizeof(uint8_t);
}

void tlv_encode_uint16_t(uint8_t* buffer, uint16_t *buf_pos1, uint16_t value)
{
    uint16_t buf_pos = *buf_pos1;
    buffer[buf_pos] = (uint8_t)((value & 0xFF00) >> 8);
    buffer[buf_pos + 1] = (uint8_t)(value & 0xFF);

    *buf_pos1 = buf_pos + sizeof(uint16_t);
}

void tlv_encode_uint32_t(uint8_t* buffer, uint16_t *buf_pos1, uint32_t value)
{
    uint16_t buf_pos = *buf_pos1;
    buffer[buf_pos + 0] = (uint8_t)((value & 0xFF000000) >> 24);
    buffer[buf_pos + 1] = (uint8_t)((value & 0x00FF0000) >> 16);
    buffer[buf_pos + 2] = (uint8_t)((value & 0x0000FF00) >> 8);
    buffer[buf_pos + 3] = (uint8_t)(value & 0x000000FF);

    *buf_pos1 = buf_pos + sizeof(uint32_t);
}

void tlv_encode_uint64_t(uint8_t* buffer, uint16_t *buf_pos1, uint64_t value)
{
    uint16_t buf_pos = *buf_pos1;
    buffer[buf_pos + 0] = (uint8_t)((value & 0xFF00000000000000L) >> 56);
    buffer[buf_pos + 1] = (uint8_t)((value & 0x00FF000000000000L) >> 48);
    buffer[buf_pos + 2] = (uint8_t)((value & 0x0000FF0000000000L) >> 40);
    buffer[buf_pos + 3] = (uint8_t)((value & 0x000000FF00000000L) >> 32);
    buffer[buf_pos + 4] = (uint8_t)((value & 0x00000000FF000000L) >> 24);
    buffer[buf_pos + 5] = (uint8_t)((value & 0x0000000000FF0000L) >> 16);
    buffer[buf_pos + 6] = (uint8_t)((value & 0x000000000000FF00L) >> 8);
    buffer[buf_pos + 7] = (uint8_t)(value & 0x00000000000000FFL);

    *buf_pos1 = buf_pos + sizeof(uint64_t);
}

void tlv_encode_int_3b(uint8_t* buffer, uint16_t *buf_pos1, uint32_t value)
{
    uint16_t buf_pos = *buf_pos1;
    buffer[buf_pos + 0] = (uint8_t)((value & 0x00FF0000) >> 16);
    buffer[buf_pos + 1] = (uint8_t)((value & 0x0000FF00) >> 8);
    buffer[buf_pos + 2] = (uint8_t)(value & 0x000000FF);

    *buf_pos1 = buf_pos + 3;
}

void tlv_encode_int_5b(uint8_t* buffer, uint16_t *buf_pos1, uint64_t value)
{
    uint16_t buf_pos = *buf_pos1;
    buffer[buf_pos + 0] = (uint8_t)((value & 0x000000FF00000000) >> 32);
    buffer[buf_pos + 1] = (uint8_t)((value & 0x00000000FF000000) >> 24);
    buffer[buf_pos + 2] = (uint8_t)((value & 0x0000000000FF0000) >> 16);
    buffer[buf_pos + 3] = (uint8_t)((value & 0x000000000000FF00) >> 8);
    buffer[buf_pos + 4] = (uint8_t)(value & 0x00000000000000FF);

    *buf_pos1 = buf_pos + 5;
}

void tlv_encode_int_6b(uint8_t* buffer, uint16_t *buf_pos1, uint64_t value)
{
    uint16_t buf_pos = *buf_pos1;
    buffer[buf_pos + 0] = (uint8_t)((value & 0x0000FF0000000000) >> 40);
    buffer[buf_pos + 1] = (uint8_t)((value & 0x000000FF00000000) >> 32);
    buffer[buf_pos + 2] = (uint8_t)((value & 0x00000000FF000000) >> 24);
    buffer[buf_pos + 3] = (uint8_t)((value & 0x0000000000FF0000) >> 16);
    buffer[buf_pos + 4] = (uint8_t)((value & 0x000000000000FF00) >> 8);
    buffer[buf_pos + 5] = (uint8_t)(value & 0x00000000000000FF);

    *buf_pos1 = buf_pos + 6;
}

void tlv_encode_binary(uint8_t* buffer, uint16_t *buf_pos1,
    uint32_t length, uint8_t *input)
{
    uint16_t buf_pos = *buf_pos1;
    memcpy(buffer + buf_pos, input, length);

    *buf_pos1 = buf_pos + length;
}


