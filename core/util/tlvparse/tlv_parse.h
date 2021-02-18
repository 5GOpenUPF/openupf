/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef _TLV_PARSE_H__
#define _TLV_PARSE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define TLV_LENGTH_LEN          2
#define TLV_TYPE_LEN            2

int tlv_decode_length(uint8_t* buffer, uint16_t *buf_pos, int buf_max);
int tlv_decode_type(uint8_t* buffer, uint16_t *buf_pos, int buf_max);
uint8_t  tlv_decode_uint8_t(uint8_t* buffer, uint16_t *buf_pos);
uint16_t tlv_decode_uint16_t(uint8_t* buffer, uint16_t *buf_pos);
uint32_t tlv_decode_uint32_t(uint8_t* buffer, uint16_t *buf_pos);
uint64_t tlv_decode_uint64_t(uint8_t* buffer, uint16_t *buf_pos);
uint32_t tlv_decode_int_3b(uint8_t* buffer, uint16_t *buf_pos);
uint64_t tlv_decode_int_5b(uint8_t* buffer, uint16_t *buf_pos1);
void tlv_encode_int_6b(uint8_t* buffer, uint16_t *buf_pos1, uint64_t value);
void tlv_decode_binary(uint8_t* buffer, uint16_t *buf_pos,
    uint32_t length, uint8_t *out);

void tlv_encode_length(uint8_t* buffer, uint16_t *buf_pos, uint16_t length);
void tlv_encode_type(uint8_t* buffer, uint16_t *buf_pos, uint16_t type);
void tlv_encode_uint8_t(uint8_t* buffer, uint16_t *buf_pos, uint8_t value);
void tlv_encode_uint16_t(uint8_t* buffer, uint16_t *buf_pos, uint16_t value);
void tlv_encode_uint32_t(uint8_t* buffer, uint16_t *buf_pos, uint32_t value);
void tlv_encode_uint64_t(uint8_t* buffer, uint16_t *buf_pos, uint64_t value);
void tlv_encode_int_3b(uint8_t* buffer, uint16_t *buf_pos, uint32_t value);
void tlv_encode_int_5b(uint8_t* buffer, uint16_t *buf_pos1, uint64_t value);
void tlv_encode_binary(uint8_t* buffer, uint16_t *buf_pos,
    uint32_t length, uint8_t *input);


#ifdef __cplusplus
}
#endif

#endif /* _TLV_PARSE_H__ */


