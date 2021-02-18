/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _COMPRESS_FUNC_H__
#define _COMPRESS_FUNC_H__

#ifdef __cplusplus
extern "C" {
#endif

/* 所有pfcp session相关结构体压缩后最大不超过的长度 */
#ifndef SESS_COMPRESSBOUND
/* Copy form LZ4_COMPRESSBOUND */
#define SESS_MAX_INPUT_SIZE        0x7E000000   /* 2 113 929 216 bytes */
#define SESS_COMPRESSBOUND(isize)  ((unsigned)(isize) > (unsigned)SESS_MAX_INPUT_SIZE ? 0 : (isize) + ((isize)/255) + 16)
#define SESS_COMPRESSBOUND_LEN  SESS_COMPRESSBOUND(max(sizeof(session_content_modify), sizeof(session_pfd_mgmt_request)))
#endif

int64_t comp_init(void);
inline int comp_compbound(int size);
int comp_compress(char *buff_in, uint32_t in_len,
    char **buff_out, uint32_t *out_len);
int comp_decompress(char *buff_in, uint32_t in_len,
    char **buff_out, uint32_t *out_len);
void comp_en_out_free(void);
void comp_de_out_free(void);

int comp_compress_userdef(char *buff_in, uint32_t in_len,
    char *buff_out, uint32_t *out_len, uint32_t max_out_len);
int comp_decompress_userdef(char *buff_in, uint32_t in_len,
    char *buff_out, uint32_t max_out_len);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _COMPRESS_FUNC_H__ */

