/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/


#include "common.h"
#include "util.h"
#include "platform.h"
#include "session_struct.h"

#include "lz4.h"
#include "compress_func.h"


static uint32_t g_max_out_length = 0;

/* ÁÙÊ±´æ´¢Ñ¹ËõºÍ½âÑ¹buffer */
static char *g_en_out = NULL;
static char *g_de_out = NULL;

#define COMP_LOCK_T     ros_rwlock_t
#define COMP_LOCK_LOCK(sl)  ros_rwlock_write_lock(sl)
#define COMP_LOCK_UNLOCK(sl)  ros_rwlock_write_unlock(sl)
#define COMP_LOCK_INIT(sl)  ros_rwlock_init(sl)

/* ÁÙÊ±´æ´¢Ñ¹ËõºÍ½âÑ¹µÄbufferËø */
COMP_LOCK_T g_en_out_lock;
COMP_LOCK_T g_de_out_lock;

int64_t comp_init(void)
{
    uint32_t max_out_len = sizeof(session_content_modify) >> 10;

    max_out_len = (max_out_len + 1) << 11;
    g_max_out_length =  max_out_len;

    g_en_out = (char *)malloc(g_max_out_length);
    if (NULL == g_en_out) {
        LOG(COMM, ERR, "malloc out buff failed.\n");
        return -1;
    }

    g_de_out = (char *)malloc(g_max_out_length);
    if (NULL == g_de_out) {
        LOG(COMM, ERR, "malloc out buff failed.\n");
        return -1;
    }

    COMP_LOCK_INIT(&g_en_out_lock);
    COMP_LOCK_INIT(&g_de_out_lock);

    return g_max_out_length << 1;
}

inline int comp_compbound(int size)
{
    return LZ4_COMPRESSBOUND(size);
}

int comp_compress(char *buff_in, uint32_t in_len,
    char **buff_out, uint32_t *out_len)
{
    int ret = 0;

    if (NULL == buff_in || NULL == buff_out || NULL == buff_out) {
        LOG(COMM, ERR, "abnormal, parameter, buff_in(%p), in_len: %u,"
            " buff_out(%p), buff_out(%p).", buff_in, in_len, buff_out, out_len);
        return -1;
    }

    COMP_LOCK_LOCK(&g_en_out_lock); /* lock */
    ret = LZ4_compress_default(buff_in, g_en_out, in_len, g_max_out_length);
    if (unlikely(ret < 1)) {
        COMP_LOCK_UNLOCK(&g_en_out_lock); /* unlock */
        LOG(COMM, ERR, "internal error - compression failed: %d\n", ret);
        return -1;
    }

    LOG(COMM, RUNNING, "compressed %u bytes into %d bytes\n", in_len, ret);

    *out_len = ret;
    *buff_out = g_en_out;

    return 0;
}

int comp_decompress(char *buff_in, uint32_t in_len,
    char **buff_out, uint32_t *out_len)
{
    int ret = 0;

    if (NULL == buff_in || NULL == buff_out || NULL == buff_out) {
        LOG(COMM, ERR, "abnormal, parameter, buff_in(%p), in_len: %u,"
            " buff_out(%p), buff_out(%p).", buff_in, in_len, buff_out, out_len);
        return -1;
    }

    COMP_LOCK_LOCK(&g_de_out_lock);
    ret = LZ4_decompress_safe(buff_in, g_de_out, in_len, g_max_out_length);
    if (unlikely(ret < 0)) {
        COMP_LOCK_UNLOCK(&g_de_out_lock);
        LOG(COMM, ERR, "internal error - decompression failed: %d\n", ret);
        return -1;
    }

    LOG(COMM, RUNNING, "decompressed %u bytes back into %u bytes\n",
        ret, in_len);

    *out_len = ret;
    *buff_out = g_de_out;

    return 0;
}

void comp_en_out_free(void)
{
    COMP_LOCK_UNLOCK(&g_en_out_lock);
}

void comp_de_out_free(void)
{
    COMP_LOCK_UNLOCK(&g_de_out_lock);
}

int comp_compress_userdef(char *buff_in, uint32_t in_len,
    char *buff_out, uint32_t *out_len, uint32_t max_out_len)
{
    int ret = 0;

    if (unlikely(NULL == buff_in || NULL == buff_out || NULL == out_len)) {
        LOG(COMM, ERR, "abnormal, parameter, buff_in(%p), in_len: %u,"
            " buff_out(%p), buff_out(%p).", buff_in, in_len, buff_out, out_len);
        return -1;
    }

    ret = LZ4_compress_default(buff_in, buff_out, in_len, max_out_len);
    if (unlikely(ret < 1)) {
        LOG(COMM, ERR, "internal error - compression failed: %d\n", ret);
        return -1;
    }

    LOG(COMM, RUNNING, "compressed %u bytes into %d bytes\n", in_len, ret);

    *out_len = ret;

    return 0;
}

int comp_decompress_userdef(char *buff_in, uint32_t in_len,
    char *buff_out, uint32_t max_out_len)
{
    int ret = 0;

    if (unlikely(NULL == buff_in || NULL == buff_out)) {
        LOG(COMM, ERR,
            "abnormal, parameter, buff_in(%p), in_len: %u, buff_out(%p), max_out_len: %u.",
            buff_in, in_len, buff_out, max_out_len);
        return -1;
    }

    /* Optional lzo1x_decompress_safe() */
    ret = LZ4_decompress_safe(buff_in, buff_out, in_len, max_out_len);
    if (unlikely(ret < 0)) {
        LOG(COMM, ERR, "internal error - decompression failed: %d\n", ret);
        return -1;
    }

    LOG(COMM, RUNNING, "decompressed %u bytes back into %u bytes\n",
        ret, in_len);

    return ret;
}


