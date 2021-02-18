/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#include "common.h"
#include "util.h"
#include "platform.h"
#include "buffer.h"

CVMX_SHARED fp_buff_pool *fp_buff_pool_head = NULL;

fp_buff_pool *fp_buff_head_get(void)
{
    return fp_buff_pool_head;
}

int64_t fp_buff_pool_init(uint32_t block_num, uint32_t block_size, uint32_t cblock_num)
{
    int32_t res_no = 0;
    uint32_t item, bit_no, flag;
    uint8_t  *tmp = NULL;
    int64_t  total_mem = 0, size = 0;
    uint64_t ret64;
    fp_buff_pool   *head = NULL;
    fp_cblk_entry  *entry = NULL;         /* point to entry pool */

    /* check size */
    if (cblock_num == 0) {
        cblock_num = 1024;
    }
    if (block_num == 0) {
        block_num = 1024;
    }
    if (block_size == 0) {
        block_size = 2048;
    }
    for (bit_no = 0; bit_no < 32; bit_no++) {
        if (block_size == (uint32_t)(1 << bit_no))
        {
            flag = G_TRUE;
            break;
        }
    }
    if (flag != G_TRUE) {
        return -1;
    }

    /* create cblk pool */
    size = cblock_num * sizeof(fp_cblk_entry) + sizeof(fp_buff_pool) + CACHE_LINE_SIZE;
    total_mem += size;
    tmp = (uint8_t *)BUFFER_SHM_MALLOC(GLB_BUFF_HEAD_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        return -1;
    }

    /* set buff pool header */
    fp_buff_pool_head = (fp_buff_pool *)tmp;

    tmp = (uint8_t *)tmp + sizeof(fp_buff_pool);
    tmp = (uint8_t *)roundup(tmp, CACHE_LINE_SIZE);

    /* init entries */
    entry = (fp_cblk_entry *)tmp;
    for (item = 0; item < cblock_num; item++) {
        entry[item].index = item;
    }

    /* init header */
    head = fp_buff_pool_head;
    head->cblk = entry;

    res_no = Res_CreatePool();
    if (res_no < 0) {
	    LOG(COMM, ERR, "Create pool fail.");
        return -1;
    }

    ret64 = Res_AddSection(res_no, 0, 0, cblock_num);
    if (ret64 == G_FAILURE) {
	    LOG(COMM, ERR, "Add section fail.");
        return -1;
    }
    head->res_cblk = res_no;
    head->cblk_max = cblock_num;

    /* create block pool */
    size = block_num;
    size *= block_size;
    total_mem += size;
    tmp = (uint8_t *)BUFFER_SHM_MALLOC(GLB_BLOCK_POOL_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        LOG(COMM, ERR, "Malloc fail.");
        return -1;
    }

    head->block = (char *)tmp;

    res_no = Res_CreatePool();
    if (res_no < 0) {
        LOG(COMM, ERR, "Create pool fail.");
        return -1;
    }

    ret64 = Res_AddSection(res_no, 0, 0, block_num);
    if (ret64 == G_FAILURE) {
        LOG(COMM, ERR, "Add section fail.");
        return -1;
    }
    head->block_bit = bit_no;
    head->res_block = res_no;
    head->block_max = block_num;

    return total_mem;
}

fp_pure_buff *fp_pure_buff_init(uint32_t block_num, uint32_t block_size, int64_t *mem_cost)
{
    int32_t res_no = 0;
    uint8_t  *tmp = NULL;
    int64_t  total_mem = 0, size = 0;
    uint64_t ret64;
    fp_pure_buff   *head = NULL;

    /* create block pool */
    size = block_size * block_num + sizeof(fp_pure_buff);
    total_mem += size;
    tmp = (uint8_t *)BUFFER_SHM_MALLOC(GLB_BLOCK_POOL_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        LOG(COMM, ERR, "Malloc fail.");
        return NULL;
    }

    head = (fp_pure_buff *)tmp;

    head->block = ((char *)tmp + sizeof(fp_pure_buff));

    res_no = Res_CreatePool();
    if (res_no < 0) {
        LOG(COMM, ERR, "Create pool fail.");
        return NULL;
    }

    ret64 = Res_AddSection(res_no, 0, 0, block_num);
    if (ret64 == G_FAILURE) {
        LOG(COMM, ERR, "Add section fail.");
        return NULL;
    }

    head->res_block  = res_no;
    head->block_max  = block_num;
    head->block_size = block_size;

    *mem_cost = total_mem;

    return head;
}

fp_cblk_entry *fp_cblk_alloc()
{
    fp_cblk_entry  *entry;
    fp_buff_pool   *head;
    uint64_t       ret64;
    uint32_t       key = 0, index;

    head = fp_buff_pool_head;
    if (!head) {
        return NULL;
    }

    ret64 = Res_Alloc(head->res_cblk, &key, &index, EN_RES_ALLOC_MODE_OC);
    if (ret64 != G_SUCCESS) {
        return NULL;
    }
    entry = &(head->cblk[index]);

    /* set default value */
    entry->buf  = NULL;
    entry->pkt  = NULL;
    entry->free = NULL;
    entry->len  = 0;
    entry->time = ros_getime();

    return entry;
}

void fp_cblk_free(fp_cblk_entry *entry)
{
    fp_buff_pool   *head;
    uint32_t       index;

    if (!entry) {
        return;
    }

    /* If buffer exist, free it */
    if (entry->buf) {
        if (entry->free)
            entry->free(entry->buf);
        entry->buf = NULL;
    }

    head = fp_buff_pool_head;
    if (!head) {
        return;
    }

    index = entry->index;
    if (index >= head->cblk_max) {
        return;
    }

    Res_Free(head->res_cblk, 0, index);

    return;
}

char *fp_block_alloc()
{
    fp_buff_pool   *head;
    uint64_t       ret64;
    uint32_t       key = 0, index;
    char           *block;

    head = fp_buff_pool_head;
    ret64 = Res_Alloc(head->res_block, &key, &index, EN_RES_ALLOC_MODE_OC);
    if (ret64 != G_SUCCESS) {
        return NULL;
    }
    block = (head->block + (index << head->block_bit));

    return block;
}

void fp_block_free(char *block)
{
    fp_buff_pool   *head;
    uint32_t       index;

    if (!block) {
        return;
    }

    head = fp_buff_pool_head;
    if (!head) {
        return;
    }

    index = ((block - head->block) >> head->block_bit);
    if (index >= head->block_max) {
        LOG(COMM, ERR,
            "free wrong block(%p), base(%p), index: %u.", block, head->block, index);
        return;
    }

    Res_Free(head->res_block, 0, index);

    return;
}

char *fp_pure_buff_alloc(fp_pure_buff *head)
{
    uint64_t       ret64;
    uint32_t       key = 0, index;
    char           *block;

    if (!head) {
        return NULL;
    }

    ret64 = Res_Alloc(head->res_block, &key, &index, EN_RES_ALLOC_MODE_OC);
    if (ret64 != G_SUCCESS) {
        return NULL;
    }
    block = (char *)(head->block + index * head->block_size);

    return block;
}

void fp_pure_buff_free(fp_pure_buff *head, char *block)
{
    uint32_t       index;

    if (!block) {
        return;
    }
    if (!head) {
        return;
    }

    index = ((block - head->block)/head->block_size);
    if (index >= head->block_max) {
        LOG(COMM, ERR,
            "free wrong block(%p), base(%p), index: %u.", block, head->block, index);
        return;
    }

    Res_Free(head->res_block, 0, index);

    return;
}


