/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __BUFFER_H__
#define __BUFFER_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE   (128)
#endif

#define BUFFER_BLOCK_DEFAULT_SIZE       (2048)
#define BUFFER_BLOCK_DEFAULT_NUM        (65536)
#define BUFFER_CBLOCK_DEFAULT_NUM       (65536)

#define BUFFER_SHM_MALLOC(name, size, align)        ros_malloc(size)
#define BUFFER_SHM_FREE(name, ptr)                  ros_free(ptr)


typedef void            (*CBLK_FREE)(void *);
#pragma pack(1)
typedef struct  tag_fp_cblk_entry
{
    NODE                node;
    uint32_t            index;          /* index in pool */
    uint8_t             lcore_id;       /* buf comes from that dpdk core */
    uint8_t             port;           /* EN_PORT_TYPE, forward port, if is EN_PORT_BUTT drop it*/
    uint16_t            len;            /* content length */
    void                *buf;           /* buffer pointer */
    char                *pkt;           /* packet pointer */
    CBLK_FREE           free;           /* func used to free buffer */
    uint32_t            time;           /* buffer time */
}fp_cblk_entry;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_buff_pool
{
    fp_cblk_entry       *cblk;
    char                *block;
    uint32_t            cblk_max;       /* max number */
    uint32_t            block_max;      /* max number */
    uint16_t            res_cblk;
    uint16_t            res_block;
    uint8_t             block_bit;      /* block size by bit */
    uint8_t             resv[3];        /* keep aligning to 8 bytes */
}fp_buff_pool;
#pragma pack()

#pragma pack(1)
typedef struct  tag_fp_pure_buff
{
    char                *block;
    uint32_t            block_max;      /* max number */
    uint32_t            block_size;     /* block size */
    uint16_t            res_block;
    uint8_t             resv[6];        /* keep aligning to 8 bytes */
}fp_pure_buff;
#pragma pack()

fp_buff_pool *fp_buff_head_get(void);

fp_pure_buff *fp_pure_buff_init(uint32_t block_num, uint32_t block_size, int64_t *mem_cost);
int64_t fp_buff_pool_init(uint32_t block_num, uint32_t block_size, uint32_t cblock_num);
fp_cblk_entry *fp_cblk_alloc(void);
void fp_cblk_free(fp_cblk_entry *entry);
char *fp_block_alloc(void);
void fp_block_free(char *block);
char *fp_pure_buff_alloc(fp_pure_buff *head);
void fp_pure_buff_free(fp_pure_buff *head, char *block);

#ifdef __cplusplus
}
#endif

#endif /* __BUFFER_H__ */

