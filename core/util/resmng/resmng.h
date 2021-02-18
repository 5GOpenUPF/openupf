/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _RES_MNG_H__
#define _RES_MNG_H__

#define RES_ALLOC_MODE
#define RES_PART_LEN                        32
#define RES_PART_LEN_MASK                   (RES_PART_LEN - 1)
#define RES_PART_LEN_BIT                    5
#define RES_COMBINE(idx, bit)               ((idx << RES_PART_LEN_BIT) + bit)
#define RES_SET_BIT(val, bitnum)            val = (val|(1<<bitnum))
#define RES_CLR_BIT(val, bitnum)            val = (val&(~(1<<bitnum)))
#define RES_TST_BIT(val, bitnum)            (val&(1<<bitnum))

#define RES_BIT_TO_MASK(allocNum)           ((1<<allocNum) - 1)
#define RES_SET_MUL_BIT(val, bitstart, bitmask) \
                                            val = (val^(bitmask<<bitstart))
#define RES_CLR_MUL_BIT(val, bitstart, bitmask) \
                                            val = (val^(bitmask<<bitstart))
#define RES_ALC_TST_MUL_BIT(val, bitstart, bitmask) \
                                            ((uint32_t)((val>>bitstart)&bitmask)\
                                                == (uint32_t)bitmask ? 1 : 0)
#define RES_CLR_TST_MUL_BIT(val, bitstart, bitmask) \
                                            (val&(bitmask<<bitstart))

#define RES_POOL_SECTION                    0
#define RES_POOL_POOL                       0
#define RES_SEC_SECTION                     1
#define RES_SEC_POOL                        1
#define RES_RESERVE_NUM                     2

#define RES_ALLOC_1                         1
#define RES_ALLOC_2                         2
#define RES_ALLOC_4                         4
#define RES_ALLOC_8                         8

#ifdef ENABLE_OCTEON_III
#define RES_MALLOC(name, size, align)       system_named_shared_memblock_getalloc(name, size, align)
#define RES_FREE(name, ptr)                 system_named_shared_memblock_free(name)
#else
#define RES_MALLOC(name, size, align)       ros_malloc(size)
#define RES_FREE(name, ptr)                 ros_free(ptr)
#endif
#define RES_MUTEX_TYPE                      ros_rwlock_t
#define RES_MUTEX_INIT(sem)                 ros_rwlock_init(sem)
#define RES_MUTEX_LOCK(sem)                 ros_rwlock_write_lock(sem)
#define RES_MUTEX_UNLOCK(sem)               ros_rwlock_write_unlock(sem)
#define RES_MUTEX_READ_LOCK(sem)            ros_rwlock_read_lock(sem)
#define RES_MUTEX_READ_UNLOCK(sem)          ros_rwlock_read_unlock(sem)

typedef int (*RES_MARK_HOOK) (uint32_t);

#if 0
#define RES_LOG(fmt, arg...) \
do { \
    printf("%s(%d) "fmt"\r\n", __FUNCTION__, __LINE__, ##arg); \
   } while((0))

#else
#define RES_LOG(fmt, arg...) \
do { \
   } while((0))
#endif

typedef enum tag_EN_RES_ALLOC_MODE
{
    EN_RES_ALLOC_MODE_OC,                   /* 独占 */
    EN_RES_ALLOC_MODE_LB,                   /* 共享 */
}EN_RES_ALLOC_MODE;

typedef struct tag_ST_RES_FIELD
{
    uint32_t       uiCurIdx;                /* 当前分配到的位置(第几个长字) */
    uint32_t       uiMaxIdx;                /* 最大可分配的位置(长字数量) */
    uint32_t       *puiField;               /* 数据起始位置 */
    RES_MUTEX_TYPE rwLock;                  /* RW lock */
}ST_RES_FIELD;

typedef struct tag_ST_RES_SECTION
{
    AVL_NODE       stNode;                  /* 二叉树，用于节点的查找、删除 */
    NODE           stList;                  /* 链表，用于顺序使用 */
    uint32_t       uiKey;                   /* Key，用于资源段的标示，例如一个ip的某些端口作为资源，这个ip就是key */
    uint32_t       uiMaxNum;                /* 本类资源的最大数量 */
    uint32_t       uiAlloced;               /* 已经分配的资源数量 */
    uint32_t       uiCurIdx;                /* 当前分配到的位置(第几个长字) */
    uint32_t       uiCurBit;                /* 当前分配到的位置(第几个位) */
    uint32_t       uiMaxIdx;                /* 最大可分配的位置(长字数量) */
    uint32_t       uiStart;                 /* 起始值 */
    uint32_t       *puiBitFld;              /* 位域标识 */
    RES_MUTEX_TYPE rwLock;                  /* RW lock */
}ST_RES_SECTION;

typedef struct tag_ST_RES_POOL
{
    uint32_t       uiIndex;                 /* 当前数据结构在总表中的序号 */
    uint32_t       uiSecNum;                /* 本pool中section数量 */
    uint32_t       uiTotal;                 /* 本pool中所有section加起来的资源数 */
    uint32_t       uiAlloced;               /* 本pool中已经分配的资源数量 */
    AVL_TREE       pstTree;                 /* section tree */
    LIST           pstList;                 /* section list */
    RES_MUTEX_TYPE rwLock;                  /* RW lock */
    ST_RES_SECTION *pstSection;             /* 当前section */
}ST_RES_POOL;

extern CVMX_SHARED ST_RES_POOL *gpstResAddrPool;

/*-----------------------------------------------------------------------------
 函数名称    : Res_PoolToIndex
 功能        : 资源池指针转换成资源序号
 输入参数    : 无
 输出参数    : 无
 返回值      : 资源序号
 函数调用说明:
 典型使用示例:
-----------------------------------------------------------------------------*/
static inline uint32_t Res_PoolToIndex(ST_RES_POOL *pstPool)
{
    return pstPool->uiIndex;
}

/*-----------------------------------------------------------------------------
 函数名称    : Res_IndexToPool
 功能        : 资源序号转换成资源池指针
 输入参数    : 无
 输出参数    : 无
 返回值      : 资源池指针
 函数调用说明:
 典型使用示例:
-----------------------------------------------------------------------------*/
static inline ST_RES_POOL *Res_IndexToPool(uint32_t uiIndex)
{
    return &gpstResAddrPool[uiIndex];
}

/*-----------------------------------------------------------------------------
 函数名称    : entry_num_to_bit
 功能        : 将entry的数量转为比特
 输入参数    : 无
 输出参数    : 无
 返回值      :
 函数调用说明:
 典型使用示例:
-----------------------------------------------------------------------------*/
static inline uint32_t Res_EntryNumToBit(uint16_t entry_num)
{
    switch (entry_num) {
        case 1: return 0;
        case 2: return 1;
        case 4: return 2;
        case 8: return 3;
        default: return 0;
    }
}

/*-----------------------------------------------------------------------------
 函数名称    : entry_bit_to_num
 功能        : 将entry的比特转为数量
 输入参数    : 无
 输出参数    : 无
 返回值      :
 函数调用说明:
 典型使用示例:
-----------------------------------------------------------------------------*/
static inline uint32_t Res_EntryBitToNum(uint16_t entry_bit)
{
    return 1 << entry_bit;
}

int Res_Init(uint32_t uiTotalPoolNum, uint32_t uiTotalSecionNum, uint32_t uiTotalFieldLen);
uint8_t  Res_IsInit(void);
ST_RES_POOL *Res_TakePool(void);
void Res_GivePool(ST_RES_POOL *pstPool);
ST_RES_SECTION *Res_TakeSection(uint32_t uiFieldNum);
void Res_GiveSection(ST_RES_SECTION *pstSection);
int  Res_CompKey(AVL_NODE *pNode, void *pValue);
uint64_t Res_AddSection(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiFirst, uint32_t uiMaxNum);
uint64_t Res_DelSection(uint32_t uiPoolNo, uint32_t uiKey);
int32_t Res_CreatePool(void);
void Res_DestroyPool(uint32_t uiPoolNo);
void Res_Free(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiRes);
uint64_t Res_Alloc(uint32_t uiPoolNo, uint32_t *puiKey, uint32_t *puiResNo, EN_RES_ALLOC_MODE enMode);
void Res_UnitTest(uint32_t uiTestID);
void Res_SectionShow(ST_RES_SECTION *pstSec);
void Res_PoolShow(uint32_t uiPoolNo);
uint64_t Res_GetNextAvailable(uint32_t uiPoolNo, uint32_t uiCurKey, uint32_t uiCurResNo,
    uint32_t *puiKey, uint32_t *puiResNo);
int32_t  Res_GetAvailableInBand(uint32_t uiPoolNo, uint32_t uiStart, uint32_t uiEnd);
int32_t Res_GetAvailAndFreeInBand(uint32_t uiPoolNo, uint32_t uiStart, uint32_t uiEnd);
uint64_t Res_IsAlloced(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiResNo);
void Res_FreeBatch(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiFrom, uint32_t uiNum);
uint64_t Res_AllocTarget(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiResNo);
uint32_t Res_GetAlloced(uint32_t uiPoolNo);
void Res_DeInit(void);
uint64_t Res_Mul_Alloc(uint32_t uiPoolNo, uint32_t *puiKey, uint32_t *puiResNo,
    EN_RES_ALLOC_MODE enMode, uint32_t uiAllocNum);
void Res_Mul_Free(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiRes, uint32_t uiFreeNum);
uint64_t Res_Mul_IsAlloced(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiResNo, uint32_t uiEntryNum);
uint64_t Res_Mul_AllocTarget(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiResNo, uint32_t uiAllocNum);
uint32_t Res_GetTotal(uint32_t uiPoolNo);
uint64_t Res_GetRangeField(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiStart, uint32_t uiResNum,
    uint32_t *puiResp);
int32_t  Res_MarkCreate(uint32_t uiBitNum);
void Res_MarkSet(int32_t uiPoolNo, uint32_t uiBitNo);
void Res_MarkClr(int32_t uiPoolNo, uint32_t uiBitNo);
int32_t  Res_MarkGetClr(int32_t uiPoolNo, int32_t uiCurBit, RES_MARK_HOOK hook);

#endif

