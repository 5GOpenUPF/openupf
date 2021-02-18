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
    EN_RES_ALLOC_MODE_OC,                   /* ��ռ */
    EN_RES_ALLOC_MODE_LB,                   /* ���� */
}EN_RES_ALLOC_MODE;

typedef struct tag_ST_RES_FIELD
{
    uint32_t       uiCurIdx;                /* ��ǰ���䵽��λ��(�ڼ�������) */
    uint32_t       uiMaxIdx;                /* ���ɷ����λ��(��������) */
    uint32_t       *puiField;               /* ������ʼλ�� */
    RES_MUTEX_TYPE rwLock;                  /* RW lock */
}ST_RES_FIELD;

typedef struct tag_ST_RES_SECTION
{
    AVL_NODE       stNode;                  /* �����������ڽڵ�Ĳ��ҡ�ɾ�� */
    NODE           stList;                  /* ��������˳��ʹ�� */
    uint32_t       uiKey;                   /* Key��������Դ�εı�ʾ������һ��ip��ĳЩ�˿���Ϊ��Դ�����ip����key */
    uint32_t       uiMaxNum;                /* ������Դ��������� */
    uint32_t       uiAlloced;               /* �Ѿ��������Դ���� */
    uint32_t       uiCurIdx;                /* ��ǰ���䵽��λ��(�ڼ�������) */
    uint32_t       uiCurBit;                /* ��ǰ���䵽��λ��(�ڼ���λ) */
    uint32_t       uiMaxIdx;                /* ���ɷ����λ��(��������) */
    uint32_t       uiStart;                 /* ��ʼֵ */
    uint32_t       *puiBitFld;              /* λ���ʶ */
    RES_MUTEX_TYPE rwLock;                  /* RW lock */
}ST_RES_SECTION;

typedef struct tag_ST_RES_POOL
{
    uint32_t       uiIndex;                 /* ��ǰ���ݽṹ���ܱ��е���� */
    uint32_t       uiSecNum;                /* ��pool��section���� */
    uint32_t       uiTotal;                 /* ��pool������section����������Դ�� */
    uint32_t       uiAlloced;               /* ��pool���Ѿ��������Դ���� */
    AVL_TREE       pstTree;                 /* section tree */
    LIST           pstList;                 /* section list */
    RES_MUTEX_TYPE rwLock;                  /* RW lock */
    ST_RES_SECTION *pstSection;             /* ��ǰsection */
}ST_RES_POOL;

extern CVMX_SHARED ST_RES_POOL *gpstResAddrPool;

/*-----------------------------------------------------------------------------
 ��������    : Res_PoolToIndex
 ����        : ��Դ��ָ��ת������Դ���
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
static inline uint32_t Res_PoolToIndex(ST_RES_POOL *pstPool)
{
    return pstPool->uiIndex;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_IndexToPool
 ����        : ��Դ���ת������Դ��ָ��
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ��ָ��
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
static inline ST_RES_POOL *Res_IndexToPool(uint32_t uiIndex)
{
    return &gpstResAddrPool[uiIndex];
}

/*-----------------------------------------------------------------------------
 ��������    : entry_num_to_bit
 ����        : ��entry������תΪ����
 �������    : ��
 �������    : ��
 ����ֵ      :
 ��������˵��:
 ����ʹ��ʾ��:
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
 ��������    : entry_bit_to_num
 ����        : ��entry�ı���תΪ����
 �������    : ��
 �������    : ��
 ����ֵ      :
 ��������˵��:
 ����ʹ��ʾ��:
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

