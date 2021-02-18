/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "resmng.h"

CVMX_SHARED ST_RES_FIELD   gstResField; /* �ݲ�֧���ͷ� */
CVMX_SHARED ST_RES_SECTION *gpstResAddrSection;
CVMX_SHARED ST_RES_POOL    *gpstResAddrPool;

CVMX_SHARED ST_RES_POOL    *gpstResPoolAssigner;
CVMX_SHARED ST_RES_POOL    *gpstResSectionAssigner;

CVMX_SHARED uint8_t gucResInitFlag = G_FALSE;

/*-----------------------------------------------------------------------------
  ��������    : Res_Init
  ����        : ��ʼ��field��
  �������    : uiTotalPoolNum    pool����
                uiTotalSecionNum  section����
                uiTotalFieldLen   field(32bit word)��Դ����
  �������    : ��
  ����ֵ      : ��
  ��������˵��:
  ����ʹ��ʾ��:
 -----------------------------------------------------------------------------*/
int Res_Init(uint32_t uiTotalPoolNum1, uint32_t uiTotalSecionNum1, uint32_t uiTotalFieldLen)
{
    uint64_t ulSize;
    uint64_t ulLoop;
    uint32_t uiTotalPoolNum = uiTotalPoolNum1 + RES_RESERVE_NUM;
    uint32_t uiTotalSecionNum = uiTotalSecionNum1 + RES_RESERVE_NUM;
    ST_RES_SECTION *pstSection;

    if (gucResInitFlag != G_FALSE)
    {
        return G_TRUE;
    }

    if (uiTotalFieldLen <= 3)
    {
        RES_LOG("field length(%d) should not less 100.",
            uiTotalFieldLen);
        return G_FALSE;
    }

    ulSize = sizeof(ST_RES_POOL)*uiTotalPoolNum;
    gpstResAddrPool = (ST_RES_POOL *)RES_MALLOC(GLB_RES_POOL_SYMBOL, ulSize, CVMX_CACHE_LINE_SIZE);
    if (!gpstResAddrPool) {
        return G_FALSE;
    }
    RES_LOG("alloc resource pool %p, size %ld bytes.",
        gpstResAddrPool, ulSize);
    memset((char *)gpstResAddrPool, 0, ulSize);
    for (ulLoop = 0; ulLoop < uiTotalPoolNum; ulLoop++)
    {
        gpstResAddrPool[ulLoop].uiIndex = ulLoop;
    }

    ulSize = sizeof(ST_RES_SECTION)*uiTotalSecionNum;
    gpstResAddrSection = (ST_RES_SECTION *)RES_MALLOC(GLB_RES_SECTION_SYMBOL, ulSize, CVMX_CACHE_LINE_SIZE);
    if (!gpstResAddrSection) {
        return G_FALSE;
    }
    RES_LOG("alloc resource section %p, size %ld bytes.",
        gpstResAddrSection, ulSize);
    memset((char *)gpstResAddrSection, 0, ulSize);

    ulSize = ((uiTotalFieldLen + 3) & 0xFFFFFFFC) * 4;  /* 32bit ������ */
    gstResField.puiField = (uint32_t *)RES_MALLOC(GLB_RES_FIELD_SYMBOL, ulSize, CVMX_CACHE_LINE_SIZE);
    if (!gstResField.puiField) {
        return G_FALSE;
    }
    RES_LOG("alloc resource field %p, size %ld bytes.",
        gstResField.puiField, ulSize); fflush(stdout);
    memset((char *)gstResField.puiField, 0, ulSize);
    gstResField.uiCurIdx = 0;
    gstResField.uiMaxIdx = uiTotalFieldLen;
    RES_MUTEX_INIT(&gstResField.rwLock);

    /* ��ʼ��section/section */
    pstSection = &gpstResAddrSection[RES_SEC_SECTION];
    pstSection->uiKey     = 0;
    pstSection->uiAlloced = 0;
    pstSection->uiMaxNum  = uiTotalSecionNum;
    pstSection->uiCurIdx  = 0;
    pstSection->uiCurBit  = 0;
    pstSection->uiMaxIdx  = ((uiTotalSecionNum + RES_PART_LEN_MASK) >> RES_PART_LEN_BIT);
    pstSection->uiStart   = 0;
    pstSection->puiBitFld = &gstResField.puiField[gstResField.uiCurIdx];
    for (ulLoop = 0; ulLoop < pstSection->uiMaxIdx - 1; ulLoop++)
    {
        pstSection->puiBitFld[ulLoop] = (uint32_t)(-1);
    }
    for (ulLoop = 0; ulLoop < pstSection->uiMaxNum - ((pstSection->uiMaxIdx - 1)<<RES_PART_LEN_BIT); ulLoop++)
    {
        RES_SET_BIT(pstSection->puiBitFld[pstSection->uiMaxIdx - 1], ulLoop);
    }
    RES_CLR_BIT(pstSection->puiBitFld[0], 0);
    RES_CLR_BIT(pstSection->puiBitFld[0], 1);
    gstResField.uiCurIdx  += pstSection->uiMaxIdx;
    RES_MUTEX_INIT(&pstSection->rwLock);

    /* ��ʼ��section/pool */
    gpstResSectionAssigner = &gpstResAddrPool[RES_SEC_POOL];
    gpstResSectionAssigner->uiTotal    = uiTotalSecionNum;
    gpstResSectionAssigner->uiSecNum   = 1;
    gpstResSectionAssigner->pstSection = pstSection;
    gpstResSectionAssigner->pstTree    = NULL;
    RES_MUTEX_INIT(&gpstResSectionAssigner->rwLock);
    avl_insert(&(gpstResSectionAssigner->pstTree), &(pstSection->stNode), 0, Res_CompKey);
    lstInit(&(gpstResSectionAssigner->pstList));
    lstAdd((LIST *)&(gpstResSectionAssigner->pstList), &(pstSection->stList));

    /* ��ʼ��pool/section */
    pstSection = &gpstResAddrSection[RES_POOL_SECTION];
    pstSection->uiKey     = 0;
    pstSection->uiAlloced = 0;
    pstSection->uiMaxNum  = uiTotalPoolNum;
    pstSection->uiCurIdx  = 0;
    pstSection->uiMaxIdx  = ((uiTotalPoolNum + RES_PART_LEN_MASK) >> RES_PART_LEN_BIT);
    pstSection->uiStart   = 0;
    pstSection->puiBitFld = &gstResField.puiField[gstResField.uiCurIdx];
    for (ulLoop = 0; ulLoop < pstSection->uiMaxIdx - 1; ulLoop++)
    {
        pstSection->puiBitFld[ulLoop] = (uint32_t)(-1);
    }
    for (ulLoop = 0; ulLoop < pstSection->uiMaxNum - ((pstSection->uiMaxIdx - 1)<<RES_PART_LEN_BIT); ulLoop++)
    {
        RES_SET_BIT(pstSection->puiBitFld[pstSection->uiMaxIdx - 1], ulLoop);
    }
    RES_CLR_BIT(pstSection->puiBitFld[0], 0);
    RES_CLR_BIT(pstSection->puiBitFld[0], 1);
    gstResField.uiCurIdx  += pstSection->uiMaxIdx;
    RES_MUTEX_INIT(&pstSection->rwLock);

    /* ��ʼ��pool/pool */
    gpstResPoolAssigner = &gpstResAddrPool[RES_POOL_POOL];
    gpstResPoolAssigner->uiTotal    = uiTotalPoolNum;
    gpstResPoolAssigner->uiSecNum   = 1;
    gpstResPoolAssigner->pstSection = pstSection;
    gpstResPoolAssigner->pstTree    = NULL;
    RES_MUTEX_INIT(&gpstResPoolAssigner->rwLock);
    avl_insert(&(gpstResPoolAssigner->pstTree), &(pstSection->stNode), (void *)0, Res_CompKey);
    lstInit(&(gpstResPoolAssigner->pstList));
    lstAdd((LIST *)&(gpstResPoolAssigner->pstList), &(pstSection->stList));

    gucResInitFlag = G_TRUE;
    RES_LOG("res init success!.\r\n");

    return G_TRUE;
}

/*-----------------------------------------------------------------------------
  ��������    : Res_DeInit
  ����        : ȥ��ʼ��field��
  �������    :
  �������    : ��
  ����ֵ      : ��
  ��������˵��:
  ����ʹ��ʾ��:
 -----------------------------------------------------------------------------*/
void Res_DeInit()
{
    if (gstResField.puiField) {
        RES_FREE(GLB_RES_FIELD_SYMBOL, gstResField.puiField);
    }

    if (gpstResAddrPool) {
        RES_FREE(GLB_RES_POOL_SYMBOL, gpstResAddrPool);
        gpstResAddrPool = NULL;
    }

    if (gpstResAddrSection) {
        RES_FREE(GLB_RES_SECTION_SYMBOL, gpstResAddrSection);
        gpstResAddrSection = NULL;
    }
}

/*-----------------------------------------------------------------------------
 ��������    : Res_TakePool
 ����        : �Ƿ���Դģ���Ѿ���ʼ��
 �������    : ��
 �������    : ��
 ����ֵ      : true��false
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint8_t Res_IsInit()
{
    return gucResInitFlag;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_TakePool
 ����        : ������Դ��
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ�صĵ�ַ
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
ST_RES_POOL *Res_TakePool()
{
    uint32_t uiKey;
    uint32_t uiResNo;

    if (!Res_Alloc(gpstResPoolAssigner->uiIndex, &uiKey, &uiResNo, EN_RES_ALLOC_MODE_OC))
    {
        return &gpstResAddrPool[uiResNo];
    }

    return NULL;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_GivePool
 ����        : �ͷ���Դ��
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ�صĵ�ַ
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_GivePool(ST_RES_POOL *pstPool)
{
    uint32_t uiKey = 0;
    uint32_t uiResNo;

    uiResNo = pstPool - gpstResAddrPool;
    Res_Free(gpstResPoolAssigner->uiIndex, uiKey, uiResNo);
}

/*-----------------------------------------------------------------------------
 ��������    : Res_TakeSection
 ����        : ����section
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ�صĵ�ַ
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
ST_RES_SECTION *Res_TakeSection(uint32_t uiFieldNum)
{
    uint32_t uiKey;
    uint32_t uiResNo;
    uint32_t *puiBitFld;
    ST_RES_SECTION *pstSection;

    if (Res_Alloc(gpstResSectionAssigner->uiIndex, &uiKey, &uiResNo, EN_RES_ALLOC_MODE_OC) == G_FAILURE)
    {
        return NULL;
    }

    RES_MUTEX_LOCK(&gstResField.rwLock);
    if (gstResField.uiCurIdx + uiFieldNum >= gstResField.uiMaxIdx)
    {
        RES_MUTEX_UNLOCK(&gstResField.rwLock);
        return NULL;
    }
    puiBitFld = &gstResField.puiField[gstResField.uiCurIdx];
    gstResField.uiCurIdx  += uiFieldNum;

    pstSection = &gpstResAddrSection[uiResNo];
    pstSection->puiBitFld = puiBitFld;

    RES_MUTEX_UNLOCK(&gstResField.rwLock);

    return pstSection;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_GiveSection
 ����        : �ͷ�section
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ�صĵ�ַ
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_GiveSection(ST_RES_SECTION *pstSection)
{
    uint32_t uiKey = 0;
    uint32_t uiResNo;

    uiResNo = pstSection - gpstResAddrSection;
    Res_Free(gpstResSectionAssigner->uiIndex, uiKey, uiResNo);
}

/*-----------------------------------------------------------------------------
  ��������    : Res_CompKey
  ����        : filter entry �ȽϺ��������ڶ���������
  �������    : pNode: �������ڵ�
                uiKey:keyֵ
  �������    : ��
  ����ֵ      : ��ȷ���0��key���ڽڵ㣬����-1��С�ڽڵ㣬����1
  ��������˵��: ������������������
  ����ʹ��ʾ��: Cache�ڵ����������������ֽڵ����Ϣ��һ����uiKey������ȷ���Ŀ�����
                ��һ����uiInfo��������hash��ͻ������£�ȷ���ҵ���˭������������
                uiInfo�Ƚ�
 -----------------------------------------------------------------------------*/
int Res_CompKey(AVL_NODE *pNode, void *pValue)
{
    ST_RES_SECTION  *pstNode  = (ST_RES_SECTION *)pNode;
    uint32_t uiKey = (uint64_t)pValue;

    if (pstNode->uiKey < uiKey)
    {
        return -1;
    }
    else if (pstNode->uiKey > uiKey)
    {
        return 1;
    }

    return 0;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_AddSection
 ����        : ���������������Դ
 �������    : ��
 �������    : ��
 ����ֵ      : G_SUCCESS G_FAILURE
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_AddSection(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiFirst, uint32_t uiMaxNum)
{
    ST_RES_SECTION *pstSec, *pstOld;
    ST_RES_POOL    *pstPool;
    uint32_t ulMaxIdx;
    uint32_t uiLoop;
    uint32_t uiStart;
    uint32_t uiNum;
    uint32_t uiEnd;
    uint32_t uiHoleStart, uiHoleEnd;
    uint32_t uiDiff;
    uint64_t tmp;
    uint8_t  ucHole = G_FALSE;

    pstPool = Res_IndexToPool(uiPoolNo);

    tmp = uiKey;
    RES_MUTEX_READ_LOCK(&pstPool->rwLock);
    pstOld = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);
    if (pstOld)
    {
        uiHoleStart = 0;
        uiHoleEnd   = 0;
        if (pstOld->uiStart < uiFirst)
        {
            uiStart = pstOld->uiStart;
        }
        else
        {
            uiStart = uiFirst;
        }

        if (pstOld->uiStart + pstOld->uiMaxNum < uiFirst + uiMaxNum)
        {
            uiEnd = uiFirst + uiMaxNum;
        }
        else
        {
            uiEnd = pstOld->uiStart + pstOld->uiMaxNum;
        }

        uiNum = uiEnd - uiStart;

        if (pstOld->uiStart + pstOld->uiMaxNum < uiFirst)
        {
            uiHoleStart = pstOld->uiStart + pstOld->uiMaxNum;
            uiHoleEnd   = uiFirst - 1;
        }
        else if (pstOld->uiStart > uiFirst + uiMaxNum)
        {
            uiHoleStart = uiFirst + uiMaxNum;
            uiHoleEnd   = pstOld->uiStart - 1;
        }

        if (uiHoleEnd > uiHoleStart)
        {
            ucHole = G_TRUE;
        }
    }
    else
    {
        uiStart = uiFirst;
        uiNum   = uiMaxNum;
        uiEnd = uiHoleStart = uiHoleEnd = 0;
    }

    ulMaxIdx = (uiNum >> RES_PART_LEN_BIT) + ((uiNum & RES_PART_LEN_MASK) ? 1 : 0);

    pstSec = Res_TakeSection(ulMaxIdx);
    if (pstSec == NULL)
    {
        return G_FAILURE;
    }

    pstSec->uiKey      = uiKey;
    pstSec->uiMaxNum   = uiNum;
    pstSec->uiStart    = uiStart;
    pstSec->uiAlloced  = 0;
    pstSec->uiCurIdx   = 0;
    pstSec->uiCurBit   = 0;
    pstSec->uiMaxIdx   = ulMaxIdx;
    RES_MUTEX_INIT(&pstSec->rwLock);

    for (uiLoop = 0; uiLoop < ulMaxIdx - 1; uiLoop++)
    {
        pstSec->puiBitFld[uiLoop] = (uint32_t)(-1);
    }
    for (uiLoop = 0; uiLoop < uiNum - ((ulMaxIdx - 1)<<RES_PART_LEN_BIT); uiLoop++)
    {
        RES_SET_BIT(pstSec->puiBitFld[ulMaxIdx - 1], uiLoop);
    }

    /* ����ж�����Ҫ�ѿճ����Ĳ�����0�������޸����ɷ������� */
    if (ucHole)
    {
        pstSec->uiMaxNum -= (uiHoleEnd - uiHoleStart + 1);
        for (uiLoop = uiHoleStart - uiStart; uiLoop <= uiHoleEnd - uiStart; uiLoop++)
        {
            RES_CLR_BIT(pstSec->puiBitFld[uiLoop >> RES_PART_LEN_BIT], (uiLoop & RES_PART_LEN_MASK));
        }
    }

    /* ����Ǻϲ�����Ҫ��ԭ���Ѿ�����ı�������� */
    if (pstOld)
    {
        uiDiff = pstOld->uiStart - uiStart;
        for (uiLoop = 0; uiLoop < pstOld->uiMaxNum; uiLoop++)
        {
            if (!RES_TST_BIT(pstOld->puiBitFld[uiLoop >> RES_PART_LEN_BIT], (uiLoop & RES_PART_LEN_MASK)))
            {
                RES_CLR_BIT(pstSec->puiBitFld[(uiLoop + uiDiff) >> RES_PART_LEN_BIT], ((uiLoop + uiDiff) & RES_PART_LEN_MASK));
            }
        }

        /* ɾ���ɵĽڵ� */
        Res_DelSection(pstPool->uiIndex, uiKey);
    }

    RES_MUTEX_LOCK(&pstPool->rwLock);
    tmp = uiKey;
    if (avl_insert(&(pstPool->pstTree), &(pstSec->stNode), (void *)tmp, Res_CompKey) == ERROR)
    {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }
    lstAdd((LIST *)&(pstPool->pstList), &(pstSec->stList));
    if (pstPool->pstSection == NULL)
    {
        pstPool->pstSection = pstSec;
    }
    pstPool->uiTotal += pstSec->uiMaxNum;
    pstPool->uiSecNum++;
    RES_MUTEX_UNLOCK(&pstPool->rwLock);

    return G_SUCCESS;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_DelSection
 ����        : ɾ�����������Դ
 �������    : ��
 �������    : ��
 ����ֵ      : G_SUCCESS G_FAILURE
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_DelSection(uint32_t uiPoolNo, uint32_t uiKey)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint64_t       tmp;

    pstPool = Res_IndexToPool(uiPoolNo);

    tmp = uiKey;

    RES_MUTEX_LOCK(&pstPool->rwLock);
    pstSec = (ST_RES_SECTION *)avl_delete(&(pstPool->pstTree), (void *)tmp, Res_CompKey);
    if (NULL == pstSec) {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }

    pstPool->uiTotal -= pstSec->uiMaxNum;
    pstPool->uiSecNum--;
    if (pstPool->pstSection == pstSec)
    {
        pstPool->pstSection = (ST_RES_SECTION *)(pstSec->stNode.right);
        if (pstPool->pstSection == pstSec)
        {
            pstPool->pstSection = NULL;
        }
    }
    lstDelete((LIST *)&(pstPool->pstList), &(pstSec->stList));
    RES_MUTEX_UNLOCK(&pstPool->rwLock);

    Res_GiveSection(pstSec);

    return G_SUCCESS;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_CreatePool
 ����        : ������Դ��
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ�صĵ�ַ
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
int32_t Res_CreatePool()
{
    ST_RES_POOL *pstPool;
    uint32_t uiKey;
    uint32_t uiResNo;

    if (G_SUCCESS == Res_Alloc(gpstResPoolAssigner->uiIndex, &uiKey, &uiResNo,
        EN_RES_ALLOC_MODE_OC))
    {
        pstPool = &gpstResAddrPool[uiResNo];

        pstPool->uiTotal = 0;
        pstPool->pstSection = NULL;
        pstPool->uiSecNum = 0;
        pstPool->uiAlloced = 0;
        lstInit(&pstPool->pstList);
        pstPool->pstTree = NULL;

        RES_MUTEX_INIT(&pstPool->rwLock);

        return pstPool->uiIndex;
    }

    return -1;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_DestroyPool
 ����        : ������Դ��
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ�صĵ�ַ
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_DestroyPool(uint32_t uiPoolNo)
{
    ST_RES_POOL *pstPool;
    ST_RES_SECTION *pstSec;
    NODE *node, *next_node;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_LOCK(&pstPool->rwLock);
    node = lstFirst(&pstPool->pstList);
    while (node)
    {
        next_node = lstNext(node);

        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        pstSec = (ST_RES_SECTION *)container_of(node, ST_RES_SECTION, stList);
        Res_DelSection(pstPool->uiIndex, pstSec->uiKey);

        node = next_node;
        RES_MUTEX_LOCK(&pstPool->rwLock);
    }
    RES_MUTEX_UNLOCK(&pstPool->rwLock);

    Res_GivePool(pstPool);
}

/*-----------------------------------------------------------------------------
 ��������    : Res_Alloc
 ����        : ��Դ����
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_Alloc(uint32_t uiPoolNo, uint32_t *puiKey, uint32_t *puiResNo, EN_RES_ALLOC_MODE enMode)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    NODE           *pstLstNode;
    uint32_t uiLoop;
    uint32_t uiBit;
    uint32_t uiTriedTimes = 0;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_LOCK(&pstPool->rwLock);
    pstSec = pstPool->pstSection;
    if (pstSec == NULL)
    {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }
    do
    {
        /* �Ȱ��ճ����� */
        for (uiLoop = pstSec->uiCurIdx; uiLoop < pstSec->uiMaxIdx; uiLoop++)
        {
            if (!pstSec->puiBitFld[uiLoop])
            {
                pstSec->uiCurBit = 0;
                continue;
            }
            else
            {
                break;
            }
        }

        if (uiLoop >= pstSec->uiMaxIdx)
        {
            /* ��section�ľ����鿴��һ�� */
            pstLstNode = lstNext(&(pstSec->stList));
            if (pstLstNode == NULL)
            {
                pstLstNode = lstFirst(&(pstPool->pstList));
            }
            pstSec = (ST_RES_SECTION *)((uint8_t *)pstLstNode - sizeof(AVL_NODE));
            if (pstSec != NULL)
            {
                pstPool->pstSection = pstSec;
            }
            pstSec->uiCurIdx = 0;
            pstSec->uiCurBit = 0;

            /* ÿ��һ��section�����û����Դ�ɷ֣����ߵ�����һ�Σ�����ߵ�����Ĵ�������section����˵��������һ�飬�����˳��� */
            uiTriedTimes++;
            if (uiTriedTimes > pstPool->uiSecNum)
            {
                break;
            }
            else
            {
                continue;
            }
        }
        else
        {
            /* �ҵ��ɷ����section������һ�� */
            for (uiBit = pstSec->uiCurBit; uiBit < RES_PART_LEN; uiBit++)
            {
                if (RES_TST_BIT(pstSec->puiBitFld[uiLoop], uiBit))
                {
                    break;
                }
            }
            if ((uiBit >= RES_PART_LEN)||(RES_COMBINE(uiLoop, uiBit) >= pstSec->uiMaxNum))
            {
                pstSec->uiCurBit = 0;
                pstSec->uiCurIdx++;
                continue;
            }

            if (enMode == EN_RES_ALLOC_MODE_OC)
            {
                RES_CLR_BIT(pstSec->puiBitFld[uiLoop], uiBit);
                pstPool->uiAlloced++;
                pstSec->uiAlloced++;
            }
            pstSec->uiCurIdx = uiLoop;
            pstSec->uiCurBit = uiBit + 1;
            RES_MUTEX_UNLOCK(&pstPool->rwLock);

            *puiResNo = (uiLoop << RES_PART_LEN_BIT) + uiBit + pstSec->uiStart;
            *puiKey   = pstSec->uiKey;

            return G_SUCCESS;
        }
    }while (1);
    RES_MUTEX_UNLOCK(&pstPool->rwLock);

    return G_FAILURE;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_Free
 ����        : ��Դ�ͷ�
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_Free(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiRes)
{
    ST_RES_POOL    *pstPool;
    ST_RES_SECTION *pstSec;
    uint32_t uiLocal;
    uint64_t tmp;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_LOCK(&pstPool->rwLock);
    tmp = uiKey;
    pstSec = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    if (!pstSec)
    {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return;
    }

    /* �ͷŵ���Դ�����ڷ�Χ�� */
    uiLocal = uiRes - pstSec->uiStart;
    if (uiLocal >= pstSec->uiMaxNum)
    {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return;
    }

    if (!RES_TST_BIT(pstSec->puiBitFld[(uiLocal >> RES_PART_LEN_BIT)], (uiLocal & RES_PART_LEN_MASK)))
    {
        RES_SET_BIT(pstSec->puiBitFld[(uiLocal >> RES_PART_LEN_BIT)], (uiLocal & RES_PART_LEN_MASK));
        --pstSec->uiAlloced;
        --pstPool->uiAlloced;
    }
    RES_MUTEX_UNLOCK(&pstPool->rwLock);
}

/*-----------------------------------------------------------------------------
 ��������    : Res_AllocTarget
 ����        : ����ָ������Դ
 �������    : ��
 �������    : ��
 ����ֵ      : ���δ��������Ϊ����״̬������G_SUCCESS������Ѿ������򷵻�G_FAILURE
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_AllocTarget(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiResNo)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint32_t uiLoop;
    uint32_t uiBit;
    uint64_t ulRet;
    uint64_t tmp;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_LOCK(&pstPool->rwLock);
    tmp = uiKey;
    pstSec = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    if (NULL == pstSec) {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }
    uiResNo -= pstSec->uiStart;
    if (uiResNo >= pstSec->uiMaxNum)
    {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }
    uiLoop = (uiResNo >> RES_PART_LEN_BIT);
    uiBit  = (uiResNo & RES_PART_LEN_MASK);
    if (RES_TST_BIT(pstSec->puiBitFld[uiLoop], uiBit))
    {
        RES_CLR_BIT(pstSec->puiBitFld[uiLoop], uiBit);
        pstPool->uiAlloced++;
        pstSec->uiAlloced++;

        ulRet = G_SUCCESS;
    }
    else
    {
        ulRet = G_FAILURE;
    }
    RES_MUTEX_UNLOCK(&pstPool->rwLock);

    return ulRet;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_IsAlloced
 ����        : ָ������Դ�Ƿ��ѷ���
 �������    : ��
 �������    : ��
 ����ֵ      : ���δ�����򷵻�G_FALSE������Ѿ������򷵻�G_TRUE
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_IsAlloced(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiResNo)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint32_t uiLoop;
    uint32_t uiBit;
    uint32_t uiLocal;
    uint64_t ulRet;
    uint64_t tmp;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_READ_LOCK(&pstPool->rwLock);
    tmp = uiKey;
    pstSec = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    uiLocal = uiResNo - pstSec->uiStart;
    if (uiLocal >= pstSec->uiMaxNum)
    {
        RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);
        return G_FALSE;
    }
    uiLoop = (uiLocal >> RES_PART_LEN_BIT);
    uiBit  = (uiLocal & RES_PART_LEN_MASK);
    if (RES_TST_BIT(pstSec->puiBitFld[uiLoop], uiBit))
    {
        /* ��Ϊ0��ζ��δ���� */
        ulRet = G_FALSE;
    }
    else
    {
        /* ����0���Ѿ������� */
        ulRet = G_TRUE;
    }
    RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);

    return ulRet;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_GetNextAvailable
 ����        : ��ȡ��һ���Ѿ��������Դ
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_GetNextAvailable(uint32_t uiPoolNo, uint32_t uiCurKey, uint32_t uiCurResNo,
    uint32_t *puiKey, uint32_t *puiResNo)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    NODE           *pstLstNode;
    uint32_t uiLoop;
    uint32_t uiBit;
    uint32_t uiIdx, uiBitTmp;
    uint64_t tmp;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_READ_LOCK(&pstPool->rwLock);
    tmp = uiCurKey;
    pstSec = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    if (pstSec == NULL)
    {
        RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }
    uiCurResNo -= pstSec->uiStart;
    uiIdx = ((uiCurResNo + 1) >> RES_PART_LEN_BIT);
    uiBitTmp = ((uiCurResNo + 1) & RES_PART_LEN_MASK);
    do
    {
        /* �Ȱ��ճ����� */
        for (uiLoop = uiIdx; uiLoop < pstSec->uiMaxIdx; uiLoop++)
        {
            if (pstSec->puiBitFld[uiLoop] == (uint32_t)(-1))
            {
                continue;
            }
            else
            {
                break;
            }
        }

        if (uiLoop >= pstSec->uiMaxIdx)
        {
            /* ��section�ľ����鿴��һ�� */
            pstLstNode = lstNext(&(pstSec->stList));
            if (pstLstNode == NULL)
            {
                // ����һȦ��û�ҵ����˳�
                RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);
                return G_FAILURE;
            }
            pstSec = (ST_RES_SECTION *)((uint8_t *)pstLstNode - sizeof(AVL_NODE));
            uiIdx = 0;
            uiBitTmp = 0;

            continue;
        }
        else
        {
            /* �ҵ��ɷ����section������һ�� */
            for (uiBit = uiBitTmp; uiBit < RES_PART_LEN; uiBit++)
            {
                if (!RES_TST_BIT(pstSec->puiBitFld[uiLoop], uiBit))
                {
                    break;
                }
            }
            if ((uiBit >= RES_PART_LEN)||(RES_COMBINE(uiLoop, uiBit) >= pstSec->uiMaxNum))
            {
                uiIdx++;
                uiBitTmp = 0;
                continue;
            }

            *puiResNo = (uiLoop << RES_PART_LEN_BIT) + uiBit + pstSec->uiStart;
            *puiKey   = pstSec->uiKey;
            RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);

            return G_SUCCESS;
        }
    }while ((uiIdx < pstSec->uiMaxIdx));

    RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);
    return G_FAILURE;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_GetAvailableInBand
 ����        : ��section������£���һ���б���Ѱ���Ѿ�����ı������0�ͽ�����
 �������    : uiPoolNo    ��Դ��
               uiStart     ��Դ��ʼ��ţ��ӱ��ʼ��������һ��
               uiEnd       ��Դ������ţ���������һ��
 �������    : ��
 ����ֵ      : �ҵ�������һ���ţ����򷵻�-1
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
int32_t Res_GetAvailableInBand(uint32_t uiPoolNo, uint32_t uiStart, uint32_t uiEnd)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint32_t uiLoop;
    uint32_t uiBit;
    uint32_t uiIdx;

    pstPool = Res_IndexToPool(uiPoolNo);

    /* If no available, return */
    if (!pstPool->uiAlloced) {
        return -1;
    }

    /* Support only one section */
    pstSec = pstPool->pstSection;

    /* Get next available */
    uiStart -= pstSec->uiStart;
    uiIdx = ((uiStart) >> RES_PART_LEN_BIT);
    uiBit = ((uiStart) & RES_PART_LEN_MASK);

    /* �Ȱ��ճ����� */
    for (uiLoop = uiIdx; uiLoop < pstSec->uiMaxIdx; uiLoop++)
    {

        if (pstSec->puiBitFld[uiLoop] == (uint32_t)(-1))
        {
            continue;
        }

        if (uiLoop >= pstSec->uiMaxIdx)
        {
            /* From header, search again */
            uiIdx = 0;
            uiBit = 0;

            return -1;
        }
        else
        {
            /* If same word, from last pos. Or from 0 */
            if (uiLoop != uiIdx) {
                uiBit = 0;
            }
            else {
                /* Do nothing */
            }

            /* �ҵ��ɷ����section������һ�� */
            for (; uiBit < RES_PART_LEN; uiBit++)
            {
                if (!RES_TST_BIT(pstSec->puiBitFld[uiLoop], uiBit))
                {
                    break;
                }
            }
            if (uiBit >= RES_PART_LEN)
            {
                uiBit = 0;
                continue;
            }

            if ((RES_COMBINE(uiLoop, uiBit) >= pstSec->uiMaxNum)
              ||(RES_COMBINE(uiLoop, uiBit) >= uiEnd))
            {
                return -1;
            }

            return (uiLoop << RES_PART_LEN_BIT) + uiBit + pstSec->uiStart;
        }
    }

    return -1;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_GetAvailAndFreeInBand
 ����        : ��section������£���һ���б���Ѱ���Ѿ�����ı����ͷŲ����أ�����0�ͽ�����
 �������    : uiPoolNo    ��Դ��
               uiStart     ��Դ��ʼ��ţ��ӱ��ʼ��������һ��
               uiEnd       ��Դ������ţ���������һ��
 �������    : ��
 ����ֵ      : �ҵ�������һ���ţ����򷵻�-1
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
int32_t Res_GetAvailAndFreeInBand(uint32_t uiPoolNo, uint32_t uiStart, uint32_t uiEnd)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint32_t uiLoop;
    uint32_t uiBit;
    uint32_t uiIdx;

    pstPool = Res_IndexToPool(uiPoolNo);

    /* If no available, return */
    if (!pstPool->uiAlloced) {
        return -1;
    }

    /* Support only one section */
    pstSec = pstPool->pstSection;

    /* Get next available */
    uiStart -= pstSec->uiStart;
    uiIdx = ((uiStart) >> RES_PART_LEN_BIT);
    uiBit = ((uiStart) & RES_PART_LEN_MASK);

    /* �Ȱ��ճ����� */
    for (uiLoop = uiIdx; uiLoop < pstSec->uiMaxIdx; uiLoop++)
    {

        if (pstSec->puiBitFld[uiLoop] == (uint32_t)(-1))
        {
            continue;
        }

        if (uiLoop >= pstSec->uiMaxIdx)
        {
            /* From header, search again */
            uiIdx = 0;
            uiBit = 0;

            return -1;
        }
        else
        {
            /* If same word, from last pos. Or from 0 */
            if (uiLoop != uiIdx) {
                uiBit = 0;
            }
            else {
                /* Do nothing */
            }

            /* �ҵ��ɷ����section������һ�� */
            for (; uiBit < RES_PART_LEN; uiBit++)
            {
                if (!RES_TST_BIT(pstSec->puiBitFld[uiLoop], uiBit))
                {
                    break;
                }
            }
            if (uiBit >= RES_PART_LEN)
            {
                uiBit = 0;
                continue;
            }

            if ((RES_COMBINE(uiLoop, uiBit) >= pstSec->uiMaxNum)
              ||(RES_COMBINE(uiLoop, uiBit) >= uiEnd))
            {
                return -1;
            }

            /* Free */
            RES_SET_BIT(pstSec->puiBitFld[uiLoop], uiBit);
            --pstSec->uiAlloced;
            --pstPool->uiAlloced;

            return (uiLoop << RES_PART_LEN_BIT) + uiBit + pstSec->uiStart;
        }
    }

    return -1;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_FreeAll
 ����        : ��Դ�ͷ�
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_FreeBatch(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiFrom, uint32_t uiNum)
{
    ST_RES_POOL    *pstPool;
    ST_RES_SECTION *pstSec;
    uint32_t       uiLoop, ulMaxIdx;
    uint64_t       tmp;

    pstPool = Res_IndexToPool(uiPoolNo);

    if (!uiNum)
    {
        return;
    }

    RES_MUTEX_LOCK(&pstPool->rwLock);
    tmp = uiKey;
    pstSec = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    if (pstSec)
    {
        pstPool->uiAlloced -= pstSec->uiAlloced;
        pstSec->uiAlloced  = 0;

        ulMaxIdx = (uiNum >> RES_PART_LEN_BIT) + ((uiNum & RES_PART_LEN_MASK) ? 1 : 0);

        for (uiLoop = 0; uiLoop < ulMaxIdx - 1; uiLoop++)
        {
            pstSec->puiBitFld[uiLoop] = (uint32_t)(-1);
        }
        for (uiLoop = 0; uiLoop < uiNum - ((ulMaxIdx - 1)<<RES_PART_LEN_BIT); uiLoop++)
        {
            RES_SET_BIT(pstSec->puiBitFld[ulMaxIdx - 1], uiLoop);
        }
    }
    RES_MUTEX_UNLOCK(&pstPool->rwLock);
}

/*-----------------------------------------------------------------------------
 ��������    : Res_GetAlloced
 ����        : ��ȡ�ѷ�����Դ��
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ��
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint32_t Res_GetAlloced(uint32_t uiPoolNo)
{
    ST_RES_POOL    *pstPool;

    pstPool = Res_IndexToPool(uiPoolNo);

    return pstPool->uiAlloced;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_GetTotal
 ����        : ��ȡ����Դ��
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ��
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint32_t Res_GetTotal(uint32_t uiPoolNo)
{
    ST_RES_POOL    *pstPool;

    pstPool = Res_IndexToPool(uiPoolNo);

    return pstPool->uiTotal;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_PoolGet
 ����        : Get pool info
 �������    : ��
 �������    : ��
 ����ֵ      : no
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_PoolGet(uint32_t uiPoolNo)
{
    ST_RES_POOL    *pstPool;
    ST_RES_SECTION *pstSec;
    NODE           *pstLstNode;

    pstPool = Res_IndexToPool(uiPoolNo);
    if (!pstPool)
    {
        return;
    }

    RES_LOG("\r\nPool %d info: \r\n", uiPoolNo);
    RES_LOG("  uiSecNum   %d: \r\n", pstPool->uiSecNum);
    RES_LOG("  uiTotal    %d: \r\n", pstPool->uiTotal);
    RES_LOG("  uiIndex    %d: \r\n", pstPool->uiIndex);
    RES_LOG("  uiAlloced  %d: \r\n", pstPool->uiAlloced);
    RES_LOG("  pstSection %p: \r\n", pstPool->pstSection);

    pstSec = pstPool->pstSection;

    do {
        Res_SectionShow(pstSec);

        /* ��section�ľ����鿴��һ�� */
        pstLstNode = lstNext(&(pstSec->stList));
        if (pstLstNode == NULL)
        {
            pstLstNode = lstFirst(&(pstPool->pstList));
        }
        pstSec = (ST_RES_SECTION *)((uint8_t *)pstLstNode - sizeof(AVL_NODE));
    }while(pstSec != pstPool->pstSection);
}

/*-----------------------------------------------------------------------------
 ��������    : Res_PoolShow
 ����        : Display pool info
 �������    : ��
 �������    : ��
 ����ֵ      : no
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_PoolShow(uint32_t uiPoolNo)
{
    ST_RES_POOL    *pstPool;
    ST_RES_SECTION *pstSec;
    NODE           *pstLstNode;

    pstPool = Res_IndexToPool(uiPoolNo);
    if (!pstPool)
    {
        return;
    }

    RES_LOG("\r\nPool %d info: \r\n", uiPoolNo);
    RES_LOG("  uiSecNum   %d: \r\n", pstPool->uiSecNum);
    RES_LOG("  uiTotal    %d: \r\n", pstPool->uiTotal);
    RES_LOG("  uiIndex    %d: \r\n", pstPool->uiIndex);
    RES_LOG("  uiAlloced  %d: \r\n", pstPool->uiAlloced);
    RES_LOG("  pstSection %p: \r\n", pstPool->pstSection);

    pstSec = pstPool->pstSection;

    do {
        Res_SectionShow(pstSec);

        /* ��section�ľ����鿴��һ�� */
        pstLstNode = lstNext(&(pstSec->stList));
        if (pstLstNode == NULL)
        {
            pstLstNode = lstFirst(&(pstPool->pstList));
        }
        pstSec = (ST_RES_SECTION *)((uint8_t *)pstLstNode - sizeof(AVL_NODE));
    }while(pstSec != pstPool->pstSection);
}

/*-----------------------------------------------------------------------------
 ��������    : Res_SectionShow
 ����        : Display section info
 �������    : ��
 �������    : ��
 ����ֵ      : no
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_SectionShow(ST_RES_SECTION *pstSec)
{
    if (!pstSec)
    {
        return;
    }

    RES_LOG("Section %p(%ld) info: \r\n", pstSec, pstSec - gpstResAddrSection);
    RES_LOG("  uiKey      %08x: \r\n", pstSec->uiKey);
    RES_LOG("  uiMaxNum   %d: \r\n", pstSec->uiMaxNum);
    RES_LOG("  uiAlloced  %d: \r\n", pstSec->uiAlloced);
    RES_LOG("  uiCurIdx   %d: \r\n", pstSec->uiCurIdx);
    RES_LOG("  uiMaxIdx   %d: \r\n", pstSec->uiMaxIdx);
    RES_LOG("  uiStart    %d: \r\n", pstSec->uiStart);
    RES_LOG("  puiBitFld  %p: \r\n", pstSec->puiBitFld);
    RES_LOG("    Fld0     %08x: \r\n", pstSec->puiBitFld[0]);
    RES_LOG("    Fld1     %08x: \r\n", pstSec->puiBitFld[1]);
}

/*-----------------------------------------------------------------------------
 ��������    : Res_UnitTest
 ����        : Unit test
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_UnitTest(uint32_t uiTestID)
{
    switch (uiTestID)
    {
        case 0:
            printf("Test %02d: test init input parameter.\r\n", uiTestID);
            Res_Init(0, 0, 0);
            Res_Init(1, 1, 1);
            Res_Init(10, 10, 1000);
            Res_PoolShow(0);
            Res_PoolShow(1);
            break;
        case 1:
            {
                int32_t                iPoolIdx;

                printf("Test %02d: test create pool.\r\n", uiTestID);
                Res_Init(10, 10, 1000);
                Res_PoolShow(0);
                Res_PoolShow(1);
                iPoolIdx = Res_CreatePool();
                printf("iPoolIdx %d.\r\n", iPoolIdx);
            }
            break;
        case 2:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;

                printf("Test %02d: test create multi pool.\r\n", uiTestID);
                Res_Init(10, 10, 1000);

                for (uiLoop = 0; uiLoop < 14; uiLoop++)
                {
                    Res_PoolShow(0);
                    Res_PoolShow(1);
                    iPoolIdx = Res_CreatePool();
                    printf("\r\n iPoolIdx %d.\r\n", iPoolIdx);
                }
            }
            break;
        case 3:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;

                printf("Test %02d: test create multi pool and destroy multi pool.\r\n", uiTestID);
                Res_Init(100, 100, 1000);
                Res_PoolShow(0);
                Res_PoolShow(1);

                for (uiLoop = 0; uiLoop < 103; uiLoop++)
                {
                    iPoolIdx = Res_CreatePool();
                    printf("\r\n iPoolIdx %d.\r\n", iPoolIdx);
                }
                Res_PoolShow(0);
                Res_PoolShow(1);

                for (uiLoop = 2; uiLoop < 102; uiLoop++)
                {
                    Res_DestroyPool(uiLoop);
                    printf("\r\n destroy %d.\r\n", uiLoop);
                }
                Res_PoolShow(0);
                Res_PoolShow(1);
            }
            break;
        case 4:
            {
                int32_t                iPoolIdx;

                printf("Test %02d: test insert section.\r\n", uiTestID);
                Res_Init(3, 3, 1000);
                iPoolIdx = Res_CreatePool();
                Res_PoolShow(0);

                Res_AddSection(iPoolIdx, 0xc0a80010, 10240, 10);
                Res_AddSection(iPoolIdx, 0x08080801, 2000, 80);
                Res_AddSection(iPoolIdx, 0x08080901, 1900, 80);
                Res_AddSection(iPoolIdx, 0x08080a01, 1500, 80);

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 5:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test alloc resource from multi sections.\r\n", uiTestID);
                Res_Init(10, 10, 1000);
                iPoolIdx = Res_CreatePool();
                Res_PoolShow(0);

                Res_AddSection(iPoolIdx, 0xc0a80010, 10240, 10);
                Res_AddSection(iPoolIdx, 0x08080801, 2000, 80);

                for (uiLoop = 0; uiLoop < 100; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_Free(iPoolIdx, 0xc0a80010, 10241);
                Res_PoolShow(iPoolIdx);

                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 6:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test add same key resource.\r\n", uiTestID);
                Res_Init(10, 10, 400);
                iPoolIdx = Res_CreatePool();
                Res_PoolShow(0);

                Res_AddSection(iPoolIdx, 0xc0a80010, 10000, 10);
                Res_AddSection(iPoolIdx, 0xc0a80010, 2000, 8);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                printf("Before free.\r\n");
                Res_PoolShow(iPoolIdx);

                Res_Free(iPoolIdx, 0xc0a80010, 10001);
                printf("After free.\r\n");
                Res_PoolShow(iPoolIdx);

                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 7:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test add same key resource.\r\n", uiTestID);
                Res_Init(10, 10, 400);
                iPoolIdx = Res_CreatePool();
                Res_PoolShow(0);

                Res_AddSection(iPoolIdx, 0xc0a80010, 10000, 10);
                Res_AddSection(iPoolIdx, 0xc0a80010, 10004, 8);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                printf("Before free.\r\n");
                Res_PoolShow(iPoolIdx);

                Res_Free(iPoolIdx, 0xc0a80010, 10001);
                printf("After free.\r\n");
                Res_PoolShow(iPoolIdx);

                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 8:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test add same key resource.\r\n", uiTestID);
                Res_Init(10, 10, 400);
                iPoolIdx = Res_CreatePool();
                Res_PoolShow(0);

                Res_AddSection(iPoolIdx, 0xc0a80010, 10000, 10);
                Res_AddSection(iPoolIdx, 0xc0a80020, 20000, 8);
                Res_AddSection(iPoolIdx, 0xc0a80030, 20000, 80);
                Res_AddSection(iPoolIdx, 0xc0a80040, 20000, 8);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                printf("Before free.\r\n");
                Res_PoolShow(iPoolIdx);

                for (uiLoop = 0; uiLoop < 80; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_Free(iPoolIdx, 0xc0a80010, 10001);
                printf("After free.\r\n");
                Res_PoolShow(iPoolIdx);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 9:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test add same key resource.\r\n", uiTestID);
                Res_Init(10, 10, 400);
                iPoolIdx = Res_CreatePool();
                Res_PoolShow(0);

                Res_AddSection(iPoolIdx, 0xc0a80010, 0, 1);
                Res_AddSection(iPoolIdx, 0xc0a80020, 0, 1);
                Res_AddSection(iPoolIdx, 0xc0a80030, 0, 1);
                Res_AddSection(iPoolIdx, 0xc0a80040, 0, 1);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_LB);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_Free(iPoolIdx, 0xc0a80010, 0);

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 10:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test add same key resource.\r\n", uiTestID);
                Res_Init(10, 10, 400);
                iPoolIdx = Res_CreatePool();
                Res_PoolShow(0);

                Res_AddSection(iPoolIdx, 0xc0a80010, 10000, 10);
                Res_AddSection(iPoolIdx, 0xc0a80020, 20000, 8);
                Res_AddSection(iPoolIdx, 0xc0a80030, 20000, 80);
                Res_AddSection(iPoolIdx, 0xc0a80040, 20000, 8);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                printf("Before free.\r\n");
                Res_PoolShow(iPoolIdx);

                for (uiLoop = 0; uiLoop < 80; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    Res_Free(iPoolIdx, 0xc0a80010, 10000 + uiLoop);
                }
                printf("After free.\r\n");
                Res_PoolShow(iPoolIdx);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 11:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test alloc dnat resource.\r\n", uiTestID);
                iPoolIdx = Res_CreatePool();

                Res_AddSection(iPoolIdx, 0xc0a80010, 0, 1);
                Res_AddSection(iPoolIdx, 0xc0a80020, 0, 1);
                Res_AddSection(iPoolIdx, 0xc0a80030, 0, 1);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_LB);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 12:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test oc resource alloc failed.\r\n", uiTestID);
                iPoolIdx = Res_CreatePool();

                Res_AddSection(iPoolIdx, 0xc0a80010, 0, 1);
                Res_AddSection(iPoolIdx, 0xc0a80020, 0, 1);
                Res_AddSection(iPoolIdx, 0xc0a80030, 0, 1);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 13:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test alloc single dnat resource.\r\n", uiTestID);
                iPoolIdx = Res_CreatePool();

                Res_AddSection(iPoolIdx, 0xc0a80010, 0, 1);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_LB);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 14:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test alloc single oc resource failed.\r\n", uiTestID);
                iPoolIdx = Res_CreatePool();

                Res_AddSection(iPoolIdx, 0xc0a80010, 0, 1);

                for (uiLoop = 0; uiLoop < 20; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 15:
            {
                int32_t                iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test alloc multi dnat resource include multi idx.\r\n", uiTestID);
                iPoolIdx = Res_CreatePool();

                Res_AddSection(iPoolIdx, 0xc0a80010, 0, 40);
                Res_AddSection(iPoolIdx, 0xc0a80020, 0, 80);
                Res_AddSection(iPoolIdx, 0xc0a80030, 0, 40);

                for (uiLoop = 0; uiLoop < 170; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_LB);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_Free(iPoolIdx, 0xc0a80010, 10);
                printf("Free 10.\r\n");
                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);


                Res_Free(iPoolIdx, 0xc0a80010, 8);
                printf("Free 8.\r\n");
                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);


                Res_Free(iPoolIdx, 0xc0a80010, 0);
                printf("Free 0.\r\n");
                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);

                Res_PoolShow(iPoolIdx);
            }
            break;
        case 16:
            {
                int32_t                 iPoolIdx;
                uint32_t                uiLoop;
                uint32_t                uiKey;
                uint32_t                uiRes;
                uint64_t                ulRet;

                printf("Test %02d: test alloc multi oc resources include multi idx.\r\n", uiTestID);
                iPoolIdx = Res_CreatePool();

                Res_AddSection(iPoolIdx, 0xc0a80010, 0, 40);
                Res_AddSection(iPoolIdx, 0xc0a80020, 0, 80);
                Res_AddSection(iPoolIdx, 0xc0a80030, 0, 40);

                for (uiLoop = 0; uiLoop < 170; uiLoop++)
                {
                    ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                    if (ulRet != G_SUCCESS)
                    {
                        printf("Alloc failed.\r\n");
                    }
                    else
                        printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);
                }

                Res_Free(iPoolIdx, 0xc0a80010, 10);
                printf("Free 10.\r\n");
                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);


                Res_Free(iPoolIdx, 0xc0a80010, 8);
                printf("Free 8.\r\n");
                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);


                Res_Free(iPoolIdx, 0xc0a80010, 0);
                printf("Free 0.\r\n");
                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);


                Res_Free(iPoolIdx, 0xc0a80020, 40);
                printf("Free 8.\r\n");
                ulRet = Res_Alloc(iPoolIdx, &uiKey, &uiRes, EN_RES_ALLOC_MODE_OC);
                if (ulRet != G_SUCCESS)
                {
                    printf("Alloc failed.\r\n");
                }
                else
                    printf("Alloc key %x, res %d.\r\n", uiKey, uiRes);


                Res_PoolShow(iPoolIdx);
            }
            break;
        default:
            printf("Wrong test id %d.\r\n", uiTestID);
            break;
    }
}

/*-----------------------------------------------------------------------------
 ��������    : Res_Mul_Alloc
 ����        : �����Դ����
 �������    : ��
 �������    : ��
 ����ֵ      : ��Դ��ʼ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_Mul_Alloc(uint32_t uiPoolNo, uint32_t *puiKey, uint32_t *puiResNo,
    EN_RES_ALLOC_MODE enMode, uint32_t uiAllocNum)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    NODE           *pstLstNode;
    uint32_t uiLoop;
    uint32_t uiBit;
    uint32_t uiTriedTimes = 0;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_LOCK(&pstPool->rwLock);
    pstSec = pstPool->pstSection;
    if (pstSec == NULL) {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }
    do {
        /*
        * �Ȱ��ճ�����, ��Ҫ�ж�һ��sec���Ƿ����㹻��entry��������
        * �������Ҫ������entry���������Ҫ���Ǵ�ż������ʼ
        */
        if (uiAllocNum > 1) {
            for (uiLoop = pstSec->uiCurIdx; uiLoop < pstSec->uiMaxIdx;
                uiLoop++) {
                if ((!pstSec->puiBitFld[uiLoop]) || (((pstSec->uiCurBit + 1) &
                    0xFFFFFFFE) + uiAllocNum > RES_PART_LEN_MASK)) {
                    pstSec->uiCurBit = 0;
                    /* û���㹻��entry�鿴��һ������ */
                    continue;
                } else {
                    break;
                }
            }
        } else {
            for (uiLoop = pstSec->uiCurIdx; uiLoop < pstSec->uiMaxIdx;
                uiLoop++) {
                if ((!pstSec->puiBitFld[uiLoop]) ||
                    (pstSec->uiCurBit + uiAllocNum > RES_PART_LEN_MASK)) {
                    pstSec->uiCurBit = 0;
                    continue;
                } else {
                    break;
                }
            }
        }

        if (uiLoop >= pstSec->uiMaxIdx) {
            /* ��section�ľ����鿴��һ�� */
            pstLstNode = lstNext(&(pstSec->stList));
            if (pstLstNode == NULL) {
                pstLstNode = lstFirst(&(pstPool->pstList));
            }
            pstSec = (ST_RES_SECTION *)((uint8_t *)pstLstNode - sizeof(AVL_NODE));
            if (pstSec != NULL) {
                pstPool->pstSection = pstSec;
            }
            pstSec->uiCurIdx = 0;
            pstSec->uiCurBit = 0;

            /*
            * ÿ��һ��section�����û����Դ�ɷ֣����ߵ�����һ�Σ�
            * ����ߵ�����Ĵ�������section����˵��������һ�飬�����˳���
            */
            uiTriedTimes++;
            if (uiTriedTimes > pstPool->uiSecNum) {
                break;
            } else {
                continue;
            }
        }
        else {
            /*
            *  �ҵ��ɷ����section��������,�����Ҫ�����entry������1,
            *  ��Ҫ��ż��λ��ʼ����
            */
            // if (uiAllocNum > 1) {
            if (0) {
                for (uiBit = (pstSec->uiCurBit + 1) & 0xFFFFFFFE;
                    uiBit + uiAllocNum < RES_PART_LEN; uiBit += 2) {
                    if (RES_ALC_TST_MUL_BIT(pstSec->puiBitFld[uiLoop],
                        uiBit, RES_BIT_TO_MASK(uiAllocNum))) {
                        break;
                    }
                }
            } else {
                for (uiBit = pstSec->uiCurBit;
                    uiBit + uiAllocNum < RES_PART_LEN; uiBit++) {
                    if (RES_ALC_TST_MUL_BIT(pstSec->puiBitFld[uiLoop],
                        uiBit, RES_BIT_TO_MASK(uiAllocNum))) {
                        break;
                    }
                }
            }
            if ((uiBit + uiAllocNum >= RES_PART_LEN)||
                (RES_COMBINE(uiLoop, uiBit + uiAllocNum) >= pstSec->uiMaxNum)) {
                pstSec->uiCurBit = 0;
                pstSec->uiCurIdx++;
                continue;
            }

            if (enMode == EN_RES_ALLOC_MODE_OC) {
                RES_CLR_MUL_BIT(pstSec->puiBitFld[uiLoop],
                    uiBit, RES_BIT_TO_MASK(uiAllocNum));
                pstPool->uiAlloced += uiAllocNum;
                pstSec->uiAlloced += uiAllocNum;
            }
            pstSec->uiCurIdx = uiLoop;
            pstSec->uiCurBit = uiBit + uiAllocNum;
            RES_MUTEX_UNLOCK(&pstPool->rwLock);

            *puiResNo = (uiLoop << RES_PART_LEN_BIT) + uiBit + pstSec->uiStart;
            *puiKey   = pstSec->uiKey;

            return G_SUCCESS;
        }
    }while (1);
    RES_MUTEX_UNLOCK(&pstPool->rwLock);

    return G_FAILURE;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_Mul_Free
 ����        : �����Դ�ͷ�
 �������    : ��
 �������    : ��
 ����ֵ      : ��
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_Mul_Free(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiRes, uint32_t uiFreeNum)
{
    ST_RES_POOL    *pstPool;
    ST_RES_SECTION *pstSec;
    uint32_t uiLocal;
    uint64_t tmp;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_LOCK(&pstPool->rwLock);
    tmp = uiKey;
    pstSec = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    if (!pstSec)
    {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return;
    }

    /* �ͷŵ���Դ�����ڷ�Χ�� */
    uiLocal = uiRes - pstSec->uiStart;
    if ((uiLocal + uiFreeNum) >= pstSec->uiMaxNum)
    {
        RES_MUTEX_UNLOCK(&pstPool->rwLock);
        return;
    }

    if (!RES_CLR_TST_MUL_BIT(pstSec->puiBitFld[(uiLocal >> RES_PART_LEN_BIT)],
        (uiLocal & RES_PART_LEN_MASK), RES_BIT_TO_MASK(uiFreeNum)))
    {
        RES_CLR_MUL_BIT(pstSec->puiBitFld[(uiLocal >> RES_PART_LEN_BIT)],
            (uiLocal & RES_PART_LEN_MASK), RES_BIT_TO_MASK(uiFreeNum));
        pstSec->uiAlloced -= uiFreeNum;
        pstPool->uiAlloced -= uiFreeNum;
    }
    RES_MUTEX_UNLOCK(&pstPool->rwLock);
}

/*-----------------------------------------------------------------------------
 ��������    : Res_Mul_IsAlloced
 ����        : ָ���Ķ����Դ�Ƿ��ѷ���
 �������    : ��
 �������    : ��
 ����ֵ      : ���δ��������Ϊ����״̬������G_FALSE������Ѿ������򷵻�G_TRUE
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_Mul_IsAlloced(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiResNo, uint32_t uiEntryNum)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint32_t uiLoop;
    uint32_t uiBit;
    uint32_t uiLocal;
    uint64_t ulRet;
    uint64_t tmp;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_READ_LOCK(&pstPool->rwLock);
    tmp = uiKey;
    pstSec = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    uiLocal = uiResNo - pstSec->uiStart;
    if ((uiLocal + uiEntryNum) >= pstSec->uiMaxNum) {
        RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);
        return G_FALSE;
    }
    uiLoop = (uiLocal >> RES_PART_LEN_BIT);
    uiBit  = (uiLocal & RES_PART_LEN_MASK);
    if (RES_ALC_TST_MUL_BIT(pstSec->puiBitFld[uiLoop], uiBit,
        RES_BIT_TO_MASK(uiEntryNum))) {
        /* ��Ϊ0��ζ��δ���� */
        ulRet = G_FALSE;
    } else {
        /* ����0���Ѿ������� */
        ulRet = G_TRUE;
    }
    RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);

    return ulRet;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_Mul_AllocTarget
 ����        : ������ָ������Դ
 �������    : ��
 �������    : ��
 ����ֵ      : ���δ��������Ϊ����״̬������G_SUCCESS��
               ����Ѿ������򷵻�G_FAILURE
 ��������˵��: ��Ϊ��ָ��uiResNoȥ���䣬��������߲�ȥ�ж��Ƿ��Ǵ�ż����ʼ����
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_Mul_AllocTarget(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiResNo, uint32_t uiAllocNum)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint32_t uiLoop;
    uint32_t uiBit;
    uint64_t ulRet;
    uint64_t tmp;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_LOCK(&pstPool->rwLock);
    tmp = uiKey;
    pstSec = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    uiLoop = (uiResNo >> RES_PART_LEN_BIT);
    uiBit  = (uiResNo & RES_PART_LEN_MASK);
    if (RES_ALC_TST_MUL_BIT(pstSec->puiBitFld[uiLoop], uiBit,
        RES_BIT_TO_MASK(uiAllocNum)))
    {
        RES_CLR_MUL_BIT(pstSec->puiBitFld[uiLoop], uiBit,
            RES_BIT_TO_MASK(uiAllocNum));
        pstPool->uiAlloced += uiAllocNum;
        pstSec->uiAlloced += uiAllocNum;

        ulRet = G_SUCCESS;
    }
    else
    {
        ulRet = G_FAILURE;
    }
    RES_MUTEX_UNLOCK(&pstPool->rwLock);

    return ulRet;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_GetRangeField
 ����        : ��ȡһ�η�Χ�ڵ���Դ�ֶ�
 �������    : Ϊ�˷���uiStart��ֵ��Ҫ��RES_PART_LEN_BIT����������Ϊ0
 �������    : ��
 ����ֵ      : ��Դ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
uint64_t Res_GetRangeField(uint32_t uiPoolNo, uint32_t uiKey, uint32_t uiStart, uint32_t uiResNum,
    uint32_t *puiResp)
{
    ST_RES_SECTION *pstSec = NULL;
    ST_RES_POOL    *pstPool = NULL;
    uint32_t uiLoop = 0, uiRespCnt = 0;
    uint32_t uiIdxNum = 0, uiBitNum = 0;
    uint64_t tmp = 0;

    pstPool = Res_IndexToPool(uiPoolNo);

    RES_MUTEX_READ_LOCK(&pstPool->rwLock);
    tmp = uiKey;
    pstSec = (ST_RES_SECTION *)avl_search(pstPool->pstTree, (void *)tmp, Res_CompKey);
    if (pstSec == NULL) {
        RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }

    uiStart -= pstSec->uiStart;
    if (uiStart & RES_PART_LEN_MASK) {
        RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }

    if ((uiStart + uiResNum) > pstSec->uiMaxNum) {
        RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);
        return G_FAILURE;
    }

    uiIdxNum = (uiResNum >> RES_PART_LEN_BIT);
    uiBitNum = (uiResNum & RES_PART_LEN_MASK);
    if (uiIdxNum) {
        for (uiLoop = (uiStart >> RES_PART_LEN_BIT); uiLoop < pstSec->uiMaxIdx; ++uiLoop) {
            puiResp[uiRespCnt] = pstSec->puiBitFld[uiLoop];
            ++uiRespCnt;
            if (uiRespCnt == uiIdxNum) {
                break;
            }
        }
    }
    if (uiBitNum) {
        uiLoop = (uiStart >> RES_PART_LEN_BIT) + uiIdxNum;
        puiResp[uiRespCnt] = pstSec->puiBitFld[uiLoop];
        puiResp[uiRespCnt] &= ~(((uint32_t)1 << (uint32_t)(RES_PART_LEN - uiBitNum)) - 1);
    }

    RES_MUTEX_READ_UNLOCK(&pstPool->rwLock);

    return G_SUCCESS;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_MarkCreate
 ����        : ����һ����־�ֶγ�
 �������    : uiBitNum  ���ӵĹ��
 �������    : ��
 ����ֵ      : ��Դ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
int32_t Res_MarkCreate(uint32_t uiBitNum)
{
    int32_t  res_no = 0;
    uint64_t ret64;

    res_no = Res_CreatePool();
    if (res_no < 0) {
        return -1;
    }

    ret64 = Res_AddSection(res_no, 0, 0, uiBitNum);
    if (ret64 == G_FAILURE) {
        return -1;
    }

    return res_no;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_MarkSet
 ����        : Ϊ�ڼ�����Դ�����
 �������    : uiPoolNo     ��Դ�ر��
               uiBitNo      ��Ҫ����ǵ���Դ���
 �������    : ��
 ����ֵ      : ��
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_MarkSet(int32_t uiPoolNo, uint32_t uiBitNo)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint32_t uiLoop;
    uint32_t uiBit;

    pstPool = Res_IndexToPool(uiPoolNo);
    pstSec = pstPool->pstSection;

    uiLoop = (uiBitNo >> RES_PART_LEN_BIT);
    uiBit  = (uiBitNo & RES_PART_LEN_MASK);
    if (RES_TST_BIT(pstSec->puiBitFld[uiLoop], uiBit))
    {
        RES_CLR_BIT(pstSec->puiBitFld[uiLoop], uiBit);
        pstPool->uiAlloced++;
    }

    return;
}

/*-----------------------------------------------------------------------------
 ��������    : Res_MarkClr
 ����        : Ϊ�ڼ�����Դ������
 �������    : uiPoolNo     ��Դ�ر��
               uiBitNo      ��Ҫ����ǵ���Դ���
 �������    : ��
 ����ֵ      : ��
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
void Res_MarkClr(int32_t uiPoolNo, uint32_t uiBitNo)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint32_t uiLoop;
    uint32_t uiBit;

    pstPool = Res_IndexToPool(uiPoolNo);
    pstSec = pstPool->pstSection;

    uiLoop = (uiBitNo >> RES_PART_LEN_BIT);
    uiBit  = (uiBitNo & RES_PART_LEN_MASK);
    if (!RES_TST_BIT(pstSec->puiBitFld[uiLoop], uiBit))
    {
        RES_SET_BIT(pstSec->puiBitFld[uiLoop], uiBit);
        pstPool->uiAlloced--;
    }

    return;
}


/*-----------------------------------------------------------------------------
 ��������    : Res_MarkGetClr
 ����        : ��ȡ�������Դ���
 �������    : uiPoolNo     ��Դ�ر��
               uiCurBit     ���ĸ���Դ��ʼ����
 �������    : ��
 ����ֵ      : ��Դ���
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
int32_t Res_MarkGetClr(int32_t uiPoolNo, int32_t uiCurBit, RES_MARK_HOOK hook)
{
    ST_RES_SECTION *pstSec;
    ST_RES_POOL    *pstPool;
    uint32_t uiLoop, uiTimes;
    uint32_t uiBit, uiIdx;
    int32_t  iTgtIndex;

    pstPool = Res_IndexToPool(uiPoolNo);

    /* If no available, return */
    if (!pstPool->uiAlloced) {
        return -1;
    }

    /* Support only one section */
    pstSec = pstPool->pstSection;

    /* Get next available */
    uiIdx = ((uiCurBit + 1) >> RES_PART_LEN_BIT);
    uiBit = ((uiCurBit + 1) & RES_PART_LEN_MASK);

    /* If not in start, need do one more time */
    uiTimes = pstPool->uiSecNum + (uiCurBit != -1);
    while(uiTimes--)
    {
        /* �Ȱ��ճ����� */
        for (uiLoop = uiIdx; uiLoop < pstSec->uiMaxIdx; uiLoop++)
        {
            if (pstSec->puiBitFld[uiLoop] == (uint32_t)(-1))
            {
                continue;
            }
            else
            {
                break;
            }
        }

        if (uiLoop >= pstSec->uiMaxIdx)
        {
            /* From header, search again */
            uiIdx = 0;
            uiBit = 0;

            continue;
        }
        else
        {
            /* If same word, from last pos. Or from 0 */
            if (uiLoop != uiIdx) {
                uiBit = 0;
            }
            else {
                /* Do nothing */
            }

            /* �ҵ��ɷ����section������һ�� */
            for (; uiBit < RES_PART_LEN; uiBit++)
            {
                if (!RES_TST_BIT(pstSec->puiBitFld[uiLoop], uiBit))
                {
                    break;
                }
            }
            if ((uiBit >= RES_PART_LEN)||(RES_COMBINE(uiLoop, uiBit) >= pstSec->uiMaxNum))
            {
                uiIdx = 0;
                uiBit = 0;
                continue;
            }

            iTgtIndex = (uiLoop << RES_PART_LEN_BIT) + uiBit + pstSec->uiStart;

            /* Release this unit if match condition */
            /* In order to make a specific session still report next time */
            if ((hook)&&(hook(iTgtIndex) == TRUE)) {
                /* Those that do not meet the requirements will be cleared after reporting */
                RES_SET_BIT(pstSec->puiBitFld[uiLoop], uiBit);
                pstPool->uiAlloced--;
            }

            return iTgtIndex;
        }
    }

    return -1;
}

/*
���Է���:
1.���ڲ���ʱ��ʹ�õ���dpdk �ĺ�����������Ҫ�ŵ�fpu�Ĵ����в��ԣ�����fpu_main.c
2.ִ�е�ʱ��������Ե�Ŀ�������������:
{
    extern int32_t Res_MarkTest(uint32_t uiBitNum1);
    Res_MarkTest(10000);
    Res_MarkTest(100000);
    Res_MarkTest(1000000);
}


���Խ��:
1.������ʹ�õ���dpdk �ľ�ҳ�ڴ棬���ֱ����malloc��Ч��������ԣ�
2.�ӽ���Ͽ�����������Խ�٣�Ч��Խ�ã�������������ʱ��һ��ʱ��Ч����࣬
  ����࣬Ч�����һ�㣬����ͬһ����������
3.������ʱ���ε�����Ϊ������ļ�����Դ�����벻����
-------------------------------1000000--------------------------
Test0: find available item.
Find target bit on 555.

Find target bit on 555.

Find target bit on 555.

Find target bit on -1.

Test1: mark all structure.
Mark 1000000 resource with markset method  cost 128350992.
Mark 1000000 resource with  32 bytes block cost 53046912.
Mark 1000000 resource with  64 bytes block cost 104569992.
Mark 1000000 resource with 128 bytes block cost 187646904.
Mark 1000000 resource with 256 bytes block cost 288254040.

Test2: count valid structure when all items are valid.
Count 1000000 resource with markset method  cost 233851368.
Count 1000000 resource with 256 bytes block cost 163757712.

Test3: count valid structure when half items are valid.
Count 500000 resource with markset method  cost 129148464.
Count 500000 resource with 256 bytes block cost 128124336.

Test4: count valid structure when 1/32 items are valid.
Count 31250 resource with markset method  cost 8247384.
Count 31250 resource with 256 bytes block cost 94090752.

Test5: count valid structure when 1/64 items are valid.
Count 15625 resource with markset method  cost 4563144.
Count 15625 resource with 256 bytes block cost 92885928.
*/
/*-----------------------------------------------------------------------------
 ��������    : Res_MarkTest
 ����        :
 �������    : uiBitNum  ���ӵĹ��
 �������    : ��
 ����ֵ      : ��
 ��������˵��:
 ����ʹ��ʾ��:
-----------------------------------------------------------------------------*/
int32_t Res_MarkTest(uint32_t uiBitNum1)
{
#if 0
    int32_t  res;
    uint64_t start_time, end_time;
    int32_t  iloop, tmp_idx;
    uint32_t uiBitNum;
    uint32_t count_all;
    char     *buf;

    struct data_temp1 {
        uint8_t valid;
        uint8_t data[31];
    };

    struct data_temp2 {
        uint8_t valid;
        uint8_t data[63];
    };

    struct data_temp3 {
        uint8_t valid;
        uint8_t data[127];
    };

    struct data_temp4 {
        uint8_t valid;
        uint8_t data[255];
    };
    struct data_temp1 *data_p1;
    struct data_temp2 *data_p2;
    struct data_temp3 *data_p3;
    struct data_temp4 *data_p4;

    if (uiBitNum1 == 0) {
        uiBitNum = 100000;
    }
    else {
        uiBitNum = uiBitNum1;
    }

    res = Res_MarkCreate(uiBitNum);
    if (res < 0) {
        printf("Create mark pool failed.\r\n");
        return -1;
    }

    printf("-------------------------------%d--------------------------\r\n", uiBitNum1);
    printf("Test0: find available item.\r\n");

    /* set and clear any item */
    Res_MarkSet(res, 555);
    tmp_idx = Res_MarkGetClr(res, -1);
    printf("Find target bit on %d.\r\n\r\n", tmp_idx);

    /* set and clear any item */
    Res_MarkSet(res, 555);
    tmp_idx = Res_MarkGetClr(res, 554);
    printf("Find target bit on %d.\r\n\r\n", tmp_idx);

    /* set and clear any item */
    Res_MarkSet(res, 555);
    tmp_idx = Res_MarkGetClr(res, 556);
    printf("Find target bit on %d.\r\n\r\n", tmp_idx);

    /* find valid when no valid */
    tmp_idx = Res_MarkGetClr(res, 556);
    printf("Find target bit on %d.\r\n\r\n", tmp_idx);


    printf("Test1: mark all structure.\r\n");

    start_time = rte_get_tsc_cycles();
    /* 1.0 mark all */
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        Res_MarkSet(res, iloop);
    }
    end_time = rte_get_tsc_cycles();
    printf("Mark %d resource with markset method  cost %ld.\r\n", uiBitNum, end_time - start_time);


    /* 1.1 mark all with 32 bytes struct */
    buf = malloc(sizeof(struct data_temp1) * uiBitNum);
    data_p1 = (struct data_temp1 *)buf;
    start_time = rte_get_tsc_cycles();
    /* mark all */
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        data_p1->valid = 1;
        data_p1++;
    }
    end_time = rte_get_tsc_cycles();
    free(buf);
    printf("Mark %d resource with  32 bytes block cost %ld.\r\n", uiBitNum, end_time - start_time);


    /* 1.2 mark all with 64 bytes struct */
    buf = malloc(sizeof(struct data_temp2) * uiBitNum);
    data_p2 = (struct data_temp2 *)buf;
    start_time = rte_get_tsc_cycles();
    /* mark all */
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        data_p2->valid = 1;
        data_p2++;
    }
    end_time = rte_get_tsc_cycles();
    free(buf);
    printf("Mark %d resource with  64 bytes block cost %ld.\r\n", uiBitNum, end_time - start_time);


    /* 1.3 mark all with 128 bytes struct */
    buf = malloc(sizeof(struct data_temp3) * uiBitNum);
    data_p3 = (struct data_temp3 *)buf;
    start_time = rte_get_tsc_cycles();
    /* mark all */
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        data_p3->valid = 1;
        data_p3++;
    }
    end_time = rte_get_tsc_cycles();
    free(buf);
    printf("Mark %d resource with 128 bytes block cost %ld.\r\n", uiBitNum, end_time - start_time);


    /* 1.4 mark all with 256 bytes struct */
    buf = malloc(sizeof(struct data_temp4) * uiBitNum);
    data_p4 = (struct data_temp4 *)buf;
    start_time = rte_get_tsc_cycles();
    /* mark all */
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        data_p4->valid = 1;
        data_p4++;
    }
    end_time = rte_get_tsc_cycles();
    printf("Mark %d resource with 256 bytes block cost %ld.\r\n", uiBitNum, end_time - start_time);


    printf("\r\nTest2: count valid structure when all items are valid.\r\n");

    /* 2.0 get next when all 1 */
    start_time = rte_get_tsc_cycles();
    /* mark all */
    count_all = 0;
    tmp_idx = -1;
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        tmp_idx = Res_MarkGetClr(res, tmp_idx);
        if (tmp_idx != -1) {
            count_all++;
        }
        else {
            break;
        }
    }
    end_time = rte_get_tsc_cycles();
    printf("Count %d resource with markset method  cost %ld.\r\n", count_all, end_time - start_time);


    /* get next when all 1 */
    data_p4 = (struct data_temp4 *)buf;
    start_time = rte_get_tsc_cycles();
    /* mark all */
    count_all = 0;
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        if (data_p4->valid == 1) {
            count_all++;
            data_p4->valid = 0;
        }
        data_p4++;
    }
    end_time = rte_get_tsc_cycles();
    printf("Count %d resource with 256 bytes block cost %ld.\r\n", count_all, end_time - start_time);


    printf("\r\nTest3: count valid structure when half items are valid.\r\n");

    /* 3.0 get next when half 1 */
    for (iloop = 0; iloop < uiBitNum; iloop += 2) {
        Res_MarkSet(res, iloop);
    }

    start_time = rte_get_tsc_cycles();
    /* mark all */
    count_all = 0;
    tmp_idx = -1;
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        tmp_idx = Res_MarkGetClr(res, tmp_idx);
        if (tmp_idx != -1) {
            count_all++;
        }
        else {
            break;
        }
    }
    end_time = rte_get_tsc_cycles();
    printf("Count %d resource with markset method  cost %ld.\r\n", count_all, end_time - start_time);


    /* get next when all 1 */
    data_p4 = (struct data_temp4 *)buf;
    /* mark all */
    count_all = 0;
    for (iloop = 0; iloop < uiBitNum; iloop += 2) {
        data_p4->valid = 1;
        data_p4++;
    }

    data_p4 = (struct data_temp4 *)buf;
    start_time = rte_get_tsc_cycles();
    /* mark all */
    count_all = 0;
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        if (data_p4->valid == 1) {
            count_all++;
            data_p4->valid = 0;
        }
        data_p4++;
    }
    end_time = rte_get_tsc_cycles();
    printf("Count %d resource with 256 bytes block cost %ld.\r\n", count_all, end_time - start_time);



    printf("\r\nTest4: count valid structure when 1/32 items are valid.\r\n");

    /* 4.0 get next when all 1 */
    for (iloop = 0; iloop < uiBitNum; iloop += 32) {
        Res_MarkSet(res, iloop);
    }

    start_time = rte_get_tsc_cycles();
    /* mark all */
    count_all = 0;
    tmp_idx = -1;
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        tmp_idx = Res_MarkGetClr(res, tmp_idx);
        if (tmp_idx != -1) {
            count_all++;
        }
        else {
            break;
        }
    }
    end_time = rte_get_tsc_cycles();
    printf("Count %d resource with markset method  cost %ld.\r\n", count_all, end_time - start_time);


    /* get next when all 1 */
    data_p4 = (struct data_temp4 *)buf;
    /* mark all */
    count_all = 0;
    for (iloop = 0; iloop < uiBitNum; iloop += 32) {
        data_p4->valid = 1;
        data_p4++;
    }

    data_p4 = (struct data_temp4 *)buf;
    start_time = rte_get_tsc_cycles();
    /* mark all */
    count_all = 0;
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        if (data_p4->valid == 1) {
            count_all++;
            data_p4->valid = 0;
        }
        data_p4++;
    }
    end_time = rte_get_tsc_cycles();
    printf("Count %d resource with 256 bytes block cost %ld.\r\n", count_all, end_time - start_time);



    printf("\r\nTest5: count valid structure when 1/64 items are valid.\r\n");

    /* 4.0 get next when all 1 */
    for (iloop = 0; iloop < uiBitNum; iloop += 64) {
        Res_MarkSet(res, iloop);
    }

    start_time = rte_get_tsc_cycles();
    /* mark all */
    count_all = 0;
    tmp_idx = -1;
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        tmp_idx = Res_MarkGetClr(res, tmp_idx);
        if (tmp_idx != -1) {
            count_all++;
        }
        else {
            break;
        }
    }
    end_time = rte_get_tsc_cycles();
    printf("Count %d resource with markset method  cost %ld.\r\n", count_all, end_time - start_time);


    /* get next when all 1 */
    data_p4 = (struct data_temp4 *)buf;
    /* mark all */
    count_all = 0;
    for (iloop = 0; iloop < uiBitNum; iloop += 64) {
        data_p4->valid = 1;
        data_p4++;
    }

    data_p4 = (struct data_temp4 *)buf;
    start_time = rte_get_tsc_cycles();
    /* mark all */
    count_all = 0;
    for (iloop = 0; iloop < uiBitNum; iloop++) {
        if (data_p4->valid == 1) {
            count_all++;
            data_p4->valid = 0;
        }
        data_p4++;
    }
    end_time = rte_get_tsc_cycles();
    printf("Count %d resource with 256 bytes block cost %ld.\r\n", count_all, end_time - start_time);

    free(buf);
#endif
    return 0;
}


