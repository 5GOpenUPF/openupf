/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "ros_libmem.h"

#ifdef ENABLE_DPDK_LIB
void rte_free(void *addr);
void *rte_malloc(const char *type, size_t size, unsigned align);
void *rte_calloc(const char *type, size_t num, size_t size, unsigned align);
#endif

void
ros_free(void *addr)
{
	if (unlikely(addr == NULL)) return;
#ifdef ENABLE_DPDK_LIB
    rte_free(addr);
#else
    free(addr);
#endif
}

void *
ros_malloc(size_t size)
{
#ifdef ENABLE_DPDK_LIB
    return rte_malloc(NULL, size, 64);
#else
	return malloc(size);
#endif
}

void *
ros_calloc(size_t nmemb, size_t size)
{
#ifdef ENABLE_DPDK_LIB
    return rte_calloc(NULL, nmemb, size, 64);
#else
	return calloc(nmemb, size);
#endif
}

/*****************************************************************************
 ��������    : ros_memset()
 ��������    : �ڴ�����.
 �²㺯��    : memset();
 �ϲ㺯��    :
 ����ȫ�ֱ���: ��.
 �޸�ȫ�ֱ���: ��.
 ���ʵ��ı�  : ��.
 �޸ĵ��ı�  : ��.
 �������    : pDest,       �����ڴ����ʼ��ַ;
               slSetChar,   ���õ��ַ�; ע��: ֻȡ���ֽ�.
               ulCount,     ���õ��ֽ���.
 �������    : ��.
 ����ֵ      : SUCESS,  �ɹ�;
               ����,    ʧ��.
 ��ע        : ��.
******************************************************************************/
void ros_memset( void *pDest, int slSetChar, int ulCount  )
{
    memset( pDest, (char)slSetChar, (size_t)ulCount );

    return;

}

/*****************************************************************************
 ��������    : ros_memzero()
 ��������    : �ڴ�����.
 �²㺯��    : memset();
 �ϲ㺯��    :
 ����ȫ�ֱ���: ��.
 �޸�ȫ�ֱ���: ��.
 ���ʵ��ı�  : ��.
 �޸ĵ��ı�  : ��.
 �������    : pDest,       �����ڴ����ʼ��ַ;
               ulCount,     ������ֽ���.
 �������    : ��.
 ����ֵ      : SUCESS,  �ɹ�;
               ����,    ʧ��.
 ��ע        : ��.
******************************************************************************/
void ros_memzero( void *pDest, int ulCount  )
{
    memset( pDest, (char)0, (size_t)ulCount );

    return;
}

/*****************************************************************************
 ��������    : ros_bzero()
 ��������    : �ڴ�����.
 �²㺯��    : memset();
 �ϲ㺯��    :
 ����ȫ�ֱ���: ��.
 �޸�ȫ�ֱ���: ��.
 ���ʵ��ı�  : ��.
 �޸ĵ��ı�  : ��.
 �������    : pDest,       �����ڴ����ʼ��ַ;
               ulCount,     ������ֽ���.
 �������    : ��.
 ����ֵ      : SUCESS,  �ɹ�;
               ����,    ʧ��.
 ��ע        : ��.
******************************************************************************/
void ros_bzero(void *s, size_t n)
{
    memset(s, 0, n);
    return;
}

/*****************************************************************************
 ��������    : ros_memcpy()
 ��������    : �ڴ濽��.
 �²㺯��    : memcpy();
 �ϲ㺯��    :
 ����ȫ�ֱ���: ��..
 �޸�ȫ�ֱ���: ��.
 ���ʵ��ı�  : ��.
 �޸ĵ��ı�  : ��.
 �������    : pDest,       ������Ŀ�Ļ�������ַ;
               pSrc,        ������Դ��������ַ;
               ulCount,     �������ֽ���.
 �������    : ��.
 ����ֵ      : SUCESS,  �ɹ�;
               ����,    ʧ��.
 ��ע        : Ŀ�Ļ�������Դ���������ص�ʱ, ����֤Դ���������ص�����,
               �ڱ���дǰ������.
******************************************************************************/
char *ros_memcpy( void *pDest, const void *pSrc, int ulCount  )
{
    /* ���ָ���� */
    if( (G_NULL == pDest) || (G_NULL == pSrc) )
    {
        return NULL;
    }

    return memcpy( pDest, pSrc, (size_t)ulCount );
}

/*****************************************************************************
 ��������    : ros_memmove()
 ��������    : �ڴ��ƶ�.
 �²㺯��    : memmove();
 �ϲ㺯��    :
 ����ȫ�ֱ���: ��.
 �޸�ȫ�ֱ���: ��.
 ���ʵ��ı�  : ��.
 �޸ĵ��ı�  : ��.
 �������    : pDest,       �ƶ���Ŀ�Ļ�������ַ;
               pSrc,        �ƶ���Դ��������ַ;
               ulCount,     �ƶ����ֽ���.
 �������    : ��.
 ����ֵ      : SUCESS,  �ɹ�;
               ����,    ʧ��.
 ��ע        : Ŀ�Ļ�������Դ���������ص�ʱ, ��֤Դ���������ص�����,
               �ڱ���дǰ������.
******************************************************************************/
void ros_memmove( void *pDest, const void *pSrc, int ulCount  )
{
    /* ���ָ���� */
    if( (G_NULL == pDest) || (G_NULL == pSrc) )
    {
        return;
    }

    memmove( pDest, pSrc, (size_t)ulCount );

    return;

}


/*****************************************************************************
 ��������    : ros_memcmp()
 ��������    : �ڴ�Ƚ�.
 �²㺯��    : memcmp();
 �ϲ㺯��    :
 ����ȫ�ֱ���: ��.
 �޸�ȫ�ֱ���: ��.
 ���ʵ��ı�  : ��.
 �޸ĵ��ı�  : ��.
 �������    : pBuf1,       ������1��ַ;
               pBuf2,       ������2��ַ;
               ulCount,     �Ƚϵ��ֽ���.
 �������    : ��.
 ����ֵ      : pslRet��     ����ɹ�, ���رȽϵĽ��
                            0 ,     ���
                            < 0,    ������1С�ڻ�����2
                            > 0,    ������1���ڻ�����2
 ��ע        : ��.
******************************************************************************/
int ros_memcmp( const void *pBuf1, const void *pBuf2, int ulCount )
{
    return  memcmp( pBuf1, pBuf2, (size_t)ulCount );
}



/*****************************************************************************
 ��������    : ros_memchr()
 ��������    : ��ָ�����ڴ滺�������ҵ�һ��ƥ����ַ�.
 �²㺯��    : memchr();
 �ϲ㺯��    :
 ����ȫ�ֱ���: ��.
 �޸�ȫ�ֱ���: ��.
 ���ʵ��ı�  : ��.
 �޸ĵ��ı�  : ��.
 �������    : pBuf,        ���ҵ��ڴ滺��������ʼ��ַ;
               slFindChar,  ���ҵ��ַ�;
               ulCount,     ���ҵ��ֽ���.
 �������    : ��.
 ����ֵ      : ������ҳɹ�, ����ָ��ƥ���ַ���ָ��.
               ����, ���ؿ�ָ��.
 ��ע        : ��.
******************************************************************************/
char* ros_memchr( const void *pBuf, int slFindChar, int ulCount )
{
    return  memchr( pBuf, slFindChar, (size_t)ulCount );
}

