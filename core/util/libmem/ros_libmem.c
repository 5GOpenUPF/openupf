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
 函数名称    : ros_memset()
 函数功能    : 内存设置.
 下层函数    : memset();
 上层函数    :
 访问全局变量: 无.
 修改全局变量: 无.
 访问到的表  : 无.
 修改到的表  : 无.
 输入参数    : pDest,       设置内存的起始地址;
               slSetChar,   设置的字符; 注意: 只取低字节.
               ulCount,     设置的字节数.
 输出参数    : 无.
 返回值      : SUCESS,  成功;
               其他,    失败.
 备注        : 无.
******************************************************************************/
void ros_memset( void *pDest, int slSetChar, int ulCount  )
{
    memset( pDest, (char)slSetChar, (size_t)ulCount );

    return;

}

/*****************************************************************************
 函数名称    : ros_memzero()
 函数功能    : 内存清零.
 下层函数    : memset();
 上层函数    :
 访问全局变量: 无.
 修改全局变量: 无.
 访问到的表  : 无.
 修改到的表  : 无.
 输入参数    : pDest,       清零内存的起始地址;
               ulCount,     清零的字节数.
 输出参数    : 无.
 返回值      : SUCESS,  成功;
               其他,    失败.
 备注        : 无.
******************************************************************************/
void ros_memzero( void *pDest, int ulCount  )
{
    memset( pDest, (char)0, (size_t)ulCount );

    return;
}

/*****************************************************************************
 函数名称    : ros_bzero()
 函数功能    : 内存清零.
 下层函数    : memset();
 上层函数    :
 访问全局变量: 无.
 修改全局变量: 无.
 访问到的表  : 无.
 修改到的表  : 无.
 输入参数    : pDest,       清零内存的起始地址;
               ulCount,     清零的字节数.
 输出参数    : 无.
 返回值      : SUCESS,  成功;
               其他,    失败.
 备注        : 无.
******************************************************************************/
void ros_bzero(void *s, size_t n)
{
    memset(s, 0, n);
    return;
}

/*****************************************************************************
 函数名称    : ros_memcpy()
 函数功能    : 内存拷贝.
 下层函数    : memcpy();
 上层函数    :
 访问全局变量: 无..
 修改全局变量: 无.
 访问到的表  : 无.
 修改到的表  : 无.
 输入参数    : pDest,       拷贝的目的缓冲区地址;
               pSrc,        拷贝的源缓冲区地址;
               ulCount,     拷贝的字节数.
 输出参数    : 无.
 返回值      : SUCESS,  成功;
               其他,    失败.
 备注        : 目的缓冲区和源缓冲区有重叠时, 不保证源缓冲区的重叠部分,
               在被改写前被拷贝.
******************************************************************************/
char *ros_memcpy( void *pDest, const void *pSrc, int ulCount  )
{
    /* 入口指针检查 */
    if( (G_NULL == pDest) || (G_NULL == pSrc) )
    {
        return NULL;
    }

    return memcpy( pDest, pSrc, (size_t)ulCount );
}

/*****************************************************************************
 函数名称    : ros_memmove()
 函数功能    : 内存移动.
 下层函数    : memmove();
 上层函数    :
 访问全局变量: 无.
 修改全局变量: 无.
 访问到的表  : 无.
 修改到的表  : 无.
 输入参数    : pDest,       移动的目的缓冲区地址;
               pSrc,        移动的源缓冲区地址;
               ulCount,     移动的字节数.
 输出参数    : 无.
 返回值      : SUCESS,  成功;
               其他,    失败.
 备注        : 目的缓冲区和源缓冲区有重叠时, 保证源缓冲区的重叠部分,
               在被改写前被拷贝.
******************************************************************************/
void ros_memmove( void *pDest, const void *pSrc, int ulCount  )
{
    /* 入口指针检查 */
    if( (G_NULL == pDest) || (G_NULL == pSrc) )
    {
        return;
    }

    memmove( pDest, pSrc, (size_t)ulCount );

    return;

}


/*****************************************************************************
 函数名称    : ros_memcmp()
 函数功能    : 内存比较.
 下层函数    : memcmp();
 上层函数    :
 访问全局变量: 无.
 修改全局变量: 无.
 访问到的表  : 无.
 修改到的表  : 无.
 输入参数    : pBuf1,       缓冲区1地址;
               pBuf2,       缓冲区2地址;
               ulCount,     比较的字节数.
 输出参数    : 无.
 返回值      : pslRet，     如果成功, 返回比较的结果
                            0 ,     相等
                            < 0,    缓冲区1小于缓冲区2
                            > 0,    缓冲区1大于缓冲区2
 备注        : 无.
******************************************************************************/
int ros_memcmp( const void *pBuf1, const void *pBuf2, int ulCount )
{
    return  memcmp( pBuf1, pBuf2, (size_t)ulCount );
}



/*****************************************************************************
 函数名称    : ros_memchr()
 函数功能    : 在指定的内存缓冲区查找第一个匹配的字符.
 下层函数    : memchr();
 上层函数    :
 访问全局变量: 无.
 修改全局变量: 无.
 访问到的表  : 无.
 修改到的表  : 无.
 输入参数    : pBuf,        查找的内存缓冲区的起始地址;
               slFindChar,  查找的字符;
               ulCount,     查找的字节数.
 输出参数    : 无.
 返回值      : 如果查找成功, 返回指向匹配字符的指针.
               否则, 返回空指针.
 备注        : 无.
******************************************************************************/
char* ros_memchr( const void *pBuf, int slFindChar, int ulCount )
{
    return  memchr( pBuf, slFindChar, (size_t)ulCount );
}

