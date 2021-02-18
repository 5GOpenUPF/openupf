/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _ROS_LIBMEM_H__
#define _ROS_LIBMEM_H__

#ifdef __cplusplus
extern "C" {
#endif
void ros_free(void *addr);
void *ros_malloc(size_t size);
void *ros_calloc(size_t nmemb, size_t size);
void ros_memset( void *pDest, int slSetChar, int ulCount);
void ros_memzero( void *pDest, int ulCount);
void ros_bzero(void *s, size_t n);
char *ros_memcpy( void *pDest, const void *pSrc, int ulCount);
void ros_memmove( void *pDest, const void *pSrc, int ulCount);
int  ros_memcmp( const void *pBuf1, const void *pBuf2, int ulCount);
char* ros_memchr( const void *pBuf, int slFindChar, int ulCount);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _ROS_LIBMEM_H__ */
