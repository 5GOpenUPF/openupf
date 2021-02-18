/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _COMMON_TYPEDEF_H__
#define _COMMON_TYPEDEF_H__

/*
define int8_t uint8_t int16_t uint16_t int32_t uint32_t int64_t uint64_t
*/
#include <stdint.h>
#include <stddef.h>

#ifndef __maybe_unused
#define __maybe_unused  __attribute__((unused))
#endif
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif


#ifndef COMMON_BYTE_ORDER
#define COMMON_BYTE_ORDER       COMMON_LITTLE_ENDIAN
#endif

#ifndef YES
#define YES                     1
#endif
#ifndef NO
#define NO                      0
#endif

#ifndef BOOL
#define BOOL                    int
#endif

#ifndef _BOOL
#define _BOOL                   int
#endif

#define ULL unsigned long long

typedef unsigned long           uint64_t;
typedef long                    int64_t;
typedef unsigned int            uint32_t;
typedef int                     int32_t;
typedef unsigned short          uint16_t;
typedef short                   int16_t;
typedef unsigned char           uint8_t;

typedef char _S8;
typedef unsigned char _U8;

typedef short _S16;
typedef unsigned short _U16;

typedef int _S32;
typedef unsigned int _U32;

typedef long _S64;
typedef unsigned long _U64;

typedef uint32_t                HASH_INDEX;

#define G_NULL                  (0)
#define G_NULL_PTR              ((void *)0)
#define G_NULL_BYTE             (0xFF)
#define G_NULL_WORD             (0xFFFF)
#define G_NULL_DWORD            (0xFFFFFFFF)

#define G_SUCCESS               ((uint64_t)0)
#define G_FAILURE               ((uint64_t)(-1))

#define G_TRUE                  (1)
#define G_FALSE                 (0)

#ifndef G_YES
#define G_YES                   (1)
#endif
#ifndef G_NO
#define G_NO                    (0)
#endif

typedef int                     (*FUNCPTR) (void);
typedef void                    (*VOIDFUNCPTR) (void);
typedef double                  (*DBLFUNCPTR) (void);
typedef float                   (*FLTFUNCPTR) (void);

#define LOCAL                   static
#define FAST                    register

#define IMPORT                  extern
#define WAIT_FOREVER            -1

#ifndef OK
#define OK                      (0)
#endif
#ifndef ERROR
#define ERROR                   (-1)
#endif

#ifndef TRUE
#define TRUE                    (1)
#endif
#ifndef FALSE
#define FALSE                   (0)
#endif

#ifndef max
#define max(a,b)                (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)                (((a) < (b)) ? (a) : (b))
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

/**
 * Force a function to be inlined
 */
#define __al_inline inline __attribute__((always_inline))

/**
 * Force a function to be noinlined
 */
#define __no_inline  __attribute__((noinline))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#ifndef is_power_of_two
#define is_power_of_two(x)	( !((x) & ((x)-1)) )
#endif

#ifndef roundup
#define roundup(x, align) (((long)(x)+((long)align-1)) & ~((long)align-1))
#endif

#ifndef rounddown
#define rounddown(x, align) ((long)(x) & ~((long)align-1))
#endif

#ifndef ALIGNED
#define ALIGNED(x, align) (((long)(x) & ((long)align-1)) == 0)
#endif

#ifndef OFFSET
#define OFFSET(structure, member) \
		((long) &(((structure *) 0) -> member))
#endif

#ifndef container_of

#define container_of(ptr, type, member) ({\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);\
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

/* 不考虑大小端，直接字节变换 */
#define SWAP_8_BYTE(_i) \
    ((((((uint64_t)(_i)) >>  0) & (uint64_t)0xff) << 56) | \
    (((((uint64_t)(_i)) >>  8) & (uint64_t)0xff) << 48) | \
    (((((uint64_t)(_i)) >> 16) & (uint64_t)0xff) << 40) | \
    (((((uint64_t)(_i)) >> 24) & (uint64_t)0xff) << 32) | \
    (((((uint64_t)(_i)) >> 32) & (uint64_t)0xff) << 24) | \
    (((((uint64_t)(_i)) >> 40) & (uint64_t)0xff) << 16) | \
    (((((uint64_t)(_i)) >> 48) & (uint64_t)0xff) <<  8) | \
    (((((uint64_t)(_i)) >> 56) & (uint64_t)0xff) <<  0))

#define SWAP_4_BYTE(_i) \
    ((((uint32_t)(_i)) & 0xff000000) >> 24) | \
    ((((uint32_t)(_i)) & 0x00ff0000) >>  8) | \
    ((((uint32_t)(_i)) & 0x0000ff00) <<  8) | \
    ((((uint32_t)(_i)) & 0x000000ff) << 24)

#define SWAP_2_BYTE(_i) \
    ((((uint16_t)(_i)) & 0xff00) >> 8) | \
    ((((uint16_t)(_i)) & 0x00ff) << 8)

//#ifndef htons
#if 0
    #ifdef USR_BIG_ENDIAN
        #ifndef htonl
            #define htonl(a)    ((unsigned int)(a))
        #endif
        #ifndef ntohl
            #define ntohl(a)    ((unsigned int)(a))
        #endif
        #ifndef htons
            #define htons(a)    ((unsigned short)(a))
        #endif
        #ifndef ntohs
            #define ntohs(a)    ((unsigned short)(a))
        #endif
    #else
        #define htonl(addr)     ((((unsigned int)(addr) & 0x000000FF)<<24) | \
                                (((unsigned int)(addr) & 0x0000FF00)<<8)  | \
                                (((unsigned int)(addr) & 0x00FF0000)>>8)  | \
                                (((unsigned int)(addr) & 0xFF000000)>>24))
        #define ntohl(addr)     htonl(addr)
        #define htons(addr)     ((((unsigned short)(addr) & 0x000000FF)<<8) | \
                                (((unsigned short)(addr) & 0x0000FF00)>>8))
        #define ntohs(addr)     htons(addr)
    #endif
#endif

#ifndef htonll
    #ifdef USR_BIG_ENDIAN
        #ifndef htonll
            #define htonll(a)    ((unsigned long)(a))
        #endif
        #ifndef ntohll
            #define ntohll(a)    ((unsigned long)(a))
        #endif
    #else             /* Motorola type */
        #define htonll(addr)    (((unsigned long) htonl(addr) << 32) | htonl(addr >> 32))
        #define ntohll(addr)    (((unsigned long) ntohl(addr) << 32) | ntohl(addr >> 32))
    #endif
#endif

#ifdef ENABLE_OCTEON_III
#define mac_to_u64(mac)                 cvmcs_nic_mac_to_64(mac)
#define mac_to_ptr(mac)                 (((uint8_t *)mac) + 2)

#ifndef likely
#define likely	                        cvmx_likely
#endif
#ifndef unlikely
#define unlikely	                    cvmx_unlikely
#endif

#ifndef __packed
#define __packed                        __attribute__((packed))
#endif

#ifndef __al_unused
#define __al_unused
#endif

#ifndef __mb_unused
#define __mb_unused
#endif

#ifndef __aligned
#define __aligned(x)                    __attribute__((aligned(x)))
#endif

#ifndef __cacheline_aligned
#define __cacheline_aligned
#endif

#ifndef __stringify
#define __stringify_1(x)                #x
#define __stringify(x)	                __stringify_1(x)
#endif

#define pkt_buf_struct                  cvmx_wqe_78xx_t
#define pkt_buf_buf_start(m)            (((pkt_buf_struct *)m)->packet_ptr.addr)
#define pkt_buf_pkt_len(m)              (((pkt_buf_struct *)m)->word1.len)
#define pkt_buf_data_len(m)             (((pkt_buf_struct *)m)->word1.len)
#define pkt_buf_data_off(m)             (((pkt_buf_struct *)m)->packet_ptr.addr)
#define pkt_buf_free(m)                 cvm_free_host_instr((cvmx_wqe_t *)m)
#define pkt_buf_set_len(m, lenval)      (((pkt_buf_struct *)m)->word1.len = (lenval))

#define ros_rwlock_t                    cvmx_rwlock_wp_lock_t
#define ros_rwlock_init                 cvmx_rwlock_wp_init
#define ros_rwlock_read_lock            cvmx_rwlock_wp_read_lock
#define ros_rwlock_read_unlock          cvmx_rwlock_wp_read_unlock
#define ros_rwlock_write_lock           cvmx_rwlock_wp_write_lock
#define ros_rwlock_write_unlock         cvmx_rwlock_wp_write_unlock

#define ros_atomic64_t                  int64_t
#define ros_atomic64_init(v)            {v=0;}
#define ros_atomic64_read               cvmx_atomic_get64
#define ros_atomic64_set                cvmx_atomic_set64
#define ros_atomic64_add                cvmx_atomic_add64
#define ros_atomic64_sub(a,b)           cvmx_atomic_add64(a, b*(-1))
#define ros_atomic64_inc(a)             cvmx_atomic_add64(a, (+1))
#define ros_atomic64_dec(a)             cvmx_atomic_add64(a, (-1))

#define ros_atomic32_t                  int32_t
#define ros_atomic32_init(v)            {v=0;}
#define ros_atomic32_read               cvmx_atomic_get32
#define ros_atomic32_set                cvmx_atomic_set32
#define ros_atomic32_add                cvmx_atomic_add32
#define ros_atomic32_sub(a,b)           cvmx_atomic_add32(a, b*(-1))
#define ros_atomic32_inc(a)             cvmx_atomic_add32(a, (+1))
#define ros_atomic32_dec(a)             cvmx_atomic_add32(a, (-1))
#else
static inline uint64_t mac_to_u64(uint8_t *mac)
{
	uint64_t macaddr = 0;
	int i;
	for (i = 0; i < 6; i++)
		macaddr = (macaddr << 8) | (uint64_t)(mac[i]);
	return macaddr;
}

#define mac_to_ptr(mac)  (((uint8_t *)mac) + 2)

#ifndef likely
#define likely(x)	                    __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)	                    __builtin_expect(!!(x), 0)
#endif

#ifndef __packed
#define __packed                        __attribute__((packed))
#endif

#ifndef __al_unused
#define __al_unused                     __attribute__((unused))
#endif

#ifndef __mb_unused
#define __mb_unused                     __attribute__((unused))
#endif

#ifndef __aligned
#define __aligned(x)                    __attribute__((aligned(x)))
#endif

#ifndef __cacheline_aligned
#define __cacheline_aligned \
    __attribute__((__aligned__(64), __section__(".data..cacheline_aligned")))
#endif

#ifndef __stringify
#define __stringify_1(x)                #x
#define __stringify(x)	                __stringify_1(x)
#endif

#define CVMX_SHARED

#define pkt_buf_struct                  struct rte_mbuf
#define pkt_buf_buf_start(m)            (((pkt_buf_struct *)m)->buf_addr)
#define pkt_buf_pkt_len(m)              rte_pktmbuf_pkt_len(((pkt_buf_struct *)m))
#define pkt_buf_data_len(m)             rte_pktmbuf_data_len(((pkt_buf_struct *)m))
#define pkt_buf_data_off(m)             (((pkt_buf_struct *)m)->data_off)
#define pkt_buf_free(m)                 dpdk_free_mbuf(((pkt_buf_struct *)m))
#define pkt_buf_set_len(m, len)         \
    rte_pktmbuf_data_len(((pkt_buf_struct *)m)) = rte_pktmbuf_pkt_len(((pkt_buf_struct *)m)) = len

#endif

#endif



