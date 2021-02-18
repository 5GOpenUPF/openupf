/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __DPDK_H__
#define __DPDK_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#define ENABLE_DPDK_DEBUG

#define MEMPOOL_CACHE_SIZE          256

#define DPDK_MAX_RX_PKT_BURST       32
#define DPDK_MAX_TX_PKT_BURST       16
#define BURST_TX_DRAIN_US           100
#define NB_SOCKETS                  8

#define DPDK_NB_MBUF	RTE_MAX(\
	(nb_ports * nb_rx_queue * RTE_TEST_RX_DESC_DEFAULT +	\
	nb_ports * nb_lcores * DPDK_MAX_RX_PKT_BURST +			\
	nb_ports * n_tx_queue * RTE_TEST_TX_DESC_DEFAULT +	\
	nb_lcores * MEMPOOL_CACHE_SIZE),			\
	(unsigned)16384)

#define RTE_TEST_RX_DESC_DEFAULT    512
#define RTE_TEST_TX_DESC_DEFAULT    512

#define DPDK_CHECK_INTERVAL         100             /* 100ms */
#define DPDK_MAX_CHECK_TIME         10              /* 1s (10 * 100ms) in total */

#define MAX_BOUND_DEV_ETHPORTS      8

enum {
    EN_MBUF_CACHE_CORE      = 0,
    EN_MBUF_CALL_STACK      = 1,
};

typedef void (*dpdk_proc_no_eal_pthr_cb_t)(uint32_t lcore_id);
typedef int (*dpdk_proc_eal_pthr_cb_t)(char *buf, int len, uint16_t port_id, void *arg);

#define DPDK_MBUF_TABLE_SIZE        (2 * DPDK_MAX_TX_PKT_BURST)
struct mbuf_table {
    uint16_t len;
    struct rte_mbuf *m_table[DPDK_MBUF_TABLE_SIZE];
};

struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[RTE_MAX_ETHPORTS];
	uint16_t n_tx_port;
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
    struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
	struct rte_mempool *direct_pool;
	struct rte_mempool *indirect_pool;
	struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

typedef enum tag_EN_DPDK_INIT_STAT
{
    EN_DPDK_INIT_STAT_NULL,
    EN_DPDK_INIT_STAT_ING,
    EN_DPDK_INIT_STAT_FAIL,
    EN_DPDK_INIT_STAT_SUCCESS,
}EN_DPDK_INIT_STAT;

struct dpdk_config {
    char        dev[MAX_BOUND_DEV_ETHPORTS][32];
    uint16_t    rx_queue;
    uint16_t    tx_queue;
    uint8_t     cpus[ROS_MAX_CPUS_NUM]; /* CPU ID array that can be used */
    uint8_t     core_num;
    uint8_t     dev_num;
};


#define DPDK_PRINTF_V(fd,fmt,Var) fprintf(fd,fmt,#Var ,Var)
#define DPDK_PRINTF_FUNC(fd,Var) fprintf(fd,"%-30s : %p(%s)\n",#Var ,Var,dpdk_GetFuncNameByAddr((void*)(Var)))
#define DPDK_PRINTF_NAME(fd,Var) fprintf(fd,"%-30s : %s\n",#Var ,Var)

/**************** DEBUG DPDK Mbuf *******************/
enum {
    DPDK_POS_USEING     = 0,
    DPDK_POS_CORE_ID,
    DPDK_POS_ALC_POS,
    DPDK_POS_FRE_POS,
    DPDK_POS_FRE_POS2,
};
#define dpdk_mbuf_record(buf_addr, line) \
    do { \
        unsigned lcore_id = rte_lcore_id(), *pos = (unsigned *)buf_addr; \
        if (pos[DPDK_POS_USEING]) { \
            LOG(COMM, MUST, "first alloc line: %d, core id: %u", pos[DPDK_POS_ALC_POS], pos[DPDK_POS_CORE_ID]); \
            LOG(COMM, MUST, "current alloc line: line(%d), core id: %u, m(%p)", line, lcore_id, buf_addr); \
        } else { \
            pos[DPDK_POS_USEING]++; \
            pos[DPDK_POS_CORE_ID] = lcore_id; \
            pos[DPDK_POS_ALC_POS] = line; \
        } \
    } while(0);

#define dpdk_mbuf_del_record(buf_addr, line) \
    do { \
        unsigned lcore_id = rte_lcore_id(), *pos = (unsigned *)(buf_addr); \
        if (pos[DPDK_POS_USEING] != 1) { \
            LOG(COMM, MUST, "repeat free: first free line: %d  core id: %u", pos[DPDK_POS_FRE_POS], pos[DPDK_POS_CORE_ID]); \
            LOG(COMM, MUST, "repeat free: current free line: %d  core id: %u, m(%p)\r\n", line, lcore_id, buf_addr); \
        } else { \
            pos[DPDK_POS_USEING]--; \
            pos[DPDK_POS_CORE_ID] = lcore_id; \
            pos[DPDK_POS_FRE_POS] = line; \
        } \
    } while(0);

void dpdk_send_packet(struct rte_mbuf *m, uint16_t port_id, const char *func, int line);
struct rte_mbuf *__dpdk_alloc_mbuf(uint32_t line);
void dpdk_free_mbuf(struct rte_mbuf *m);
#if (defined(ENABLE_DPDK_DEBUG))
#define dpdk_alloc_mbuf() __dpdk_alloc_mbuf(__LINE__)
#else
struct rte_mbuf *dpdk_alloc_mbuf(void);
#endif

void dpdk_dump_packet_1(uint8_t *buf, uint16_t buf_len, const char *func, uint32_t line);
#define dpdk_dump_packet(buf, buf_len)  dpdk_dump_packet_1((uint8_t *)buf, buf_len, __FUNCTION__, __LINE__)

uint8_t dpdk_get_first_core_id(void);
uint8_t *dpdk_get_cpus(void);
uint8_t dpdk_get_core_num(void);
int32_t dpdk_init(struct pcf_file *conf, void *ssct, void *extra_task);
void dpdk_deinit(void);
uint64_t dpdk_get_tx_offload(void);
int dpdk_packet_stat(char *str);
int dpdk_packet_stat_promu(comm_msg_fpu_stat *stat);
uint32_t dpdk_get_mtu(void);
void dpdk_set_mtu(uint32_t new_mtu);
void dpdk_show_mempool_stat(struct cli_def *cli, int show_all);
uint8_t *dpdk_get_mac(uint16_t portid);

#endif /* __DPDK_H__ */

