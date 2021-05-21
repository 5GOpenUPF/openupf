/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _FP_DPDK_ADAPTER_H__
#define _FP_DPDK_ADAPTER_H__

#ifdef __cplusplus
extern "C" {
#endif

#define FP_DROP_PORT_ID     0xFF

#pragma pack(1)
typedef struct  tag_fp_dpdk_tx_queue
{
    ros_rwlock_t        dpdk_tx_lock[COMM_MSG_MAX_DPDK_CORE_NUM];
    LIST                dpdk_tx_lst[COMM_MSG_MAX_DPDK_CORE_NUM];    /* DPDK send packet queue */
}fp_dpdk_tx_queue;
#pragma pack()


#define FP_SHM_MALLOC(name, size, align)    ros_malloc(size)
#define FP_SHM_FREE(name, ptr)              ros_free(ptr)

inline uint32_t fp_get_coreid(void);
inline uint64_t fp_get_cycle(void);
inline uint64_t fp_get_freq(void);
int      fp_channel_init(void);
int      fp_send_to_phy_port(void *wqe1, uint32_t port, uint8_t ucCsumEnable);
int      fp_send_to_chn_port(char *buf, uint32_t len);
int32_t  fp_init_prepare(void *conf);
int32_t  fp_init_prepare_deinit();
int      fp_get_input_stat(char *str);
int      fp_get_input_stat_promu(comm_msg_fpu_stat *stat);
void     fp_clean_input_stat(void);
uint32_t fp_get_mtu(void);
void     fp_set_mtu(uint32_t new_mtu);
void     fp_get_fast_head_symbol(char *symbol_name, uint32_t type);
void     fp_get_fast_bucket_symbol(char *symbol_name, uint32_t type);
void     fp_dpdk_add_cblk_buf(void *cblock);
void     fp_dpdk_send_cblk_buf(uint32_t lcore_id);

inline void __fp_fwd_snd_to_phy(void *m, uint16_t port_id, const char *func, int line);
#define fp_fwd_snd_to_phy(m, port_id) __fp_fwd_snd_to_phy(m, port_id, __FUNCTION__, __LINE__)


#define fp_free_pkt(m)  dpdk_free_mbuf(m)

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _FP_DPDK_ADAPTER_H__ */

