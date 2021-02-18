/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _FP_DPDK_ADAPTER_H__
#define _FP_DPDK_ADAPTER_H__

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(1)
typedef struct  tag_fp_dpdk_tx_queue
{
    ros_rwlock_t        dpdk_tx_lock[COMM_MSG_FP_STAT_CORE_NUM];
    LIST                dpdk_tx_lst[COMM_MSG_FP_STAT_CORE_NUM];    /* dpdk Need to send buffer queue */
}fp_dpdk_tx_queue;
#pragma pack()


#define FP_SHM_MALLOC(name, size, align)    ros_malloc(size)
#define FP_SHM_FREE(name, ptr)              ros_free(ptr)

inline uint16_t fp_port_to_index_public(uint16_t port);
inline uint32_t fp_get_coreid(void);
inline uint64_t fp_get_cycle(void);
inline uint64_t fp_get_freq(void);
inline void     __fp_free_pkt(void *buf, int line);
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

inline void __fp_fwd_snd_to_n3_phy(void *m, const char *func, int line);
inline void __fp_fwd_snd_to_n6_phy(void *m, const char *func, int line);
#define fp_fwd_snd_to_n3_phy(m) __fp_fwd_snd_to_n3_phy(m, __FUNCTION__, __LINE__)
#define fp_fwd_snd_to_n6_phy(m) __fp_fwd_snd_to_n6_phy(m, __FUNCTION__, __LINE__)
#define fp_fwd_snd_to_n4_phy(m) __fp_fwd_snd_to_n4_phy(m, __FUNCTION__, __LINE__)
#define fp_fwd_snd_to_n9_phy(m) __fp_fwd_snd_to_n9_phy(m, __FUNCTION__, __LINE__)


#define fp_free_pkt(m) \
    do { \
        __fp_free_pkt(m, __LINE__); \
    } while(0);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _FP_DPDK_ADAPTER_H__ */

