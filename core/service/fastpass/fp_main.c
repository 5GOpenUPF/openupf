/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include <unistd.h>
#include <getopt.h>
#include <time.h>

#include "common.h"
#include "util.h"
#include "platform.h"
#include "proto.h"
#include "comm_msg.h"
#include "key_extract.h"
#include "fp_msg.h"
#include "fp_main.h"
#include "fp_fwd_ipv4.h"
#include "fp_fwd_ipv6.h"
#include "fp_fwd_eth.h"
#include "fp_start.h"
#include "fp_qer.h"
#include "fp_recycle.h"
#include "fp_frag.h"
#include "fp_dns.h"

#ifndef ENABLE_OCTEON_III
#include "service.h"
#include <rte_mbuf.h>
#include <rte_meter.h>
#include "dpdk.h"
#include "fp_dpdk_adapter.h"

#else
#include "fp_nic_adapter.h"

#endif


CVMX_SHARED fp_fast_table       *fp_fast_table_head[COMM_MSG_FAST_BUTT] = {NULL};
CVMX_SHARED fp_inst_table       *fp_inst_table_head = NULL;
CVMX_SHARED fp_far_table        *fp_far_table_head = NULL;
CVMX_SHARED fp_bar_table        *fp_bar_table_head = NULL;
CVMX_SHARED fp_qer_table        *fp_qer_table_head = NULL;
CVMX_SHARED fp_urr_mac_table    *fp_mac_table_head = NULL;
CVMX_SHARED fp_pure_buff        *fp_frag_buff_head = NULL;
extern CVMX_SHARED fp_buff_pool *fp_buff_pool_head;

CVMX_SHARED uint8_t *fp_fast_table_entry_pool_free = NULL;
CVMX_SHARED uint8_t *fp_fast_table_shadow_pool_free = NULL;

CVMX_SHARED uint32_t fp_host_n3_local_ip;
CVMX_SHARED uint8_t  fp_host_n3_local_ipv6[IPV6_ALEN];
CVMX_SHARED uint32_t fp_net_n3_local_ip;
CVMX_SHARED uint64_t fp_n3_local_mac;

CVMX_SHARED uint32_t fp_host_n6_local_ip;
CVMX_SHARED uint32_t fp_net_n6_local_ip;
CVMX_SHARED uint8_t  fp_host_n6_local_ipv6[IPV6_ALEN];
CVMX_SHARED uint64_t fp_n6_local_mac;

CVMX_SHARED uint32_t fp_host_n4_local_ip;
CVMX_SHARED uint32_t fp_net_n4_local_ip;
CVMX_SHARED uint8_t  fp_host_n4_local_ipv6[IPV6_ALEN];
CVMX_SHARED uint64_t fp_n4_local_mac;

CVMX_SHARED uint32_t fp_host_n9_local_ip;
CVMX_SHARED uint32_t fp_net_n9_local_ip;
CVMX_SHARED uint8_t  fp_host_n9_local_ipv6[IPV6_ALEN];
CVMX_SHARED uint64_t fp_n9_local_mac;

CVMX_SHARED uint16_t fp_extension_type = 17516;
CVMX_SHARED uint8_t  fp_head_enrich_enable = 1;

/* Need to configure */
CVMX_SHARED comm_msg_system_config_t fp_config_info;

CVMX_SHARED uint32_t fp2sp_first_pkt_stat[COMM_MSG_FP_STAT_BUTT][COMM_MSG_FP_STAT_CORE_NUM];

CVMX_SHARED ros_rwlock_t fp_sock_lock[FP_SOCK_BUTT];

CVMX_SHARED fpu_Signaling_trace_t fpu_sig_trace[MAX_TRACE_FLOW_NUM];
CVMX_SHARED	fpu_Signaling_trace_ueip_t fpu_sig_trace_ueip = {0};

/* Capture packet to spu */
CVMX_SHARED uint32_t fp_capture_pkt_to_spu = 0;

CVMX_SHARED uint16_t fp_c_vlan_id[EN_PORT_BUTT] = {0}, fp_s_vlan_id[EN_PORT_BUTT] = {0};
CVMX_SHARED uint16_t fp_c_vlan_type[EN_PORT_BUTT], fp_s_vlan_type[EN_PORT_BUTT];

CVMX_SHARED fp_connect_mb_channel_cfg fp_mb_chnl_cfg;

inline fp_connect_mb_channel_cfg *fp_get_mb_chnl_config(void)
{
    return &fp_mb_chnl_cfg;
}

void fp_trace_capture_packet(int trace_flag, void *mbuf)
{
    if (trace_flag) {
        ros_rwlock_write_lock(&fpu_sig_trace_ueip.rwlock);
        fp_write_wireshark(rte_pktmbuf_mtod((struct rte_mbuf *)mbuf, void *),
            pkt_buf_data_len(mbuf));
        ros_rwlock_write_unlock(&fpu_sig_trace_ueip.rwlock);
    }
}

void fp_packet_stat_count(uint32_t stat_mod)
{
    uint32_t core_id = fp_get_coreid();

    if (core_id == LCORE_ID_ANY) {
        core_id = dpdk_get_first_core_id();
    }

    ++fp2sp_first_pkt_stat[stat_mod][core_id];
}

static inline uint32_t fp_packet_stat_get(uint32_t stat_mod, uint8_t core_id)
{
    return fp2sp_first_pkt_stat[stat_mod][core_id];
}

uint8_t *fp_get_port_mac(uint8_t port)
{
#ifndef ENABLE_OCTEON_III
    return dpdk_get_mac(fp_port_to_index_public(port));

#else
    static uint8_t g_error_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    return g_error_mac;
#endif
}

comm_msg_system_config_t *fp_config_var_get(void)
{
    return &fp_config_info;
}

uint32_t fp_get_time(void)
{
    return ros_getime();
}

void fp_forward_pkt_to_sp(fp_packet_info *pkt_info, fp_fast_entry *entry,
    int trace_flag, uint8_t pkt_type)
{
#ifdef RECORD_FAST_INFO_NEW_VER
#else
    /* Set fast ID after pkt header tail */
    SET_FAST_TID(pkt_info->buf, entry->index);
    SET_FAST_TYPE(pkt_info->buf, pkt_type);
#endif
    LOG_TRACE(FASTPASS, DEBUG, trace_flag,
        "Sent packet to sp, head_type: %d, fast_tid: %u", pkt_type, entry->index);

    /* Not found matched item, forward to sp */
    if (unlikely(ERROR == fp_send_to_chn_port(rte_pktmbuf_mtod((struct rte_mbuf *)pkt_info->arg, char *),
                    rte_pktmbuf_data_len((struct rte_mbuf *)pkt_info->arg)))) {
        LOG_TRACE(FASTPASS, ERR, trace_flag,
            "forward ipv4 packet to sp port failed!");
    }
}

void fp_forward_pkt_buf_to_sp(char *buf, uint32_t len, fp_fast_entry *entry,
    int trace_flag, uint8_t pkt_type)
{
#ifdef RECORD_FAST_INFO_NEW_VER
    /* Record fast ID and fast type */
    SET_FAST_TID(&buf[len], entry->index);
    SET_FAST_TYPE(&buf[len], pkt_type);
    len += RECORD_FAST_INFO_LEN;
#else
    /* Set fast ID after pkt header tail */
    SET_FAST_TID(buf, entry->index);
    SET_FAST_TYPE(buf, pkt_type);
#endif
    LOG_TRACE(FASTPASS, DEBUG, trace_flag,
        "Sent packet to sp, fast_tid:%u", entry->index);

    /* Not found matched item, forward to sp */
    if (unlikely(ERROR == fp_send_to_chn_port(buf, len))) {
        LOG_TRACE(FASTPASS, ERR, trace_flag, "forward ipv4 packet to sp port failed!");
    }
}

int fp_phy_pkt_entry(char *buf, int len, uint16_t port_id, void *arg)
{
    struct packet_desc  desc = {.buf = buf, .len = len, .offset = 0};
    fp_packet_info      pkt_info = {.buf = buf, .len = len, .arg = arg};

    /* 后续考虑绑定多个端口可以使用port_id参数作为判断条件 */

#if (defined(ENABLE_DPDK_DEBUG))
    dpdk_mbuf_record(((struct rte_mbuf *)arg)->buf_addr, __LINE__);

    if (unlikely(0 == len)) {
        LOG(FASTPASS, ERR, "ERROR: buf(%p), len: %d, arg(%p), core_id: %hu", buf, len, arg, fp_get_coreid());
        dpdk_dump_packet(buf, 64);
        fp_free_pkt(arg);
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
        return -1;
    }
#endif

    if (unlikely(!fp_start_is_run())) {
        fp_free_pkt(arg);
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
        LOG(FASTPASS, ERR,
            "recv buf %p, len %d, but system is not configured!", buf, len);
        return -1;
    }

    if (unlikely(packet_dissect(&desc, &pkt_info.match_key) < 0)) {
        LOG(FASTPASS, PERIOD, "packet dissect failed!");
        fp_free_pkt(arg);
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
        return -1;
    }

    /* Distinguish between Ethernet II and 802.3 */
    if (likely(0 == FLOW_MASK_FIELD_ISSET(pkt_info.match_key.field_offset, FLOW_FIELD_ETHERNET_DL))) {
        /* Ethernet II should be >= 1536(0x0600) */

        LOG(FASTPASS, PERIOD, "Recv Ethernet II packet");

        if (likely(FLOW_MASK_FIELD_ISSET(pkt_info.match_key.field_offset, FLOW_FIELD_L1_IPV4))) {
            fp_pkt_ipv4_entry(&pkt_info);
        }
        else if (FLOW_MASK_FIELD_ISSET(pkt_info.match_key.field_offset, FLOW_FIELD_L1_IPV6)) {
            fp_pkt_ipv6_entry(&pkt_info);
        }
        else {
            struct pro_arp_hdr *arp_hdr = FlowGetARPHeader(&pkt_info.match_key);
            if (arp_hdr) {
                LOG(FASTPASS, PERIOD, "Recv ARP packet----");

                /* N3 arp */
                fp_free_pkt(arg);
                fp_packet_stat_count(COMM_MSG_FP_STAT_ARP);
                return 0;
            }
            else {
                fp_free_pkt(arg);
                fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
                return 0;
            }
        }

    }
    else {
        /* 802.3 should be <= 1500 */
        LOG(FASTPASS, PERIOD, "Recv IEEE 802.3 packet");

        //fp_free_pkt(arg);
        fp_pkt_eth_n6_entry(&pkt_info);
    }

    LOG(FASTPASS, RUNNING,
        "handle packet(buf %p, len %d) finished!\r\n", buf, len);

    return 0;
}

int fp_phy_n4_pkt_entry(char *buf, int len, void *arg)
{
    struct packet_desc  desc = {.buf = buf, .len = len, .offset = 0};
    fp_packet_info      pkt_info = {.buf = buf, .len = len, .arg = arg};

    if (!fp_start_is_run()) {
        fp_free_pkt(arg);
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
        LOG(FASTPASS, ERR,
            "recv buf %p, len %d, but system is not configured!", buf, len);
        return -1;
    }

    if (unlikely(packet_dissect(&desc, &pkt_info.match_key) < 0)) {
        LOG(FASTPASS, PERIOD, "packet dissect failed!");
        fp_free_pkt(arg);
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
        return -1;
    }

    /* Distinguish between Ethernet II and 802.3 */
    if (likely(0 == FLOW_MASK_FIELD_ISSET(pkt_info.match_key.field_offset, FLOW_FIELD_ETHERNET_LLC))) {
        /* Ethernet II should be >= 1536(0x0600) */

        if (likely(FLOW_MASK_FIELD_ISSET(pkt_info.match_key.field_offset, FLOW_FIELD_L1_IPV4))) {
            fp_pkt_ipv4_n4_entry(&pkt_info);
        }
        else if (FLOW_MASK_FIELD_ISSET(pkt_info.match_key.field_offset, FLOW_FIELD_L1_IPV6)) {
            fp_pkt_ipv6_n4_entry(&pkt_info);
        }
        else {
            fp_free_pkt(arg);
            fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
            return 0;
        }

    }
    else {
        /* 802.3 should be <= 1500 */
        fp_free_pkt(arg);
    }

    LOG(FASTPASS, RUNNING,
        "handle n4 packet(buf %p, len %d) finished!\r\n", buf, len);

    return 0;
}

inline void *fp_fast_table_get(uint32_t type)
{
    return fp_fast_table_head[type];
}

inline void *fp_inst_table_get()
{
    return fp_inst_table_head;
}

inline void *fp_far_table_get()
{
    return fp_far_table_head;
}

inline void *fp_bar_table_get()
{
    return fp_bar_table_head;
}

inline void *fp_qer_table_get()
{
    return fp_qer_table_head;
}

inline void *fp_mac_table_get()
{
    return fp_mac_table_head;
}

inline void *fp_buff_pool_get()
{
    return fp_buff_pool_head;
}

inline void *fp_frag_buff_get()
{
    return fp_frag_buff_head;
}

int64_t fp_fast_table_init(uint32_t cfg_bucket_number, uint32_t cfg_table_size)
{
    int32_t res_no = 0;
    uint32_t bucket_num, bit_no, flag, size, item, table_size, type;
    uint8_t  *tmp;
    uint64_t ret64;
    int64_t  total_mem = 0;
    fp_fast_table  *head;
    fp_fast_entry  *entry;         /* point to entry pool */
    fp_fast_shadow *shadow;        /* point to shadow pool */
    char symbol_name[32];

    /* Bucket number must be power of 2 */
    bucket_num = cfg_bucket_number;
    for (bit_no = 0; bit_no < 32; bit_no++) {
        if (bucket_num == (uint32_t)(1 << bit_no))
        {
            flag = G_TRUE;
            break;
        }
    }
    if ((bucket_num != 0)&&(flag != G_TRUE)) {
        LOG(FASTPASS, ERR,
        "bucket number(%d) must be power of 2.", bucket_num);
        return -1;
    }
    if (!cfg_table_size) {
        LOG(FASTPASS, ERR, "table size(%d) is zero.", cfg_table_size);
        return -1;
    }
    table_size = cfg_table_size;

    /* Create entry pool */
    size = table_size * FP_CACHE_LINE + FP_CACHE_LINE;
    total_mem += size;
    tmp = (uint8_t *)FP_SHM_MALLOC(GLB_FAST_TABLE_POOL_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        return -1;
    }
    fp_fast_table_entry_pool_free = tmp;
    entry = (fp_fast_entry *)(uint64_t)(roundup((uint64_t)tmp, FP_CACHE_LINE));

    LOG(FASTPASS, RUNNING,
        "alloc port entry pool, address %p(%p), %d bytes for %d entries.",
        tmp, entry, size, bucket_num);

    /* Create entry shadow */
    size = table_size * sizeof(fp_fast_shadow);
    total_mem += size;
    tmp = (uint8_t *)FP_SHM_MALLOC(GLB_FAST_SHADOW_POOL_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        return -1;
    }
    shadow = (fp_fast_shadow *)tmp;
    for (item = 0; item < table_size; item++) {
        ros_rwlock_init(&shadow[item].rwlock);
        lstInit(&shadow[item].list);
        shadow[item].index = item;
        shadow[item].entry = NULL;
    }
    fp_fast_table_shadow_pool_free = tmp;
    LOG(FASTPASS, RUNNING,
        "alloc port shadow, address %p, %d bytes for %d entries.",
        tmp, size, bucket_num);

    /* Create a pool for all table(entry + shadow) */
    /* 3 types buckets share same resource pool */
    res_no = Res_CreatePool();
    if (res_no < 0) {
        return -1;
    }
    ret64 = Res_AddSection(res_no, 0, 0, table_size);
    if (ret64 == G_FAILURE) {
        return -1;
    }

    /* Create bucket */
    for (type = COMM_MSG_FAST_IPV4; type < COMM_MSG_FAST_BUTT; type++)
    {
        /* calculate memory size */
        size = bucket_num * sizeof(fp_fast_bucket) + sizeof(fp_fast_table) + CACHE_LINE_SIZE;

        /* alloc memory */
        fp_get_fast_head_symbol(symbol_name, type);
        tmp = (uint8_t *)FP_SHM_MALLOC(symbol_name, size, CACHE_LINE_SIZE);
        if (!tmp) {
            return -1;
        }
        ros_memset(tmp, 0, size);
        total_mem += size;
        LOG(FASTPASS, RUNNING,
            "alloc port type %d bucket, address %p, %d bytes for %d buckets.",
            type, tmp, size, bucket_num);

        /* set fast header */
        fp_fast_table_head[type] = (fp_fast_table *)tmp;

        /* set bucket memory */
        tmp = (uint8_t *)tmp + sizeof(fp_fast_table);
        tmp = (uint8_t *)roundup(tmp, CACHE_LINE_SIZE);

        /* init bucket */
        head = fp_fast_table_head[type];
        head->bucket = (fp_fast_bucket *)tmp;
        for (item = 0; item < bucket_num; item++) {
            head->bucket[item].hash_tree = NULL;
            ros_rwlock_init(&head->bucket[item].rwlock);
        }

        head->entry  = entry;
        head->shadow = shadow;
        head->res_no = res_no;

        head->port_no     = 0;
        head->port_type   = type;
        head->entry_max   = table_size;
        head->bucket_mask = bucket_num - 1;

        LOG(FASTPASS, RUNNING,
            "port type %d bucket init success.", type);

    }

    LOG(FASTPASS, RUNNING,
        "memory in total %ld(%ld M) bytes!\r\n",
        total_mem, (total_mem >> 20));

    return total_mem;
}

int64_t fp_inst_table_init()
{
    int32_t res_no = 0;
    uint32_t size, item, table_size;
    uint8_t  *tmp = NULL;
    int64_t  total_mem = 0;
    uint64_t ret64;
    fp_inst_table       *head = NULL;
    fp_inst_entry       *entry = NULL;         /* point to entry pool */
    fp_far_entry        *far_entry = NULL;
    fp_far_table        *far_head = NULL;
    fp_bar_entry        *bar_entry = NULL;
    fp_bar_table        *bar_head = NULL;
    fp_qer_entry        *qer_entry = NULL;
    fp_qer_table        *qer_head = NULL;
    fp_urr_mac_table    *mac_head = NULL;
    comm_msg_system_config_t *fp_config = fp_config_var_get();

    /* 1. Init inst table */
    if (fp_config->session_num) {
        table_size = fp_config->session_num * MAX_PDR_NUM;
    }
    else {
        return -1;
    }

    /* Alloc one big block memory, include head and table */
    /* Put head here, can decrease tlb change */
    size = table_size * sizeof(fp_inst_entry) + sizeof(fp_inst_table) + CACHE_LINE_SIZE;
    tmp = (uint8_t *)FP_SHM_MALLOC(GLB_INST_TABLE_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        return -1;
    }
    ros_memset(tmp, 0, size);
    total_mem += size;

    fp_inst_table_head = (fp_inst_table *)tmp;

    /* Get inst table memory */
    tmp = (uint8_t *)tmp + sizeof(fp_inst_table);
    tmp = (uint8_t *)roundup(tmp, CACHE_LINE_SIZE);

    entry = (fp_inst_entry *)tmp;
    for (item = 0; item < table_size; item++) {
        entry[item].index = item;
        entry[item].valid = G_FALSE;
        ros_rwlock_init(&entry[item].rwlock);
    }

    head = fp_inst_table_get();
    head->entry = entry;

    res_no = Res_CreatePool();
    if (res_no < 0) {
        return -1;
    }

    ret64 = Res_AddSection(res_no, 0, 0, table_size);
    if (ret64 == G_FAILURE) {
        return -1;
    }
    head->res_no    = res_no;
    head->entry_max = table_size;

    /* create dirty resource pool */
    head->res_stat = Res_MarkCreate(table_size);
    head->cur_stat_entry = -1;
#ifndef ENABLE_OCTEON_III
{
    head->stat_timer = ros_timer_create(ROS_TIMER_MODE_PERIOD,
        1 * ROS_TIMER_TICKS_PER_SEC, (uint64_t)0,
        fp_msg_inst_second_timer);

    /* start it */
    ros_timer_start(head->stat_timer);
}
#else
    fp_timer_func = fp_msg_inst_second_timer;
#endif

    /* add orphan instance entry only in init */
    head->entry[COMM_MSG_ORPHAN_NUMBER].config.choose.d.flag_far1 = 1;
    head->entry[COMM_MSG_ORPHAN_NUMBER].config.far_index1 = 0;
    head->entry[COMM_MSG_ORPHAN_NUMBER].valid = G_TRUE;
    dl_list_init(&head->entry[COMM_MSG_ORPHAN_NUMBER].far_node);
    dl_list_init(&head->entry[COMM_MSG_ORPHAN_NUMBER].far2_node);

    if (G_FAILURE == Res_AllocTarget(head->res_no, 0, COMM_MSG_ORPHAN_NUMBER)) {
        LOG(FASTPASS, ERR, "add orphan instance entry failed.");
        return -1;
    }

    LOG(FASTPASS, RUNNING,
        "alloc instance pool %p, %d bytes for %d entries."
        " Cost memory %d(%dM) bytes.",
        tmp, size, table_size, size, size>>20);

    /* 2. Init far table */
    table_size = fp_config->session_num * MAX_FAR_NUM;
    size = table_size * sizeof(fp_far_entry) + sizeof(fp_far_table) + CACHE_LINE_SIZE;
    tmp = (uint8_t *)FP_SHM_MALLOC(GLB_FAR_TABLE_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        return -1;
    }
    ros_memset((uint8_t *)tmp, 0, size);
    total_mem += size;

    fp_far_table_head = (fp_far_table *)tmp;

    tmp = (uint8_t *)tmp + sizeof(fp_far_table);
    tmp = (uint8_t *)roundup(tmp, CACHE_LINE_SIZE);

    far_entry = (fp_far_entry *)tmp;
    for (item = 0; item < table_size; item++) {
        far_entry[item].index = item;
        far_entry[item].valid = G_FALSE;
        ros_rwlock_init(&far_entry[item].rwlock);
        dl_list_init(&far_entry[item].inst_lst);
        dl_list_init(&far_entry[item].inst2_lst);
    }

    far_head = fp_far_table_get();
    far_head->entry = far_entry;

    res_no = Res_CreatePool();
    if (res_no < 0) {
        return -1;
    }

    ret64 = Res_AddSection(res_no, 0, 0, table_size);
    if (ret64 == G_FAILURE) {
        return -1;
    }
    far_head->res_no    = res_no;
    far_head->entry_max = table_size;

    /* add orphan far entry */
    if (G_FAILURE == Res_AllocTarget(far_head->res_no, 0, COMM_MSG_ORPHAN_NUMBER)) {
        LOG(FASTPASS, ERR, "create orphan far failed.");
        return -1;
    }
    far_head->entry[COMM_MSG_ORPHAN_NUMBER].config.action.d.drop = 1;
    far_head->entry[COMM_MSG_ORPHAN_NUMBER].valid = G_TRUE;
    dl_list_add_tail(&far_head->entry[COMM_MSG_ORPHAN_NUMBER].inst_lst,
        &head->entry[COMM_MSG_ORPHAN_NUMBER].far_node);

    LOG(FASTPASS, RUNNING,
        "alloc far pool %p, %d bytes for %d entries."
        " Cost memory %d(%dM) bytes.",
        tmp, size, table_size, size, size>>20);


    /* 3. Init bar table */
    table_size = fp_config->session_num * MAX_BAR_NUM;
    size = table_size * sizeof(fp_bar_entry) + sizeof(fp_bar_table) + CACHE_LINE_SIZE;
    tmp = (uint8_t *)FP_SHM_MALLOC(GLB_BAR_TABLE_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        return -1;
    }
    ros_memset((uint8_t *)tmp, 0, size);
    total_mem += size;

    fp_bar_table_head = (fp_bar_table *)tmp;

    tmp = (uint8_t *)tmp + sizeof(fp_bar_table);
    tmp = (uint8_t *)roundup(tmp, CACHE_LINE_SIZE);

    bar_entry = (fp_bar_entry *)tmp;
    for (item = 0; item < table_size; item++) {
        bar_entry[item].index = item;
        bar_entry[item].valid = G_FALSE;
        ros_rwlock_init(&bar_entry[item].rwlock);
    }

    bar_head = fp_bar_table_get();
    bar_head->entry = bar_entry;

    res_no = Res_CreatePool();
    if (res_no < 0) {
        return -1;
    }

    ret64 = Res_AddSection(res_no, 0, 0, table_size);
    if (ret64 == G_FAILURE) {
        return -1;
    }
    bar_head->res_no    = res_no;
    bar_head->entry_max = table_size;

    LOG(FASTPASS, RUNNING,
        "alloc bar pool %p, %d bytes for %d entries."
        " Cost memory %d(%dM) bytes.",
        tmp, size, table_size, size, size>>20);

    /* 5. Init qer table */
    table_size = fp_config->session_num * MAX_QER_NUM;
    size = table_size * sizeof(fp_qer_entry) + sizeof(fp_qer_table) + CACHE_LINE_SIZE;
    tmp = (uint8_t *)FP_SHM_MALLOC(GLB_QER_TABLE_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        return -1;
    }
    ros_memset(tmp, 0, size);
    total_mem += size;

    fp_qer_table_head = (fp_qer_table *)tmp;

    tmp = (uint8_t *)tmp + sizeof(fp_qer_table);
    tmp = (uint8_t *)roundup(tmp, CACHE_LINE_SIZE);

    qer_entry = (fp_qer_entry *)tmp;
    for (item = 0; item < table_size; item++) {
        qer_entry[item].index = item;
        qer_entry[item].valid = G_FALSE;
        ros_rwlock_init(&qer_entry[item].qos_lock);
    }

    qer_head = fp_qer_table_get();
    qer_head->entry = qer_entry;

    res_no = Res_CreatePool();
    if (res_no < 0) {
        return -1;
    }

    ret64 = Res_AddSection(res_no, 0, 0, table_size);
    if (ret64 == G_FAILURE) {
        return -1;
    }
    qer_head->res_no    = res_no;
    qer_head->entry_max = table_size;

    LOG(FASTPASS, RUNNING,
        "alloc qer pool %p, %d bytes for %d entries."
        " Cost memory %d(%dM) bytes.",
        tmp, size, table_size, size, size>>20);


    /* 6. Init mac table */
    table_size = fp_config->session_num * MAX_URR_NUM;
    size = table_size * sizeof(fp_urr_mac_entry) + sizeof(fp_urr_mac_table) + CACHE_LINE_SIZE;
    tmp = (uint8_t *)FP_SHM_MALLOC(GLB_MAC_TABLE_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        return -1;
    }
    ros_memset(tmp, 0, size);
    total_mem += size;

    fp_mac_table_head = (fp_urr_mac_table *)tmp;

    tmp = (uint8_t *)tmp + sizeof(fp_urr_mac_table);
    tmp = (uint8_t *)roundup(tmp, CACHE_LINE_SIZE);

    mac_head = fp_mac_table_get();
    mac_head->entry = (fp_urr_mac_entry *)tmp;

    res_no = Res_CreatePool();
    if (res_no < 0) {
        return -1;
    }

    ret64 = Res_AddSection(res_no, 0, 0, table_size);
    if (ret64 == G_FAILURE) {
        return -1;
    }
    mac_head->res_no    = res_no;
    mac_head->entry_max = table_size;

    LOG(FASTPASS, RUNNING,
        "alloc mac pool %p, %d bytes for %d entries."
        " Cost memory %d(%dM) bytes.",
        tmp, size, table_size, size, size>>20);

    return total_mem;
}

void fp_collect_status(comm_msg_fpu_stat *stat)
{
    uint32_t pkt_cnt = 0;
    uint32_t iloop, stat_mod_cnt;

    fp_get_input_stat_promu(stat);

    for (stat_mod_cnt = 0; stat_mod_cnt < COMM_MSG_FP_STAT_BUTT; ++stat_mod_cnt) {
        pkt_cnt = 0;
        for (iloop = 0; iloop < COMM_MSG_FP_STAT_CORE_NUM; iloop++) {
            pkt_cnt += fp_packet_stat_get(stat_mod_cnt, iloop);
        }
        stat->external_stat[stat_mod_cnt] = htonl(pkt_cnt);
    }

    if (fp_start_is_run()) {
        fp_fast_table    *fast_head = fp_fast_table_get(COMM_MSG_FAST_IPV4);
        fp_inst_table    *inst_head = fp_inst_table_get();
        fp_far_table     *far_head = fp_far_table_get();
        fp_bar_table     *bar_head = fp_bar_table_get();
        fp_qer_table     *qer_head = fp_qer_table_get();
        fp_buff_pool     *buff_head = fp_buff_pool_get();
        fp_urr_mac_table *mac_head = fp_mac_table_get();


        /* fast resource */
        stat->fp_fast_stat = htonl(Res_GetAlloced(fast_head->res_no));

        /* instance resource */
        stat->fp_inst_stat = htonl(Res_GetAlloced(inst_head->res_no));

        /* far resource */
        stat->fp_far_stat = htonl(Res_GetAlloced(far_head->res_no));

        /* qer resource */
        stat->fp_qer_stat = htonl(Res_GetAlloced(qer_head->res_no));

        /* bar resource */
        stat->fp_bar_stat = htonl(Res_GetAlloced(bar_head->res_no));

        /* cblock resource */
        stat->fp_cblk_stat = htonl(Res_GetAlloced(buff_head->res_cblk));

        /* block resource */
        stat->fp_block_stat = htonl(Res_GetAlloced(buff_head->res_block));

        /* mac resource */
        stat->fp_mac_stat = htonl(Res_GetAlloced(mac_head->res_no));
    }
}

int32_t fp_init_phaseI()
{
    int       ret, cnt;
    int64_t   mem_cost;

    /* 3.Init resource management */
    ret = Res_Init(30, 30, 1000*FP_1K);
    if (ret != G_TRUE) {
        LOG(FASTPASS, MUST, "Res_Init failed!");
        return -1;
    }

    for (cnt = FP_SOCK_TO_SPU_CTRL; cnt < FP_SOCK_BUTT; ++cnt) {
        ros_rwlock_init(&fp_sock_lock[cnt]);
    }

    /* 4.Configure buffer pool */
    mem_cost = fp_buff_pool_init(BUFFER_BLOCK_DEFAULT_NUM, BUFFER_BLOCK_DEFAULT_SIZE, BUFFER_CBLOCK_DEFAULT_NUM);
    if (mem_cost < 0) {
        LOG(FASTPASS, MUST, "buffer init failed!");
        return -1;
    }
    LOG(FASTPASS, RUNNING,
        "alloc buff block, %d entries cost memory %ld(%ld M) bytes.\r\n",
        65536, mem_cost, mem_cost >> 20);

    fp_frag_buff_head = fp_pure_buff_init(8192, 65536, &mem_cost);
    if (!fp_frag_buff_head) {
        LOG(FASTPASS, MUST, "frag pool init failed!");
        return -1;
    }
    LOG(FASTPASS, RUNNING,
        "alloc frag block, %d entries cost memory %ld(%ld M) bytes.\r\n",
        8192, mem_cost, mem_cost >> 20);

    /* 5.Configure channels which coneect to other dockers */
    ret = fp_channel_init();
    if (ret < 0) {
        LOG(FASTPASS, MUST, "channel init failed!");
        return -1;
    }

    LOG(FASTPASS, MUST, "------phase I init success------\n");
    return 0;
}

void fp_init_phaseI_deinit(void)
{
    if (fp_buff_pool_head) {

        /* Block is another memory block, free it first */
        if (fp_buff_pool_head->block) {
            FP_SHM_FREE(GLB_BLOCK_POOL_SYMBOL, fp_buff_pool_head->block);
            fp_buff_pool_head->block = NULL;
            Res_DestroyPool(fp_buff_pool_head->res_block);
        }

        Res_DestroyPool(fp_buff_pool_head->res_cblk);
        FP_SHM_FREE(GLB_BUFF_HEAD_SYMBOL, fp_buff_pool_head);
        fp_buff_pool_head = NULL;
    }

    if (fp_frag_buff_head) {

        /* Block is another memory block, free it first */
        if (fp_frag_buff_head->block) {
            FP_SHM_FREE(GLB_BLOCK_POOL_SYMBOL, fp_frag_buff_head->block);
            fp_frag_buff_head->block = NULL;
            Res_DestroyPool(fp_frag_buff_head->res_block);
        }

        FP_SHM_FREE(GLB_BUFF_HEAD_SYMBOL, fp_frag_buff_head);
        fp_frag_buff_head = NULL;
    }
}

int32_t fp_init_phaseII(void)
{
    int64_t   ret;
    /* First add the memory used by ros_timer */
#ifndef ENABLE_OCTEON_III
    int64_t   total_mem = sizeof(struct ros_timer) * ROS_TIMER_EACH_CORE_MAX_NUM;
#else
    int64_t   total_mem = 0;
#endif
    comm_msg_system_config_t *fp_config = fp_config_var_get();

    /* 1.Configure port fast pool */
    ret = fp_fast_table_init(fp_config->fast_bucket_num,
                fp_config->fast_num);
    if (ret < 0) {
        LOG(FASTPASS, MUST, "port init failed(%ld)!", ret);
        return -1;
    }
    total_mem += ret;

    /* Init fast entries recycle function */
    fp_recycle_init(fp_config->fast_num);


    /* 2.Configure instance pool */
    ret = fp_inst_table_init();
    if (ret < 0) {
        LOG(FASTPASS, MUST, "instance init failed!");
        return -1;
    }
    total_mem += ret;

    /* 3. Configure dns pool */
    ret = fp_dns_node_init(fp_config->dns_num);
    if (ret < 0) {
        LOG(FASTPASS, MUST, "DNS init failed!");
        return -1;
    }
    total_mem += ret;

    /* 4.Configure route pool */
    /* Don't support route parse on fastpass */

    /* 5.Update local ip and mac */
    fp_net_n3_local_ip      = htonl(fp_config->upf_ip[EN_PORT_N3].ipv4);
    fp_host_n3_local_ip     = fp_config->upf_ip[EN_PORT_N3].ipv4;
	memcpy(fp_host_n3_local_ipv6, fp_config->upf_ip[EN_PORT_N3].ipv6, IPV6_ALEN);
    memcpy(((uint8_t *)(&fp_n3_local_mac)) + 2, fp_get_port_mac(EN_PORT_N3), ETH_ALEN);

    fp_net_n6_local_ip      = htonl(fp_config->upf_ip[EN_PORT_N6].ipv4);
    fp_host_n6_local_ip     = fp_config->upf_ip[EN_PORT_N6].ipv4;
	memcpy(fp_host_n6_local_ipv6, fp_config->upf_ip[EN_PORT_N6].ipv6, IPV6_ALEN);
    memcpy(((uint8_t *)(&fp_n6_local_mac)) + 2, fp_get_port_mac(EN_PORT_N6), ETH_ALEN);

	fp_net_n4_local_ip      = htonl(fp_config->upf_ip[EN_PORT_N4].ipv4);
    fp_host_n4_local_ip     = fp_config->upf_ip[EN_PORT_N4].ipv4;
	memcpy(fp_host_n4_local_ipv6, fp_config->upf_ip[EN_PORT_N4].ipv6, IPV6_ALEN);
    memcpy(((uint8_t *)(&fp_n4_local_mac)) + 2, fp_get_port_mac(EN_PORT_N4), ETH_ALEN);

    fp_net_n9_local_ip      = htonl(fp_config->upf_ip[EN_PORT_N9].ipv4);
    fp_host_n9_local_ip     = fp_config->upf_ip[EN_PORT_N9].ipv4;
	memcpy(fp_host_n9_local_ipv6, fp_config->upf_ip[EN_PORT_N9].ipv6, IPV6_ALEN);
    memcpy(((uint8_t *)(&fp_n9_local_mac)) + 2, fp_get_port_mac(EN_PORT_N9), ETH_ALEN);

    LOG(FASTPASS, MUST,
        "------phase II init success(cost memory %ld M)------\n",
        total_mem >> 20);

    return 0;
}

void fp_init_phaseII_deinit(void)
{
    EN_COMM_MSG_FAST_TYPE   type;
    char        symbol_name[32];

    /* First clear fast entry */
    for (type = COMM_MSG_FAST_IPV4; type < COMM_MSG_FAST_BUTT; type++) {
        if (fp_fast_table_head[type]) {
            fp_fast_clear(type);
        }
    }

    /* Free entry and shadow */
    if (fp_fast_table_entry_pool_free) {
        FP_SHM_FREE(GLB_FAST_TABLE_POOL_SYMBOL, fp_fast_table_entry_pool_free);
        fp_fast_table_entry_pool_free = NULL;
    }
    if (fp_fast_table_shadow_pool_free) {
        FP_SHM_FREE(GLB_FAST_SHADOW_POOL_SYMBOL, fp_fast_table_shadow_pool_free);
        fp_fast_table_shadow_pool_free = NULL;
    }

    /* 3 types buckets share same table resource, free any one will be ok */
    if (fp_fast_table_head[COMM_MSG_FAST_IPV4]) {
        Res_DestroyPool(fp_fast_table_head[COMM_MSG_FAST_IPV4]->res_no);
    }

    /* Free 3 types buckets */
    for (type = COMM_MSG_FAST_IPV4; type < COMM_MSG_FAST_BUTT; type++)
    {
        if (fp_fast_table_head[type]) {
            fp_get_fast_head_symbol(symbol_name, type);
            FP_SHM_FREE(symbol_name, fp_fast_table_head[type]);
            fp_fast_table_head[type] = NULL;
        }
    }

    if (fp_inst_table_head) {
        /* stop it */
#ifndef ENABLE_OCTEON_III
        ros_timer_del(fp_inst_table_head->stat_timer);
        sleep(2); /* Let the running timer finish */
#else
        fp_timer_func = NULL;
#endif
        Res_DestroyPool(fp_inst_table_head->res_no);
        FP_SHM_FREE(GLB_INST_TABLE_SYMBOL, fp_inst_table_head);
        fp_inst_table_head = NULL;
    }

    if (fp_far_table_head) {
        Res_DestroyPool(fp_far_table_head->res_no);
        FP_SHM_FREE(GLB_FAR_TABLE_SYMBOL, fp_far_table_head);
        fp_far_table_head = NULL;
    }

    if (fp_bar_table_head) {
        Res_DestroyPool(fp_bar_table_head->res_no);
        FP_SHM_FREE(GLB_BAR_TABLE_SYMBOL, fp_bar_table_head);
        fp_bar_table_head = NULL;
    }

    if (fp_qer_table_head) {
        Res_DestroyPool(fp_qer_table_head->res_no);
        FP_SHM_FREE(GLB_QER_TABLE_SYMBOL, fp_qer_table_head);
        fp_qer_table_head = NULL;
    }

    if (fp_mac_table_head) {
        Res_DestroyPool(fp_mac_table_head->res_no);
        FP_SHM_FREE(GLB_MAC_TABLE_SYMBOL, fp_mac_table_head);
        fp_mac_table_head = NULL;
    }

    fp_dns_deinit();

    /* When reconnect to spu, also need call deinit/init to initialize phase II */
    /* Resource module don't reinit because its resource size don't change */
    //Res_DeInit();
}

void fp_deinit(void)
{
    fp_init_prepare_deinit();
    fp_init_phaseI_deinit();
    fp_init_phaseII_deinit();
}

int fp_ip_show(struct cli_def *cli,int argc, char **argv)
{
    cli_print(cli,"n3  port: %08x %lx\r\n",
        fp_host_n3_local_ip, fp_n3_local_mac);
    cli_print(cli,"n6  port: %08x %lx\r\n",
        fp_host_n6_local_ip, fp_n6_local_mac);

    return 0;
}

int fp_show_signal_trace_ueip(struct cli_def *cli,int argc, char **argv)
{
	cli_print(cli,"sig trace ueip: %x\r\n", fpu_sig_trace_ueip.ueip);
	return 0;
}

int fp_show_packet_stat(struct cli_def *cli,int argc, char **argv)
{
    uint32_t iloop;
    uint32_t pkt_cnt = 0, stat_mod_cnt;
    char str[2048];
    fp_buff_pool *head = (fp_buff_pool *)fp_buff_pool_get();

    fp_get_input_stat(str);
    cli_print(cli,"%s\r\n", str);

    for (stat_mod_cnt = 0; stat_mod_cnt < COMM_MSG_FP_STAT_BUTT; ++stat_mod_cnt) {
        char mod_name[128];

        pkt_cnt = 0;
        for (iloop = 0; iloop < COMM_MSG_FP_STAT_CORE_NUM; iloop++) {
            pkt_cnt += fp_packet_stat_get(stat_mod_cnt, iloop);
        }

        switch (stat_mod_cnt) {
            case COMM_MSG_FP_STAT_N3_MATCH:
                sprintf(mod_name, "N3_MATCH");
                break;
            case COMM_MSG_FP_STAT_N3_NOMATCH:
                sprintf(mod_name, "N3_NOMATCH");
                break;
            case COMM_MSG_FP_STAT_N3_ECHO:
                sprintf(mod_name, "N3_ECHO");
                break;
            case COMM_MSG_FP_STAT_N6_MATCH:
                sprintf(mod_name, "N6_MATCH");
                break;
            case COMM_MSG_FP_STAT_N6_NOMATCH:
                sprintf(mod_name, "N6_NOMATCH");
                break;
            case COMM_MSG_FP_STAT_MOD_FAST:
                sprintf(mod_name, "MOD_FAST");
                break;
            case COMM_MSG_FP_STAT_FROM_SPU:
                sprintf(mod_name, "FROM_SPU");
                break;
            case COMM_MSG_FP_STAT_REPORT_REQ:
                sprintf(mod_name, "REPORT_REQ");
                break;
            case COMM_MSG_FP_STAT_ARP:
                sprintf(mod_name, "ARP");
                break;
			case COMM_MSG_FP_STAT_ICMP:
                sprintf(mod_name, "ICMP");
                break;
            case COMM_MSG_FP_STAT_ROUTE:
                sprintf(mod_name, "ROUTE");
                break;
            case COMM_MSG_FP_STAT_UP_RECV:
                sprintf(mod_name, "UP_RECV");
                break;
            case COMM_MSG_FP_STAT_UP_FWD:
                sprintf(mod_name, "UP_FWD");
                break;
            case COMM_MSG_FP_STAT_UP_DROP:
                sprintf(mod_name, "UP_DROP");
                break;
            case COMM_MSG_FP_STAT_DOWN_RECV:
                sprintf(mod_name, "DOWN_RECV");
                break;
            case COMM_MSG_FP_STAT_DOWN_FWD:
                sprintf(mod_name, "DOWN_FWD");
                break;
            case COMM_MSG_FP_STAT_DOWN_DROP:
                sprintf(mod_name, "DOWN_DROP");
                break;
            case COMM_MSG_FP_STAT_UNSUPPORT_PKT:
                sprintf(mod_name, "UNSUPPORT_PKT");
                break;
            case COMM_MSG_FP_STAT_ERR_PROC:
                sprintf(mod_name, "ERR_PROC");
                break;

            default:
                sprintf(mod_name, "INDEX(%u)", stat_mod_cnt);
                break;
        }

        cli_print(cli,"%s: %u\r\n", mod_name, pkt_cnt);
    }

    if (NULL != head)
        cli_print(cli,"cur_cblock: %u\r\n", Res_GetAlloced(head->res_cblk));

#ifndef ENABLE_OCTEON_III
    if (argc > 0 && 0 == strncmp(argv[0], "all", 3)) {
        dpdk_show_mempool_stat(cli, 1);
    } else {
        dpdk_show_mempool_stat(cli, 0);
    }
#endif

    if (argc > 0 && 0 == strncmp(argv[0], "clean", strlen("clean"))) {
        fp_clean_input_stat();
        memset(fp2sp_first_pkt_stat, 0, sizeof(fp2sp_first_pkt_stat));
    }

    return 0;
}

int fp_conf_signal_trace(struct cli_def *cli,int argc, char **argv)
{
    fpu_Signaling_trace_t arg_st;
    uint32_t st_cnt = 0;

    if (argc < 2) {
        cli_print(cli,"Parameters too few...\r\n");
        goto err;
    }

    if (0 == strncmp(argv[1], "add", 3)) {
        if (argc < 7) {
            cli_print(cli,"Parameters too few...\r\n");
            goto err;
        }

        if (1 != inet_pton(AF_INET, argv[2], &arg_st.sip)) {
            LOG(FASTPASS, ERR, "inet_pton failed, error: %s.", strerror(errno));
            return -1;
        }
        if (1 != inet_pton(AF_INET, argv[3], &arg_st.dip)) {
            LOG(FASTPASS, ERR, "inet_pton failed, error: %s.", strerror(errno));
            return -1;
        }
        arg_st.sip = htonl(arg_st.sip);
        arg_st.dip = htonl(arg_st.dip);
        arg_st.spt = htons(atoi(argv[4]));
        arg_st.dpt = htons(atoi(argv[5]));
        arg_st.pro = atoi(argv[6]);
        arg_st.valid = 1;

        for (; st_cnt < MAX_TRACE_FLOW_NUM; ++st_cnt) {
            if (fpu_sig_trace[st_cnt].valid == 0) {
                memcpy(&fpu_sig_trace[st_cnt], &arg_st, sizeof(fpu_Signaling_trace_t));
                break;
            }
        }
        if (st_cnt >= MAX_TRACE_FLOW_NUM) {
            cli_print(cli,"Not enough signaling tracking resources.\r\n");
            return -1;
        }
    } else if (0 == strncmp(argv[1], "del", 3)) {
        if (argc < 7) {
            cli_print(cli,"Parameters too few...\r\n");
            goto err;
        }

        if (1 != inet_pton(AF_INET, argv[2], &arg_st.sip)) {
            LOG(FASTPASS, ERR, "inet_pton failed, error: %s.", strerror(errno));
            return -1;
        }
        if (1 != inet_pton(AF_INET, argv[3], &arg_st.dip)) {
            LOG(FASTPASS, ERR, "inet_pton failed, error: %s.", strerror(errno));
            return -1;
        }
        arg_st.sip = htonl(arg_st.sip);
        arg_st.dip = htonl(arg_st.dip);
        arg_st.spt = htons(atoi(argv[4]));
        arg_st.dpt = htons(atoi(argv[5]));
        arg_st.pro = atoi(argv[6]);
        arg_st.valid = 1;

        for (st_cnt = 0; st_cnt < MAX_TRACE_FLOW_NUM; ++st_cnt) {
            if (fpu_sig_trace[st_cnt].valid &&
                fpu_sig_trace[st_cnt].sip == arg_st.sip &&
                fpu_sig_trace[st_cnt].dip == arg_st.dip &&
                fpu_sig_trace[st_cnt].spt == arg_st.spt &&
                fpu_sig_trace[st_cnt].dpt == arg_st.dpt &&
                fpu_sig_trace[st_cnt].pro == arg_st.pro) {
                fpu_sig_trace[st_cnt].valid = 0;
                /* continue, prevent duplicate data */
            }
        }
    } else if (0 == strncmp(argv[1], "clr", 3)) {
        for (st_cnt = 0; st_cnt < MAX_TRACE_FLOW_NUM; ++st_cnt) {
            fpu_sig_trace[st_cnt].valid = 0;
        }
    } else {
        goto err;
    }

    return 0;

err:
    cli_print(cli,"Please input: %s <add|del|clr> <src_ip> <dest_ip> <src_port> <dest_port> <protocol>\r\n", argv[0]);
    return -1;
}

int fp_check_signal_trace(uint32_t sip, uint32_t dip, uint16_t spt, uint16_t dpt, uint8_t pro)
{
    int cnt;

    for (cnt = 0; cnt < MAX_TRACE_FLOW_NUM; ++cnt) {
        if (fpu_sig_trace[cnt].valid &&
            fpu_sig_trace[cnt].sip == sip &&
            fpu_sig_trace[cnt].dip == dip &&
            fpu_sig_trace[cnt].spt == spt &&
            fpu_sig_trace[cnt].dpt == dpt &&
            fpu_sig_trace[cnt].pro == pro) {
            return G_TRUE;
        }
    }

	if (fpu_sig_trace_ueip.ueip &&
        ((ntohl(sip) == fpu_sig_trace_ueip.ueip) || (ntohl(dip) == fpu_sig_trace_ueip.ueip))) {
		return G_TRUE;
	}

    return G_FALSE;
}

int fp_stats_resource_info(struct cli_def *cli,int argc, char **argv)
{
    fp_fast_table    *fast_head = fp_fast_table_get(COMM_MSG_FAST_IPV4);
    fp_inst_table    *inst_head = fp_inst_table_get();
    fp_far_table     *far_head = fp_far_table_get();
    fp_bar_table     *bar_head = fp_bar_table_get();
    fp_qer_table     *qer_head = fp_qer_table_get();
    fp_buff_pool     *buff_head = fp_buff_pool_get();
    fp_urr_mac_table *mac_head = fp_mac_table_get();
    fp_dns_table *dns_head = fp_dns_table_get_public();

    if (!fp_start_is_run()) {
        cli_print(cli,"fpu not running.\r\n");
        return 0;
    }
    cli_print(cli,"                Maximum number        Use number        \n");

    /* fast resource */
    cli_print(cli,"fast:            %-8u             %-8u\n", fast_head->entry_max,
        Res_GetAlloced(fast_head->res_no));

    /* instance resource */
    cli_print(cli,"inst:            %-8u             %-8u\n", inst_head->entry_max,
        Res_GetAlloced(inst_head->res_no));

    /* far resource */
    cli_print(cli,"far:             %-8u             %-8u\n", far_head->entry_max,
        Res_GetAlloced(far_head->res_no));

    /* qer resource */
    cli_print(cli,"qer:             %-8u             %-8u\n", qer_head->entry_max,
        Res_GetAlloced(qer_head->res_no));

    /* bar resource */
    cli_print(cli,"bar:             %-8u             %-8u\n", bar_head->entry_max,
        Res_GetAlloced(bar_head->res_no));

    /* cblock resource */
    cli_print(cli,"cblk:            %-8u             %-8u\n", buff_head->cblk_max,
        Res_GetAlloced(buff_head->res_cblk));

    /* block resource */
    cli_print(cli,"block:           %-8u             %-8u\n", buff_head->block_max,
        Res_GetAlloced(buff_head->res_block));

    /* mac resource */
    cli_print(cli,"mac:             %-8u             %-8u\n", mac_head->entry_max,
        Res_GetAlloced(mac_head->res_no));

    /* dns resource */
    cli_print(cli,"dns:             %-8u             %-8u\n", dns_head->entry_max,
        Res_GetAlloced(dns_head->res_no));

    return 0;
}

int fp_show_cblock_info(struct cli_def *cli, int argc, char **argv)
{
    fp_buff_pool *buff_head = fp_buff_pool_get();
    fp_cblk_entry *cblk;

    if (!fp_start_is_run()) {
        printf("fpu not running.\r\n");
        return 0;
    }
    cli_print(cli,"                Maximum number        Use number        \n");

    /* cblock resource */
    cli_print(cli,"cblk:            %-8u             %-8u\n", buff_head->cblk_max,
        Res_GetAlloced(buff_head->res_cblk));

    /* block resource */
    cli_print(cli,"block:           %-8u             %-8u\n", buff_head->block_max,
        Res_GetAlloced(buff_head->res_block));

    if (argc > 0) {
        int index = atoi(argv[0]);
        int print_len = 50;
        uint32_t cnt;
        uint8_t *buf;

        if (0 == strncmp(argv[0], "help", 4)) {
            goto help;
        }

        if (index >= buff_head->cblk_max) {
            cli_print(cli,"Index too large. Less than %u is required.\n", buff_head->cblk_max);
            return -1;
        }
        cblk = &buff_head->cblk[index];
        cli_print(cli,"cblk->lcore_id: %d\n", cblk->lcore_id);
        cli_print(cli,"cblk->port:     %d\n", cblk->port);
        cli_print(cli,"cblk->len:      %d\n", cblk->len);
        cli_print(cli,"cblk->buf:      (%p)\n", cblk->buf);
        cli_print(cli,"cblk->pkt:      (%p)\n", cblk->pkt);
        cli_print(cli,"cblk->time:     %u\n\n", cblk->time);

        buf = (uint8_t *)cblk->pkt;
        if (argc > 1) {
            print_len = atoi(argv[1]) & 0xFFFFFFF0;
        }
        if (cblk->len < print_len)
            print_len = cblk->len  & 0xFFFFFFF0;

        cli_print(cli,"packet info:\n");
        for (cnt = 0; cnt < print_len; cnt += 16) {
            cli_print(cli,"%02x %02x %02x %02x %02x %02x %02x %02x    %02x %02x %02x %02x %02x %02x %02x %02x\n",
                buf[cnt + 0], buf[cnt + 1], buf[cnt + 2], buf[cnt + 3],
                buf[cnt + 4], buf[cnt + 5], buf[cnt + 6], buf[cnt + 7],
                buf[cnt + 8], buf[cnt + 9], buf[cnt + 10], buf[cnt + 11],
                buf[cnt + 12], buf[cnt + 13], buf[cnt + 14], buf[cnt + 15]);
        }
    }

    return 0;

help:
    cli_print(cli,"cblk [index|help] [print length]\n");
    return 0;
}

int fp_set_head_enrich_flag(struct cli_def *cli, int argc, char **argv)
{
	if(argc < 2)
	{
		cli_print(cli,"please input head_enrich enable/disable/mod\n");
		return -1;
	}

	if((!strcmp(argv[1],"mod")) && (argc < 3))
	{
		cli_print(cli,"please input head_enrich mod value(17516/18888)\n");
		return -1;
	}

	if(!strcmp(argv[1],"enable"))
	{
		fp_head_enrich_enable = 1;
	}
	else if(!strcmp(argv[1],"disable"))
	{
		fp_head_enrich_enable = 0;
	}
	else if(!strcmp(argv[1],"mod"))
	{
		fp_extension_type = atoi(argv[2]);
	}
	else
	{
		cli_print(cli,"please input head_enrich enable/disable/mod\n");
		return -1;
	}

	return 0;
}

int fp_cli_start_sent_task(struct cli_def *cli, int argc, char **argv)
{
    return 0;
}

int fp_cli_stop_sent_task(struct cli_def *cli, int argc, char **argv)
{
    return 0;
}

int fp_cli_pkt_test_resend(struct cli_def *cli, int argc, char **argv)
{
    return 0;
}

int fp_cli_pkt_stat_start_task(struct cli_def *cli, int argc, char **argv)
{
    return 0;
}

int fp_cli_pkt_stat_stop_task(struct cli_def *cli, int argc, char **argv)
{
    return 0;
}

int fp_cli_pkt_stat_clear(struct cli_def *cli, int argc, char **argv)
{
    return 0;
}

uint32_t fp_get_capture2spu_switch(void)
{
    return fp_capture_pkt_to_spu;
}

int fp_set_capture2spu_switch(struct cli_def *cli, int argc, char **argv)
{
    uint32_t tmp;

    if (argc < 1) {
        LOG(FASTPASS, ERR, "");
        goto help;
    }

    tmp = atoi(argv[0]);
    cli_print(cli, "capture_switch %u ==> %u\n", fp_capture_pkt_to_spu, tmp);
    fp_capture_pkt_to_spu = tmp;

    return 0;

help:

    cli_print(cli, "cap2spu <1|0>\n");
    return -1;
}

int fp_set_vlan(struct cli_def *cli, int argc, char **argv)
{
    uint8_t port_type, argc_cnt = 0;

    if (argc < 4) {
        if (argc == 1 && 0 == strncmp(argv[argc_cnt], "show", 4)) {
            char port_name[EN_PORT_BUTT][3] = {"N3", "N6", "N4"};
            uint8_t cnt;

            cli_print(cli, "Port        Type        TPID        VID");
            for (cnt = 0; cnt < EN_PORT_BUTT; ++cnt) {
                cli_print(cli, "%s          C-Vlan      0x%04hx      %hu",
                    port_name[cnt], ntohs(fp_c_vlan_type[cnt]), fp_c_vlan_id[cnt]);
                cli_print(cli, "%s          S-Vlan      0x%04hx      %hu\n",
                    port_name[cnt], ntohs(fp_s_vlan_type[cnt]), fp_s_vlan_id[cnt]);
            }
            return 0;
        }

        cli_print(cli, "Parameters too few...");
        goto help;
    }

    if (0 == strncmp(argv[argc_cnt], "N3", 2)) {
        port_type = EN_PORT_N3;
    } else if (0 == strncmp(argv[argc_cnt], "N6", 2)) {
        port_type = EN_PORT_N6;
    } else if (0 == strncmp(argv[argc_cnt], "N4", 2)) {
        port_type = EN_PORT_N4;
    } else {
        goto help;
    }
    ++argc_cnt;

    if (0 == strncmp(argv[argc_cnt], "c", 1)) {
        fp_c_vlan_type[port_type] = htons(strtol(argv[++argc_cnt], NULL, 16));
        fp_c_vlan_id[port_type] = strtol(argv[++argc_cnt], NULL, 10);;
    } else if (0 == strncmp(argv[argc_cnt], "s", 1)) {
        fp_s_vlan_type[port_type] = htons(strtol(argv[++argc_cnt], NULL, 16));
        fp_s_vlan_id[port_type] = atoi(argv[++argc_cnt]);
    } else {
        goto help;
    }

    return 0;

help:
    cli_print(cli, "vlan_set [show] <outer if> <c|s> <TPID> <VID>");
    cli_print(cli, "outer if:   N3 | N4 | N6 | N9");
    cli_print(cli, "TPID:       0x8100 | 0x88a8");
    cli_print(cli, "e.g. vlan-set N3 c 0x8100 100");
    cli_print(cli, "e.g. vlan-set N6 s 0x88a8 200");
    cli_print(cli, "e.g. vlan-set show");

    return -1;
}


