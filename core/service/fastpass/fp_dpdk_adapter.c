/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include <rte_mbuf.h>
#include <rte_meter.h>

#include "dpdk.h"

#include "fp_msg.h"
#include "fp_start.h"
#include "fp_dpdk_adapter.h"
#include "fp_backend_mgmt.h"

/* Used for dpdk mode data transmit */
fp_dpdk_tx_queue fp_dpdk_queue;

CVMX_SHARED uint16_t fp_dpdk_port_num;

extern CVMX_SHARED uint16_t fp_c_vlan_id[EN_PORT_BUTT], fp_s_vlan_id[EN_PORT_BUTT];
extern CVMX_SHARED uint16_t fp_c_vlan_type[EN_PORT_BUTT], fp_s_vlan_type[EN_PORT_BUTT];


static inline uint16_t fp_port_to_index(uint16_t port)
{
    /* The port value is converted to the DPDK port ID, port must less EN_PORT_BUTT */
    return fp_dpdk_port_num == (uint16_t)EN_PORT_BUTT ? (uint16_t)port : 0;
}

inline uint16_t fp_port_to_index_public(uint16_t port)
{
    return fp_port_to_index(port);
}

inline uint32_t fp_get_coreid(void)
{
    return rte_lcore_id();
}

inline uint64_t fp_get_cycle(void)
{
    return rte_get_tsc_cycles();
}

inline uint64_t fp_get_freq(void)
{
    return rte_get_tsc_hz();
}

inline void __fp_free_pkt(void *buf, int line)
{
#if (defined(ENABLE_DPDK_DEBUG))
    dpdk_mbuf_del_record(((struct rte_mbuf *)buf)->buf_addr, line);
#endif
    /* if dpdk, free dpdk packet pointer */
    dpdk_free_mbuf((struct rte_mbuf *)buf);
}

/* Forwards the pkt to host channel */
int fp_send_to_chn_port(char *buf, uint32_t len)
{
    char send_buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len;
    comm_msg_header_t *msg;
    comm_msg_ie_t *ie = NULL;

    msg = fp_fill_msg_header((uint8_t *)send_buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd  = htons(EN_COMM_MSG_MATCH_SESSION);
    if (len > (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON)) {
        LOG(FASTPASS, ERR, "Send buffer to SMU failed, buffer length too long.");
        return -1;
    }
    memcpy(ie->data, buf, len);

    buf_len = COMM_MSG_IE_LEN_COMMON + len;
    ie->index = 0;
    ie->len = htons(buf_len);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);
    if (0 > fp_msg_send((char *)send_buf, buf_len)) {
        LOG(UPC, ERR, "Send msg to SMU failed.");
    }

    return 0;
}

static inline void fp_outer_add_vlan(void *m, uint8_t port_type)
{
#if 1
    if (fp_c_vlan_id[port_type]) {
        pkt_buf_struct *mbuf = (pkt_buf_struct *)m;

        mbuf->ol_flags |= PKT_TX_VLAN_PKT;
        mbuf->vlan_tci = fp_c_vlan_id[port_type];


        if (fp_s_vlan_id[port_type]) {
            mbuf->ol_flags |= PKT_TX_QINQ_PKT;
            mbuf->vlan_tci_outer = fp_s_vlan_id[port_type];
        }
    }
#else
    if (fp_c_vlan_id[port_type]) {
        pkt_buf_struct *mbuf = (pkt_buf_struct *)m;
        uint8_t *pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);
        uint8_t ofs_len = VLAN_HLEN;
        uint8_t mac_addr[12];
        uint16_t *vlan_type = (uint16_t *)&pkt[8];
        union vlan_tci *vlan_value = (union vlan_tci *)&pkt[10];

        memcpy(mac_addr, pkt, sizeof(mac_addr));

        *vlan_type = fp_c_vlan_type[port_type];
        vlan_value->s.vid = fp_c_vlan_id[port_type];
        vlan_value->s.dei = 0;
        vlan_value->s.pri = 0;
        vlan_value->data = htons(vlan_value->data);

        if (fp_s_vlan_id[port_type]) {
            vlan_type = (uint16_t *)&pkt[4];
            vlan_value = (union vlan_tci *)&pkt[6];

            ofs_len += VLAN_HLEN;

            *vlan_type = fp_s_vlan_type[port_type];
            vlan_value->s.vid = fp_s_vlan_id[port_type];
            vlan_value->s.dei = 0;
            vlan_value->s.pri = 0;
            vlan_value->data = htons(vlan_value->data);
        }

        mbuf->l2_len += ofs_len;

        memcpy(pkt - ofs_len, mac_addr, sizeof(mac_addr));

        pkt_buf_data_off(mbuf) -= ofs_len;
        pkt_buf_set_len(mbuf, pkt_buf_data_len(mbuf) + ofs_len);
    }
#endif
}

inline void __fp_fwd_snd_to_n3_phy(void *m, const char *func, int line)
{
	/* dest addr */
    fp_be_copy_port_mac(EN_PORT_N3, rte_pktmbuf_mtod((struct rte_mbuf *)m, uint8_t *));

    fp_outer_add_vlan(m, EN_PORT_N3);

    dpdk_send_packet(m, fp_port_to_index(EN_PORT_N3), func, line);
}

inline void __fp_fwd_snd_to_n6_phy(void *m, const char *func, int line)
{
	/* dest addr */
    fp_be_copy_port_mac(EN_PORT_N6, rte_pktmbuf_mtod((struct rte_mbuf *)m, uint8_t *));

    fp_outer_add_vlan(m, EN_PORT_N6);

    dpdk_send_packet(m, fp_port_to_index(EN_PORT_N6), func, line);
}

inline void __fp_fwd_snd_to_n9_phy(void *m, const char *func, int line)
{
	/* dest addr */
    fp_be_copy_port_mac(EN_PORT_N9, rte_pktmbuf_mtod((struct rte_mbuf *)m, uint8_t *));

    fp_outer_add_vlan(m, EN_PORT_N9);

    dpdk_send_packet(m, fp_port_to_index(EN_PORT_N9), func, line);
}

inline void __fp_fwd_snd_to_n4_phy(void *m, const char *func, int line)
{
	/* dest addr */
    fp_be_copy_port_mac(EN_PORT_N4, rte_pktmbuf_mtod((struct rte_mbuf *)m, uint8_t *));

    fp_outer_add_vlan(m, EN_PORT_N4);

    dpdk_send_packet(m, fp_port_to_index(EN_PORT_N4), func, line);
}

void fp_dpdk_add_cblk_buf(void *cblock)
{
    fp_cblk_entry *cblk = (fp_cblk_entry *)cblock;
    uint32_t lcore_id = cblk->lcore_id;

    ros_rwlock_write_lock(&fp_dpdk_queue.dpdk_tx_lock[lcore_id]);
    lstAdd(&fp_dpdk_queue.dpdk_tx_lst[lcore_id], &cblk->node);
    ros_rwlock_write_unlock(&fp_dpdk_queue.dpdk_tx_lock[lcore_id]);
}

void fp_dpdk_send_cblk_buf(uint32_t lcore_id)
{
    /* Send cblock buffer */
    fp_cblk_entry *cblk;
    struct rte_mbuf *m;

    if (fp_start_is_run()) {
        ros_rwlock_write_lock(&fp_dpdk_queue.dpdk_tx_lock[lcore_id]);
        cblk = (fp_cblk_entry *)lstGet(&fp_dpdk_queue.dpdk_tx_lst[lcore_id]);
        while (NULL != cblk) {
            switch (cblk->port) {
                case EN_PORT_N3:
                    if (cblk->free) {
                        /* Alloc buffer */
                        m = dpdk_alloc_mbuf();
                        if (unlikely(NULL == m)) {
                            fp_free_pkt(cblk->buf);
                            LOG(FASTPASS, ERR, "Alloc Mbuf fail.\r\n");
                            break;
                        }

                        /* Copy content and set length */
                        rte_memcpy(rte_pktmbuf_mtod(m, void *), cblk->pkt, cblk->len);
                        rte_pktmbuf_pkt_len(m) = cblk->len;
                        rte_pktmbuf_data_len(m) = cblk->len;

                        fp_fwd_snd_to_n3_phy(m);
                    } else {

                        fp_fwd_snd_to_n3_phy(cblk->buf);
                    }

                    break;

                case EN_PORT_N6:
                    if (cblk->free) {
                        /* Alloc buffer */
                        m = dpdk_alloc_mbuf();
                        if (unlikely(NULL == m)) {
                            fp_free_pkt(cblk->buf);
                            LOG(FASTPASS, ERR, "Alloc Mbuf fail.\r\n");
                            break;
                        }

                        /* Copy content and set length */
                        rte_memcpy(rte_pktmbuf_mtod(m, void *), cblk->pkt, cblk->len);
                        rte_pktmbuf_pkt_len(m) = cblk->len;
                        rte_pktmbuf_data_len(m) = cblk->len;

                        fp_fwd_snd_to_n6_phy(m);
                    } else {

                        fp_fwd_snd_to_n6_phy(cblk->buf);
                    }
                    break;

                case EN_PORT_N4:
                    /* Recv from N4 */
                    if (cblk->free) {
                        /* Alloc buffer */
                        m = dpdk_alloc_mbuf();
                        if (unlikely(NULL == m)) {
                            fp_free_pkt(cblk->buf);
                            LOG(FASTPASS, ERR, "Alloc Mbuf fail.\r\n");
                            break;
                        }

                        /* Copy content and set length */
                        rte_memcpy(rte_pktmbuf_mtod(m, void *), cblk->pkt, cblk->len);
                        rte_pktmbuf_pkt_len(m) = cblk->len;
                        rte_pktmbuf_data_len(m) = cblk->len;

                        fp_fwd_snd_to_n4_phy(m);
                    } else {

                        fp_fwd_snd_to_n4_phy(cblk->buf);
                    }
                    break;

                case EN_PORT_N9:
                    /* Recv from N9 */
                    if (cblk->free) {
                        /* Alloc buffer */
                        m = dpdk_alloc_mbuf();
                        if (unlikely(NULL == m)) {
                            fp_free_pkt(cblk->buf);
                            LOG(FASTPASS, ERR, "Alloc Mbuf fail.\r\n");
                            break;
                        }

                        /* Copy content and set length */
                        rte_memcpy(rte_pktmbuf_mtod(m, void *), cblk->pkt, cblk->len);
                        rte_pktmbuf_pkt_len(m) = cblk->len;
                        rte_pktmbuf_data_len(m) = cblk->len;

                        fp_fwd_snd_to_n9_phy(m);
                    } else {

                        fp_fwd_snd_to_n9_phy(cblk->buf);
                    }
                    break;

                default:
                    fp_free_pkt(cblk->buf);
                    break;
            }

            /* if the buffer what cblk linked not our own block, need set null before free cblk */
            fp_cblk_free(cblk);

            cblk = (fp_cblk_entry *)lstGet(&fp_dpdk_queue.dpdk_tx_lst[lcore_id]);
        }
        ros_rwlock_write_unlock(&fp_dpdk_queue.dpdk_tx_lock[lcore_id]);
    }
}

int fp_channel_init()
{
    uint32_t loop;
    fp_connect_mb_channel_cfg *mb_chnl_cfg = fp_get_mb_chnl_config();

    for (loop = 0; loop < COMM_MSG_FP_STAT_CORE_NUM; loop++) {
        lstInit(&fp_dpdk_queue.dpdk_tx_lst[loop]);
        ros_rwlock_init(&fp_dpdk_queue.dpdk_tx_lock[loop]);
    }

    /* Set callback function */
    comm_msg_cmd_callback   = fp_msg_proc;

    if (0 > fp_be_init(mb_chnl_cfg)) {
        LOG(FASTPASS, ERR, "initialization backend failed.");
        return -1;
    }

    return 0;
}

int fpu_check_eth_name(char *ethname)
{
    if (if_nametoindex(ethname) == 0) {
        return ERROR;
    }

    return OK;
}

static int fp_parse_cfg(struct pcf_file *conf)
{
    fp_connect_mb_channel_cfg *mb_chnl_cfg = fp_get_mb_chnl_config();
    int index = 0;
    struct kv_pair fp_key_pair[] = {
        { "dpdk_mtu", NULL },
        { "mb_ips", NULL },
        { "mb_port", NULL },
        { NULL, NULL, }
    };

    while (fp_key_pair[index].key != NULL) {
        fp_key_pair[index].val = pcf_get_key_value(conf,
                     SECTION_SRV_NAME, fp_key_pair[index].key);
        if (!fp_key_pair[index].val) {
            LOG(FASTPASS, ERR, "Can't get key[%s] in section[%s].\n",
                fp_key_pair[index].key, SECTION_SRV_NAME);
            return -1;
        }
        ++index;
    }
    index = 0;

    /* dpdk_mtu */
    if (strlen(fp_key_pair[index].val) > 0) {
        uint32_t mtu_size;

        mtu_size = strtol(fp_key_pair[index].val, NULL, 10);
        dpdk_set_mtu(mtu_size);
        index++;
    }
    else {
        LOG(FASTPASS, ERR, "Invalid %s:%s config.\n", fp_key_pair[index].key,
            fp_key_pair[index].val);
        return -1;
    }

    /* mb_ips */
    mb_chnl_cfg->mb_ips_num = 0;
    if (strlen(fp_key_pair[index].val) > 0) {
        char *valid_ip = fp_key_pair[index].val, *token = NULL, print_str[512];
        uint16_t print_len = 0;

        for (token = strsep(&valid_ip, "|"); token != NULL; token = strsep(&valid_ip, "|")) {
            if (*token == 0) {
                continue;
            }

            mb_chnl_cfg->mb_ips[mb_chnl_cfg->mb_ips_num++]= htonl(inet_addr(token));
            print_len += sprintf(&print_str[print_len], "%s ", token);
        }
        ++index;

        LOG(FASTPASS, MUST, "Set load-balancer IP number: %d, IP: %s.", mb_chnl_cfg->mb_ips_num, print_str);
    } else {
        LOG(FASTPASS, ERR, "Parse config failed, key: %s, value: %s",
            fp_key_pair[index].key, fp_key_pair[index].val);
        return -1;
    }

    /* mb_port */
    if (strlen(fp_key_pair[index].val) > 0) {
        mb_chnl_cfg->mb_port = strtol(fp_key_pair[index].val, NULL, 10);
        ++index;
    } else {
        LOG(FASTPASS, ERR, "Parse config failed, key: %s, value: %s",
            fp_key_pair[index].key, fp_key_pair[index].val);
        return -1;
    }

    return 0;
}

int32_t fp_init_prepare(void *conf1)
{
    struct pcf_file *conf = (struct pcf_file *)conf1;
    int       ret;

    /* 1.Parse parameters */
    ret = fp_parse_cfg(conf);
    if (ret != 0) {
        LOG(FASTPASS, ERR, "parse configure failed!");
        return -1;
    }

    /* 2.Init DPDK if it's useful */
    ret = dpdk_init(conf, fp_phy_pkt_entry, fp_dpdk_send_cblk_buf);
    if (ret != 0) {
        LOG(FASTPASS, ERR, "dpdk_init failed!");
        return -1;
    }
    fp_dpdk_port_num = (uint16_t)rte_eth_dev_count_avail();

    LOG(FASTPASS, RUNNING, "------DPDK init success------\n");

    return 0;
}

int32_t  fp_init_prepare_deinit()
{
    dpdk_deinit();

    return 0;
}

uint32_t fp_get_mtu()
{
    return dpdk_get_mtu();
}

void fp_set_mtu(uint32_t new_mtu)
{
    dpdk_set_mtu(new_mtu);
}

int fp_get_input_stat(char *str)
{
    dpdk_packet_stat(str);
    return 0;
}

int fp_get_input_stat_promu(comm_msg_fpu_stat *stat)
{
    dpdk_packet_stat_promu(stat);
    return 0;
}

void fp_clean_input_stat()
{
}

void fp_get_fast_head_symbol(char *symbol_name, uint32_t type)
{
}

void fp_get_fast_bucket_symbol(char *symbol_name, uint32_t type)
{
}


