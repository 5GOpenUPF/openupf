/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "dpdk.h"
#include "fp_backend_mgmt.h"


static fp_backend_config g_backend_config;


static inline fp_backend_config *fp_be_get_config(void)
{
    return &g_backend_config;
}

fp_backend_config *fp_be_get_config_public(void)
{
    return &g_backend_config;
}

void fp_be_copy_port_mac(uint8_t port, uint8_t *mac)
{
    memcpy(mac, g_backend_config.loadbalancer_mac[port], ETH_ALEN);
}

static inline void fp_be_reset_hb_cnt()
{
    ros_atomic32_init(&g_backend_config.hb_cnt);
}

inline void fp_be_reset_hb_cnt_public()
{
    fp_be_reset_hb_cnt();
}

static inline uint32_t fp_be_get_work_state(void)
{
    return ros_atomic32_read(&g_backend_config.work_state);
}

void fp_be_set_work_state(uint32_t state)
{
    switch (state) {
        case EN_BE_WAIT_INIT:
            break;

        case EN_BE_INITIALIZING:
            break;

        case EN_BE_WORKING:
            break;
    }

    ros_atomic32_set(&g_backend_config.work_state, state);
}

inline comm_msg_channel_common *fp_be_get_channel_cli(void)
{
    return (comm_msg_channel_common *)&g_backend_config.channel_client;
}

inline uint64_t fp_be_get_flag_key(void)
{
    return g_backend_config.flag_key;
}

static inline void fp_be_fill_hb_config(comm_msg_backend_config *hb_cfg)
{
    fp_backend_config *be_cfg = fp_be_get_config();
    uint8_t cnt;

    /* Filling config */
    hb_cfg->key = be_cfg->flag_key;
    hb_cfg->dpdk_lcores = dpdk_get_core_num() - 1; /* Minus the number of control cores */
    for (cnt = 0; cnt < hb_cfg->dpdk_lcores; ++cnt) {
        ros_memcpy(hb_cfg->mac[cnt], fp_get_port_mac(cnt), ETH_ALEN);
    }
}

void fp_be_active(void)
{
    char buf[256];
    uint32_t buf_len = 0;
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    comm_msg_backend_config *hb_cfg;

    msg = fp_fill_msg_header((uint8_t *)buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd = htons(EN_COMM_MSG_BACKEND_ACTIVE);
    ie->index = 0;
    hb_cfg = (comm_msg_backend_config *)ie->data;

    /* Filling config */
    fp_be_fill_hb_config(hb_cfg);

    buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_backend_config);
    ie->len = htons(buf_len);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    /* Send to Management-end */
    if (0 > fp_msg_send(buf, buf_len)) {
        LOG(FASTPASS, ERR, "Send buffer to MB failed.");
    }
}

void fp_be_deactive(void)
{
    char buf[256];
    uint32_t buf_len = 0;
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    comm_msg_backend_config *hb_cfg;

    msg = fp_fill_msg_header((uint8_t *)buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd = htons(EN_COMM_MSG_BACKEND_DEACTIVE);
    ie->index = 0;
    hb_cfg = (comm_msg_backend_config *)ie->data;

    /* Filling config */
    fp_be_fill_hb_config(hb_cfg);

    buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_backend_config);
    ie->len = htons(buf_len);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    /* Send to Management-end */
    if (0 > fp_msg_send(buf, buf_len)) {
        LOG(FASTPASS, ERR, "Send buffer to MB failed.");
    }
}

/**
 * Judge whether the FPU is in a healthy state
 *
 * @return
 *   - 1: Healthy.
 *   - 0: Unhealthy.
 */

static int fp_be_is_healthy(void)
{
    uint8_t dpdk_port_nb = dpdk_get_port_num();
    uint8_t port_cnt;

    /* Check DPDK port */
    for (port_cnt = 0; port_cnt < dpdk_port_nb; ++port_cnt) {
        if (0 == dpdk_port_linked(port_cnt))
            return 0;
    }

    return 1;
}

void *fp_be_heartbeat_task(void *arg)
{
    fp_backend_config *be_cfg = fp_be_get_config();
    char hb_buf[256];
    uint32_t hb_buf_len = 0;
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    comm_msg_backend_config *hb_cfg;
    uint8_t send_success;
    uint8_t last_state = 0; /* 0:Deactivated  1:Activated */

    msg = fp_fill_msg_header((uint8_t *)hb_buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd = htons(EN_COMM_MSG_BACKEND_HB);
    ie->index = 0;
    hb_cfg = (comm_msg_backend_config *)ie->data;

    /* Filling config */
    fp_be_fill_hb_config(hb_cfg);

    hb_buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_backend_config);
    ie->len = htons(hb_buf_len);
    hb_buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(hb_buf_len);

    for (;;) {
        /* Key value changes after re registration */
        hb_cfg->key = be_cfg->flag_key;
        ros_atomic32_inc(&be_cfg->hb_cnt);

        /* Check health status */
        if (fp_be_is_healthy()) {
            /* Send to Management-end */
            if (0 > fp_msg_send(hb_buf, hb_buf_len)) {
                LOG(FASTPASS, ERR, "Send buffer to MB failed.");
                send_success = FALSE;
            } else {
                send_success = TRUE;
            }

            if (ros_atomic32_read(&be_cfg->hb_cnt) >= FP_BACKEND_HB_TIMEOUT_MAX) {
                if (send_success) {
                    /* Try to switch the connection */
                    //comm_msg_channel_common *chnl_com = fp_be_get_channel_cli();

                    //ros_rwlock_write_lock(&chnl_com->rw_lock); /* lock */
                    //close(chnl_com->fd);
                    //chnl_com->fd = -1;
                    //chnl_com->work_flag = FALSE;
                    //ros_rwlock_write_unlock(&chnl_com->rw_lock); /* unlock */
                }
                fp_be_reset_hb_cnt();
            }
            last_state = 1;
        } else {
            /* Tell the management-end to deactive the backend */
            if (1 == last_state)
                fp_be_deactive();
            last_state = 0;
        }

        sleep(FP_BACKEND_HEARTBEAT_INTERVAL);
    }

    return NULL;
}

int64_t fp_be_init(fp_connect_mb_channel_cfg *mb_chnl_cfg)
{
    fp_backend_config *be_cfg = fp_be_get_config();
    cpu_set_t cpuset;
    pthread_attr_t attr1;
    uint8_t *sys_core = dpdk_get_cpus();

    ros_atomic32_set(&be_cfg->work_state, EN_BE_WAIT_INIT);
    ros_atomic32_init(&be_cfg->hb_cnt);
    be_cfg->flag_key = ros_rdtsc() ^ (uint64_t)rand();

    /* Connect load-balancer */
    if (0 > comm_msg_create_channel_client(&be_cfg->channel_client, mb_chnl_cfg->mb_ips, mb_chnl_cfg->mb_ips_num,
        mb_chnl_cfg->mb_port, sys_core, 1)) {
        LOG(LB, ERR , "Create channel-client failed.");
        return -1;
    }

    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    CPU_SET(sys_core[0], &cpuset);

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(COMM, ERR, "Pthread set affinity fail on core(%d)", sys_core[0]);
        return -1;
    }

	if (pthread_create(&be_cfg->pthr_id, &attr1, fp_be_heartbeat_task, NULL) != 0)    {
		LOG(COMM, ERR, "Fail to create tcp client pthread, errno:%s", strerror(errno));
		return -1;
	}

    return 0;
}


