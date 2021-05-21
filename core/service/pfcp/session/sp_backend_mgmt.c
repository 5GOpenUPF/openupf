/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_audit.h"
#include "sp_backend_mgmt.h"


static upc_management_end_config g_upc_management_end_config;
static upc_backend_mgmt g_upc_backend_mgmt;

static char g_backend_heartbeat_buf[256];
static uint32_t g_backend_heartbeat_len;

static inline upc_backend_mgmt *upc_get_backend_mgmt(void)
{
    return &g_upc_backend_mgmt;
}

upc_backend_mgmt *upc_get_backend_mgmt_public(void)
{
    return &g_upc_backend_mgmt;
}

static inline upc_backend_config *upc_get_backend_config(uint8_t be_index)
{
    return &g_upc_backend_mgmt.backend_table[be_index];
}

upc_backend_config *upc_get_backend_config_public(uint8_t be_index)
{
    return &g_upc_backend_mgmt.backend_table[be_index];
}

static inline int upc_get_backend_pool(void)
{
    return g_upc_backend_mgmt.pool_id;
}

static inline upc_management_end_config *upc_mb_config_get(void)
{
    return &g_upc_management_end_config;
}

upc_management_end_config *upc_mb_config_get_public(void)
{
    return upc_mb_config_get();
}

static inline comm_msg_channel_common *upc_mb_get_channel_common(void)
{
    return (comm_msg_channel_common *)&g_upc_management_end_config.chnl_client;
}

void upc_mb_set_work_status(int16_t status)
{
    switch (status) {
        case EN_UPC_STATE_DISCONNECTED:
            break;

        case EN_UPC_STATE_CONNECTED:
            break;

        default:
            return;
    }

    ros_atomic32_set(&g_upc_management_end_config.work_state, status);
}

static inline int16_t upc_mb_get_work_status(void)
{
    return ros_atomic32_read(&g_upc_management_end_config.work_state);
}

void upc_mb_copy_port_mac(uint8_t port, uint8_t *mac)
{
    memcpy(mac, g_upc_management_end_config.lb_mac[port], ETH_ALEN);
}

static inline comm_msg_header_t *upc_mb_fill_msg_header(uint8_t *buf)
{
    comm_msg_header_t *msg_hdr = (comm_msg_header_t *)buf;

    msg_hdr->magic_word    = htonl(COMM_MSG_MAGIC_WORD);
    msg_hdr->comm_id       = 0;
    msg_hdr->major_version = COMM_MSG_MAJOR_VERSION;
    msg_hdr->minor_version = COMM_MSG_MINOR_VERSION;
    msg_hdr->total_len     = COMM_MSG_HEADER_LEN;

    return msg_hdr;
}

void upc_mb_update_lb_config(comm_msg_heartbeat_config *cfg, uint8_t update_index)
{
    upc_management_end_config *mb_cfg = upc_mb_config_get();

    memcpy((void *)mb_cfg->lb_mac, cfg->mac, EN_PORT_BUTT * ETH_ALEN);
}

static inline void upc_mb_build_hb_req(char *buf, uint16_t *buf_len)
{
    upc_config_info *upc_conf = upc_get_config();
    upc_management_end_config *mb_cfg = upc_mb_config_get();
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    comm_msg_heartbeat_config *hb_cfg;
    uint32_t total_len;

    msg = upc_mb_fill_msg_header((uint8_t *)buf);

    ie = (comm_msg_ie_t *)(msg->payload);
    ie->cmd = htons(EN_COMM_MSG_MB_HB);
    ie->index = 0;
    hb_cfg = (comm_msg_heartbeat_config *)ie->data;

    /* Filling config */
    hb_cfg->key = mb_cfg->local_key;
    memcpy(hb_cfg->mac[EN_PORT_N3], upc_conf->n4_local_mac, ETH_ALEN);
    memcpy(hb_cfg->mac[EN_PORT_N6], upc_conf->n4_local_mac, ETH_ALEN);
    memcpy(hb_cfg->mac[EN_PORT_N9], upc_conf->n4_local_mac, ETH_ALEN);
    memcpy(hb_cfg->mac[EN_PORT_N4], upc_conf->n4_local_mac, ETH_ALEN);

    total_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_heartbeat_config);
    ie->len = htons(total_len);
    total_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(total_len);

    *buf_len = total_len;
}

void *upc_mb_heartbeat_task(void *arg)
{
    upc_management_end_config *mb_cfg = upc_mb_config_get();
    char        hb_buf[256];
    uint16_t    hb_buf_len;
    uint8_t     send_success;
    comm_msg_rules_ie_t *ie = (comm_msg_rules_ie_t *)(hb_buf + COMM_MSG_HEADER_LEN);

    upc_mb_build_hb_req(hb_buf, &hb_buf_len);

    for (;;) {
        if (HA_STATUS_ACTIVE == upc_get_work_status()) {
            ie->rules_num = htonl(Res_GetAlloced(upc_get_backend_pool()));
            ros_atomic32_inc(&mb_cfg->hb_cnt);
            if (0 > comm_msg_channel_client_send(upc_mb_get_channel_common(), hb_buf, hb_buf_len)) {
                LOG(UPC, RUNNING, "Connection failed.");
                send_success = FALSE;
            } else {
                send_success = TRUE;
            }

            if (ros_atomic32_read(&mb_cfg->hb_cnt) >= UPC_MB_TIMEOUT_MAX) {
                if (EN_UPC_STATE_CONNECTED == upc_mb_get_work_status()) {
                    upc_mb_set_work_status(EN_UPC_STATE_DISCONNECTED);
                    mb_cfg->peer_key = 0;
                } else {
                    if (send_success) {
                        comm_msg_channel_common *chnl_com = upc_mb_get_channel_common();

                        ros_rwlock_write_lock(&chnl_com->rw_lock); /* lock */
                        close(chnl_com->fd);
                        chnl_com->fd = -1;
                        chnl_com->work_flag = FALSE;
                        ros_rwlock_write_unlock(&chnl_com->rw_lock); /* unlock */
                    }
                }

                ros_atomic32_init(&mb_cfg->hb_cnt);
            }
        }

        sleep(UPC_MB_HEARTBEAT_INTERVAL);
    }

    return NULL;
}


int64_t upc_mb_init(upc_config_info *upc_conf)
{
    upc_management_end_config *mb_cfg = upc_mb_config_get();
    cpu_set_t cpuset;
    pthread_attr_t attr1;
    uint8_t cnt;

    ros_atomic32_set(&mb_cfg->work_state, EN_UPC_STATE_DISCONNECTED);
    mb_cfg->local_key = ros_rdtsc() ^ (uint64_t)upc_conf->ha_remote_ip[0];
    ros_atomic32_init(&mb_cfg->hb_cnt);

    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    for (cnt = 0; cnt < upc_conf->core_num; ++cnt) {
        CPU_SET(upc_conf->cpus[cnt], &cpuset);
    }

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(UPC, ERR, "Pthread set affinity fail on core(%d)", upc_conf->cpus[0]);
        return -1;
    }

	if (pthread_create(&mb_cfg->hb_timer_pth, &attr1, upc_mb_heartbeat_task, NULL) != 0)    {
		LOG(UPC, ERR, "Fail to create tcp client pthread, errno:%s", strerror(errno));
		return -1;
	}

    return 0;
}

static inline int upc_backend_compare(struct rb_node *node, void *key)
{
    upc_backend_config *be_cfg = (upc_backend_config *)node;
    uint64_t key_vlu = *(uint64_t *)key;

    if (be_cfg->be_config.key > key_vlu) {
        return -1;
    } else if (be_cfg->be_config.key < key_vlu) {
        return 1;
    }

    return 0;
}

void upc_tell_backend_change_active_mac(void)
{
    upc_management_end_config *mb_cfg = upc_mb_config_get();
    uint8_t buf[COMM_MSG_CTRL_BUFF_LEN];
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    upc_backend_config *cur_cfg;
    uint32_t buf_len;
    int32_t cur_index, pool_id = upc_get_backend_pool();
    comm_msg_heartbeat_config *be_reg_cfg;

    msg = upc_fill_msg_header(buf);

    ie = (comm_msg_ie_t *)(msg->payload);
    ie->cmd = htons(EN_COMM_MSG_BACKEND_RESET_LBMAC);
    ie->index = 0;

    /* Filling node data config */
    be_reg_cfg = (comm_msg_heartbeat_config *)ie->data;

    /* Set config */
    be_reg_cfg->key = 0;
    memcpy(be_reg_cfg->mac, mb_cfg->lb_mac, EN_PORT_BUTT * ETH_ALEN);

    buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_heartbeat_config);
    ie->len = htons(buf_len);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    cur_index = COMM_MSG_BACKEND_START_INDEX - 1;
    while (-1 != (cur_index = Res_GetAvailableInBand(pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER))) {
        cur_cfg = upc_get_backend_config((uint8_t)cur_index);

        /* Send to backend */
        if (0 > comm_msg_channel_reply(cur_cfg->fd, (char *)buf, buf_len)) {
            LOG(UPC, ERR, "Send buffer to fd %d failed.", cur_cfg->fd);
        }
    }
}

int upc_tell_lb_adjust_backend(uint32_t *index_arr, uint32_t index_num, uint16_t cmd)
{
    uint8_t buf[COMM_MSG_CTRL_BUFF_LEN];
    comm_msg_header_t *msg = NULL;
    comm_msg_rules_ie_t *ie = NULL;
    uint32_t total_len;
    upc_backend_config *be_cfg;
    comm_msg_backend_config *be_reg;
    uint32_t cnt, be_reg_cnt = 0, be_reg_max;

    be_reg_max = (COMM_MSG_CTRL_BUFF_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_backend_config);

    msg = upc_fill_msg_header((uint8_t *)buf);
    ie = (comm_msg_rules_ie_t *)(msg->payload);

    ie->cmd = htons(cmd);
    be_reg = (comm_msg_backend_config *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        be_cfg = upc_get_backend_config(index_arr[cnt]);

        ros_memcpy(&be_reg[be_reg_cnt], &be_cfg->be_config, sizeof(comm_msg_backend_config));
        ++be_reg_cnt;

        if (be_reg_cnt >= be_reg_max) {
            total_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_backend_config) * be_reg_cnt;
            ie->rules_num = htonl(be_reg_cnt);
            ie->len = htons(total_len);
            total_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(total_len);
            if (0 > comm_msg_channel_client_send(upc_mb_get_channel_common(), (char *)buf, total_len)) {
                LOG(UPC, ERR, "Send buffer to LB failed.");
                return -1;
            }
            be_reg_cnt = 0;
        }
    }

    if (be_reg_cnt > 0) {
        total_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_backend_config) * be_reg_cnt;
        ie->rules_num = htonl(be_reg_cnt);
        ie->len = htons(total_len);
        total_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(total_len);
        if (0 > comm_msg_channel_client_send(upc_mb_get_channel_common(), (char *)buf, total_len)) {
            LOG(UPC, ERR, "Send buffer to LB failed.");
            return -1;
        }
        be_reg_cnt = 0;
    }

    return 0;
}

void upc_lb_register_all_backend(void)
{
    uint8_t buf[COMM_MSG_CTRL_BUFF_LEN];
    comm_msg_header_t *msg = NULL;
    comm_msg_rules_ie_t *ie = NULL;
    uint32_t total_len;
    upc_backend_mgmt *be_mgmt = upc_get_backend_mgmt();
    upc_backend_config *be_cfg;
    int32_t cur_index = COMM_MSG_BACKEND_START_INDEX - 1;
    comm_msg_backend_config *be_reg;
    uint32_t be_reg_cnt = 0, be_reg_max;

    be_reg_max = (COMM_MSG_CTRL_BUFF_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_backend_config);

    msg = upc_fill_msg_header((uint8_t *)buf);
    ie = (comm_msg_rules_ie_t *)(msg->payload);

    ie->cmd = htons(EN_COMM_MSG_MB_REGISTER);
    be_reg = (comm_msg_backend_config *)ie->data;

    ros_rwlock_write_lock(&be_mgmt->lock);/* lock */
    cur_index = Res_GetAvailableInBand(be_mgmt->pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER);
    while (-1 != cur_index) {
        be_cfg = upc_get_backend_config(cur_index);
        if (FALSE == ros_atomic16_read(&be_cfg->valid)) {
            cur_index = Res_GetAvailableInBand(be_mgmt->pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER);
            continue;
        }

        memcpy(&be_reg[be_reg_cnt], &be_cfg->be_config, sizeof(comm_msg_backend_config));
        ++be_reg_cnt;

        if (be_reg_cnt >= be_reg_max) {
            total_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_backend_config) * be_reg_cnt;
            ie->rules_num = htonl(be_reg_cnt);
            ie->len = htons(total_len);
            total_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(total_len);
            if (0 > comm_msg_channel_client_send(upc_mb_get_channel_common(), (char *)buf, total_len)) {
                LOG(UPC, ERR, "Send buffer to LB failed.");
            }
            be_reg_cnt = 0;
        }

        cur_index = Res_GetAvailableInBand(be_mgmt->pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER);
    }
    ros_rwlock_write_unlock(&be_mgmt->lock);/* unlock */

    if (be_reg_cnt > 0) {
        total_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_backend_config) * be_reg_cnt;
        ie->rules_num = htonl(be_reg_cnt);
        ie->len = htons(total_len);
        total_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(total_len);
        if (0 > comm_msg_channel_client_send(upc_mb_get_channel_common(), (char *)buf, total_len)) {
            LOG(UPC, ERR, "Send buffer to LB failed.");
        }
        be_reg_cnt = 0;
    }
}

void upc_tell_backend_re_register(int fd)
{
    uint8_t buf[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t ie_len = 0;
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    uint32_t total_len;

    msg = upc_fill_msg_header((uint8_t *)buf);
    ie = (comm_msg_ie_t *)(msg->payload);

    ie->cmd = htons(EN_COMM_MSG_BACKEND_RE_REGIS);
    ie->index = 0;
    ie_len = sprintf((char *)&ie->data[0], "Should be re register.");
    ie->len = COMM_MSG_IE_LEN_COMMON + ie_len;

    total_len = COMM_MSG_HEADER_LEN + ie->len;
    ie->len = htons(ie->len);
    msg->total_len = htonl(total_len);

    /* Send to backend */
    if (0 > comm_msg_channel_reply(fd, (char *)buf, total_len)) {
        LOG(UPC, ERR, "Send buffer to fd %d failed.", fd);
    }
}

void upc_tell_backend_config(int fd)
{
    upc_management_end_config *mb_cfg = upc_mb_config_get();
    upc_config_info *upc_cfg = upc_get_config();
    uint8_t buf[COMM_MSG_CTRL_BUFF_LEN];
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    uint32_t total_len;
    comm_msg_system_config_t *send_cfg;
    uint8_t cnt;

    msg = upc_fill_msg_header((uint8_t *)buf);
    ie = (comm_msg_ie_t *)(msg->payload);

    ie->cmd = htons(EN_COMM_MSG_BACKEND_CONFIG);
    ie->index = 0;
    send_cfg    = (comm_msg_system_config_t *)ie->data;

    send_cfg->session_num       = htonl(upc_cfg->session_num);
    send_cfg->fast_num          = htonl(upc_cfg->fast_num);
    send_cfg->fast_bucket_num   = htonl(upc_cfg->fast_bucket_num);
    send_cfg->block_num         = htonl(upc_cfg->block_num);
    send_cfg->block_size        = htonl(upc_cfg->block_size);
    send_cfg->cblock_num        = htonl(upc_cfg->cblock_num);
    send_cfg->dns_num           = htonl(upc_cfg->dns_num);

    ros_memcpy(&send_cfg->upf_ip, &upc_cfg->upf_ip_cfg, sizeof(session_ip_addr) * EN_PORT_BUTT);
    ros_memcpy(send_cfg->upf_mac, mb_cfg->lb_mac, EN_PORT_BUTT * ETH_ALEN);
    for (cnt = 0; cnt < EN_PORT_BUTT; ++cnt) {
        send_cfg->upf_ip[cnt].ipv4  = htonl(send_cfg->upf_ip[cnt].ipv4);
    }

    total_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_system_config_t);
    ie->len = htons(total_len);
    total_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(total_len);

    /* Send to backend */
    if (0 > comm_msg_channel_reply(fd, (char *)buf, total_len)) {
        LOG(UPC, ERR, "Send buffer to fd %d failed.", fd);
    }
}

int upc_tell_backend_shutdown(uint64_t be_key)
{
    uint8_t buf[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t ie_len = 0;
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    uint32_t total_len;
    upc_backend_config *be_cfg;

    be_cfg = upc_backend_search(be_key);
    if (NULL == be_cfg) {
        return -1;
    }

    msg = upc_fill_msg_header((uint8_t *)buf);
    ie = (comm_msg_ie_t *)(msg->payload);

    ie->cmd = htons(EN_COMM_MSG_BACKEND_SHUTDOWN);
    ie->index = 0;
    ie_len = sprintf((char *)&ie->data[0], "Shutdown now.");
    ie->len = COMM_MSG_IE_LEN_COMMON + ie_len;

    total_len = COMM_MSG_HEADER_LEN + ie->len;
    ie->len = htons(ie->len);
    msg->total_len = htonl(total_len);

    /* Send to backend */
    if (0 > comm_msg_channel_reply(be_cfg->fd, (char *)buf, total_len)) {
        LOG(UPC, ERR, "Send buffer to fd %d failed.", be_cfg->fd);
    }

    return 0;
}

static inline void upc_backend_heartbeat_buffer_create(char *buf, uint32_t *len)
{
    uint16_t ie_len;
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    uint32_t buf_len;

    msg = upc_fill_msg_header((uint8_t *)buf);

    ie = (comm_msg_ie_t *)(msg->payload);
    ie->cmd = htons(EN_COMM_MSG_BACKEND_HB);
    ie->index = 0;

    /* Filling config */
    ie_len = sprintf((char *)ie->data, "I am Alive");

    ie_len += COMM_MSG_IE_LEN_COMMON;
    ie->len = htons(ie_len);

    buf_len = COMM_MSG_HEADER_LEN + ie_len;
    msg->total_len = htonl(buf_len);

    *len = buf_len;
}

void upc_backend_heartbeat_reply(int fd)
{
    /* Send to backend */
    if (0 > comm_msg_channel_reply(fd, g_backend_heartbeat_buf, g_backend_heartbeat_len)) {
        LOG(UPC, ERR, "Send buffer to fd %d failed.", fd);
    }
}

void upc_get_backend_validity(int fd)
{
    uint8_t buf[COMM_MSG_CTRL_BUFF_LEN];
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    uint32_t total_len;

    msg = upc_fill_msg_header((uint8_t *)buf);
    ie = (comm_msg_ie_t *)(msg->payload);

    ie->cmd = htons(EN_COMM_MSG_BACKEND_VALIDITY);
    ie->index = 0;

    total_len = COMM_MSG_IE_LEN_COMMON;
    ie->len = htons(total_len);
    total_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(total_len);

    /* Send to backend */
    if (0 > comm_msg_channel_reply(fd, (char *)buf, total_len)) {
        LOG(UPC, ERR, "Send buffer to fd %d failed.", fd);
    }
}

int upc_backend_compare_validity(comm_msg_entry_val_config_t *val_cfg)
{
    uint32_t field_num = 0, cnt = 0, peer_del = 0, peer_add = 0, diff = 0;
    uint32_t remainder = 0;
    uint32_t del_arr[ONCE_CHANGE_NUMBER_MAX], del_num = 0;
    uint32_t add_arr[ONCE_CHANGE_NUMBER_MAX], add_num = 0;
    uint8_t val_data[SERVICE_BUF_TOTAL_LEN];
    comm_msg_entry_val_config_t *local_val_cfg = (comm_msg_entry_val_config_t *)val_data;

    LOG(LB, RUNNING, "Backend compare validity.");

    if (NULL == val_cfg) {
        LOG(LB, ERR, "Abnormal parameter, val_cfg(%p).", val_cfg);
        return -1;
    }

    if (G_SUCCESS != Res_GetRangeField(upc_get_backend_pool(), 0,
        val_cfg->start, val_cfg->entry_num, local_val_cfg->data)) {
        LOG(LB, ERR, "Get range field failed, start: %u, entry_num: %u.",
            val_cfg->start, val_cfg->entry_num);
        return -1;
    }

    field_num = val_cfg->entry_num >> RES_PART_LEN_BIT;
    for (cnt = 0; cnt < field_num; ++cnt) {
        diff = local_val_cfg->data[cnt] ^ val_cfg->data[cnt];
        if (diff) {
            uint32_t start_bit = val_cfg->start + (cnt << RES_PART_LEN_BIT);

            peer_add = (local_val_cfg->data[cnt] & diff) ^ diff;
            peer_del = (val_cfg->data[cnt] & diff) ^ diff;

            if (peer_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    /* Tell LB */
                    if (0 > upc_tell_lb_adjust_backend(del_arr, del_num, EN_COMM_MSG_MB_UNREGISTER)) {
                        LOG(UPC, ERR, "Tell LB unregister backend failed");
                    }
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, peer_del, del_arr, &del_num);
            }
            if (peer_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    /* Tell LB */
                    if (0 > upc_tell_lb_adjust_backend(add_arr, add_num, EN_COMM_MSG_MB_REGISTER)) {
                        LOG(UPC, ERR, "Tell LB unregister backend failed");
                    }
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, peer_add,
                    add_arr, &add_num);
            }
        }
    }

    remainder = val_cfg->entry_num & RES_PART_LEN_MASK;
    if (remainder) {
        diff = local_val_cfg->data[cnt] ^ val_cfg->data[cnt];
        diff &= ~((1 << (RES_PART_LEN - remainder)) - 1);
        if (diff) {
            uint32_t start_bit = val_cfg->start + (cnt << RES_PART_LEN_BIT);

            peer_add = (local_val_cfg->data[cnt] & diff) ^ diff;
            peer_del = (val_cfg->data[cnt] & diff) ^ diff;

            if (peer_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    /* Tell LB */
                    if (0 > upc_tell_lb_adjust_backend(del_arr, del_num, EN_COMM_MSG_MB_UNREGISTER)) {
                        LOG(UPC, ERR, "Tell LB unregister backend failed");
                    }
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, peer_del, del_arr, &del_num);
            }
            if (peer_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    /* Tell LB */
                    if (0 > upc_tell_lb_adjust_backend(add_arr, add_num, EN_COMM_MSG_MB_REGISTER)) {
                        LOG(UPC, ERR, "Tell LB unregister backend failed");
                    }
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, peer_add, add_arr, &add_num);
            }
        }
    }

    if (del_num > 0) {
        /* Tell LB */
        if (0 > upc_tell_lb_adjust_backend(del_arr, del_num, EN_COMM_MSG_MB_UNREGISTER)) {
            LOG(UPC, ERR, "Tell LB unregister backend failed");
        }
    }
    if (add_num > 0) {
        /* Tell LB */
        if (0 > upc_tell_lb_adjust_backend(add_arr, add_num, EN_COMM_MSG_MB_REGISTER)) {
            LOG(UPC, ERR, "Tell LB unregister backend failed");
        }
    }

    return 0;
}

upc_backend_config *upc_backend_register(comm_msg_backend_config *be_hb_config, int fd)
{
    upc_backend_mgmt *be_mgmt = upc_get_backend_mgmt();
    upc_backend_config *be_cfg;
    uint32_t res_key, res_index;

    if (G_FAILURE == Res_Alloc(upc_get_backend_pool(), &res_key, &res_index, EN_RES_ALLOC_MODE_OC)) {
        LOG(UPC, ERR, "Backend register failed, resouce alloc failed.\n");
        return NULL;
    }

    be_cfg = upc_get_backend_config(res_index);

    ros_memcpy(&be_cfg->be_config, be_hb_config, sizeof(comm_msg_backend_config));
    ros_atomic32_set(&be_cfg->be_state, EN_BACKEND_INIT);
    ros_atomic16_init(&be_cfg->be_timeout_times);
    be_cfg->fd = fd;

    ros_rwlock_write_lock(&be_mgmt->lock);/* lock */
    if (0 > rbtree_insert(&be_mgmt->be_root, &be_cfg->be_node,
        &be_cfg->be_config.key, upc_backend_compare)) {
        ros_rwlock_write_unlock(&be_mgmt->lock);/* unlock */
        Res_Free(upc_get_backend_pool(), res_key, res_index);
        LOG(SESSION, ERR, "insert backend failed, key: %lu.", be_cfg->be_config.key);
        return NULL;
    }
    ros_rwlock_write_unlock(&be_mgmt->lock);/* unlock */

    LOG(UPC, MUST, "Backend registered successful, key: 0x%lx, be_index: %u.",
        be_hb_config->key, res_index);

    return be_cfg;
}

void upc_backend_unregister(uint8_t be_index)
{
    upc_backend_mgmt *be_mgmt = upc_get_backend_mgmt();
    upc_backend_config *be_cfg;

    if (G_FALSE == Res_IsAlloced(upc_get_backend_pool(), 0, be_index)) {
        return;
    }

    be_cfg = upc_get_backend_config(be_index);

    ros_rwlock_write_lock(&be_mgmt->lock);/* lock */
    rbtree_erase(&be_cfg->be_node, &be_mgmt->be_root);
    ros_rwlock_write_unlock(&be_mgmt->lock);/* unlock */

    ros_rwlock_write_lock(&be_cfg->lock);/* lock */
    ros_atomic16_init(&be_cfg->be_timeout_times);
    be_cfg->fd = -1;
    ros_rwlock_write_unlock(&be_cfg->lock);/* unlock */

    if (TRUE == ros_atomic16_read(&be_cfg->valid)) {
        switch (upc_get_work_status()) {
            case HA_STATUS_ACTIVE:
            case HA_STATUS_SMOOTH2ACTIVE:
                /* Tell LB */
                if (0 > upc_tell_lb_adjust_backend(&be_cfg->index, 1, EN_COMM_MSG_MB_UNREGISTER)) {
                    LOG(UPC, ERR, "Tell LB unregister backend failed, key: %lu", be_cfg->be_config.key);
                }

                /* Tell standby SMU */
                if (upc_hk_sync_backend) {
                    if (0 > upc_hk_sync_backend(&be_cfg->index, 1, HA_CREATE)) {
                        LOG(UPC, ERR, "Sync backend config failed, key: %lu", be_cfg->be_config.key);
                    }
                }
                break;
            default:
                break;
        }
    }

    ros_atomic16_set(&be_cfg->valid, FALSE);
    Res_Free(upc_get_backend_pool(), 0, be_index);

    LOG(UPC, MUST, "Backend unregistered successful, key: 0x%lx, be_index: %d.",
        be_cfg->be_config.key, be_index);
}

void upc_backend_activate(upc_backend_config *be_cfg)
{
    if (NULL == be_cfg) {
        LOG(LB, ERR, "Parameter error, be_cfg(%p)", be_cfg);
        return;
    }

    ros_atomic16_set(&be_cfg->valid, TRUE);
    ros_atomic32_set(&be_cfg->be_state, EN_BACKEND_RUN);

    switch (upc_get_work_status()) {
        case HA_STATUS_ACTIVE:
        case HA_STATUS_SMOOTH2ACTIVE:
            /* Tell LB */
            if (0 > upc_tell_lb_adjust_backend(&be_cfg->index, 1, EN_COMM_MSG_MB_REGISTER)) {
                LOG(UPC, ERR, "Tell LB register backend failed, key: %lu", be_cfg->be_config.key);
            }

            /* Tell standby SMU */
            if (upc_hk_sync_backend) {
                if (0 > upc_hk_sync_backend(&be_cfg->index, 1, HA_CREATE)) {
                    LOG(UPC, ERR, "Sync backend config failed, key: %lu", be_cfg->be_config.key);
                }
            }
            break;
        default:
            break;
    }

    LOG(LB, MUST, "Backend activate successful, be_key: %lu", be_cfg->be_config.key);
}

upc_backend_config *upc_backend_search(uint64_t be_key)
{
    upc_backend_mgmt *be_mgmt = upc_get_backend_mgmt();
    upc_backend_config *be_cfg;

    ros_rwlock_read_lock(&be_mgmt->lock); /* lock */
    be_cfg = (upc_backend_config *)rbtree_search(&be_mgmt->be_root, &be_key, upc_backend_compare);
    if (NULL == be_cfg) {
        LOG(UPC, DEBUG, "No such backend key: %lu.", be_key);
        ros_rwlock_read_unlock(&be_mgmt->lock); /* unlock */

        return NULL;
    }
    ros_rwlock_read_unlock(&be_mgmt->lock); /* unlock */
    LOG(UPC, DEBUG, "Backend search successful, key: %lu.", be_key);

    return be_cfg;
}

static void *upc_backend_heartbeat_task(void *arg)
{
    upc_backend_config *cur_cfg = NULL;
    int32_t pool_id = upc_get_backend_pool(), cur_index;

    for (;;) {
        cur_index = COMM_MSG_BACKEND_START_INDEX - 1;

        if (HA_STATUS_ACTIVE == upc_get_work_status()) {
            /* 这里使用Res_GetAvailableInBand而不去判断有效性是为了清除注册成功但超时未激活的backend */
            while (-1 != (cur_index = Res_GetAvailableInBand(pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER))) {
                cur_cfg = upc_get_backend_config((uint8_t)cur_index);

                if (UPC_BACKEND_TIMEOUT_MAX > ros_atomic16_add_return(&cur_cfg->be_timeout_times, 1)) {
                    continue;
                } else {
                    LOG(UPC, MUST, "Back-end heartbeat timed out, ready to unregister it.\n");
                    upc_backend_unregister((uint8_t)cur_index);
                }
            }
        }

        /* Scan interval */
        sleep(3);
    }

    return NULL;
}

int32_t upc_backend_init(upc_config_info *upc_cfg)
{
    upc_backend_mgmt *be_mgmt = upc_get_backend_mgmt();
    upc_backend_config *be_cfg;
    uint32_t cnt;
    cpu_set_t cpuset;
    pthread_attr_t attr1;
    pthread_t pthr_id;
    int pool_id;

    /* Init backend-table and hash-table */
    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        LOG(UPC, ERR, "Res_CreatePool failed.\n");
        return -1;
    }
    /* Start from 1, UPC_INVALID_BACKEND_INDEX */
    if (G_FAILURE == Res_AddSection(pool_id, 0, COMM_MSG_BACKEND_START_INDEX,
        COMM_MSG_BACKEND_NUMBER - COMM_MSG_BACKEND_START_INDEX)) {
        LOG(UPC, ERR, "Res_AddSection failed.\n");
        return -1;
    }

    /* Init hash table */
    be_cfg = be_mgmt->backend_table;
    for (cnt = 0; cnt < COMM_MSG_BACKEND_NUMBER; ++cnt) {
        ros_atomic16_init(&be_cfg[cnt].be_timeout_times);
        ros_rwlock_init(&be_cfg[cnt].lock);
        be_cfg[cnt].fd = -1;
        be_cfg[cnt].index = cnt;
    }

    be_mgmt->pool_id = pool_id;
    g_upc_backend_mgmt.be_root = RB_ROOT_INIT_VALUE;
    ros_rwlock_init(&g_upc_backend_mgmt.lock);
    be_mgmt->last_num = 0;

    upc_backend_heartbeat_buffer_create(g_backend_heartbeat_buf, &g_backend_heartbeat_len);

    /* Init backend heartbeat task */
    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    for (cnt = 0; cnt < upc_cfg->core_num; ++cnt) {
        CPU_SET(upc_cfg->cpus[cnt], &cpuset);
    }

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(UPC, ERR, "Pthread set affinity fail on core(%d)", upc_cfg->cpus[0]);
        return -1;
    }

	if (pthread_create(&pthr_id, &attr1, upc_backend_heartbeat_task, NULL) != 0)    {
		LOG(UPC, ERR, "Fail to create tcp client pthread, errno:%s", strerror(errno));
		return -1;
	}

    if (0 > upc_mb_init(upc_cfg)) {
        LOG(UPC, ERR, "Init management-end failed.");
        return -1;
    }

    LOG(UPC, RUNNING, "Backend management init success\n");

    return 0;
}

void upc_backend_deinit(void)
{
    upc_management_end_config *mb_cfg = upc_mb_config_get();

    comm_msg_channel_server_shutdown(&mb_cfg->be_mgmt_server);
    comm_msg_channel_client_shutdown(&mb_cfg->chnl_client);

};

int upc_backend_init_audit_fsm(const struct FSM_table *fsm_tables, int fsm_table_num, enum AUDIT_RULES rule)
{
    uint32_t cnt;
    upc_backend_config *be_cfg;

    for (cnt = COMM_MSG_BACKEND_START_INDEX; cnt < COMM_MSG_BACKEND_NUMBER; ++cnt) {
        be_cfg = upc_get_backend_config(cnt);
        if (0 > FSM_init(&be_cfg->fsm[rule], NORMAL, fsm_tables, fsm_table_num, (void *)be_cfg)) {
            LOG(UPC, ERR, "init audit FSM failed.");
            return -1;
        }
    }

    return 0;
}

uint32_t upc_backend_get_active_num(void)
{
    upc_backend_mgmt *be_mgmt = upc_get_backend_mgmt();
    int32_t cur_index = COMM_MSG_BACKEND_START_INDEX - 1;
    upc_backend_config *be_cfg;
    uint32_t act_cnt = 0;

    ros_rwlock_write_lock(&be_mgmt->lock);/* lock */
    cur_index = Res_GetAvailableInBand(be_mgmt->pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER);
    while (-1 != cur_index) {
        be_cfg = upc_get_backend_config(cur_index);
        if (TRUE == ros_atomic16_read(&be_cfg->valid)) {
            ++act_cnt;
        } else {
            LOG(UPC, MUST, "Backend index: %d not active, key: %lu", cur_index, be_cfg->be_config.key);
        }

        cur_index = Res_GetAvailableInBand(be_mgmt->pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER);
    }
    ros_rwlock_write_unlock(&be_mgmt->lock);/* unlock */

    return act_cnt;
}

