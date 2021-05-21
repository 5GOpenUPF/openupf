/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "lb_backend_mgmt.h"


static uint8_t lb_hash_table[LB_HASH_1_NUMBER][LB_HASH_2_NUMBER];

static lb_backend_mgmt g_backend_mgmt;
static uint64_t lb_flag_key;
static uint64_t lb_peer_flag_key;

static char lb_heartbeat_buf[512];
static uint32_t lb_heartbeat_len;

static inline lb_backend_mgmt *lb_get_backend_mgmt(void)
{
    return &g_backend_mgmt;
}

lb_backend_mgmt *lb_get_backend_mgmt_public(void)
{
    return lb_get_backend_mgmt();
}

static inline lb_backend_config *lb_get_backend_config(uint8_t be_index)
{
    return &g_backend_mgmt.backend_table[be_index];
}

lb_backend_config *lb_get_backend_config_public(uint8_t be_index)
{
    return &g_backend_mgmt.backend_table[be_index];
}

static inline int lb_get_backend_pool(void)
{
    return g_backend_mgmt.be_pool_id;
}

int lb_get_backend_pool_public(void)
{
    return g_backend_mgmt.be_pool_id;
}

comm_msg_channel_server *lb_get_backend_mgmt_server(void)
{
    return &g_backend_mgmt.mb_mgmt_server;
}

uint8_t lb_get_hash_vlaue(uint8_t hash1, uint16_t hash2)
{
    return lb_hash_table[hash1][hash2];
}

void lb_hash_table_update(uint8_t hash1, uint16_t hash2, uint8_t be_index)
{
    lb_hash_table[hash1][hash2] = be_index;
}

void lb_reset_mb_heartbeat_count(void)
{
    ros_atomic32_init(&g_backend_mgmt.mb_heartbeat_cnt);
}

uint64_t lb_get_local_flag_key(void)
{
    return lb_flag_key;
}

void lb_set_peer_flag_key(uint64_t vlu)
{
    lb_peer_flag_key = vlu;
}

uint64_t lb_get_peer_flag_key(void)
{
    return lb_peer_flag_key;
}

static inline int lb_backend_compare(struct rb_node *node, void *key)
{
    lb_backend_config *be_cfg = (lb_backend_config *)node;
    uint64_t key_vlu = *(uint64_t *)key;

    if (be_cfg->be_config.key > key_vlu) {
        return -1;
    } else if (be_cfg->be_config.key < key_vlu) {
        return 1;
    }

    return 0;
}

void lb_backend_table_update(lb_sync_backend_config *be_data)
{
    switch (be_data->valid) {
        case 0:
            /* Unregister backend */
            lb_backend_unregister(be_data->be_index);
            break;

        default:
            /* Register/Update backend */
            {
                lb_backend_config *be_cfg;

                if (G_TRUE == Res_IsAlloced(lb_get_backend_pool(), 0, be_data->be_index)) {
                    be_cfg = lb_get_backend_config(be_data->be_index);

                    /* 只更新部分数据, 其他数据可能是固定不变的 */
                    ros_atomic32_set(&be_cfg->assign_count, be_data->assign_count);
                } else {
                    if (G_FAILURE == Res_AllocTarget(lb_get_backend_pool(), 0, be_data->be_index)) {
                        LOG(LB, ERR, "Backend register failed, resouce alloc failed.\n");
                        return;
                    }

                    be_cfg = lb_get_backend_config(be_data->be_index);

                    memcpy(&be_cfg->be_config, &be_data->be_config, sizeof(comm_msg_backend_config));
                    ros_atomic16_set(&be_cfg->valid, TRUE);
                    ros_atomic32_set(&be_cfg->assign_count, be_data->assign_count);

                    LOG(LB, MUST, "Backend registered successful, key: 0x%lx, be_index: %d.",
                        be_cfg->be_config.key,
                        be_data->be_index);
                }
            }
            break;
    }
}

/**
 * @return
 *  Destination backend config
 */
static inline lb_backend_config *lb_choose_backend(void)
{
    lb_backend_config *cur_cfg = NULL, *min_cfg = NULL;
    int32_t cur_index = COMM_MSG_BACKEND_START_INDEX - 1;

    cur_index = Res_GetAvailableInBand(lb_get_backend_pool(), cur_index + 1, COMM_MSG_BACKEND_NUMBER);
    while (-1 != cur_index) {
        cur_cfg = lb_get_backend_config(cur_index);
        if (FALSE == ros_atomic16_read(&cur_cfg->valid)) {
            continue;
        }

        if (NULL != min_cfg &&
            ros_atomic32_read(&cur_cfg->assign_count) > ros_atomic32_read(&min_cfg->assign_count)) {
            /* Nothing to do */
        } else {
            min_cfg = cur_cfg;
        }

        cur_index = Res_GetAvailableInBand(lb_get_backend_pool(), cur_index + 1, COMM_MSG_BACKEND_NUMBER);
    }

    if (likely(NULL != min_cfg)) {
        ros_atomic32_inc(&min_cfg->assign_count);
    } else {
        LOG(LB, ERR, "No available backend was found.\n");
        return NULL;
    }

    LOG(LB, RUNNING, "Backend %u is selected for processing.", min_cfg->index);

    return min_cfg;
}

/**
 * @param hash
 *  Calculated using UEIP
 * @param dest_mac
 *  Destination MAC address
 * @return
 *  - 0 Success
 *  - -1 Failed
 */
int lb_match_backend(uint32_t hash, uint8_t *dest_mac)
{
    uint8_t hash_1 = (hash >> 24) ^ ((hash >> 16) & 0x000000FF);
    uint16_t hash_2 = hash & 0x000000FFFF;
    uint8_t be_index, port_index;
    lb_backend_config *be_cfg;

    /**
     *  LBU classifies the flow of the same PDR in advance and forwards it to the port of the corresponding FPU
     *
     *       ________
     *      |        |       _________
     *  ===>|   LBU  |----->|FPU1->|p1|
     *      |________|      | ---->|p2|
     *          |           |_________|
     *          |       _________
     *          +----->|FPU2->|p1|
     *                 | ---->|p2|
     *                 |_________|
     */

    be_index = lb_hash_table[hash_1][hash_2];
    be_cfg = lb_get_backend_config(be_index);

    if (ros_atomic16_read(&be_cfg->valid)) {
        /* Valid, forward it here */
    } else {
        /* Invalid, modify the backend ID of the hash table */
        be_cfg = lb_choose_backend();
        if (unlikely(NULL == be_cfg)) {
            return -1;
        }
        lb_hash_table[hash_1][hash_2] = (uint8_t)be_cfg->index;
        if (lb_hk_delay_sync_hash) {
            lb_hk_delay_sync_hash(hash_1, hash_2, (uint8_t)be_cfg->index);
        }
        if (lb_hk_delay_sync_be) {
            lb_hk_delay_sync_be((uint8_t)be_cfg->index);
        }
    }

    if (unlikely(0 == be_cfg->be_config.dpdk_lcores)) {
        LOG(LB, ERR, "Serious error, the number of backend dpdk cores cannot be 0");
        return -1;
    }
    port_index = (hash_1 ^ (uint8_t)hash_2) % be_cfg->be_config.dpdk_lcores;
    ros_memcpy(dest_mac, be_cfg->be_config.mac[port_index], ETH_ALEN);
    LOG(LB, DEBUG, "Match backend port: %d, destination MAC: %02x:%02x:%02x:%02x:%02x:%02x",
        port_index, dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);

    return 0;
}

void lb_ha_tell_backend_change_active_mac(uint8_t local_active)
{
    uint8_t buf[COMM_MSG_CTRL_BUFF_LEN];
    uint16_t ie_len;
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    lb_backend_config *cur_cfg;
    uint32_t buf_len;
    int32_t cur_index, pool_id = lb_get_backend_pool_public();
    comm_msg_heartbeat_config *lb_reset_cfg;

    msg = lb_fill_msg_header(buf);

    ie = (comm_msg_ie_t *)(msg->payload);
    ie->cmd = htons(EN_COMM_MSG_LBMAC_RESET);
    ie->index = 0;

    /* Filling node data config */
    lb_reset_cfg = (comm_msg_heartbeat_config *)ie->data;

    /* Set config */
    switch (local_active) {
        case TRUE:
            memcpy(lb_reset_cfg->mac[EN_PORT_N3], lb_get_local_port_mac(EN_LB_PORT_INT), ETH_ALEN);
            memcpy(lb_reset_cfg->mac[EN_PORT_N6], lb_get_local_port_mac(EN_LB_PORT_INT), ETH_ALEN);
            memcpy(lb_reset_cfg->mac[EN_PORT_N9], lb_get_local_port_mac(EN_LB_PORT_INT), ETH_ALEN);
            memcpy(lb_reset_cfg->mac[EN_PORT_N4], lb_get_local_port_mac(EN_LB_PORT_INT), ETH_ALEN);
            break;

        default:
            memcpy(lb_reset_cfg->mac[EN_PORT_N3], lb_get_peer_port_mac(EN_LB_PORT_INT), ETH_ALEN);
            memcpy(lb_reset_cfg->mac[EN_PORT_N6], lb_get_peer_port_mac(EN_LB_PORT_INT), ETH_ALEN);
            memcpy(lb_reset_cfg->mac[EN_PORT_N9], lb_get_peer_port_mac(EN_LB_PORT_INT), ETH_ALEN);
            memcpy(lb_reset_cfg->mac[EN_PORT_N4], lb_get_peer_port_mac(EN_LB_PORT_INT), ETH_ALEN);
            break;
    }

    ie_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_heartbeat_config);
    ie->len = htons(ie_len);

    buf_len = COMM_MSG_HEADER_LEN + ie_len;
    msg->total_len = htonl(buf_len);

    cur_index = COMM_MSG_BACKEND_START_INDEX - 1;
    while (-1 != (cur_index = Res_GetAvailableInBand(pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER))) {
        cur_cfg = lb_get_backend_config_public((uint8_t)cur_index);
        if (cur_cfg->fd > 0) {
           /* Send to backend */
            if (0 > comm_msg_channel_reply(cur_cfg->fd, (char *)buf, buf_len)) {
                LOG(LB, ERR, "Send buffer to fd %d failed.", cur_cfg->fd);
            }
        }
    }
}

void lb_backend_heartbeat_buffer_create(char *buf, uint32_t *len)
{
    uint16_t ie_len;
    comm_msg_header_t *msg = NULL;
    comm_msg_ie_t *ie = NULL;
    uint32_t buf_len;
    comm_msg_heartbeat_config *mb_cfg;

    msg = lb_fill_msg_header((uint8_t *)buf);

    ie = (comm_msg_ie_t *)(msg->payload);
    ie->cmd = htons(EN_COMM_MSG_MB_HB);
    ie->index = 0;

    /* Filling node data config */
    mb_cfg = (comm_msg_heartbeat_config *)ie->data;

    /* Set config */
    mb_cfg->key = lb_flag_key;
    memcpy(mb_cfg->mac[EN_PORT_N3], lb_get_local_port_mac(EN_LB_PORT_INT), ETH_ALEN);
    memcpy(mb_cfg->mac[EN_PORT_N6], lb_get_local_port_mac(EN_LB_PORT_INT), ETH_ALEN);
    memcpy(mb_cfg->mac[EN_PORT_N9], lb_get_local_port_mac(EN_LB_PORT_INT), ETH_ALEN);
    memcpy(mb_cfg->mac[EN_PORT_N4], lb_get_local_port_mac(EN_LB_PORT_INT), ETH_ALEN);

    ie_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_heartbeat_config);
    ie->len = htons(ie_len);

    buf_len = COMM_MSG_HEADER_LEN + ie_len;
    msg->total_len = htonl(buf_len);

    *len = buf_len;
}

void lb_backend_heartbeat_reply(int fd)
{
    comm_msg_rules_ie_t *ie = (comm_msg_rules_ie_t *)(lb_heartbeat_buf + COMM_MSG_HEADER_LEN);

    ie->rules_num = htonl(Res_GetAlloced(lb_get_backend_pool()));
    /* Send to backend */
    if (0 > comm_msg_channel_reply(fd, lb_heartbeat_buf, lb_heartbeat_len)) {
        LOG(LB, ERR, "Send buffer to fd %d failed.", fd);
    }
}

void lb_backend_validity(int fd)
{
    lb_backend_mgmt *be_mgmt = lb_get_backend_mgmt();
    uint32_t cnt = 0, send_times = 0, remainder = 0;
    comm_msg_header_t *msg;
    comm_msg_ie_t *ie;
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len = 0;
    comm_msg_entry_val_config_t *val_cfg = NULL;
    uint32_t max_num = (COMM_MSG_BACKEND_NUMBER - COMM_MSG_BACKEND_START_INDEX);

    msg = lb_fill_msg_header(buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd     = htons(EN_COMM_MSG_BACKEND_VALIDITY);
    ie->index   = htonl(0);
    val_cfg  = (comm_msg_entry_val_config_t *)ie->data;

    send_times = max_num / MAX_CHECK_VALIDITY_NUMBER;
    for (cnt = 0; cnt < send_times; ++cnt) {
        val_cfg->start = cnt * MAX_CHECK_VALIDITY_NUMBER + COMM_MSG_BACKEND_START_INDEX; /* Start with 1 */
        val_cfg->entry_num = MAX_CHECK_VALIDITY_NUMBER;

        if (G_SUCCESS != Res_GetRangeField(be_mgmt->be_pool_id, 0,
            val_cfg->start, val_cfg->entry_num, val_cfg->data)) {
            LOG(LB, ERR, "Get range field failed, start: %u, entry_num: %u.",
                val_cfg->start, val_cfg->entry_num);
            return;
        }

        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_entry_val_config_t) +
            ((val_cfg->entry_num >> RES_PART_LEN_BIT) * sizeof(uint32_t)) +
            ((val_cfg->entry_num & RES_PART_LEN_MASK) ? sizeof(uint32_t) : 0);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);

        if (0 > comm_msg_channel_reply(fd, (char *)buf, buf_len)) {
            LOG(LB, ERR, "Send buffer to fd %d failed.", fd);
            return;
        }
    }

    remainder = max_num % MAX_CHECK_VALIDITY_NUMBER;
    if (remainder) {
        val_cfg->start = cnt * MAX_CHECK_VALIDITY_NUMBER + COMM_MSG_BACKEND_START_INDEX;
        val_cfg->entry_num = remainder;

        if (G_SUCCESS != Res_GetRangeField(be_mgmt->be_pool_id, 0,
            val_cfg->start, val_cfg->entry_num, val_cfg->data)) {
            LOG(FASTPASS, ERR, "Get range field failed, start: %u, entry_num: %u.",
                val_cfg->start, val_cfg->entry_num);
            return;
        }

        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_entry_val_config_t) +
            ((val_cfg->entry_num >> RES_PART_LEN_BIT) * sizeof(uint32_t)) +
            ((val_cfg->entry_num & RES_PART_LEN_MASK) ? sizeof(uint32_t) : 0);
        ie->len        = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);

        if (0 > comm_msg_channel_reply(fd, (char *)buf, buf_len)) {
            LOG(LB, ERR, "Send buffer to fd %d failed.", fd);
            return;
        }
    }
}

lb_backend_config *lb_backend_register(comm_msg_backend_config *reg_cfg)
{
    lb_backend_mgmt *be_mgmt = lb_get_backend_mgmt();
    lb_backend_config *be_cfg;
    uint32_t res_key, res_index;

    if (G_FAILURE == Res_Alloc(lb_get_backend_pool(), &res_key, &res_index, EN_RES_ALLOC_MODE_OC)) {
        LOG(LB, ERR, "Backend register failed, resouce alloc failed.\n");
        return NULL;
    }

    be_cfg = lb_get_backend_config(res_index);

    ros_memcpy(&be_cfg->be_config, reg_cfg, sizeof(comm_msg_backend_config));
    ros_atomic16_set(&be_cfg->valid, TRUE);
    ros_atomic32_init(&be_cfg->assign_count);

    ros_rwlock_write_lock(&be_mgmt->lock); /* lock */
    if (0 > rbtree_insert(&be_mgmt->be_root, &be_cfg->be_node, &be_cfg->be_config.key, lb_backend_compare)) {
        LOG(LB, ERR, "Insert backend to RB-tree failed.");
        Res_Free(lb_get_backend_pool(), res_key, res_index);
        ros_rwlock_write_unlock(&be_mgmt->lock); /* unlock */

        return NULL;
    }
    ros_rwlock_write_unlock(&be_mgmt->lock); /* unlock */

    LOG(LB, MUST, "Backend registered successful, key: 0x%lx, be_index: %u.",
        be_cfg->be_config.key, res_index);

    if (lb_hk_sync_be_table) {
        lb_hk_sync_be_table(res_index);
    }

    return be_cfg;
}

void lb_backend_unregister(uint8_t be_index)
{
    lb_backend_mgmt *be_mgmt = lb_get_backend_mgmt();
    uint32_t cnt1, cnt2;
    lb_backend_config *be_cfg;

    be_cfg = lb_get_backend_config(be_index);

    if (G_FALSE == Res_IsAlloced(lb_get_backend_pool(), 0, be_index) &&
        FALSE == ros_atomic16_read(&be_cfg->valid)) {
        return;
    }

    ros_rwlock_write_lock(&be_mgmt->lock); /* lock */
    rbtree_erase(&be_cfg->be_node, &be_mgmt->be_root);
    ros_rwlock_write_unlock(&be_mgmt->lock); /* unlock */

    ros_atomic16_set(&be_cfg->valid, FALSE);

    if (ros_atomic32_read(&be_cfg->assign_count) > 0) {
        for (cnt1 = 0; cnt1 < LB_HASH_1_NUMBER; ++cnt1) {
            for (cnt2 = 0; cnt2 < LB_HASH_2_NUMBER; ++cnt2) {
                if (lb_hash_table[cnt1][cnt2] == (uint8_t)be_index) {
                    lb_hash_table[cnt1][cnt2] = 0;
                }
            }
        }
    }

    ros_atomic32_init(&be_cfg->assign_count);
    be_cfg->fd = -1;
    Res_Free(lb_get_backend_pool(), 0, be_index);

    if (lb_hk_sync_be_table) {
        lb_hk_sync_be_table(be_index);
    }

    LOG(LB, MUST, "Backend unregistered successful, key: 0x%lx, be_index: %u.",
        be_cfg->be_config.key, be_index);
}

lb_backend_config *lb_backend_search(uint64_t be_key)
{
    lb_backend_mgmt *be_mgmt = lb_get_backend_mgmt();
    lb_backend_config *be_cfg;

    ros_rwlock_read_lock(&be_mgmt->lock); /* lock */
    be_cfg = (lb_backend_config *)rbtree_search(&be_mgmt->be_root, &be_key, lb_backend_compare);
    if (NULL == be_cfg) {
        LOG(LB, ERR, "Search backend failed, no such backend key: %lu.", be_key);
        ros_rwlock_read_unlock(&be_mgmt->lock); /* unlock */

        return NULL;
    }
    ros_rwlock_read_unlock(&be_mgmt->lock); /* unlock */

    LOG(LB, RUNNING, "Backend search successful, key: %lu.", be_key);

    return be_cfg;
}

static void *lb_mb_heartbeat_task(void *arg)
{
    lb_backend_mgmt *be_mgmt = lb_get_backend_mgmt();

    for (;;) {

        if (LB_STATUS_ACTIVE == lb_get_work_status() && lb_mb_work_state_get_public()) {
            if (LB_BACKEND_TIMEOUT_MAX <= ros_atomic32_add_return(&be_mgmt->mb_heartbeat_cnt, 1)) {
                int32_t cur_index = COMM_MSG_BACKEND_START_INDEX - 1;
                int32_t pool_id = lb_get_backend_pool();

                lb_mb_work_state_set(FALSE);
                ros_atomic32_init(&be_mgmt->mb_heartbeat_cnt);

                /* Unregister all backend */
                while (-1 != (cur_index = Res_GetAvailableInBand(pool_id, cur_index + 1, COMM_MSG_BACKEND_NUMBER))) {
                    lb_backend_unregister(cur_index);
                }
            }
        }

        /* Scan interval */
        sleep(2);
    }

    return NULL;
}

int32_t lb_backend_init(lb_system_config *system_cfg)
{
    lb_backend_mgmt *be_mgmt = lb_get_backend_mgmt();
    uint32_t cnt;
    cpu_set_t cpuset;
    pthread_attr_t attr1;
    pthread_t pthr_id;

    /* Init backend-table and hash-table */
    be_mgmt->be_pool_id = Res_CreatePool();
    if (be_mgmt->be_pool_id < 0) {
        LOG(LB, ERR, "Res_CreatePool failed.\n");
        return -1;
    }

    if (G_FAILURE == Res_AddSection(be_mgmt->be_pool_id, 0, COMM_MSG_BACKEND_START_INDEX,
        COMM_MSG_BACKEND_NUMBER - COMM_MSG_BACKEND_START_INDEX)) {
        LOG(LB, ERR, "Res_AddSection failed.\n");
        return -1;
    }

    /* Init hash table */
    memset(lb_hash_table, 0, sizeof(lb_hash_table));
    for (cnt = 0; cnt < COMM_MSG_BACKEND_NUMBER; ++cnt) {
        ros_atomic16_init(&be_mgmt->backend_table[cnt].valid);
        ros_atomic32_init(&be_mgmt->backend_table[cnt].assign_count);
        ros_rwlock_init(&be_mgmt->backend_table[cnt].lock);
        be_mgmt->backend_table[cnt].fd = -1;
        be_mgmt->backend_table[cnt].index = cnt;
    }

    be_mgmt->be_root = RB_ROOT_INIT_VALUE;
    be_mgmt->mb_fd = -1;
    ros_atomic32_init(&be_mgmt->mb_heartbeat_cnt);
    ros_rwlock_init(&be_mgmt->lock);

    lb_flag_key = ros_rdtsc() ^ (uint64_t)system_cfg->ha_remote_ip[0];
    lb_backend_heartbeat_buffer_create(lb_heartbeat_buf, &lb_heartbeat_len);

    /* Init backend heartbeat task */
    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    CPU_SET(system_cfg->cpus[0], &cpuset);

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(LB, ERR, "Pthread set affinity fail on core(%d)", system_cfg->cpus[0]);
        return -1;
    }

    if (pthread_create(&pthr_id, &attr1, lb_mb_heartbeat_task, NULL) != 0)    {
        LOG(LB, ERR, "Fail to create tcp client pthread, errno:%s", strerror(errno));
        return -1;
    }

    /* Init backend management service */
    if (0 == system_cfg->ha_remote_ip_num) {
        /* Only master can be create backend channel */
        if (0 > comm_msg_create_channel_server(&be_mgmt->mb_mgmt_server,
            system_cfg->be_mgmt_port, system_cfg->cpus, 1)) {
            LOG(LB, ERR, "Create channel server failed.");
            return -1;
        }
    }

    LOG(LB, RUNNING, "Backend management init success\n");

    return 0;
}

