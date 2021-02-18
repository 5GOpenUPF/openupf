/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "comm_msg.h"
#include "trans.h"

extern CVMX_SHARED uint16_t comm_msg_comm_id;


static inline uint32_t trans_get_time(void)
{
    return ros_getruntime();
}

static void trans_make_header(void *buf)
{
    comm_msg_header_t   *msg_hdr;
#if (defined(PRODUCT_IS_smu))
    uint8_t             localmac[6] = {0x00, 0x3c, 0x53, 0x50, 0x55, 0x3e};
    uint8_t             peermac[6]  = {0x00, 0x88, 0x88, 0x88, 0x88, 0x88};
#else
    uint8_t             localmac[6] = {0x00, 0x88, 0x88, 0x88, 0x88, 0x88};
    uint8_t             peermac[6]  = {0x00, 0x3c, 0x53, 0x50, 0x55, 0x3e};
#endif
    struct pro_eth_hdr  *eth;

    if (unlikely(NULL == buf)) {
        return;
    }

    eth = (struct pro_eth_hdr *)buf;

    /* set mac header */
    memcpy(eth->source, localmac, ETH_ALEN);
    memcpy(eth->dest, peermac, ETH_ALEN);
    eth->eth_type = SERVICE_PROTO;

    /* set msg header */
    msg_hdr = (comm_msg_header_t *)(eth + 1);

    /* set default msg header */
    msg_hdr->magic_word    = htonl(COMM_MSG_MAGIC_WORD);
    msg_hdr->comm_id       = htons(comm_msg_comm_id);
    msg_hdr->major_version = COMM_MSG_MAJOR_VERSION;
    msg_hdr->minor_version = COMM_MSG_MINOR_VERSION;
}

static comm_msg_header_t *trans_get_msg_hdr(char *pkt)
{
    return (comm_msg_header_t *)(pkt + ETH_HLEN);
}

static void trans_remove_wait_train(trans_train_mng *mng, uint16_t ack_index)
{
    if (ack_index >= mng->max_num) {
        LOG(COMM, ERR, "Abnormal parameter, ack_index: %u > max: %u",
            ack_index, mng->max_num);
        return;
    }

    ros_rwlock_write_lock(&mng->rwlock); /* lock */
    if (G_TRUE == Res_IsAlloced(mng->pool_id, 0, ack_index)) {
        LOG(COMM, PERIOD, "klist-del index: %u, node(%p), node->next(%p), node->prev(%p)",
            ack_index, &mng->entry[ack_index].node, mng->entry[ack_index].node.next,
            mng->entry[ack_index].node.prev);
        dl_list_del(&mng->entry[ack_index].node);
        Res_Free(mng->pool_id, 0, ack_index);
    } else {
        /* Redundancy is not handled */
    }
    ros_rwlock_write_unlock(&mng->rwlock); /* unlock */
}

static int trans_write_ack(trans_train_mng *mng, uint16_t send_index, uint16_t ans_index)
{
    if (send_index == TRANS_NO_ACK_INDEX)
        return 0; /* Skip */

    ros_rwlock_write_lock(&mng->rwlock); /* lock */
    if (ans_index == TRANS_NO_ACK_INDEX) {
        if (G_FAILURE == Res_AllocTarget(mng->ack2_pool, 0, send_index)) {
            ros_rwlock_write_unlock(&mng->rwlock); /* unlock */
            LOG(COMM, ERR, "Duplicate message received");
            return -1;
        }
    } else {
        if (G_FAILURE == Res_AllocTarget(mng->ack_pool, 0, send_index)) {
            ros_rwlock_write_unlock(&mng->rwlock); /* unlock */
            LOG(COMM, ERR, "Duplicate message received");
            return -1;
        }
    }
    ros_rwlock_write_unlock(&mng->rwlock); /* unlock */

    return 0;
}

static void trans_read_ack(uint16_t pool_id, uint32_t res_end, uint16_t *ack_arr,
    uint32_t *ack_num, uint16_t max_num)
{
    int32_t cur_index = -1;
    uint16_t ack_cnt = 0;

    cur_index = Res_GetAvailAndFreeInBand(pool_id, cur_index + 1, res_end);
    for (; -1 != cur_index;) {
        if (ack_cnt < max_num) {
            ack_arr[ack_cnt] = htons((uint16_t)cur_index);
            ++ack_cnt;
        } else {
            break;
        }

        cur_index = Res_GetAvailAndFreeInBand(pool_id, cur_index + 1, res_end);
    }

    *ack_num = ack_cnt;
}

int trans_reset(trans_train_mng *mng)
{
    trans_train_entry *train;
    struct dl_list *pos, *next;
    comm_msg_header_t *hb_msg;

    ros_rwlock_write_lock(&mng->rwlock); /* lock */

    /* if reset, release all local resend queue */
    dl_list_for_each_safe(pos, next, &mng->lst_wait) {
        train = (trans_train_entry *)container_of(pos,
            trans_train_entry, node);

        dl_list_del(&train->node);
        Res_Free(mng->pool_id, 0, train->index);
    }

    if (mng->train) {
        Res_Free(mng->pool_id, 0, mng->train->index);
        mng->train = NULL;
    }

    Res_FreeBatch(mng->ack_pool, 0, 0, mng->max_num);

    hb_msg = trans_get_msg_hdr(mng->hb_buf);
    hb_msg->comm_id = htons(comm_msg_comm_id);
    ros_rwlock_write_unlock(&mng->rwlock); /* unlock */

    return OK;
}

static trans_train_entry *trans_create(trans_train_mng *mng)
{
    trans_train_entry *train;
    uint32_t index, key;

    /* get cblk */
    if (G_FAILURE == Res_Alloc(mng->pool_id, &key, &index, EN_RES_ALLOC_MODE_OC)) {
        LOG(COMM, ERR, "Trans resource exhaustion.");
        return NULL;
    }

    train = &mng->entry[index];

    /* make header */
    train->buf_len  = COMM_MSG_HEADER_LEN + ETH_HLEN;
    trans_make_header(train->buf);

    /* enroll a new train */
    mng->train      = train;

    return train;
}

static inline void trans_depart(trans_train_mng *mng, trans_train_entry *train)
{
    comm_msg_header_t *msg_hdr = trans_get_msg_hdr(train->buf);

    LOG(COMM, PERIOD, "depart a train, length %d, local index %d.",
        train->buf_len, train->index);

    /* set index */
    msg_hdr->index  = htons((uint16_t)train->index);
    msg_hdr->answer = htons((uint16_t)train->index);

    /* set length */
    msg_hdr->total_len = htonl(train->buf_len - ETH_HLEN);

    /* save departure time */
    train->resend_time = trans_get_time() + TRANS_TRAIN_RESEND_INTERVAL;

    /* depart train */
    dl_list_add_tail(&mng->lst_wait, &train->node);
    mng->send(mng->token, train->buf, train->buf_len);

    mng->train = NULL;
}

static inline void trans_create_ack_depart(trans_train_mng *mng)
{
    trans_train_entry *old_train = mng->train, *new_train; /* save old train */
    comm_msg_header_t *msg_hdr;
    comm_msg_trans_ack_ie_t *ack_ie;
    uint16_t max_fill_num;

    /* Create new train */
    new_train = trans_create(mng);
    if (NULL == new_train) {
        return;
    }
    msg_hdr = trans_get_msg_hdr(new_train->buf);

    /* set index */
    msg_hdr->index  = htons((uint16_t)new_train->index);
    msg_hdr->answer = htons(TRANS_NO_ACK_INDEX);

    /* fill ack */
    max_fill_num = (SERVICE_BUF_MAX_LEN - new_train->buf_len);
    max_fill_num = max_fill_num > sizeof(comm_msg_trans_ack_ie_t) ? max_fill_num - sizeof(comm_msg_trans_ack_ie_t) : 0;
    max_fill_num >>= 1; /* divide sizeof(uint16_t) */
    if (max_fill_num) {
        uint16_t ack_fill_len;

        ack_ie = (comm_msg_trans_ack_ie_t *)(new_train->buf + new_train->buf_len);
        ack_ie->cmd = htons(EN_COMM_MSG_TRANS_REPLY_ACK);
        trans_read_ack(mng->ack_pool, mng->max_num, ack_ie->ack, &ack_ie->ack_num, max_fill_num);
        ack_fill_len = ack_ie->ack_num * sizeof(ack_ie->ack[0]) + sizeof(comm_msg_trans_ack_ie_t);
        ack_ie->ack_num = htonl(ack_ie->ack_num);
        ack_ie->len = htons(ack_fill_len);
        new_train->buf_len += ack_fill_len;
        LOG(COMM, PERIOD, "depart ack number: %u", htonl(ack_ie->ack_num));
    }

    /* set length */
    msg_hdr->total_len = htonl(new_train->buf_len - ETH_HLEN);

    /* save departure time */
    new_train->resend_time = trans_get_time() + TRANS_TRAIN_RESEND_INTERVAL;

    /* depart train */
    dl_list_add_tail(&mng->lst_wait, &new_train->node);
    mng->send(mng->token, new_train->buf, new_train->buf_len);

    LOG(COMM, PERIOD, "depart a reply train, length %d, local index %d.",
        new_train->buf_len, new_train->index);

    mng->train = old_train;
}

static void trans_create_ack2_depart(trans_train_mng *mng)
{
    char buf[SERVICE_BUF_TOTAL_LEN];
    uint16_t buf_len;
    comm_msg_header_t *msg_hdr;
    comm_msg_trans_ack_ie_t *ack_ie;
    uint16_t max_fill_num;

    trans_make_header(buf);
    msg_hdr = trans_get_msg_hdr(buf);
    buf_len = COMM_MSG_HEADER_LEN + ETH_HLEN;

    /* set index */
    msg_hdr->index  = htons(TRANS_NO_ACK_INDEX);
    msg_hdr->answer = htons(TRANS_NO_ACK_INDEX);

    /* fill ack */
    max_fill_num = (SERVICE_BUF_MAX_LEN - buf_len);
    max_fill_num = max_fill_num > sizeof(comm_msg_trans_ack_ie_t) ? max_fill_num - sizeof(comm_msg_trans_ack_ie_t) : 0;
    max_fill_num >>= 1; /* divide sizeof(uint16_t) */
    if (max_fill_num) {
        uint16_t ack_fill_len;

        ack_ie = (comm_msg_trans_ack_ie_t *)(buf + buf_len);
        ack_ie->cmd = htons(EN_COMM_MSG_TRANS_REPLY_ACK);
        trans_read_ack(mng->ack2_pool, mng->max_num, ack_ie->ack, &ack_ie->ack_num, max_fill_num);
        ack_fill_len = ack_ie->ack_num * sizeof(ack_ie->ack[0]) + sizeof(comm_msg_trans_ack_ie_t);
        ack_ie->ack_num = htonl(ack_ie->ack_num);
        ack_ie->len = htons(ack_fill_len);
        buf_len += ack_fill_len;
        LOG(COMM, PERIOD, "depart ack2 number: %u", htonl(ack_ie->ack_num));
    }

    /* set length */
    msg_hdr->total_len = htonl(buf_len - ETH_HLEN);

    /* depart train */
    mng->send(mng->token, buf, buf_len);

    LOG(COMM, PERIOD, "depart a reply train, length %d, local index %d.",
        buf_len, TRANS_NO_ACK_INDEX);
}

void *trans_loop_task(void *arg)
{
    trans_train_mng     *mng = (trans_train_mng *)arg;
    trans_train_entry   *train; /* current train */
    struct dl_list   *pos, *next;
    uint32_t            send_num;
    uint64_t            cut_us, next_round_us;
    uint64_t            tsc_resolution_hz = ros_get_tsc_hz();
    uint64_t            per_us_tsc = ros_get_tsc_hz() / 1000000;
    uint64_t            detecte_interval_hz = (TRANS_SEND_QUEUE_DETECTION_INTERVAL * tsc_resolution_hz / 1000000);

    for (;;) {
        next_round_us = (ros_rdtsc() + detecte_interval_hz) / per_us_tsc;

        ros_rwlock_write_lock(&mng->rwlock); /* lock */

        /* Send queue */
        /* Process not urgent buffer */
        if (mng->train && (mng->train->buf_len > (ETH_HLEN + COMM_MSG_HEADER_LEN))) {
            /* train depart */
            trans_depart(mng, mng->train);

            /* new train */
            trans_create(mng);
        }

        if (Res_GetAlloced(mng->ack_pool)) {
            trans_create_ack_depart(mng);
        }
        if (Res_GetAlloced(mng->ack2_pool)) {
            trans_create_ack2_depart(mng);
        }

        /* Resend queue */
        /* Retransmit only the first part of the message */
        send_num = 0;
        dl_list_for_each_safe(pos, next, &mng->lst_wait) {
            train = (trans_train_entry *)container_of(pos,
                trans_train_entry, node);
            if (train->resend_time < trans_get_time()) {
                if (send_num < TRANS_PER_TIME_SEND_NUM) {
                    LOG(COMM, ERR, "Resend train, index: %hu", train->index);
                    mng->send(mng->token, train->buf, train->buf_len);
                    train->resend_time = trans_get_time() + TRANS_TRAIN_RESEND_INTERVAL;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        ros_rwlock_write_unlock(&mng->rwlock); /* unlock */

        /* send heartbeat ie */
        if (mng->next_hb_time < trans_get_time()) {
            mng->send(mng->token, mng->hb_buf, mng->hb_buf_len);
            mng->next_hb_time = trans_get_time() + TRANS_TRAIN_HEARTBEAT_INTERVAL;
        }

        cut_us = ros_rdtsc() / per_us_tsc;
        /* No usleep for less than 1 ms */
        if ((next_round_us - 1000) > cut_us) {
            usleep(next_round_us - cut_us);
        }
    }

    return NULL;
}

int trans_send(trans_train_mng *mng, comm_msg_ie_t *ie, uint16_t len, uint8_t urgent)
{
    trans_train_entry *train;   /* current train */

    if (unlikely(len > TRANS_MTU_SIZE)) {
        LOG(COMM, ERR, "Error: IE command: 0x%x, Send buffer length too long, The message could not be sent.",
            ie->cmd);
        return ERROR;
    }

    ros_rwlock_write_lock(&mng->rwlock); /* lock */

    /* get current train */
    train = mng->train;
    if (unlikely(NULL == train)) {
        /* if no train, create one */
        train = trans_create(mng);
        if (NULL == train) {
            ros_rwlock_write_unlock(&mng->rwlock); /* unlock */
            return ERROR;
        }
    }

    /* if train full, send out then create new */
    if (train->buf_len + len > TRANS_MTU_SIZE) {
        /* train depart */
        trans_depart(mng, train);

        /* new train */
        train = trans_create(mng);
        if (NULL == train) {
            ros_rwlock_write_unlock(&mng->rwlock); /* unlock */
            return ERROR;
        }
    }

    /* get on the train */
    memcpy(train->buf + train->buf_len, ie, len);
    train->buf_len += len;

    /* if urgent, send immediately */
    if (urgent) {
        /* train depart */
        trans_depart(mng, train);

        /* new train */
        train = trans_create(mng);
        if (NULL == train) {
            ros_rwlock_write_unlock(&mng->rwlock); /* unlock */
            return ERROR;
        }
    }
    ros_rwlock_write_unlock(&mng->rwlock); /* unlock */

    LOG(COMM, PERIOD, "send ie %p, length %d, urgent flag %d",
        ie, len, urgent);

    return OK;
}

int trans_recv(void *trans_mng, uint8_t *inbuf, uint32_t inlen)
{
    comm_msg_header_t   *cmd_header;
    int32_t             reminder_len;
    trans_train_mng     *mng = (trans_train_mng *)trans_mng;
    uint16_t            comm_id;

    if ((NULL == mng)|| (NULL == inbuf) || (inlen < COMM_MSG_HEADER_LEN)) {
        LOG(COMM, ERR, "Incorrect parameter input, mng(%p), inbuf(%p), inlen(%d)", mng, inbuf, inlen);
        return ERROR;
    }

    LOG(COMM, PERIOD, "Recv msg buf(%p), length: %u.", inbuf, inlen);

    /* 1. parse header */
    cmd_header = (comm_msg_header_t *)(inbuf);

    reminder_len = ntohl(cmd_header->total_len);
    if (reminder_len != inlen) {
        LOG(COMM, ERR, "Invalid msg length(%u), not equal to packet length(%u).",
            reminder_len, inlen);
        return ERROR;
    }
    if (cmd_header->magic_word != ntohl(COMM_MSG_MAGIC_WORD))
    {
        LOG(COMM, ERR,
            "protocol error in magic word(%x).",
            ntohl(cmd_header->magic_word));
        return ERROR;
    }
    if (cmd_header->major_version != COMM_MSG_MAJOR_VERSION)
    {
        LOG(COMM, ERR,
            "protocol error in major version(%d).",
            cmd_header->major_version);
        return ERROR;
    }
    if (cmd_header->minor_version != COMM_MSG_MINOR_VERSION)
    {
        LOG(COMM, ERR,
            "protocol error in minor version(%d).",
            cmd_header->minor_version);
        return ERROR;
    }
    comm_id = htons(cmd_header->comm_id);

    if (0 != trans_write_ack(mng, htons(cmd_header->index), htons(cmd_header->answer))) {
        LOG(COMM, RUNNING, "Discard duplicate messages, drop it.");
        return ERROR;
    }

    LOG(COMM, PERIOD,
        "get packet, magic %08x, train length %u, ie from offset %lu, comm_id %d, local index %d",
        ntohl(cmd_header->magic_word), ntohl(cmd_header->total_len), COMM_MSG_HEADER_LEN,
        htons(cmd_header->comm_id), htons(cmd_header->index));

    reminder_len -= COMM_MSG_HEADER_LEN;

    return comm_msg_parse_ie(trans_mng, cmd_header->payload, reminder_len, comm_id);
}

void trans_reply_ack(void *trans_mng, comm_msg_ie_t *ie)
{
    comm_msg_trans_ack_ie_t *trans_ie = (comm_msg_trans_ack_ie_t *)ie;
    uint32_t cnt;

    LOG(COMM, PERIOD, "recv reply ack number: %u.", trans_ie->ack_num);
    for (cnt = 0; cnt < trans_ie->ack_num; ++cnt) {
        trans_remove_wait_train(trans_mng, ntohs(trans_ie->ack[cnt]));
    }
}

trans_train_mng *trans_register(void *token, TRANS_SEND send)
{
    trans_train_mng     *mng;
    comm_msg_ie_t       *ie;
    comm_msg_header_t   *hb_msg;
    pthread_t           thread_id;
    int32_t             res_no = 0, ack_res = 0, ack2_res = 0;
    uint8_t             *tmp = NULL;
    int64_t             total_mem = 0, size = 0;
    int32_t             loop;
    uint32_t            train_num = TRANS_TRAIN_NUM;

    LOG(COMM, ERR, "sizoef trans_train_mng: %lu", sizeof(trans_train_mng));
    /* alloc management block */
    size = train_num * sizeof(trans_train_entry) + sizeof(trans_train_mng);
    total_mem += size;
    tmp = (uint8_t *)TRANS_SHM_MALLOC(GLB_TRANS_POOL_SYMBOL, size, CACHE_LINE_SIZE);
    if (NULL == tmp) {
        LOG(FASTPASS, ERR, "Malloc failed.");
        return NULL;
    }
    ros_memset(tmp, 0, size);

    mng = (trans_train_mng *)tmp;
    for (loop = 0; loop < train_num; loop++) {
        mng->entry[loop].index = loop;
    }

    res_no = Res_CreatePool();
    if (res_no < 0) {
        LOG(FASTPASS, ERR, "Create pool fail.");
        goto fail;
    }
    if (G_FAILURE == Res_AddSection(res_no, 0, 0, train_num)) {
        LOG(FASTPASS, ERR, "Add section fail.");
        goto fail;
    }

    ack_res = Res_CreatePool();
    if (ack_res < 0) {
        LOG(FASTPASS, ERR, "Create pool fail.");
        goto fail;
    }
    if (G_FAILURE == Res_AddSection(ack_res, 0, 0, train_num)) {
        LOG(FASTPASS, ERR, "Add section fail.");
        goto fail;
    }

    ack2_res = Res_CreatePool();
    if (ack2_res < 0) {
        LOG(FASTPASS, ERR, "Create pool fail.");
        goto fail;
    }
    if (G_FAILURE == Res_AddSection(ack2_res, 0, 0, train_num)) {
        LOG(FASTPASS, ERR, "Add section fail.");
        goto fail;
    }

    mng->pool_id        = (uint16_t)res_no;
    mng->ack_pool       = (uint16_t)ack_res;
    mng->ack2_pool      = (uint16_t)ack2_res;
    mng->max_num        = train_num;
    mng->send           = send;
    mng->token          = token;
    mng->next_hb_time   = trans_get_time() + TRANS_TRAIN_HEARTBEAT_INTERVAL;
    mng->hb_tmo         = 0;
    dl_list_init(&mng->lst_wait);
    ros_rwlock_init(&mng->rwlock);

    /* Fill heartbeat message */
    trans_make_header(mng->hb_buf);
    hb_msg = trans_get_msg_hdr(mng->hb_buf);
    ie = (comm_msg_ie_t *)hb_msg->payload;
    ie->cmd         = htons(EN_COMM_MSG_HEARTBEAT);
    ie->len         = htons(COMM_MSG_IE_LEN_COMMON);
    ie->index       = 0;
    hb_msg->index   = htons(TRANS_NO_ACK_INDEX);
    hb_msg->answer  = htons(TRANS_NO_ACK_INDEX);
    mng->hb_buf_len = COMM_MSG_HEADER_LEN + ETH_HLEN + COMM_MSG_IE_LEN_COMMON;
    hb_msg->total_len = htonl(mng->hb_buf_len - ETH_HLEN);

    if (0 != pthread_create(&thread_id, NULL, trans_loop_task, mng)) {
        LOG(COMM, ERR, "pthread_create fail ");
        goto fail;
    }

    return mng;

fail:

    TRANS_SHM_FREE(GLB_TRANS_POOL_SYMBOL, tmp);
    return NULL;
}

