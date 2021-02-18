/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#ifndef _TRANS_H__
#define _TRANS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "comm_msg.h"


#define TRANS_HEARDBEAT_PERIOD              100     /* 100*10ms */
#define TRANS_TIMEOUT                       2
/* TRANS_MTU_SIZE需要大于或等于SERVICE_BUF_TOTAL_LEN否则会出现消息无法发送或者其他异常 */
#define TRANS_MTU_SIZE                      SERVICE_BUF_TOTAL_LEN
#define TRANS_WINDOW_SIZE                   8
#define TRANS_MAX_WAITING_QUEUE             128
#define TRANS_MAX_SEND_NUM                  1000

#define TRANS_SHM_MALLOC(name, size, align) ros_malloc(size)
#define TRANS_SHM_FREE(name, ptr)           ros_free(ptr)

typedef int32_t (*TRANS_SEND)(void *token, char *buf, uint32_t len);


#define TRANS_HEARTBEAT_TIMEOUT_TIMES       3
typedef enum {
    EN_TRANS_NORMAL     = 1,
    EN_TRANS_ABNORMAL,
} EN_TRANS_STATE;

/* TRANS train max number, Do not be greater than or equal to 0xFFFF(TRANS_HEARTBEAT_INDEX) */
#define TRANS_TRAIN_NUM         10000

/* the message does not need to be answered */
#define TRANS_NO_ACK_INDEX   0xFFFF

/* TRANS heartbeat and resend interval time, Unit: seconds */
#define TRANS_TRAIN_HEARTBEAT_INTERVAL      1

/* TRANS resend interval time, Unit: seconds */
#define TRANS_TRAIN_RESEND_INTERVAL         2

/* TRANS Message sending queue detection interval, Unit: Microseconds */
#define TRANS_SEND_QUEUE_DETECTION_INTERVAL     100000
#define TRANS_PER_TIME_SEND_NUM                 100


#pragma pack(1)
typedef struct tag_trans_train_entry {
    struct dl_list          node;
    uint32_t                index;
    uint32_t                resend_time;    /* resend time */
    uint32_t                buf_len;
    uint32_t                spare;  /* Spare */
    char                    buf[SERVICE_BUF_TOTAL_LEN];
} trans_train_entry;
#pragma pack()

#pragma pack(1)
typedef struct tag_trans_train_mng {
    struct dl_list          lst_wait; /* Wait first ACK queue */
    trans_train_entry       *train;         /* current train */
    TRANS_SEND              send;
    void                    *token;         /* service token */
    ros_rwlock_t            rwlock;
    uint32_t                next_hb_time;   /* Next heartbeat time */
    uint16_t                max_num;
    uint16_t                pool_id;        /* Train entry resource pool */
    uint16_t                ack_pool;       /* Save ACK index */
    uint16_t                ack2_pool;      /* Save ACK2 index */
    uint8_t                 hb_tmo;         /* Heartbeat timeout times */
    uint8_t                 hb_buf_len;
    char                    hb_buf[70];     /* Need >= 38 */
    /*------------cache line 128-------------*/

    trans_train_entry       entry[0];
} trans_train_mng;
#pragma pack()

int  trans_send(trans_train_mng *mng, comm_msg_ie_t *ie, uint16_t len, uint8_t urgent);
int  trans_recv(void *token, uint8_t *inbuf, uint32_t inlen);
void trans_reply_ack(void *trans_mng, comm_msg_ie_t *ie);
int  trans_reset(trans_train_mng *mng);
trans_train_mng *trans_register(void *token, TRANS_SEND send);


#ifdef __cplusplus
}
#endif

#endif /* _TRANS_H__ */

