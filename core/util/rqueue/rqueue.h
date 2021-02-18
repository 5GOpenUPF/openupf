/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _RQUEUE_H__
#define _RQUEUE_H__

#if 0
#define RQ_LOG(fmt, arg...) \
do { \
    printf("%s(%d) "fmt"\r\n", __FUNCTION__, __LINE__, ##arg); \
   } while((0))

#else
#define RQ_LOG(fmt, arg...) \
do { \
   } while((0))
#endif

#define RQUEUE_CACHE_LINE_SIZE      (128)

/**
*   unit: Microsecond
*   CPU: Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz
*   When setting the sleep time to 100, the CPU usage is 6%
*   When setting the sleep time to 200, the CPU usage is 2%
*   When setting the sleep time to 500, the CPU usage is 1%
*/
#define RQUEUE_PER_ROUND_WAIT_TIME  (400)


#define RQUEUE_ALIGN(val, align) \
	(((val) + ((typeof(val))(align) - 1)) & (~((typeof(val))((align) - 1))))

#define RQUEUE_IS_ALIGN(val, align) \
	((val) == ((val) & (~((typeof(val))((align) - 1)))))


enum EN_RQ_NODE_STATUS {
    /* The node Can write */
    RQ_NODE_IDLE        = 0,

    /* The node is written and can be read */
    RQ_NODE_FULL        = 1,
};

/* Ring queue node */
typedef struct tag_ring_queue_node_t {
    ros_atomic16_t      flag;       /* EN_RQ_NODE_STATUS */
    uint8_t             spare[2];   /* Spare */
    int32_t             data_len;   /* Length of valid data */
    char                *data;      /* data pointer, always points to a valid address */
} rqueue_node_t;

/* Ring queue control block */
typedef struct tar_rqueue_cb_t {
    uint8_t             *db;            /* Data block */
    uint32_t            db_size;        /* Size of each Data block */
    uint32_t            node_num;       /* Number of ring queue node */
    rqueue_node_t       *rq_node;       /* Node of ring queue */
    uint32_t            produce_offset; /* Next enqueue offset */
    uint32_t            consume_offset; /* Next dequeue offset */
    uint32_t            node_num_mask;  /* Mask of ring queue node */
    uint8_t             rq_num;         /* The number of RQ structure arrays */
    uint8_t             spare[3];
} rqueue_cb_t;


#define rqueue_destroy(rq_cb) \
    do { \
        __rqueue_destroy(rq_cb); \
        rq_cb = NULL; \
    } while((0))\

rqueue_cb_t *rqueue_create(uint8_t rq_num, uint32_t db_size, uint32_t qnode_num);
void __rqueue_destroy(rqueue_cb_t *rq_cb);
rqueue_node_t *rqueue_produce_round_s(rqueue_cb_t *rq_cb);
rqueue_node_t *rqueue_produce_round_m(rqueue_cb_t *rq_cb);
rqueue_node_t *rqueue_consume_round_s(rqueue_cb_t *rq_cb);
rqueue_node_t *rqueue_consume_round_m(rqueue_cb_t *rq_cb);
rqueue_node_t *rqueue_produce_always_s(rqueue_cb_t *rq_cb);
rqueue_node_t *rqueue_produce_always_m(rqueue_cb_t *rq_cb);
rqueue_node_t *rqueue_consume_always_s(rqueue_cb_t *rq_cb);
rqueue_node_t *rqueue_consume_always_m(rqueue_cb_t *rq_cb);
void rqueue_set_produce_flag(rqueue_node_t *rq_node);
void rqueue_set_consume_flag(rqueue_node_t *rq_node);

int rqueue_create_mul_affipthr(pthread_t *pthr_arr, void *(*pthr_cb)(void *),
    void *arg, uint8_t cpus[], uint8_t num);



#endif  /* #ifndef  _RQUEUE_H__ */

