/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "rqueue.h"

/* Test code */
static uint32_t test_times = 10000;
/* end */

static inline int rqueue_is_power_of_2(uint32_t n)
{
	return n && !(n & (n - 1));
}

static inline uint32_t rqueue_align32pow2(register uint32_t x)
{
    x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x + 1;
}

/*
* 每个队列只支持单生产者单消费者
* rq_num: 需要创建多少个环形队列
* db_size: 每个节点的数据块大小
* qnode_num: 每个队列的节点数量
*/
rqueue_cb_t *rqueue_create(uint8_t rq_num, uint32_t db_size, uint32_t qnode_num)
{
    rqueue_cb_t *rq_cb;
    rqueue_node_t *rq_node, *rq_node_pos;
    uint8_t *db, *db_pos;
    uint32_t cnt;
    uint8_t rq_cnt;

    if (0 == rq_num) {
        RQ_LOG("Parameter error, rq_num:%u Cannot be 0.", rq_num);
        return NULL;
    }

    if (0 == rqueue_is_power_of_2(qnode_num)) {
        qnode_num = rqueue_align32pow2(qnode_num);
    }

    db_size = RQUEUE_ALIGN(db_size, 8);

    rq_cb = ros_calloc(rq_num, sizeof(rqueue_cb_t));
    if (NULL == rq_cb) {
        RQ_LOG("Calloc memory failed.");
        return NULL;
    }
    rq_node = ros_calloc(qnode_num * rq_num, sizeof(rqueue_node_t));
    if (NULL == rq_node) {
        ros_free(rq_cb);
        RQ_LOG("Calloc memory failed.");
        return NULL;
    }
    db = ros_calloc(qnode_num * rq_num, db_size);
    if (NULL == db) {
        ros_free(rq_cb);
        ros_free(rq_node);
        RQ_LOG("Calloc memory failed.");
        return NULL;
    }

    for (rq_cnt = 0; rq_cnt < rq_num; ++rq_cnt) {
        rq_node_pos = &rq_node[qnode_num * rq_cnt];
        db_pos = &db[db_size * qnode_num * rq_cnt];

        /* Init Rqueue CB */
        rq_cb[rq_cnt].db                = db_pos;
        rq_cb[rq_cnt].db_size           = db_size;
        rq_cb[rq_cnt].node_num          = qnode_num;
        rq_cb[rq_cnt].rq_node           = rq_node_pos;
        rq_cb[rq_cnt].produce_offset    = 0;
        rq_cb[rq_cnt].consume_offset    = 0;
        rq_cb[rq_cnt].node_num_mask     = qnode_num - 1;
        rq_cb[rq_cnt].rq_num            = rq_num;

        /* Init Rqueue node */
        for (cnt = 0; cnt < qnode_num; ++cnt) {
            ros_atomic16_set(&rq_node_pos[cnt].flag, RQ_NODE_IDLE);
            rq_node_pos[cnt].data_len   = 0;
            rq_node_pos[cnt].data       = (char *)&db_pos[cnt * db_size];
        }
    }

    return rq_cb;
}

void __rqueue_destroy(rqueue_cb_t *rq_cb)
{
    if (unlikely(NULL == rq_cb)) {
        RQ_LOG("Parameter abnormal, rq_cb(%p).", rq_cb);
        return;
    }

    ros_free(rq_cb->db);
    ros_free(rq_cb->rq_node);
    ros_free(rq_cb);
}

/* 任何情况下取出来的节点都要去设置为FULL状态 */
static inline rqueue_node_t *__rqueue_produce_check(rqueue_cb_t *rq_cb)
{
    rqueue_node_t *rq_node = &rq_cb->rq_node[rq_cb->produce_offset];

    if (RQ_NODE_IDLE == ros_atomic16_read(&rq_node->flag)) {
        rq_cb->produce_offset = (rq_cb->produce_offset + 1) & rq_cb->node_num_mask;
        return rq_node;
    } else {
        return NULL;
    }
}

static inline rqueue_node_t *__rqueue_consume_check(rqueue_cb_t *rq_cb)
{
    rqueue_node_t *rq_node = &rq_cb->rq_node[rq_cb->consume_offset];

    if (RQ_NODE_FULL == ros_atomic16_read(&rq_node->flag)) {
        rq_cb->consume_offset = (rq_cb->consume_offset + 1) & rq_cb->node_num_mask;
        return rq_node;
    } else {
        return NULL;
    }
}

/* 查询单个队列 */
rqueue_node_t *rqueue_produce_round_s(rqueue_cb_t *rq_cb)
{
    return __rqueue_produce_check(rq_cb);
}

/* 查询多个队列 */
rqueue_node_t *rqueue_produce_round_m(rqueue_cb_t *rq_cb)
{
    rqueue_node_t *rq_node;
    int16_t rq_cnt;

    for (rq_cnt = rq_cb->rq_num - 1; rq_cnt >= 0; --rq_cnt) {

        rq_node = __rqueue_produce_check(&rq_cb[rq_cnt]);
        if (rq_node) {
            return rq_node;
        }
    }

    return NULL;
}

/* 查询单个队列 */
rqueue_node_t *rqueue_consume_round_s(rqueue_cb_t *rq_cb)
{
    return __rqueue_consume_check(rq_cb);
}

/* 查询多个队列 */
rqueue_node_t *rqueue_consume_round_m(rqueue_cb_t *rq_cb)
{
    rqueue_node_t *rq_node;
    int16_t rq_cnt;

    for (rq_cnt = rq_cb->rq_num - 1; rq_cnt >= 0; --rq_cnt) {

        rq_node = __rqueue_consume_check(&rq_cb[rq_cnt]);
        if (rq_node) {
            return rq_node;
        }
    }

    return NULL;
}

/* 查询单个队列，直到获取到可用节点 */
rqueue_node_t *rqueue_produce_always_s(rqueue_cb_t *rq_cb)
{
    rqueue_node_t *rq_node;

    while (1) {
        rq_node = __rqueue_produce_check(rq_cb);
        if (rq_node) {
            return rq_node;
        }

        usleep(RQUEUE_PER_ROUND_WAIT_TIME);
    }

    return NULL;
}

/* 查询多个队列，直到获取到可用节点 */
/* 任何情况下取出来的节点都要去设置为FULL状态 */
rqueue_node_t *rqueue_produce_always_m(rqueue_cb_t *rq_cb)
{
    rqueue_node_t *rq_node;
    int16_t rq_cnt;

    while (1) {
        for (rq_cnt = rq_cb->rq_num - 1; rq_cnt >= 0; --rq_cnt) {

            rq_node = __rqueue_produce_check(&rq_cb[rq_cnt]);
            if (rq_node) {
                return rq_node;
            }
        }

        usleep(RQUEUE_PER_ROUND_WAIT_TIME);
    }

    return NULL;
}

rqueue_node_t *rqueue_consume_always_s(rqueue_cb_t *rq_cb)
{
    rqueue_node_t *rq_node;

    while (1) {
        rq_node = __rqueue_consume_check(rq_cb);
        if (rq_node) {
            return rq_node;
        }

        usleep(RQUEUE_PER_ROUND_WAIT_TIME);
    }

    return NULL;
}

rqueue_node_t *rqueue_consume_always_m(rqueue_cb_t *rq_cb)
{
    rqueue_node_t *rq_node;
    int16_t rq_cnt;

    while (1) {
        for (rq_cnt = rq_cb->rq_num - 1; rq_cnt >= 0; --rq_cnt) {

            rq_node = __rqueue_consume_check(&rq_cb[rq_cnt]);
            if (rq_node) {
                return rq_node;
            }
        }

        usleep(RQUEUE_PER_ROUND_WAIT_TIME);
    }

    return NULL;
}

void rqueue_set_produce_flag(rqueue_node_t *rq_node)
{
    ros_atomic16_set(&rq_node->flag, RQ_NODE_FULL);
}

void rqueue_set_consume_flag(rqueue_node_t *rq_node)
{
    ros_atomic16_set(&rq_node->flag, RQ_NODE_IDLE);
}

int rqueue_create_mul_affipthr(pthread_t *pthr_arr, void *(*pthr_cb)(void *),
    void *arg, uint8_t cpus[], uint8_t num)
{
    uint8_t cnt;
    uint8_t cancel_cnt;
    cpu_set_t cpuset;
    pthread_attr_t attr1;

    for (cnt = 0; cnt < num; ++cnt) {

        pthread_attr_init(&attr1);

        CPU_ZERO(&cpuset);
        CPU_SET(cpus[cnt], &cpuset);
        if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
            goto cancel_pthread;
        }

        if (pthread_create(&pthr_arr[cnt], &attr1, pthr_cb, arg) != 0) {
    		goto cancel_pthread;
    	}

        pthread_attr_destroy(&attr1);
    }

    return OK;

cancel_pthread:

    for (cancel_cnt = 0; cancel_cnt < cnt; ++cancel_cnt) {
        pthread_cancel(pthr_arr[cancel_cnt]);
    }

    return ERROR;
}


/********************Below is the test code*********************/

static void *rqueue_sync_produce_cb(void *arg)
{
    rqueue_cb_t *rq_cb = arg;
    rqueue_node_t *rq_node;
    uint32_t cnt;

    /* produce */
    for (cnt = 0; cnt < test_times; ++cnt) {
        rq_node = rqueue_produce_round_m(rq_cb);
        if (rq_node) {
            ros_memset(rq_node->data, 'a', 128);
            rq_node->data_len = 128;
            rqueue_set_produce_flag(rq_node);
        } else {
            if (cnt < rq_cb->node_num)
                printf("Get produce node failed.\r\n");
            break;
        }
    }
    printf("Produce node: %u\r\n", cnt);

    return NULL;
}

void *rqueue_sync_consume_cb(void *arg)
{
    rqueue_cb_t *rq_cb = arg;
    rqueue_node_t *rq_node;
    uint32_t cnt;

    /* consume */
    for (cnt = 0; cnt < test_times; ++cnt) {
        rq_node = rqueue_consume_round_m(rq_cb);
        if (rq_node) {
            uint32_t db_cnt;

            if (rq_node->data_len != 128) {
                printf("Data length error: %u\r\n", rq_node->data_len);
                break;
            }

            for (db_cnt = 0; db_cnt < 128; ++db_cnt) {
                if (rq_node->data[db_cnt] != 'a')
                    printf("Data %u error: %c\r\n", db_cnt, rq_node->data[db_cnt]);
            }
            rqueue_set_consume_flag(rq_node);
        } else {
            if (cnt < rq_cb->node_num)
                printf("Get consume node failed.\r\n");
            break;
        }
    }
    printf("Consume node: %u\r\n", cnt);

    return NULL;
}

void *rqueue_async_produce_cb(void *arg)
{
    rqueue_cb_t *rq_cb = arg;
    rqueue_node_t *rq_node;
    uint32_t cnt;

    /* produce */
    for (cnt = 0; cnt < test_times; ++cnt) {
        rq_node = rqueue_produce_always_m(rq_cb);
        if (rq_node) {
            ros_memset(rq_node->data, 'a', 128);
            rq_node->data_len = 128;
            rqueue_set_produce_flag(rq_node);
        } else {
            if (cnt < test_times)
                printf("Get produce node failed.\r\n");
            break;
        }
    }
    printf("Produce node: %u\r\n", cnt);

    return NULL;
}

void *rqueue_async_consume_cb(void *arg)
{
    rqueue_cb_t *rq_cb = arg;
    rqueue_node_t *rq_node;
    uint32_t cnt;

    /* consume */
    for (cnt = 0; cnt < test_times; ++cnt) {
        rq_node = rqueue_consume_always_m(rq_cb);
        if (rq_node) {
            uint32_t db_cnt;

            if (rq_node->data_len != 128) {
                printf("Data length error: %u\r\n", rq_node->data_len);
                break;
            }

            for (db_cnt = 0; db_cnt < 128; ++db_cnt) {
                if (rq_node->data[db_cnt] != 'a')
                    printf("Data %u error: %c\r\n", db_cnt, rq_node->data[db_cnt]);
            }
            rqueue_set_consume_flag(rq_node);
        } else {
            if (cnt < test_times)
                printf("Get consume node failed.\r\n");
            break;
        }
    }
    printf("Consume node: %u\r\n", cnt);

    return NULL;
}

void *rqueue_idle_consume_cb(void *arg)
{
    rqueue_cb_t *rq_cb = arg;
    rqueue_node_t *rq_node;

    printf("Current core id: %d\r\n", sched_getcpu());

    /* consume */
    rq_node = rqueue_consume_always_m(rq_cb);
    if (rq_node) {
        printf("Get consume node abnormal.\r\n");
        rqueue_set_consume_flag(rq_node);
    } else {
        printf("Get consume node failed.\r\n");
        return NULL;
    }
    printf("Test idle Rqueue finish\r\n");

    return NULL;
}

int rqueue_test(int argc, char *argv[])
{
    if (argc < 1) {
        printf("Parameter too few.\r\n");
        goto help;
    }

    if (argc > 1) {
        test_times = strtol(argv[1], NULL, 10);
    }

    if (0 == strncmp(argv[0], "sync", strlen("sync"))) {
        rqueue_cb_t *rq_cb;

        rq_cb = rqueue_create(1, 1000, 64);
        if (NULL == rq_cb) {
            printf("Create rqueue failed.\r\n");
        }

        /* produce */
        rqueue_sync_produce_cb(rq_cb);

        /* consume */
        rqueue_sync_consume_cb(rq_cb);

        rqueue_destroy(rq_cb);
    }
    else if (0 == strncmp(argv[0], "async", strlen("async"))) {
        rqueue_cb_t *rq_cb;
        pthread_t p_id, c_id;

        rq_cb = rqueue_create(1, 1000, 64);
        if (NULL == rq_cb) {
            printf("Create rqueue failed.\r\n");
        }

        /* produce */
        if (0 != pthread_create(&p_id, NULL, rqueue_async_produce_cb, rq_cb)) {
            printf("Create pthread failed.\r\n");
            rqueue_destroy(rq_cb);
            return -1;
        }

        /* consume */
        if (0 != pthread_create(&c_id, NULL, rqueue_async_consume_cb, rq_cb)) {
            printf("Create pthread failed.\r\n");
            rqueue_destroy(rq_cb);
            return -1;
        }

        if (0 != pthread_join(p_id, NULL)) {
			printf("join pthread failed.\r\n");
		}
        if (0 != pthread_join(c_id, NULL)) {
			printf("join pthread failed.\r\n");
		}

        rqueue_destroy(rq_cb);
    }
    else if (0 == strncmp(argv[0], "idle", strlen("idle"))) {
        rqueue_cb_t *rq_cb;
        pthread_t c_id;

        /* 单核接收空闲队列测试 */
        rq_cb = rqueue_create(1, 1000, 64);
        if (NULL == rq_cb) {
            printf("Create rqueue failed.\r\n");
        }

        /* consume */
        if (0 != pthread_create(&c_id, NULL, rqueue_idle_consume_cb, rq_cb)) {
            printf("Create pthread failed.\r\n");
            rqueue_destroy(rq_cb);
            return -1;
        }

        sleep(10);
        if (0 != pthread_cancel(c_id)) {
			printf("join pthread failed.\r\n");
		}
        printf("pthread ready join\r\n");

        if (0 != pthread_join(c_id, NULL)) {
			printf("join pthread failed.\r\n");
		}

        rqueue_destroy(rq_cb);
    }

    return 0;

help:
    printf("    rqueue <sync|async|idle> [test_times]\r\n");
    printf("\r\n");
    return -1;
}


