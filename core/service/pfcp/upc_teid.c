/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "upc_teid.h"
#include "upc_node.h"
#include "upc_seid.h"

struct upc_teid_mgmt g_upc_teid_mgmt = {NULL};
struct upc_choose_id_mgmt *g_choose_mgmt;


void upc_teid_choose_mgmt_init(uint32_t index)
{
    ros_memset(&g_choose_mgmt[index], 0, sizeof(struct upc_choose_id_mgmt));
}

struct upc_choose_id_mgmt *upc_teid_choose_mgmt_get(uint32_t index)
{
    return &g_choose_mgmt[index];
}

inline struct upc_teid_mgmt *upc_teid_mgmt_get(void)
{
    return &g_upc_teid_mgmt;
}

inline struct upc_teid_table *upc_teid_table_get(uint32_t node_index)
{
    return &g_upc_teid_mgmt.teid_table[node_index];
}

inline struct upc_teid_entry *upc_teid_get_from_index(
    uint32_t node_index, uint32_t teid_index)
{
    return &g_upc_teid_mgmt.teid_table[node_index].teid_entry[teid_index];
}

static inline uint32_t upc_teid_node_bit_get(uint32_t node_num)
{
    switch (node_num) {
        case 1:
            return 0;
        case 2:
            return 1;
        case 4:
            return 2;
        case 8:
            return 3;
        case 16:
            return 4;
        case 32:
            return 5;
        default:
            LOG(UPC, ERR, "node_num %u error, default node_num = 32.",
                node_num);
            return 5;
    }
}

static inline uint32_t upc_teid_average_mask_get(uint32_t node_num)
{
    switch (node_num) {
        case 1:
            return 0xFFFFFFFF;
        case 2:
            return 0x7FFFFFFF;
        case 4:
            return 0x3FFFFFFF;
        case 8:
            return 0x1FFFFFFF;
        case 16:
            return 0xFFFFFFF;
        case 32:
            return 0x7FFFFFF;
        default:
            LOG(UPC, ERR, "node_num %u error, default node_num = 32.",
                node_num);
            return 0x7FFFFFF;
    }
}

static int upc_teid_is_valid(struct upc_teid_table *table,
    uint32_t teid_index)
{
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();
    struct upc_teid_entry *entry = NULL;

    if (NULL == table || teid_index > teid_mgmt->node_teid_mask) {
        LOG(UPC, ERR, "Parameter error, table(%p), teid_index: %u",
            table, teid_index);
        return G_FALSE;
    }

    if (teid_index >= table->max_num) {
        LOG(UPC, ERR, "teid index %u invalid.", teid_index);
        return G_FALSE;
    }

    if (G_FALSE == Res_IsAlloced(table->pool_id, 0, teid_index)) {
        LOG(UPC, ERR, "No such teid, teid_index: %u.",
            teid_index);
        return G_FALSE;
    }
    entry = &table->teid_entry[teid_index];
    if (G_FALSE == entry->valid) {
        LOG(UPC, ERR, "teid_index %u invalid.", teid_index);
        return G_FALSE;
    }

    return G_TRUE;
}

static uint32_t upc_teid_add_cfg(uint32_t node_index, uint32_t teid_index)
{
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();
    struct upc_teid_table *table = NULL;
    struct upc_teid_entry *entry = NULL;

    table = upc_teid_table_get(node_index);
    ros_rwlock_write_lock(&table->lock); /* lock */

    entry = upc_teid_get_from_index(node_index, teid_index);
    entry->valid = G_TRUE;
    ros_atomic16_set(&entry->cur_use, 0);

    ros_rwlock_write_unlock(&table->lock); /* unlock */

    ros_atomic32_add(&table->use_num, 1);
    ros_atomic32_add(&teid_mgmt->teid_use_num, 1);

    return entry->teid;
}

uint32_t upc_teid_alloc(uint32_t node_index)
{
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();
    struct upc_teid_table *table = NULL;
    uint32_t res_key = 0, res_index = 0, ret = 0;

    if (node_index >= teid_mgmt->node_max_num) {
        LOG(UPC, ERR, "node index %u error.", node_index);
        return (uint32_t)-1;
    }

    table = upc_teid_table_get(node_index);
    if (G_FAILURE == Res_Alloc(table->pool_id, &res_key,
        &res_index, EN_RES_ALLOC_MODE_OC)) {
        LOG(UPC, ERR, "Res_Alloc teid failed, node_index: %u.",
            node_index);
        return (uint32_t)-1;
    }

    ret = upc_teid_add_cfg(node_index, res_index);

    return ret;
}

int upc_teid_alloc_target(uint32_t teid)
{
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();
    struct upc_teid_table *table = NULL;
    uint32_t node_index =
        UPC_TEID_GET_NODE_INDEX(teid, teid_mgmt->node_bit_num);
    uint32_t teid_index =
        UPC_TEID_GET_TEID_INDEX(teid, teid_mgmt->node_teid_mask);

    if (node_index >= teid_mgmt->node_max_num) {
        LOG(UPC, ERR, "node index %u error.", node_index);
        return (uint32_t)-1;
    }

    table = upc_teid_table_get(node_index);
    if (G_FAILURE == Res_AllocTarget(table->pool_id, 0, teid_index)) {
        LOG(UPC, ERR, "Alloc target teid already exist, node_index: %u, teid_index: %u.",
            node_index, teid_index);
        return 0;
    }

    upc_teid_add_cfg(node_index, teid_index);

    return 0;
}

int upc_teid_add_target(uint32_t teid)
{
    if (0 > upc_teid_alloc_target(teid)) {
        LOG(UPC, ERR, "Alloc target teid failed, teid: %u.", teid);
        return -1;
    }

    if (0 > upc_teid_used_add(teid)) {
        LOG(UPC, ERR, "Add teid used num failed, teid: %u.", teid);
        return -1;
    }

    return 0;
}

int upc_teid_free(uint32_t teid)
{
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();
    struct upc_teid_table *table = NULL;
    uint32_t node_index =
        UPC_TEID_GET_NODE_INDEX(teid, teid_mgmt->node_bit_num);
    uint32_t teid_index =
        UPC_TEID_GET_TEID_INDEX(teid, teid_mgmt->node_teid_mask);

    table = upc_teid_table_get(node_index);
    ros_rwlock_write_lock(&table->lock); /* lock */
    if (G_FALSE == upc_teid_is_valid(table, teid_index)) {
        ros_rwlock_write_unlock(&table->lock); /* unlock */
        LOG(UPC, ERR, "free teid failed, teid_index: %u, node_index: %u.",
            teid_index, node_index);
        return -1;
    }

    Res_Free(table->pool_id, 0, teid_index);
    ros_atomic32_sub(&table->use_num, 1);
    ros_atomic32_sub(&teid_mgmt->teid_use_num, 1);
    ros_rwlock_write_unlock(&table->lock); /* unlock */

    return 0;
}

int upc_teid_is_alloced(uint32_t teid)
{
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();
    struct upc_teid_table *table = NULL;
    uint32_t node_index =
        UPC_TEID_GET_NODE_INDEX(teid, teid_mgmt->node_bit_num);
    uint32_t teid_index =
        UPC_TEID_GET_TEID_INDEX(teid, teid_mgmt->node_teid_mask);

    table = upc_teid_table_get(node_index);
    if (G_FALSE == upc_teid_is_valid(table, teid_index)) {
        LOG(UPC, ERR, "teid is invalid, teid: %u.", teid);
        return G_FALSE;
    }

    return G_TRUE;
}

int upc_teid_sum(uint32_t node_index)
{
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();
    struct upc_teid_table *table = NULL;
    uint32_t sum = 0;

    if (node_index >= teid_mgmt->node_max_num) {
        LOG(UPC, RUNNING,
            "node index %u is invalid, return all node teid sum.", node_index);

        sum = ros_atomic32_read(&teid_mgmt->teid_use_num);
    } else {
        table = upc_teid_table_get(node_index);

        sum = ros_atomic32_read(&table->use_num);
    }

    LOG(UPC, RUNNING, "sum is %u.", sum);

    return sum;
}

static struct upc_teid_entry *upc_teid_get_entry(uint32_t teid)
{
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();
    struct upc_teid_table *table = NULL;
    struct upc_teid_entry *entry = NULL;
    uint32_t node_index =
        UPC_TEID_GET_NODE_INDEX(teid, teid_mgmt->node_bit_num);
    uint32_t teid_index =
        UPC_TEID_GET_TEID_INDEX(teid, teid_mgmt->node_teid_mask);

    table = upc_teid_table_get(node_index);
    ros_rwlock_write_lock(&table->lock); /* lock */
    if (G_FALSE == upc_teid_is_valid(table, teid_index)) {
        ros_rwlock_write_unlock(&table->lock); /* unlock */
        LOG(UPC, ERR, "Teid get failed, no such entry, teid_index: %u, node_index: %u.",
            teid_index, node_index);
        return NULL;
    }
    entry = upc_teid_get_from_index(node_index, teid_index);
    ros_rwlock_write_unlock(&table->lock); /* unlock */

    return entry;
}

int upc_teid_used_add(uint32_t teid)
{
    struct upc_teid_entry *entry = NULL;

    entry = upc_teid_get_entry(teid);
    if (NULL == entry) {
        LOG(UPC, ERR, "get teid entry failed, teid: %u.", teid);
        return -1;
    }
    ros_atomic16_add(&entry->cur_use, 1);

    return 0;
}

int upc_teid_used_sub(uint32_t teid)
{
    struct upc_teid_entry *entry = NULL;

    entry = upc_teid_get_entry(teid);
    if (NULL == entry) {
        LOG(UPC, ERR, "get teid entry failed, teid: %u.", teid);
        return -1;
    }

    if (0 == ros_atomic16_sub_return(&entry->cur_use, 1)) {
        LOG(UPC, RUNNING, "no entry used this teid, ready to free it.");
        if (-1 == upc_teid_free(teid)) {
            LOG(UPC, ERR, "free teid %u failed.", teid);
        }
    }

    return 0;
}

int upc_teid_used_set(uint32_t teid, int16_t use_num)
{
    struct upc_teid_entry *entry = NULL;

    entry = upc_teid_get_entry(teid);
    if (NULL == entry) {
        LOG(UPC, ERR, "get teid entry failed, teid: %u.", teid);
        return -1;
    }
    ros_atomic16_set(&entry->cur_use, use_num);

    return 0;
}

int upc_teid_used_get(uint32_t teid)
{
    struct upc_teid_entry *entry = NULL;
    int sum = 0;

    entry = upc_teid_get_entry(teid);
    if (NULL == entry) {
        LOG(UPC, ERR, "get teid entry failed, teid: %u.", teid);
        return -1;
    }
    sum = ros_atomic16_read(&entry->cur_use);

    return sum;
}

int64_t upc_teid_init(uint32_t node_num, uint32_t teid_num)
{
    upc_config_info *upc_conf = upc_get_config();
    uint32_t index = 0, table_cnt = 0;
    int pool_id = -1;
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();
    struct upc_teid_table *teid_table = NULL;
    struct upc_teid_entry *teid_entry = NULL;
    uint32_t max_num = 0, start_teid_num = 0;
    int64_t size = 0, total_mem = 0;

    if (0 == node_num || 32 < node_num || 0 == teid_num) {
        LOG(UPC, ERR,
            "Abnormal parameter, node_num: %u, teid_num: %u.",
            node_num, teid_num);
        return -1;
    }
    /* init upc teid mgmt */
    size = sizeof(struct upc_teid_table) * node_num;
    total_mem += size;
    teid_table = ros_malloc(size);
    if (NULL == teid_table) {
        LOG(UPC, ERR,
            "upc teid init failed, no enough memory, node_num: %u.",
            node_num);
        return -1;
    }
    ros_memset(teid_table, 0, size);

    teid_mgmt->teid_table = teid_table;
    teid_mgmt->node_max_num = node_num;
    teid_mgmt->node_bit_num = upc_teid_node_bit_get(node_num);
    teid_mgmt->node_teid_mask = upc_teid_average_mask_get(node_num);
    teid_mgmt->node_teid_max = teid_mgmt->node_teid_mask + 1;
	ros_rwlock_init(&teid_mgmt->lock);
    ros_atomic32_set(&teid_mgmt->teid_use_num, 0);

    /* init upc teid table */
    max_num = teid_num / node_num;
    for (table_cnt = 0; table_cnt < node_num; ++table_cnt) {
        size = sizeof(struct upc_teid_entry) * (max_num + 1); /* 此处多加一个是为了不让其分配一个为0的teid */
        total_mem += size;
        teid_entry = ros_malloc(size);
        if (NULL == teid_entry) {
            LOG(UPC, ERR,
                "upc teid init failed, no enough memory, teid_num: %u.",
                teid_num);
            return -1;
        }
        ros_memset(teid_entry, 0, size);

        start_teid_num = teid_mgmt->node_teid_max * table_cnt;
        /* 此处判断是为了不让其分配一个为0的teid */
        for (index = 0; index <= max_num; ++index) {
            teid_entry[index].index  = index;
            teid_entry[index].teid   = start_teid_num + index;
            teid_entry[index].valid  = G_FALSE;
    		ros_atomic16_set(&teid_entry[index].cur_use, 0);
        }

        pool_id = Res_CreatePool();
        if (pool_id < 0) {
            LOG(UPC, ERR, "Res_CreatePool failed.");
            return -1;
        }
        if (G_FAILURE == Res_AddSection(pool_id, 0, 1, max_num)) {
            LOG(UPC, ERR, "Res_AddSection failed.");
            return -1;
        }

        teid_table[table_cnt].index = table_cnt;
        teid_table[table_cnt].pool_id = pool_id;
        teid_table[table_cnt].teid_entry = teid_entry;
        teid_table[table_cnt].max_num = max_num;
    	ros_rwlock_init(&teid_table[table_cnt].lock);
        ros_atomic32_set(&teid_table[table_cnt].use_num, 0);
    }

    /* Init TEID choose management */
    /* Session ID starts at 1 */
    size = sizeof(struct upc_choose_id_mgmt) * (upc_conf->session_num + 1);
    total_mem += size;
    g_choose_mgmt = ros_malloc(size);
    if (NULL == g_choose_mgmt) {
        LOG(UPC, ERR,
            "upc teid choose init failed, no enough memory, choose_num: %u.",
            upc_conf->session_num + 1);
        return -1;
    }
    ros_memset(g_choose_mgmt, 0, size);

    LOG(UPC, RUNNING, "TEID POOL init success.");
    return total_mem;
}

/* TEST CODE */
void upc_teid_test_alloc(int argc, char **argv)
{
    --argc;
    ++argv;
    if (argc < 1) {
        LOG(UPC, ERR, "Invalid argument, Too little.\n");
        return;
    }

    if (0 == strcmp(argv[0], "repeat")) {
        int32_t cnt = 0, err_num = 0, teid_index_num = atoi(argv[1]);

        if (argc < 2) {
            LOG(UPC, ERR, "Invalid argument, Too little.\n");
            return;
        }

        for (cnt = 0; cnt < teid_index_num; ++cnt) {
            if ((uint32_t)-1 == upc_teid_alloc(1)) {
                ++err_num;
            }
        }

        LOG(UPC, ERR, "test alloc teid finish, error number: %d.\n", err_num);

    } else {
        uint32_t node_index = atoi(argv[0]);
        __maybe_unused uint32_t teid = 0;

        teid = upc_teid_alloc(node_index);

        LOG(UPC, ERR, "test alloc teid finish, teid: %u.\n", teid);
    }
}

void upc_teid_test_free(int argc, char **argv)
{
    struct upc_teid_mgmt *teid_mgmt = upc_teid_mgmt_get();

    --argc;
    ++argv;
    if (argc < 1) {
        LOG(UPC, ERR, "Invalid argument, Too little.\n");
        return;
    }

    if (0 == strcmp(argv[0], "repeat")) {
        if (argc < 3) {
            LOG(UPC, ERR, "Invalid argument, Too little.\n");
            return;
        }
        if (0 == strcmp(argv[1], "reverse")) {
            int cnt = 0, err_num = 0, teid = 0, teid_index_num = atoi(argv[2]);

            for (cnt = teid_index_num - 1; cnt >= 0; ++cnt) {
                teid = UPC_TEID_GET_TEID(1, teid_mgmt->node_teid_max, cnt);
                if (-1 == upc_teid_free(teid)) {
                    ++err_num;
                }
            }

            LOG(UPC, ERR, "test free teid finish, error number: %d.\n",
                err_num);
        } else if (0 == strcmp(argv[1], "order")) {
            int cnt = 0, err_num = 0, teid = 0, teid_index_num = atoi(argv[2]);

            for (cnt = 0; cnt < teid_index_num; ++cnt) {
                teid = UPC_TEID_GET_TEID(1, teid_mgmt->node_teid_max, cnt);
                if (-1 == upc_teid_free(teid)) {
                    ++err_num;
                }
            }

            LOG(UPC, ERR, "test free teid finish, error number: %d.\n",
                err_num);
        } else {
            LOG(UPC, ERR, "Invalid argument.\n");
        }
    } else {
        int teid = atoi(argv[0]);

        if (-1 == upc_teid_free(teid)) {
            LOG(UPC, ERR, "test free teid %u failed.\n", teid);
        }
    }
}

void upc_teid_test_validity(int argc, char **argv)
{
    __maybe_unused int ret = G_FALSE;
    int teid = 0;

    --argc;
    ++argv;
    if (argc < 1) {
        LOG(UPC, ERR, "Invalid argument, Too little.\n");
        return;
    }
    teid = atoi(argv[0]);

    ret = upc_teid_is_alloced(teid);

    LOG(UPC, ERR, "test teid vaildity finish, teid %u %s.\n",
        teid, ret ? "valid":"invalid");
}

void upc_teid_test_sum(int argc, char **argv)
{
    int node_index = 0;
    __maybe_unused int sum = 0;

    --argc;
    ++argv;
    if (argc < 1) {
        LOG(UPC, ERR, "Invalid argument, Too little.\n");
        return;
    }

    node_index = atoi(argv[0]);

    sum = upc_teid_sum(node_index);

    LOG(UPC, ERR, "test teid sum, node index %u alloced %d teid.\n",
        node_index, sum);
}

int upc_cmd_teid(struct cli_def *cli,int argc, char **argv)
{
    if (argc < 1) {
        LOG(UPC, ERR, "Invalid argument, Too little.\n");
        return -1;
    }

    if (0 == strcmp(argv[0], "alloc")) {
        upc_teid_test_alloc(argc, argv);
    } else if (0 == strcmp(argv[0], "free")) {
        upc_teid_test_free(argc, argv);
    } else if (0 == strcmp(argv[0], "valid")) {
        upc_teid_test_validity(argc, argv);
    } else if (0 == strcmp(argv[0], "sum")) {
        upc_teid_test_sum(argc, argv);
    } else {
        LOG(UPC, ERR, "Invalid argument.\n");
    }

    return 0;
}


