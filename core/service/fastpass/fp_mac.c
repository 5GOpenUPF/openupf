/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "service.h"
#include "comm_msg.h"
#include "fp_msg.h"
#include "fp_main.h"
#include "fp_mac.h"

#ifdef ENABLE_FP_URR
static fp_urr_mac_entry *fp_urr_mac_entry_alloc();
static int  fp_urr_mac_entry_free(fp_urr_mac_entry *entry);
static void fp_urr_mac_dec(fp_urr_entry *urr_entry, uint64_t input_mac);
static void fp_urr_mac_inc(fp_urr_entry *urr_entry, uint64_t input_mac);

static int fp_urr_mac_walk_time(AVLU64_NODE *avl_node, void *input_arg)
{
    fp_urr_mac_entry *entry = (fp_urr_mac_entry *)avl_node;
    fp_urr_entry *urr_entry = (fp_urr_entry *)input_arg;
    uint32_t eth_inact_time;
    uint32_t cur_time = fp_get_time();

    eth_inact_time = urr_entry->config.eth_inact_time;

    /* Too long time not receive packet from this mac */
    if (entry->last_pkt.cnt + eth_inact_time < cur_time) {
        fp_urr_mac_dec(urr_entry, entry->mac);
    }
    else {
        /* Do nothing */
    }

    return OK;
}

static void
fp_urr_mac_dec(fp_urr_entry *urr_entry, uint64_t input_mac)
{
    fp_urr_mac_bucket   *mac_bucket;
    fp_urr_mac_entry    *mac_entry;
    comm_msg_urr_mac_t  *mac_list;

    /* Get bucket entry */
    mac_bucket = &urr_entry->mac_bucket;

    /* Get on tree */
    ros_rwlock_write_lock(&mac_bucket->rwlock);
    mac_entry = (fp_urr_mac_entry *)avluint64_delete(&mac_bucket->tree,
        input_mac);
    if (NULL == mac_entry) {

        LOG(FASTPASS, RUNNING, "try to delete mac %lx, but not find.",
            input_mac);
        ros_rwlock_write_unlock(&mac_bucket->rwlock);
        return;
    }

    /* Add to dec list */
    mac_list = mac_bucket->obs_mac;
    if (mac_list->mac_num < FP_URR_MAC_MAX) {
        mac_list->mac[mac_list->mac_num] = input_mac;
        mac_list->mac_num++;
    }
    ros_rwlock_write_unlock(&mac_bucket->rwlock);

    /* Free entry */
    fp_urr_mac_entry_free(mac_entry);
}

static void
fp_urr_mac_inc(fp_urr_entry *urr_entry, uint64_t input_mac)
{
    fp_urr_mac_bucket   *mac_bucket;
    fp_urr_mac_entry    *mac_entry;
    comm_msg_urr_mac_t  *mac_list;

    /* Alloc entry */
    mac_entry = (fp_urr_mac_entry *)fp_urr_mac_entry_alloc();

    /* Fill entry */
    mac_entry->mac = input_mac;
    ros_atomic32_set(&mac_entry->last_pkt, fp_get_time());

    /* Get bucket entry */
    mac_bucket = &urr_entry->mac_bucket;

    /* Get on tree */
    ros_rwlock_write_lock(&mac_bucket->rwlock);
    if (OK != avluint64_insert(&mac_bucket->tree, (AVLU64_NODE *)mac_entry)) {

        ros_rwlock_write_unlock(&mac_bucket->rwlock);
        return;
    }

    /* Add to dec list */
    mac_list = mac_bucket->new_mac;
    if (mac_list->mac_num < FP_URR_MAC_MAX) {
        mac_list->mac[mac_list->mac_num] = input_mac;
        mac_list->mac_num++;
    }
    ros_rwlock_write_unlock(&mac_bucket->rwlock);
}

char *fp_urr_mac_copy(char *buff, comm_msg_urr_mac_t *mac_list)
{
    char *new_buf;

    if (mac_list->mac_num) {
        new_buf = ros_memcpy(buff, mac_list,
            (mac_list->mac_num + 1) * sizeof(uint64_t));
    }

    return new_buf;
}

void fp_urr_mac_chk(fp_urr_entry *urr_entry, uint64_t input_mac)
{
    fp_urr_mac_bucket   *mac_bucket;
    fp_urr_mac_entry    *entry;         /* point to entry pool */

    /* Get bucket entry */
    mac_bucket = &urr_entry->mac_bucket;

    /* Get on tree */
    ros_rwlock_read_lock(&mac_bucket->rwlock);
    entry = (fp_urr_mac_entry *)avluint64_search(mac_bucket->tree, input_mac);
    ros_rwlock_read_unlock(&mac_bucket->rwlock);
    if (!entry)
    {
        return;
    }
    fp_urr_mac_inc(urr_entry, input_mac);

    return;
}

void fp_urr_mac_proc_timer(void *timer, uint64_t para)
{
    comm_msg_urr_mac_t  *new_list, *obs_list;
    fp_urr_mac_bucket   *mac_bucket;
    fp_urr_entry        *urr_entry = (fp_urr_entry *)para;

    if (OK != avluint64_treewalk(urr_entry->mac_bucket.tree, G_NULL, G_NULL,
        G_NULL, G_NULL, (AVLU64_CALLBACK)fp_urr_mac_walk_time, &urr_entry))
    {
        LOG(FASTPASS, ERR,
            "walk urr(%d) mac tree(%p) failed.",
            urr_entry->index, &urr_entry->mac_bucket);
        return;
    }

    mac_bucket = &urr_entry->mac_bucket;
    new_list   = mac_bucket->new_mac;
    obs_list   = mac_bucket->obs_mac;
    if ((new_list)||(obs_list)) {
        fp_urr_send_report(urr_entry, FP_URR_TRIGGER_MACAR);
    }
}

void fp_urr_mac_create_bucket(fp_urr_entry *urr_entry)
{
    fp_urr_mac_bucket   *mac_bucket;
    comm_msg_urr_mac_t  *mac_list;

    /* Get bucket entry */
    mac_bucket = &urr_entry->mac_bucket;

    mac_bucket->tree    = NULL;
    mac_bucket->new_mac = (comm_msg_urr_mac_t *)fp_block_alloc();
    mac_bucket->obs_mac = (comm_msg_urr_mac_t *)fp_block_alloc();

    mac_list = mac_bucket->new_mac;
    mac_list->mac_num = 0;
    mac_list->type    = COMM_MSG_URR_MAC_TYPE_NEW;

    mac_list = mac_bucket->obs_mac;
    mac_list->mac_num = 0;
    mac_list->type    = COMM_MSG_URR_MAC_TYPE_OBS;

    ros_rwlock_init(&mac_bucket->rwlock);

    return;
}

void fp_urr_mac_destroy_bucket(fp_urr_entry *urr_entry)
{
    fp_urr_mac_bucket   *mac_bucket;

    /* Get bucket entry */
    mac_bucket = &urr_entry->mac_bucket;

    /* Free node */
    avluint64_destroy(mac_bucket->tree, (AVLU64_FREE)fp_urr_mac_entry_free);

    mac_bucket->tree = 0;
    fp_block_free((char *)mac_bucket->new_mac);
    fp_block_free((char *)mac_bucket->obs_mac);

    ros_rwlock_init(&mac_bucket->rwlock);

    return;
}

static fp_urr_mac_entry *fp_urr_mac_entry_alloc()
{
    fp_urr_mac_table    *head;
    fp_urr_mac_entry    *entry;
    uint64_t            ret64;
    uint32_t            key = 0, index;

    head = (fp_urr_mac_table *)fp_mac_table_get();
    ret64 = Res_Alloc(head->res_no, &key, &index, EN_RES_ALLOC_MODE_OC);
    if (ret64 != G_SUCCESS) {
        return NULL;
    }
    entry = (head->entry + index);

    return entry;
}

static int fp_urr_mac_entry_free(fp_urr_mac_entry *entry)
{
    fp_urr_mac_table    *head;
    uint32_t            index;

    if (!entry) {
        return ERROR;
    }

    head = (fp_urr_mac_table *)fp_mac_table_get();
    if (!head) {
        return ERROR;
    }

    index = (entry - head->entry);
    if (index >= head->entry_max) {
        LOG(FASTPASS, ERR,
            "free wrong mac entry(%p), base(%p).", entry, head->entry);
        return ERROR;
    }

    Res_Free(head->res_no, 0, index);

    return OK;
}
#endif

