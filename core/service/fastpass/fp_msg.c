/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"

#include "fp_fwd_ipv4.h"
#include "fp_fwd_ipv6.h"
#include "fp_fwd_nonip.h"
#include "fp_fwd_eth.h"
#include "fp_fwd_common.h"
#include "fp_start.h"
#include "fp_urr.h"
#include "fp_qer.h"
#include "fp_recycle.h"
#include "fp_frag.h"
#include "fp_dns.h"
#ifndef ENABLE_OCTEON_III
#include <rte_mbuf.h>
#endif

#include "fp_backend_mgmt.h"
#include "fp_msg.h"

#ifndef FP_METER_TB_PERIOD_MIN
#define FP_METER_TB_PERIOD_MIN      100
#endif

#ifdef ENABLE_OCTEON_III
extern struct pro_ipv4_hdr *pkt_get_l3_header1(char *buf, int len);
#endif

extern CVMX_SHARED uint16_t comm_msg_comm_id;
extern CVMX_SHARED fpu_Signaling_trace_ueip_t fpu_sig_trace_ueip;

static uint32_t fp_fast_send_buff_pkt(fp_fast_shadow *shadow);
static uint32_t fp_fast_link_del(uint32_t inst_index, fp_fast_shadow *shadow);
static uint32_t fp_fast_table_del(fp_fast_table *head, uint32_t entry_no,
    uint32_t aux_info);
static uint32_t fp_fast_free_buff_chain(fp_fast_shadow *shadow);
static uint32_t fp_msg_inst_param_check(comm_msg_inst_config *inst_config);
static uint32_t fp_msg_inst_del_proc(uint32_t index);
static void fp_msg_inst_copy(comm_msg_inst_config *dst,
    comm_msg_inst_config *src);
static void fp_msg_far_copy(comm_msg_far_config *dst, comm_msg_far_config *src);
static void fp_msg_bar_copy(comm_msg_bar_config *dst, comm_msg_bar_config *src);
static void fp_msg_qer_copy(comm_msg_qer_config *dst, comm_msg_qer_config *src);
void fp_msg_urr_copy(comm_msg_urr_config *dst, comm_msg_urr_config *src);

static inline uint32_t fp_msg_get_table_type(uint32_t table_no)
{
    return ((table_no & 0xC) >> 2);
}

static inline uint32_t fp_msg_get_port_no(uint32_t table_no)
{
    return (table_no & 0x3);
}

static uint32_t fp_msg_rules_val(int res_no, uint16_t cmd, uint32_t max_num)
{
    uint32_t cnt = 0, send_times = 0, remainder = 0;
    comm_msg_header_t *msg;
    comm_msg_ie_t *ie;
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len = 0;
    comm_msg_entry_val_config_t *fp_val_cfg = NULL;

    msg = fp_fill_msg_header(buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd     = htons(cmd);
    ie->index   = htonl(0);
    fp_val_cfg  = (comm_msg_entry_val_config_t *)ie->data;

    send_times = max_num / MAX_CHECK_VALIDITY_NUMBER;
    for (cnt = 0; cnt < send_times; ++cnt) {
        fp_val_cfg->start = cnt * MAX_CHECK_VALIDITY_NUMBER;
        fp_val_cfg->entry_num = MAX_CHECK_VALIDITY_NUMBER;

        if (G_SUCCESS != Res_GetRangeField(res_no, 0,
            fp_val_cfg->start, fp_val_cfg->entry_num, fp_val_cfg->data)) {
            LOG(FASTPASS, ERR, "Get range field failed, start: %u, entry_num: %u.",
                fp_val_cfg->start, fp_val_cfg->entry_num);
            return -1;
        }

        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_entry_val_config_t) +
            ((fp_val_cfg->entry_num >> RES_PART_LEN_BIT) * sizeof(uint32_t)) +
            ((fp_val_cfg->entry_num & RES_PART_LEN_MASK) ? sizeof(uint32_t) : 0);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        fp_msg_entry_val_hton(fp_val_cfg);

        if (0 > fp_msg_send((char *)buf, buf_len)) {
            LOG(FASTPASS, ERR, "Send msg to spu failed.");
            return EN_COMM_ERRNO_SEND_MSG_ERROR;
        }
    }

    remainder = max_num % MAX_CHECK_VALIDITY_NUMBER;
    if (remainder) {
        fp_val_cfg->start = cnt * MAX_CHECK_VALIDITY_NUMBER;
        fp_val_cfg->entry_num = remainder;

        if (G_SUCCESS != Res_GetRangeField(res_no, 0,
            fp_val_cfg->start, fp_val_cfg->entry_num, fp_val_cfg->data)) {
            LOG(FASTPASS, ERR, "Get range field failed, start: %u, entry_num: %u.",
                fp_val_cfg->start, fp_val_cfg->entry_num);
            return -1;
        }

        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_entry_val_config_t) +
            ((fp_val_cfg->entry_num >> RES_PART_LEN_BIT) * sizeof(uint32_t)) +
            ((fp_val_cfg->entry_num & RES_PART_LEN_MASK) ? sizeof(uint32_t) : 0);
        ie->len        = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        fp_msg_entry_val_hton(fp_val_cfg);

        if (0 > fp_msg_send((char *)buf, buf_len)) {
            LOG(FASTPASS, ERR, "Send msg to spu failed.");
            return EN_COMM_ERRNO_SEND_MSG_ERROR;
        }
    }

    return EN_COMM_ERRNO_OK;
}

inline void fp_msg_entry_val_hton(comm_msg_entry_val_config_t *val_cfg)
{
    uint32_t cnt = 0, fld_num = val_cfg->entry_num >> RES_PART_LEN_BIT;

    LOG(FASTPASS, DEBUG, "start: %u, entry_num: %u.",
        val_cfg->start, val_cfg->entry_num);
    for (cnt = 0; cnt < fld_num; ++cnt) {
        val_cfg->data[cnt] = htonl(val_cfg->data[cnt]);
    }

    if (val_cfg->entry_num & RES_PART_LEN_MASK) {
        val_cfg->data[cnt] = htonl(val_cfg->data[cnt]);
    }

    val_cfg->start = htonl(val_cfg->start);
    val_cfg->entry_num = htonl(val_cfg->entry_num);
}

uint32_t fp_msg_entry_del(comm_msg_ie_t *ie)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    uint32_t type;
    uint32_t index;
    comm_msg_fast_ie_t      *entry_ie;
    fp_fast_table           *head;
    fp_fast_entry           *entry;
    fp_fast_shadow          *shadow;
    comm_msg_fast_cfg       *entry_cfg;

    entry_ie = (comm_msg_fast_ie_t *)ie;

    type  = fp_msg_get_table_type(entry_ie->table);
    index = entry_ie->index;

    head = fp_fast_table_get(type);
    if (!head) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    /* Check index */
    if (index >= head->entry_max) {
        ret = EN_COMM_ERRNO_ITEM_NUM_OVERFLOW;
        return ret;
    }

    /* Check entry validation */
    entry = fp_fast_entry_get(head, index);
    if (!entry->valid) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    /* Get shadow */
    shadow = fp_fast_shadow_get(head, entry->index);

    /* Free buffered packets if exist */
    fp_fast_free_buff_chain(shadow);

    /* Remove node from link */
    entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);
    fp_fast_link_del(entry_cfg->inst_index, shadow);

    /* Release node */
    ret = fp_fast_free(head, index);

    LOG(FASTPASS, RUNNING,
        "del fast entry %d from tree(type %d).",
        index, type);

    return ret;
}

uint32_t fp_msg_entry_mod(comm_msg_ie_t *ie)
{
    uint32_t type;
    uint32_t index;
    uint32_t ret = EN_COMM_ERRNO_OK;
    uint32_t old_inst_index, new_inst_index, new_far_index;
    comm_msg_fast_ie_t  *entry_ie;
    fp_fast_entry       *entry;
    fp_fast_table       *head;
    fp_fast_shadow      *shadow;
    fp_far_entry        *far_entry;
    fp_bar_entry        *bar_entry = NULL;
    comm_msg_fast_cfg   *entry_cfg, *input_cfg;
    fp_inst_entry       *inst_entry;

    entry_ie = (comm_msg_fast_ie_t *)ie;

    type = fp_msg_get_table_type(entry_ie->table);
    index = entry_ie->index;

    LOG(FASTPASS, RUNNING,
        "mod fast entry %d(type %d).",
        index, type);

    head = fp_fast_table_get(type);
    if (!head) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    /* Check index */
    if (index >= head->entry_max) {
        ret = EN_COMM_ERRNO_ITEM_NUM_OVERFLOW;
        return ret;
    }

    /* Check alloc status */
    if (!Res_IsAlloced(head->res_no, 0, index)) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    input_cfg = (comm_msg_fast_cfg *)&(entry_ie->data);

    /* Check if or not entry num changed */
    entry = fp_fast_entry_get(head, index);
    entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);
    old_inst_index = entry_cfg->inst_index;

    /* Copy entry config */
    fp_msg_fast_copy(entry_cfg, input_cfg);
    new_inst_index = entry_cfg->inst_index;
    new_far_index = entry_cfg->far_index;

    /* Get shadow */
    shadow = fp_fast_shadow_get(head, index);

    /* Check out inst queue */
    if (old_inst_index != new_inst_index) {
        /* Transfer charged traffic for TCP handshake */
        if (entry_cfg->is_tcp && 0 == entry_cfg->tcp_push) {
            /* Last match of TCP packets */
            fp_inst_table *inst_head = fp_inst_table_get();
            fp_inst_entry *old_inst, *new_inst;

            old_inst = fp_inst_entry_get(old_inst_index);
            new_inst = fp_inst_entry_get(new_inst_index);
            ros_atomic64_sub(&old_inst->stat.forw_bytes, ros_atomic16_read(&entry_cfg->tcp_hs_stat));
            ros_atomic64_add(&new_inst->stat.forw_bytes, ros_atomic16_read(&entry_cfg->tcp_hs_stat));
            ros_atomic16_init(&entry_cfg->tcp_hs_stat);
            Res_MarkSet(inst_head->res_stat, old_inst_index);
            Res_MarkSet(inst_head->res_stat, new_inst_index);
            LOG(FASTPASS, RUNNING, "Re record TCP handshake volume.");
        }

        /* Old one is not zero, need remove it from link */
        if (EN_COMM_ERRNO_OK != fp_fast_link_del(old_inst_index, shadow)) {
            fp_fast_free_buff_chain(shadow);

            /* Release node */
            fp_fast_free(head, index);
            return EN_COMM_ERRNO_OTHER_ERROR;
        }
        /* Add fast entry to new inst list */
        else if (EN_COMM_ERRNO_OK != fp_fast_link_add(new_inst_index, shadow)) {
            /* inst deleted */
            fp_fast_free_buff_chain(shadow);

            /* Release node */
            fp_fast_free(head, index);
            return EN_COMM_ERRNO_OTHER_ERROR;
        }
    }

    /* Check action */
    inst_entry = fp_inst_entry_get(new_inst_index);
    if ((!inst_entry)||(!inst_entry->valid)) {
        LOG(FASTPASS, ERR, "get inst entry failed!");
        fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

        /* Consider success */
        return ret;
    }

    /* If don't support predefined rules, far is must */
    far_entry = fp_far_entry_get(new_far_index);
    if ((!far_entry)||(!far_entry->valid)) {
        LOG(FASTPASS, ERR, "get far entry failed!");
        fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

        /* Consider success */
        return ret;
    }

    /* Check bar */
    if (far_entry->config.choose.d.section_bar) {
        bar_entry = fp_bar_entry_get(far_entry->config.bar_index);
        if ((!bar_entry)||(!bar_entry->valid)) {
            LOG(FASTPASS, ERR, "get bar entry failed!");
            fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

            /* Consider success */
            return ret;
        }
        if (far_entry->config.action.d.buff) {
            /* If action is buff, set start time */
            /* But if old action is buff(time is not zero),
            ignore it */
            if (!ros_atomic32_read(&(bar_entry->container.time_start))) {
                ros_atomic32_set(&(bar_entry->container.time_start),
                    fp_get_time());
            }
        }
    }
    if ((far_entry->config.action.d.buff)
      ||(far_entry->config.action.d.nocp)) {

        fp_bar_container    *bar_cont;
        uint32_t            buff_pkts_cnt;

        if ((far_entry->config.choose.d.section_bar)
          &&(bar_entry != NULL)){
            bar_cont = &(bar_entry->container);
        }
        else {
            fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
            LOG(FASTPASS, ERR,
                "no bar configured, but set buff/nocp action.");
            ret = EN_COMM_ERRNO_PARAM_INVALID;
            return ret;
        }

        ros_rwlock_write_lock(&shadow->rwlock);
        buff_pkts_cnt = lstCount(&(shadow->list));
        ros_atomic32_set(&(bar_cont->pkts_count), buff_pkts_cnt);
        ros_rwlock_write_unlock(&shadow->rwlock);

        /* Return, don't handle buffered packet */
        LOG(FASTPASS, RUNNING,
            "new action is buff/nocp.");
        return ret;
    }
    else if (entry_cfg->temp_flag) {

        /* Return, don't handle buffered packet */
        LOG(FASTPASS, RUNNING,
            "new action is temp.");
        fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
        return ret;
    }
    else {
        /* Handle buffered packets if exist */
        fp_fast_send_buff_pkt(shadow);
    }

    fp_packet_stat_count(COMM_MSG_FP_STAT_MOD_FAST);

    return ret;
}

uint32_t fp_msg_entry_sum(comm_msg_ie_t *ie)
{
    comm_msg_fast_ie_t *entry_ie;
    fp_fast_table   *head;
    uint32_t        sum_num;
    uint32_t        type;

    entry_ie = (comm_msg_fast_ie_t *)ie;

    type = fp_msg_get_table_type(entry_ie->table);

    LOG(FASTPASS, RUNNING,
        "sum fast entry number of tree(type %d).", type);

    if (type >= COMM_MSG_FAST_BUTT) {
        return 0;
    }

    head = fp_fast_table_get(type);
    if (!head) {
        return 0;
    }

    sum_num = Res_GetAlloced(head->res_no);

    LOG(FASTPASS, RUNNING, "GET total fast entry number %d.", sum_num);

    return sum_num;
}

uint32_t fp_msg_entry_get(comm_msg_ie_t *ie)
{
    uint32_t type;
    uint32_t index;
    uint32_t ret = EN_COMM_ERRNO_OK;
    comm_msg_fast_ie_t      *entry_ie;
    fp_fast_entry           *entry;
    fp_fast_table           *head;
    comm_msg_header_t       *msg;
    comm_msg_ie_t           *resp_ie;
    uint8_t                 buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                buf_len = 0;

    entry_ie = (comm_msg_fast_ie_t *)ie;

    type = fp_msg_get_table_type(entry_ie->table);
    index = entry_ie->index;

    LOG(FASTPASS, RUNNING, "get fast entry %d(type %d).", index, type);

    head = fp_fast_table_get(type);
    if (!head) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    /* Check index */
    if (index >= head->entry_max) {
        ret = EN_COMM_ERRNO_ITEM_NUM_OVERFLOW;
        return ret;
    }

    /* Check entry validation */
    entry = fp_fast_entry_get(head, index);
    if (!entry->valid) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    msg = fp_fill_msg_header(buf);
    resp_ie = COMM_MSG_GET_IE(msg);
    resp_ie->cmd   = htons(ie->cmd);
    resp_ie->index = htonl(ie->index);
    ros_memcpy(resp_ie->data, entry->cfg_data, COMM_MSG_IE_LEN_FAST);

    buf_len = COMM_MSG_IE_LEN_COMMON + COMM_MSG_IE_LEN_FAST;
    resp_ie->len   = htons(buf_len);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    if (0 > fp_msg_send((char *)buf, buf_len)) {
        LOG(FASTPASS, ERR, "Send msg to spu failed.");
        return EN_COMM_ERRNO_SEND_MSG_ERROR;
    }
    LOG(FASTPASS, RUNNING, "get port type %d entry %d info.", type, entry->index);

    return ret;
}

uint32_t fp_msg_entry_clr(comm_msg_ie_t *ie)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    uint32_t type;
    comm_msg_fast_ie_t      *entry_ie;

    entry_ie = (comm_msg_fast_ie_t *)ie;

    type = fp_msg_get_table_type(entry_ie->table);

    LOG(FASTPASS, RUNNING,
        "clr fast table(type %d).", type);

    ret = fp_fast_clear(type);

    return ret;
}

uint32_t fp_msg_entry_show(struct cli_def *cli,uint32_t type_no, uint32_t entry_no)
{
    fp_fast_table           *head;
    fp_fast_shadow          *shadow;
    fp_fast_entry           *entry;
    comm_msg_fast_cfg       *entry_cfg;

    if (type_no >= COMM_MSG_FAST_BUTT) {
        cli_print(cli,"  type error  [type 0:ipv4, 1:ipv6, 2:mac]\n");
        return -1;
    }
    head  = fp_fast_table_get(type_no);

    if (entry_no >= head->entry_max) {
        cli_print(cli,"  entry error!\n"
               "  beyond entry max, should be less than %d\n",
               head->entry_max);
        return -1;
    }

    entry = fp_fast_entry_get(head, entry_no);
    /* detail info */
    entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);
    /* Get shadow */
    shadow = fp_fast_shadow_get(head, entry->index);

    if (entry_no != entry->index) {
        cli_print(cli,"  not find fasttable\n");
        return -1;
    }

    cli_print(cli,"entry index       %d\n",entry->index);
    cli_print(cli,"entry aux_info    %08x\n",entry->aux_info);

    cli_print(cli,"shadow_index      %d\n",shadow->index);
    cli_print(cli,"shadow_key        %x\n",shadow->key);
    cli_print(cli,"shadow_list_count %d\n",shadow->list.count);
    cli_print(cli,"shadow_head       %d\n",type_no);

    cli_print(cli,"temp_flag         %d\n",entry_cfg->temp_flag);
    cli_print(cli,"pdr_si            %d\n",entry_cfg->pdr_si);
    cli_print(cli,"inst_index        %d\n",entry_cfg->inst_index);
    cli_print(cli,"mac               %02x:%02x:%02x:%02x:%02x:%02x\n",
                            entry_cfg->dst_mac[0],entry_cfg->dst_mac[1],
                            entry_cfg->dst_mac[2],entry_cfg->dst_mac[3],
                            entry_cfg->dst_mac[4],entry_cfg->dst_mac[5]);

    return 0;
}


uint32_t fp_msg_inst_add(comm_msg_ie_t *ie)
{
    uint32_t cnt = 0;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    fp_inst_table *inst_head = fp_inst_table_get();
    fp_inst_entry *inst_entry = NULL;
    comm_msg_inst_ie_data *ie_data = NULL;
    fp_far_entry *far_entry = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ie_data = (comm_msg_inst_ie_data *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t tmp_index = ntohl(ie_data[cnt].index);

        LOG(FASTPASS, RUNNING, "add inst entry %u to table.", tmp_index);
        /* Check index */
        if (tmp_index >= inst_head->entry_max) {
            LOG(FASTPASS, ERR, "The inst entry index overflow,"
                " entry num: %u.", tmp_index);
            continue;
        }

        if (fp_msg_inst_param_check(&ie_data[cnt].cfg)) {
            return EN_COMM_ERRNO_PARAM_INVALID;
        }

        if (G_SUCCESS != Res_AllocTarget(inst_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "The inst entry is existing,"
                " entry num: %u.", tmp_index);
            continue;
        }

        inst_entry = fp_inst_entry_get(tmp_index);

        /* Init fast list */
        ros_rwlock_init(&inst_entry->lstlock);
        lstInit(&inst_entry->lstfast);

        /* Copy entry config */
        ros_rwlock_write_lock(&inst_entry->rwlock); /* lock */
        ros_memset(&inst_entry->config, 0, sizeof(comm_msg_inst_config));
        dl_list_init(&inst_entry->far_node);
        dl_list_init(&inst_entry->far2_node);
        fp_msg_inst_copy(&inst_entry->config, &ie_data[cnt].cfg);
        inst_entry->valid = G_TRUE;

        inst_entry->max_act = inst_entry->config.max_act;
        if (inst_entry->config.immediately_act) {
            inst_entry->inact = inst_entry->config.inact;
            Res_MarkSet(inst_head->res_stat, inst_entry->index);
        }
        ros_rwlock_write_unlock(&inst_entry->rwlock); /* unlock */

        /* Update far entry, point back */
        if (inst_entry->config.choose.d.flag_far1) {
            far_entry = fp_far_entry_get(inst_entry->config.far_index1);
            if (NULL == far_entry) {
                LOG(FASTPASS, ERR, "Far entry get fail, index: %u",
                    inst_entry->config.far_index1);
                fp_msg_inst_del_proc(tmp_index);
                return EN_COMM_ERRNO_ITEM_CHECK_FAILED;
            }
            ros_rwlock_write_lock(&inst_entry->rwlock); /* lock */
            dl_list_add_tail(&far_entry->inst_lst, &inst_entry->far_node);
            ros_rwlock_write_unlock(&inst_entry->rwlock); /* unlock */
        }

        if (inst_entry->config.choose.d.flag_far2) {
            far_entry = fp_far_entry_get(inst_entry->config.far_index2);
            if (NULL == far_entry) {
                LOG(FASTPASS, ERR, "Far entry get fail, index: %u",
                    inst_entry->config.far_index2);
                fp_msg_inst_del_proc(tmp_index);
                return EN_COMM_ERRNO_ITEM_CHECK_FAILED;
            }
            ros_rwlock_write_lock(&inst_entry->rwlock); /* lock */
            dl_list_add_tail(&far_entry->inst2_lst, &inst_entry->far2_node);
            ros_rwlock_write_unlock(&inst_entry->rwlock); /* unlock */
        }
    }

	LOG(FASTPASS, RUNNING, "inst(%u) collect_thres %lu!", inst_entry->index, inst_entry->config.collect_thres);
    return EN_COMM_ERRNO_OK;
}

static inline void fp_msg_inst_del_fast(fp_inst_entry *inst_entry)
{
    fp_fast_shadow  *shadow;
    NODE            *node;

    /* Delete all related fast entry */
    ros_rwlock_write_lock(&inst_entry->lstlock);
    node = lstGet(&inst_entry->lstfast);
    ros_rwlock_write_unlock(&inst_entry->lstlock);
    while (node) {
        shadow = (fp_fast_shadow *)node;
        fp_fast_free(shadow->head, shadow->index);

        /* Get next fast entry */
        ros_rwlock_write_lock(&inst_entry->lstlock);
        node = lstGet(&inst_entry->lstfast);
        ros_rwlock_write_unlock(&inst_entry->lstlock);
    }
}

static uint32_t fp_msg_inst_del_proc(uint32_t index)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    fp_inst_entry   *inst_entry;
    fp_inst_table   *inst_head = fp_inst_table_get();
    fp_fast_shadow  *shadow;
    NODE            *node;
    fp_far_entry    *far_entry = NULL;

    /* Check index */
    if (index >= inst_head->entry_max) {
        ret = EN_COMM_ERRNO_ITEM_NUM_OVERFLOW;
        return ret;
    }

    /* Get entry */
    inst_entry  = fp_inst_entry_get(index);

    /* Check item */
    if (NULL == inst_entry || G_FALSE == inst_entry->valid) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    /* Delete all related fast entry */
    ros_rwlock_write_lock(&inst_entry->lstlock);
    node = lstGet(&inst_entry->lstfast);
    ros_rwlock_write_unlock(&inst_entry->lstlock);
    LOG(FASTPASS, RUNNING,
        "get linked first fast node is %p.", node);
    while (node) {

        shadow = (fp_fast_shadow *)node;
        fp_fast_free(shadow->head, shadow->index);

        /* Get next fast entry */
        ros_rwlock_write_lock(&inst_entry->lstlock);
        node = lstGet(&inst_entry->lstfast);
        ros_rwlock_write_unlock(&inst_entry->lstlock);
    }

    /* Set invalid */
    ros_rwlock_write_lock(&inst_entry->rwlock);
    inst_entry->valid = G_FALSE;
    if (inst_entry->config.choose.d.flag_far1) {
        far_entry = fp_far_entry_get(inst_entry->config.far_index1);
        ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
        dl_list_del(&inst_entry->far_node);
        ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
    }
    if (inst_entry->config.choose.d.flag_far2) {
        far_entry = fp_far_entry_get(inst_entry->config.far_index2);
        ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
        dl_list_del(&inst_entry->far2_node);
        ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
    }
    /* It is planned to check and report the residual statistics here,
    *  but the SPU is deleted before the FPU
    */
    Res_MarkClr(inst_head->res_stat, inst_entry->index);

    ros_rwlock_write_unlock(&inst_entry->rwlock);

    /* Free res */
    Res_Free(inst_head->res_no, 0, index);

    return ret;
}

uint32_t fp_msg_inst_del(comm_msg_ie_t *ie)
{
    uint32_t *index = NULL, cnt = 0;
    uint32_t ret = EN_COMM_ERRNO_OK;
    comm_msg_rules_ie_t *entry_ie = (comm_msg_rules_ie_t *)ie;

    index = (uint32_t *)entry_ie->data;

    LOG(FASTPASS, RUNNING, "DEL inst entry number %u.", entry_ie->rules_num);

    for (cnt = 0; cnt < entry_ie->rules_num; ++cnt) {
        ret = fp_msg_inst_del_proc(ntohl(index[cnt]));
    }

    return ret;
}

uint32_t fp_msg_inst_ins(comm_msg_ie_t *ie)
{
    uint32_t index, key = 0;
    uint32_t ret = EN_COMM_ERRNO_OK;
    uint64_t ret64;
    fp_inst_table           *inst_head;
    fp_inst_entry           *inst_entry;
    comm_msg_inst_config    *cfg;
    comm_msg_inst_config    *core;
    fp_far_entry            *far_entry;

    inst_head = fp_inst_table_get();
    if (!inst_head) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    /* Get cfg */
    cfg = (comm_msg_inst_config *)(ie->data);
    if (fp_msg_inst_param_check(cfg)) {
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ret64 = Res_Alloc(inst_head->res_no, &key, &index, EN_RES_ALLOC_MODE_OC);
    if (ret64 != G_SUCCESS) {
        ret = EN_COMM_ERRNO_RESOURCE_NOT_ENOUGH;
        return ret;
    }

    /* Get entry */
    inst_entry = fp_inst_entry_get(index);

    /* Check item */
    if (inst_entry->valid) {
        ret = EN_COMM_ERRNO_ITEM_CONFLICT;
        return ret;
    }

    /* Get core */
    core   = &(inst_entry->config);
    ros_memset(core, 0, sizeof(comm_msg_inst_config));

    /* Get cfg */
    cfg = (comm_msg_inst_config *)(ie->data);

    /* Copy content */
    fp_msg_inst_copy(core, cfg);

    /* Init fast list */
    ros_rwlock_init(&inst_entry->lstlock);
    lstInit(&inst_entry->lstfast);

    /* Set valid */
    ros_rwlock_write_lock(&inst_entry->rwlock);
    inst_entry->valid = G_TRUE;
    ros_rwlock_write_unlock(&inst_entry->rwlock);

    /* Update far entry, point back */
    if (inst_entry->config.choose.d.flag_far1) {
        far_entry = fp_far_entry_get(inst_entry->config.far_index1);
        ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
        dl_list_add_tail(&far_entry->inst_lst, &inst_entry->far_node);
        ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
    }

    if (inst_entry->config.choose.d.flag_far2) {
        far_entry = fp_far_entry_get(inst_entry->config.far_index2);
        ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
        dl_list_add_tail(&far_entry->inst2_lst, &inst_entry->far2_node);
        ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
    }

    LOG(FASTPASS, RUNNING, "INS inst entry on %d.", index);

    return index;
}

static uint32_t fp_msg_inst_mod_proc(fp_inst_entry *inst_entry)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    fp_fast_shadow          *shadow;
    fp_far_entry            *far_entry;
    comm_msg_inst_config    *config;
    NODE                    *node;
    char                    action_str[64];

    if (NULL == inst_entry) {
        /* No inst refer to it */
        return EN_COMM_ERRNO_OK;
    }

    /* Get core structure */
    config = &(inst_entry->config);

    if (config->choose.d.flag_far1) {
        /* Get configuration */
        far_entry = fp_far_entry_get(config->far_index1);
        if ((!far_entry)||(!far_entry->valid)) {
            ret = EN_COMM_ERRNO_PARAM_INVALID;
            return ret;
        }

        fp_get_action_str(far_entry->config.action.value, action_str);
        LOG(FASTPASS, RUNNING, "new action is %s.", action_str);

        /* Check action, if not buff or nocp, send buffered packets */
        if ((far_entry->config.action.d.buff)
          ||(far_entry->config.action.d.nocp)) {
            LOG(FASTPASS, RUNNING,
                "new action is buff/nocp, don't handle packets.");
            return ret;
        }
        else {
            /* Handle all related fast entry, But don't delete */
            ros_rwlock_write_lock(&inst_entry->lstlock);
            node = lstFirst(&inst_entry->lstfast);
            ros_rwlock_write_unlock(&inst_entry->lstlock);

            LOG(FASTPASS, RUNNING, "get fast list header %p.", node);

            while (node) {
                comm_msg_fast_cfg *cfg;

                /* If not temp, handle packet */
                shadow = (fp_fast_shadow *)node;
                cfg = (comm_msg_fast_cfg *)(shadow->entry->cfg_data);
                if (!cfg->temp_flag) {
                    /* Handle buffered packets if exist */
                    fp_fast_send_buff_pkt(shadow);
                }

                /* Get next fast entry */
                ros_rwlock_write_lock(&inst_entry->lstlock);
                node = lstNext(node);
                ros_rwlock_write_unlock(&inst_entry->lstlock);
            }
        }
    }

    LOG(FASTPASS, RUNNING, "proc inst entry %d modification.",
        inst_entry->index);

    return ret;
}

uint32_t fp_msg_inst_mod(comm_msg_ie_t *ie)
{
    uint32_t cnt = 0;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    fp_inst_table *inst_head = fp_inst_table_get();
    fp_inst_entry *inst_entry = NULL;
    comm_msg_inst_ie_data *ie_data = NULL;
    comm_msg_inst_config  *input_cfg = NULL;
    comm_msg_inst_config  *core = NULL;
    fp_far_entry *far_entry = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ie_data = (comm_msg_inst_ie_data *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t tmp_index = ntohl(ie_data[cnt].index);

        LOG(FASTPASS, RUNNING, "modify inst entry %u.", tmp_index);
        /* Check index */
        if (tmp_index >= inst_head->entry_max) {
            LOG(FASTPASS, ERR, "modify entry index: %u overflow.", tmp_index);
            continue;
        }

        if (fp_msg_inst_param_check(&ie_data[cnt].cfg)) {
            LOG(FASTPASS, ERR, "inst param check failed, entry index: %u.", tmp_index);
            continue;
        }

        /* Get entry */
        inst_entry = fp_inst_entry_get(tmp_index);
        if ((!inst_entry) || (!inst_entry->valid)) {
            LOG(FASTPASS, ERR, "modify inst entry failed, index: %u invaild.", tmp_index);
            continue;
        }

        /* Check alloc */
        if (G_TRUE != Res_IsAlloced(inst_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "modify inst entry %u failed, resource not allocated.",
                tmp_index);
            continue;
        }

        /* Remove node from far */
        ros_rwlock_write_lock(&inst_entry->rwlock); /* lock */
        if (inst_entry->config.choose.d.flag_far1) {
            far_entry = fp_far_entry_get(inst_entry->config.far_index1);
            ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
            dl_list_del(&inst_entry->far_node);
            ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
        }
        if (inst_entry->config.choose.d.flag_far2) {
            far_entry = fp_far_entry_get(inst_entry->config.far_index2);
            ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
            dl_list_del(&inst_entry->far2_node);
            ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
        }

        /* Get core */
        core = &(inst_entry->config);
        ros_memset(core, 0, sizeof(comm_msg_inst_config));

        /* Get cfg */
        input_cfg = &ie_data[cnt].cfg;

        /* Copy content */
        /* It's different with ADD, here need mutex */
        fp_msg_inst_copy(core, input_cfg);

        /* Update far entry, point back */
        if (inst_entry->config.choose.d.flag_far1) {
            far_entry = fp_far_entry_get(inst_entry->config.far_index1);
            ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
            dl_list_add_tail(&far_entry->inst_lst, &inst_entry->far_node);
            ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
        }
        if (inst_entry->config.choose.d.flag_far2) {
            far_entry = fp_far_entry_get(inst_entry->config.far_index2);
            ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
            dl_list_add_tail(&far_entry->inst2_lst, &inst_entry->far2_node);
            ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
        }
        ros_rwlock_write_unlock(&inst_entry->rwlock);

        /* Handle far or bar modification */
        fp_msg_inst_mod_proc(inst_entry);

        /* Consider clearing the existing fast entry on instance to ensure that some matching rules are modified by SPU.
        *  However, considering that it is involved in the cache message, it will not be processed temporarily
        */
    }

    return EN_COMM_ERRNO_OK;
}

uint32_t fp_msg_inst_get(void)
{
    uint32_t entry_num = 0;
    int32_t cur_index = -1;
    fp_inst_entry *inst_entry = NULL;
    fp_inst_table *inst_head = fp_inst_table_get();
    comm_msg_inst_ie_data *ie_data = NULL;
    comm_msg_header_t *msg;
    comm_msg_rules_ie_t *ie = NULL;
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len = 0;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_inst_ie_data);

    msg = fp_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd     = htons(EN_COMM_MSG_UPU_INST_GET);
    ie_data  = (comm_msg_inst_ie_data *)ie->data;
    entry_num = 0;

    cur_index = Res_GetAvailableInBand(inst_head->res_no, cur_index + 1, inst_head->entry_max);
    while (-1 != cur_index) {
        inst_entry = fp_inst_entry_get(cur_index);
        if (!inst_entry->valid) {
            LOG(FASTPASS, ERR, "The inst entry %u is alloced, but invalid.", cur_index);
            cur_index = Res_GetAvailableInBand(inst_head->res_no, cur_index + 1, inst_head->entry_max);
            continue;
        }
        ie_data[entry_num].index = htonl(inst_entry->index);
        ros_rwlock_read_lock(&inst_entry->rwlock);
        fp_msg_inst_copy(&ie_data[entry_num].cfg, &inst_entry->config);
        ros_rwlock_read_unlock(&inst_entry->rwlock);
        ++entry_num;

        if (entry_num >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_inst_ie_data) * entry_num;
            ie->rules_num = htonl(entry_num);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > fp_msg_send((char *)buf, buf_len)) {
                LOG(UPC, ERR, "Send msg to spu failed.");
            }
            entry_num = 0;
        }

        cur_index = Res_GetAvailableInBand(inst_head->res_no, cur_index + 1, inst_head->entry_max);
    }

    if (entry_num > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_inst_ie_data) * entry_num;
        ie->rules_num = htonl(entry_num);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > fp_msg_send((char *)buf, buf_len)) {
            LOG(UPC, ERR, "Send msg to spu failed.");
        }
        entry_num = 0;
    }

    return EN_COMM_ERRNO_OK;
}

uint32_t fp_msg_inst_sum()
{
    fp_inst_table   *head;
    uint32_t        sum_num;

    head = fp_inst_table_get();
    if (!head) {
        return COMM_MSG_INVALID_INDEX;
    }

    sum_num = Res_GetAlloced(head->res_no);

    LOG(FASTPASS, RUNNING, "GET inst entry number %d.", sum_num);

    return sum_num;
}

uint32_t fp_msg_inst_clr()
{
    uint32_t index;
    uint32_t type;
    uint32_t ret = EN_COMM_ERRNO_OK;
    fp_inst_entry           *inst_entry;
    fp_inst_table           *inst_head;

    inst_head = fp_inst_table_get();
    if (!inst_head) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    for (index = 0; index < inst_head->entry_max; index++) {
        inst_entry = fp_inst_entry_get(index);
        if (inst_entry->valid)
        {
            ros_rwlock_write_lock(&inst_entry->rwlock); /* lock */
            inst_entry->valid = G_FALSE;
            if (inst_entry->config.choose.d.flag_far1) {
                dl_list_del(&inst_entry->far_node);
            }
            if (inst_entry->config.choose.d.flag_far2) {
                dl_list_del(&inst_entry->far2_node);
            }
            ros_rwlock_write_unlock(&inst_entry->rwlock); /* unlock */
            Res_Free(inst_head->res_no, 0, index);
        }
    }

    for (type = COMM_MSG_FAST_IPV4; type < COMM_MSG_FAST_BUTT; type++) {
        ret = fp_fast_clear(type);
    }

    LOG(FASTPASS, RUNNING, "DEL inst entry %d.", index);

    return ret;
}

uint32_t fp_msg_inst_show(struct cli_def *cli,uint32_t inst_num)
{
    fp_inst_entry           *inst_entry;
    fp_inst_table           *inst_head;
    uint8_t                  cnt;
    inst_head = fp_inst_table_get();
    if (inst_num >= inst_head->entry_max) {
        cli_print(cli,"  entry error!\n"
               "  beyond entry max, should be less than %d\n",
               inst_head->entry_max);
        return -1;
    }
    inst_entry = fp_inst_entry_get(inst_num);

    if (inst_entry->valid) {
        cli_print(cli,"index            %d\n",inst_entry->index);
        cli_print(cli,"immediately active %d\n",inst_entry->config.immediately_act);
        cli_print(cli,"--choose--\n");
        cli_print(cli,"  qer          : %d\n",inst_entry->config.choose.d.flag_qer);
        cli_print(cli,"  urr          : %d\n",inst_entry->config.choose.d.flag_urr);
        cli_print(cli,"  far          : %d\n",inst_entry->config.choose.d.flag_far1);
        cli_print(cli,"  rm header    : %d\n\n",inst_entry->config.choose.d.\
            flag_rm_header);
        cli_print(cli,"outer header removal present    %d\n",
            inst_entry->config.rm_outh.ohr_flag);
        cli_print(cli,"outer header removal type       %d\n",
            inst_entry->config.rm_outh.type);
        cli_print(cli,"outer header removal flag       %d\n",
            inst_entry->config.rm_outh.flag);
        cli_print(cli,"far index1       %d\n",inst_entry->config.far_index1);
        cli_print(cli,"far index2       %d\n",inst_entry->config.far_index2);
        cli_print(cli,"urr number       %d\n",inst_entry->config.urr_number);
        for(cnt = 0; cnt < inst_entry->config.urr_number; cnt++) {
            cli_print(cli,"urr index        %d\n",inst_entry->config.urr_index[cnt]);
        }
        cli_print(cli,"qer number       %d\n",inst_entry->config.qer_number);
        for(cnt = 0; cnt < inst_entry->config.qer_number; cnt++) {
            cli_print(cli,"qer index        %d\n",inst_entry->config.qer_index[cnt]);
        }
        cli_print(cli,"light            %d\n",inst_entry->control.light);
        cli_print(cli,"urr bnum         %d\n",inst_entry->control.urr_bnum);
        for(cnt = 0; cnt < inst_entry->control.urr_bnum; cnt++) {
            cli_print(cli,"urr bqos         %d\n",inst_entry->control.urr_bqos[cnt]);
        }
        cli_print(cli,"urr anum         %d\n",inst_entry->control.urr_anum);
        for(cnt = 0; cnt < inst_entry->control.urr_anum; cnt++) {
            cli_print(cli,"urr_aqos         %d\n",inst_entry->control.urr_aqos[cnt]);
        }
        cli_print(cli,"urr dnum         %d\n",inst_entry->control.urr_dnum);
        for(cnt = 0; cnt < inst_entry->control.urr_bnum; cnt++) {
            cli_print(cli,"urr drop         %d\n",inst_entry->control.urr_drop[cnt]);
        }
        cli_print(cli,"inact            %u\n",inst_entry->config.inact);
        cli_print(cli,"max act          %u\n",inst_entry->config.max_act);
    } else {
        cli_print(cli,"  not find inst table\n");
    }
    return 0;
}

int fp_msg_init_check_timeout(uint32_t inst_index)
{
    fp_inst_entry *inst_entry;

    inst_entry = fp_inst_entry_get(inst_index);
    if (!inst_entry || !inst_entry->valid) {
        return TRUE;
    }

    if (inst_entry->config.inact) {
        if (inst_entry->inact) {
            inst_entry->inact--;
            return FALSE;
        }
        else {
            return TRUE;
        }
    } else if (inst_entry->config.max_act) {
        if (inst_entry->max_act) {
            inst_entry->max_act--;
            return FALSE;
        }
        else {
            return TRUE;
        }
    } else {
        return TRUE;
    }
}

uint8_t *fp_msg_inst_stat_collect(uint8_t *buf, uint32_t *buf_len, uint32_t buf_max, fp_inst_table *head)
{
    fp_inst_entry *inst_entry;
    comm_msg_header_t *msg;
    comm_msg_rules_ie_t *ie = NULL;
    comm_msg_urr_stat_conf_t *stat;
    uint32_t entry_num = 0;
    int32_t  cur_index;
    uint32_t tmp_len = 0;/* ie total length */
    int64_t tmp_value, pkt_trigger = 0;
    uint32_t max_rules = (buf_max - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_urr_stat_conf_t);

    msg = fp_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd   = htons(EN_COMM_MSG_UPU_FP_STAT);

    /* set init */
    entry_num = 0;
    cur_index = head->cur_stat_entry;
    stat = (comm_msg_urr_stat_conf_t *)ie->data;
    inst_entry = NULL;

    while (entry_num < max_rules) {

        /* get next available */
        cur_index = Res_MarkGetClr(head->res_stat, cur_index, fp_msg_init_check_timeout);
        if (cur_index == COMM_MSG_ORPHAN_NUMBER) {
            continue;
        }
        if (cur_index == -1) {
            break;
        }

        /* not first */
        if (inst_entry) {
            /* if index reverse, we consider it reaches end */
            if (cur_index < inst_entry->index) {
                break;
            }
        }

        /* get entry */
        inst_entry = fp_inst_entry_get(cur_index);
        if (!inst_entry || !inst_entry->valid) {
            LOG(FASTPASS, ERR, "The inst entry %u is (%p), 'valid' is %d.",
                cur_index, inst_entry, inst_entry ? inst_entry->valid : 0);
            continue;
        }

		ros_rwlock_write_lock(&inst_entry->rwlock);

        /* fill stat */
        tmp_value = ros_atomic64_read(&inst_entry->stat.forw_pkts);
        ros_atomic64_set(&stat[entry_num].urr_stat.forw_pkts, htonll(tmp_value));
        ros_atomic64_sub(&inst_entry->stat.forw_pkts, tmp_value);
        pkt_trigger += tmp_value;

        tmp_value = ros_atomic64_read(&inst_entry->stat.forw_bytes);
        ros_atomic64_set(&stat[entry_num].urr_stat.forw_bytes, htonll(tmp_value));
        ros_atomic64_sub(&inst_entry->stat.forw_bytes, tmp_value);

        tmp_value = ros_atomic64_read(&inst_entry->stat.drop_pkts);
        ros_atomic64_set(&stat[entry_num].urr_stat.drop_pkts, htonll(tmp_value));
        ros_atomic64_sub(&inst_entry->stat.drop_pkts, tmp_value);
        pkt_trigger += tmp_value;

        tmp_value = ros_atomic64_read(&inst_entry->stat.drop_bytes);
        ros_atomic64_set(&stat[entry_num].urr_stat.drop_bytes, htonll(tmp_value));
        ros_atomic64_sub(&inst_entry->stat.drop_bytes, tmp_value);

        tmp_value = ros_atomic64_read(&inst_entry->stat.err_cnt);
        ros_atomic64_set(&stat[entry_num].urr_stat.err_cnt, htonll(tmp_value));
        ros_atomic64_sub(&inst_entry->stat.err_cnt, tmp_value);

		ros_rwlock_write_unlock(&inst_entry->rwlock);

        LOG(FASTPASS, RUNNING, "inst entry %u, fwd_pkts: %ld, fwd_bytes: %ld, drop_pkts: %ld, drop_bytes: %ld, err_cnt: %ld.",
            cur_index,
            ntohll(ros_atomic64_read(&stat[entry_num].urr_stat.forw_pkts)),
            ntohll(ros_atomic64_read(&stat[entry_num].urr_stat.forw_bytes)),
            ntohll(ros_atomic64_read(&stat[entry_num].urr_stat.drop_pkts)),
            ntohll(ros_atomic64_read(&stat[entry_num].urr_stat.drop_bytes)),
            ntohll(ros_atomic64_read(&stat[entry_num].urr_stat.err_cnt)));

        /* Update inactive count */
        if (pkt_trigger) {
            inst_entry->inact = inst_entry->config.inact;
        }

        stat[entry_num].inst_index = htonl(cur_index);

        /* count entry number */
        ++entry_num;
    }

    ie->rules_num   = htonl(entry_num);
    tmp_len         = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_urr_stat_conf_t) * entry_num;
    ie->len         = htons(tmp_len);
    tmp_len         += COMM_MSG_HEADER_LEN;
    msg->total_len  = htonl(tmp_len);

    head->cur_stat_entry = cur_index;

    LOG(FASTPASS, PERIOD, "Collect entry number: %u.", entry_num);
    if (entry_num > 0) {
        *buf_len = tmp_len;
    }

    return (uint8_t *)ie;
}

void fp_msg_inst_second_timer(void *timer, uint64_t para)
{
    fp_inst_table *inst_head = (fp_inst_table *)fp_inst_table_get();
    uint8_t  buf[FP_TIMER_BUFF_SIZE];
    uint32_t buf_len = 0, buf_max;
    uint32_t report_count = 200;
    int32_t  last_index;

    /* 1. collect stat of packets */
    LOG(FASTPASS, PERIOD, "Collect URR status timer.");

    /* report stat from first node */
    inst_head->cur_stat_entry = -1;
    while(report_count--) {

        last_index = inst_head->cur_stat_entry;
        buf_max = FP_TIMER_BUFF_SIZE;
        fp_msg_inst_stat_collect(buf, &buf_len, buf_max, inst_head);
        if (buf_len > 0) {
            if (0 > fp_msg_send((char *)buf, buf_len)) {
                LOG(FASTPASS, ERR, "Send msg to spu failed.");
            }
        }

        /* no more entry or reach end */
        if (inst_head->cur_stat_entry >= last_index) {
            break;
        }
    }

    /* 2. recycle fast table */
    fp_recycle_entry();

    return;
}

#ifndef ENABLE_FP_URR
static uint32_t fp_msg_inst_light_mod(comm_msg_ie_t *ie)
{
    uint32_t cnt, tmp_index;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    comm_msg_update_inst_light_t *inst_light;
    fp_inst_table *inst_head = fp_inst_table_get();
    fp_inst_entry *inst_entry = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    inst_light = (comm_msg_update_inst_light_t *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        tmp_index = ntohl(inst_light[cnt].inst_index);

        LOG(FASTPASS, RUNNING, "update inst entry %u, light: %d.", tmp_index, inst_light[cnt].light);
        /* Check index */
        if (tmp_index >= inst_head->entry_max) {
            LOG(FASTPASS, ERR, "modify entry index: %u overflow.", tmp_index);
            continue;
        }

        /* Get entry */
        inst_entry = fp_inst_entry_get(tmp_index);
        if ((!inst_entry) || (!inst_entry->valid)) {
            LOG(FASTPASS, ERR, "modify inst entry failed, index: %u invaild.", tmp_index);
            continue;
        }

        /* Check alloc */
        if (G_TRUE != Res_IsAlloced(inst_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "modify inst entry %u failed, resource not allocated.",
                tmp_index);
            continue;
        }

        /* Copy content */
        ros_rwlock_write_lock(&inst_entry->rwlock);
        if (inst_light[cnt].light > COMM_MSG_LIGHT_RED) {
            inst_entry->control.light = COMM_MSG_LIGHT_RED;
        } else {
            inst_entry->control.light = inst_light[cnt].light;
        }
        ros_rwlock_write_unlock(&inst_entry->rwlock);
    }

    return EN_COMM_ERRNO_OK;
}

static uint32_t fp_msg_inst_thres_mod(comm_msg_ie_t *ie)
{
    uint32_t cnt, tmp_index;
	uint64_t collect_thres;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    comm_msg_update_inst_thres_t *inst_thres;
    fp_inst_table *inst_head = fp_inst_table_get();
    fp_inst_entry *inst_entry = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    inst_thres = (comm_msg_update_inst_thres_t *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        tmp_index = ntohl(inst_thres[cnt].inst_index);
		collect_thres = ntohll(inst_thres->collect_thres);
        LOG(FASTPASS, RUNNING, "update inst entry %u, collect thres: %lu.", tmp_index, collect_thres);
        /* Check index */
        if (tmp_index >= inst_head->entry_max) {
            LOG(FASTPASS, ERR, "modify entry index: %u overflow.", tmp_index);
            continue;
        }

        /* Get entry */
        inst_entry = fp_inst_entry_get(tmp_index);
        if ((!inst_entry) || (!inst_entry->valid)) {
            LOG(FASTPASS, ERR, "modify inst entry failed, index: %u invaild.", tmp_index);
            continue;
        }

        /* Check alloc */
        if (G_TRUE != Res_IsAlloced(inst_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "modify inst entry %u failed, resource not allocated.",
                tmp_index);
            continue;
        }

        /* Copy content */
        ros_rwlock_write_lock(&inst_entry->rwlock);
        inst_entry->config.collect_thres= collect_thres;
        ros_rwlock_write_unlock(&inst_entry->rwlock);
    }

    return EN_COMM_ERRNO_OK;
}

#endif

uint32_t fp_msg_far_add(comm_msg_ie_t *ie)
{
    uint32_t cnt = 0;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    fp_far_table *far_head = fp_far_table_get();
    fp_far_entry *far_entry = NULL;
    comm_msg_far_ie_data *ie_data = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ie_data = (comm_msg_far_ie_data *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t tmp_index = ntohl(ie_data[cnt].index);

        LOG(FASTPASS, RUNNING, "add far entry %u to table.", tmp_index);
        /* Check index */
        if (tmp_index >= far_head->entry_max) {
            LOG(FASTPASS, ERR, "The far entry index overflow,"
                " entry num: %u.", tmp_index);
            continue;
        }

        if (G_SUCCESS != Res_AllocTarget(far_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "The far entry is existing,"
                " entry num: %u.", tmp_index);
            continue;
        }

        far_entry = fp_far_entry_get(tmp_index);

        /* Copy entry config */
        ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
        ros_memset(&far_entry->config, 0, sizeof(comm_msg_far_config));
        dl_list_init(&far_entry->inst_lst);
        dl_list_init(&far_entry->inst2_lst);
        fp_msg_far_copy(&far_entry->config, &ie_data[cnt].cfg);
        far_entry->valid = G_TRUE;
        ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
    }

    return EN_COMM_ERRNO_OK;
}

static uint32_t fp_msg_far_del_proc(uint32_t index)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    fp_far_table *far_head = fp_far_table_get();
    fp_far_entry *far_entry;
    struct dl_list *pos = NULL, *next = NULL;

    /* Check index */
    if (index >= far_head->entry_max) {
        ret = EN_COMM_ERRNO_ITEM_NUM_OVERFLOW;
        return ret;
    }

    /* Check alloc status */
    if (!Res_IsAlloced(far_head->res_no, 0, index)) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    far_entry = fp_far_entry_get(index);
    ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
    far_entry->valid = G_FALSE;
    dl_list_for_each_safe(pos, next, &far_entry->inst_lst) {
        dl_list_del(pos);
    }
    dl_list_for_each_safe(pos, next, &far_entry->inst2_lst) {
        dl_list_del(pos);
    }
    ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */

    /* Free res */
    Res_Free(far_head->res_no, 0, index);

    return ret;
}

uint32_t fp_msg_far_del(comm_msg_ie_t *ie)
{
    uint32_t *index = NULL, cnt = 0;
    uint32_t ret = EN_COMM_ERRNO_OK;
    comm_msg_rules_ie_t *entry_ie = (comm_msg_rules_ie_t *)ie;

    index = (uint32_t *)entry_ie->data;

    LOG(FASTPASS, RUNNING, "del far entry number %u.", entry_ie->rules_num);

    for (cnt = 0; cnt < entry_ie->rules_num; ++cnt) {
        ret = fp_msg_far_del_proc(ntohl(index[cnt]));
    }

    return ret;
}

uint32_t fp_msg_far_mod(comm_msg_ie_t *ie)
{
    uint32_t cnt = 0;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    fp_far_table *far_head = fp_far_table_get();
    fp_far_entry *far_entry = NULL;
    comm_msg_far_ie_data *ie_data = NULL;
    uint8_t tmp_ohc_flag;
    comm_msg_outh_cr_t tmp_ohc;
    comm_msg_far_action_t tmp_act;
    struct dl_list *pos = NULL, *next = NULL;
    fp_inst_entry *inst_entry = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ie_data = (comm_msg_far_ie_data *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t tmp_index = ntohl(ie_data[cnt].index);

        LOG(FASTPASS, RUNNING, "modify far entry %u.", tmp_index);
        /* Check index */
        if (tmp_index >= far_head->entry_max) {
            LOG(FASTPASS, ERR, "modify entry index: %u overflow.", tmp_index);
            continue;
        }

        /* Check alloc status */
        if (!Res_IsAlloced(far_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "modify entry index: %u invaild.", tmp_index);
            continue;
        }

        far_entry = fp_far_entry_get(tmp_index);

        /* Save the data before modification */
        tmp_ohc_flag = far_entry->config.choose.d.flag_out_header1;
        tmp_act.value = far_entry->config.action.value;
        ros_memcpy(&tmp_ohc, &far_entry->config.forw_cr_outh, sizeof(tmp_ohc));

        /* Copy entry config */
        ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
        fp_msg_far_copy(&far_entry->config, &ie_data[cnt].cfg);
        ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */

        /* If the condition is met, the existing fast table needs to be deleted */
        if ((tmp_ohc_flag != far_entry->config.choose.d.flag_out_header1) ||
            (tmp_ohc.ipv4 != far_entry->config.forw_cr_outh.ipv4) ||
            (ros_memcmp(&tmp_ohc.ipv6, &far_entry->config.forw_cr_outh.ipv6, IPV6_ALEN)) ||
            ((tmp_act.value != far_entry->config.action.value) && far_entry->config.action.d.nocp)) {

            ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
            dl_list_for_each_safe(pos, next, &far_entry->inst_lst) {
                ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
                inst_entry = (fp_inst_entry *)container_of(pos,
                                     fp_inst_entry, far_node);

                fp_msg_inst_del_fast(inst_entry);
                ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
            }
            dl_list_for_each_safe(pos, next, &far_entry->inst2_lst) {
                ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
                inst_entry = (fp_inst_entry *)container_of(pos,
                                     fp_inst_entry, far2_node);

                fp_msg_inst_del_fast(inst_entry);
                ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
            }
            ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
        }

        /* Handle far or bar modification */
        ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
        dl_list_for_each_safe(pos, next, &far_entry->inst_lst) {
            ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
            inst_entry = (fp_inst_entry *)container_of(pos,
                                 fp_inst_entry, far_node);

            fp_msg_inst_mod_proc(inst_entry);
            ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
        }
        dl_list_for_each_safe(pos, next, &far_entry->inst2_lst) {
            ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
            inst_entry = (fp_inst_entry *)container_of(pos,
                                 fp_inst_entry, far2_node);

            fp_msg_inst_mod_proc(inst_entry);
            ros_rwlock_write_lock(&far_entry->rwlock); /* lock */
        }
        ros_rwlock_write_unlock(&far_entry->rwlock); /* unlock */
    }

    return EN_COMM_ERRNO_OK;
}


uint32_t fp_msg_far_sum()
{
    fp_far_table        *far_head;
    uint32_t            sum_num;

    far_head = fp_far_table_get();

    sum_num = Res_GetAlloced(far_head->res_no);

    LOG(FASTPASS, RUNNING, "GET total far entry number %d.", sum_num);

    return sum_num;
}

uint32_t fp_msg_far_get(void)
{
    uint32_t entry_num = 0;
    int32_t cur_index = -1;
    fp_far_entry *far_entry = NULL;
    fp_far_table *far_head = fp_far_table_get();
    comm_msg_far_ie_data *ie_data = NULL;
    comm_msg_header_t *msg;
    comm_msg_rules_ie_t *ie = NULL;
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len = 0;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_far_ie_data);

    msg = fp_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd  = htons(EN_COMM_MSG_UPU_FAR_GET);
    ie_data  = (comm_msg_far_ie_data *)ie->data;
    entry_num = 0;

    cur_index = Res_GetAvailableInBand(far_head->res_no, cur_index + 1, far_head->entry_max);
    while (-1 != cur_index) {
        far_entry = fp_far_entry_get(cur_index);
        if (!far_entry->valid) {
            LOG(FASTPASS, ERR, "The far entry %u is alloced, but invalid.", cur_index);
            cur_index = Res_GetAvailableInBand(far_head->res_no, cur_index + 1, far_head->entry_max);
            continue;
        }
        ie_data[entry_num].index = htonl(far_entry->index);
        ros_rwlock_read_lock(&far_entry->rwlock);
        fp_msg_far_copy(&ie_data[entry_num].cfg, &far_entry->config);
        ros_rwlock_read_unlock(&far_entry->rwlock);
        ++entry_num;

        if (entry_num >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_far_ie_data) * entry_num;
            ie->rules_num = htonl(entry_num);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > fp_msg_send((char *)buf, buf_len)) {
                LOG(UPC, ERR, "Send msg to spu failed.");
            }
            entry_num = 0;
        }

        cur_index = Res_GetAvailableInBand(far_head->res_no, cur_index + 1, far_head->entry_max);
    }

    if (entry_num > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_far_ie_data) * entry_num;
        ie->rules_num = htonl(entry_num);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > fp_msg_send((char *)buf, buf_len)) {
            LOG(UPC, ERR, "Send msg to spu failed.");
        }
        entry_num = 0;
    }

    return EN_COMM_ERRNO_OK;
}


uint32_t fp_msg_far_clr()
{
    return EN_COMM_ERRNO_UNSUPPORTED;
}

uint32_t fp_msg_far_show(struct cli_def *cli,uint32_t far_num)
{
    fp_far_entry            *far_entry;
    fp_far_table            *far_head;
    far_head = fp_far_table_get();
    struct dl_list *pos = NULL, *next = NULL;
    fp_inst_entry *inst_entry = NULL;

    /* Check index */
    if (far_num >= far_head->entry_max) {
        cli_print(cli,"  entry error!\n"
               "  beyond entry max, should be less than %d\n",
               far_head->entry_max);
        return -1;
    }
    far_entry = fp_far_entry_get(far_num);
    if (far_entry->valid == 0) {
        cli_print(cli,"  not find far table\n");
        return -1;
    }
    cli_print(cli,"index             %d\n",far_entry->index);
    cli_print(cli,"far_id            %d\n",far_entry->config.far_id);
    cli_print(cli,"action            %d\n",far_entry->config.action.value);
    cli_print(cli,"if                %d\n",far_entry->config.forw_if);
    cli_print(cli,"  --far choose--\r\n");
    cli_print(cli,"  forwarding      : %d\r\n",
        far_entry->config.choose.d.section_forwarding);
    cli_print(cli,"    redirect      : %d\r\n",
        far_entry->config.choose.d.flag_redirect);
    cli_print(cli,"    out_header    : %d\r\n",
        far_entry->config.choose.d.flag_out_header1);
    cli_print(cli,"    trans level   : %d\r\n",
        far_entry->config.choose.d.flag_transport_level1);
    cli_print(cli,"    forward_policy: %d\r\n",
        far_entry->config.choose.d.flag_forward_policy1);
    cli_print(cli,"    header_enrich : %d\r\n",
        far_entry->config.choose.d.flag_header_enrich);
    cli_print(cli,"  bar             : %s\r\n",
        (far_entry->config.choose.d.section_bar)?"exist":"no");
#ifdef FAR_DUPL_ENABLE
    cli_print(cli,"  duplicating num : %d\r\n",
        far_entry->config.choose.d.section_dupl_num);
#endif
    switch (far_entry->config.choose.d.flag_redirect) {
        case 1:
            {
                char ip_str[256];
                uint32_t tmp_addr = htonl(far_entry->config.forw_redirect.ipv4_addr);

                if (NULL == inet_ntop(AF_INET, &tmp_addr, ip_str, sizeof(ip_str))) {
                    cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                cli_print(cli,"redirect IPv4     %s\n", ip_str);
            }
            break;

        case 2:
            {
                char ip_str[256];

                if (NULL == inet_ntop(AF_INET6, far_entry->config.forw_redirect.ipv6_addr,
                    ip_str, sizeof(ip_str))) {
                    cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                cli_print(cli,"redirect IPv6     %s\n", ip_str);
            }
            break;

        case 3:
            cli_print(cli,"redirect URL      %s\n", far_entry->config.forw_redirect.url);
            break;

        case 4:
            cli_print(cli,"redirect SIP URL  %s\n", far_entry->config.forw_redirect.sip_url);
            break;

        case 5:
            {
                char ip_str[256];
                uint32_t tmp_addr = htonl(far_entry->config.forw_redirect.v4_v6.ipv4);

                if (NULL == inet_ntop(AF_INET, &tmp_addr, ip_str, sizeof(ip_str))) {
                    cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                cli_print(cli,"redirect IPv4     %s\n", ip_str);

                if (NULL == inet_ntop(AF_INET6, far_entry->config.forw_redirect.v4_v6.ipv6,
                    ip_str, sizeof(ip_str))) {
                    cli_print(cli, "inet_ntop failed, error: %s.", strerror(errno));
                    break;
                }
                cli_print(cli,"redirect IPv6     %s\n", ip_str);
            }
            break;
    }
    if (far_entry->config.choose.d.flag_out_header1) {
        cli_print(cli,"--outheader--\n");
        cli_print(cli,"   teid    %d\n",
            far_entry->config.forw_cr_outh.teid);
        cli_print(cli,"   type    %02x\n",
            far_entry->config.forw_cr_outh.type.value);
        cli_print(cli,"   port    %d\n",far_entry->config.forw_cr_outh.port);
        cli_print(cli,"   ipv4    %08x\n",far_entry->config.forw_cr_outh.ipv4);
        cli_print(cli,"   ctag    flags:0x%x  value:0x%x\n",
            far_entry->config.forw_cr_outh.ctag.vlan_flag.value,
            far_entry->config.forw_cr_outh.ctag.vlan_value.data);
        cli_print(cli,"   stag    flags:0x%x  value:0x%x\n",
            far_entry->config.forw_cr_outh.stag.vlan_flag.value,
            far_entry->config.forw_cr_outh.stag.vlan_value.data);
    }

    if (far_entry->config.choose.d.flag_transport_level1) {
        cli_print(cli,"--transport--\n");
        cli_print(cli,"   tos     %d\n",far_entry->config.forw_trans.tos);
        cli_print(cli,"   mask    %d\n",far_entry->config.forw_trans.mask);
    }

    if (far_entry->config.choose.d.flag_forward_policy1) {
    }


    if (far_entry->config.choose.d.flag_header_enrich) {
    }

    dl_list_for_each_safe(pos, next, &far_entry->inst_lst) {
        inst_entry = (fp_inst_entry *)container_of(pos,
                             fp_inst_entry, far_node);

        cli_print(cli," --inst_entry-- \n");
        fp_msg_inst_show(cli, inst_entry->index);
    }
    dl_list_for_each_safe(pos, next, &far_entry->inst2_lst) {
        inst_entry = (fp_inst_entry *)container_of(pos,
                             fp_inst_entry, far2_node);

        cli_print(cli," --inst_entry-- \n");
        fp_msg_inst_show(cli, inst_entry->index);
    }

    cli_print(cli,"bar index       %d\n",far_entry->config.bar_index);

#ifdef FAR_DUPL_ENABLE
    if (far_entry->config.choose.d.section_dupl_num) {
        cli_print(cli,"   --dupl-- \n");
        cli_print(cli,"  dupl_if   %d\n",far_entry->config.dupl_cfg[0].dupl_if);
        cli_print(cli,"  teid      %d\n",
            far_entry->config.dupl_cfg[0].cr_outh.teid);
        cli_print(cli,"  port      %d\n",
            far_entry->config.dupl_cfg[0].cr_outh.port);

    }
#endif

    return 0;
}

uint32_t fp_msg_bar_add(comm_msg_ie_t *ie)
{
    uint32_t cnt = 0;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    fp_bar_table *bar_head = fp_bar_table_get();
    fp_bar_entry *bar_entry = NULL;
    comm_msg_bar_ie_data *ie_data = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ie_data = (comm_msg_bar_ie_data *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t tmp_index = ntohl(ie_data[cnt].index);

        LOG(FASTPASS, RUNNING, "add bar entry %u to table.", tmp_index);
        /* Check index */
        if (tmp_index >= bar_head->entry_max) {
            LOG(FASTPASS, ERR, "The bar entry index overflow,"
                " entry num: %u.", tmp_index);
            continue;
        }

        if (G_SUCCESS != Res_AllocTarget(bar_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "The bar entry is existing,"
                " entry num: %u.", tmp_index);
            continue;
        }

        bar_entry = fp_bar_entry_get(tmp_index);

        /* Copy entry config */
        ros_rwlock_write_lock(&bar_entry->rwlock); /* lock */
        ros_memset(&bar_entry->config, 0, sizeof(comm_msg_bar_config));
        fp_msg_bar_copy(&bar_entry->config, &ie_data[cnt].cfg);
        bar_entry->valid = G_TRUE;
        ros_rwlock_write_unlock(&bar_entry->rwlock); /* unlock */
    }

    return EN_COMM_ERRNO_OK;
}

uint32_t fp_msg_bar_del(comm_msg_ie_t *ie)
{
    uint32_t *index = NULL, cnt = 0;
    comm_msg_rules_ie_t     *entry_ie;
    fp_bar_table            *bar_head = fp_bar_table_get();
    fp_bar_entry            *bar_entry;

    entry_ie = (comm_msg_rules_ie_t *)ie;

    LOG(FASTPASS, RUNNING, "del bar entry num %d.", entry_ie->rules_num);

    index = (uint32_t *)entry_ie->data;

    for (cnt = 0; cnt < entry_ie->rules_num; ++cnt) {
        uint32_t tmp_index = ntohl(index[cnt]);
        /* Check index */
        if (tmp_index < bar_head->entry_max) {
           /* Check alloc status */
            if (!Res_IsAlloced(bar_head->res_no, 0, tmp_index)) {
                continue;
            }

            bar_entry = fp_bar_entry_get(tmp_index);
            ros_rwlock_write_lock(&bar_entry->rwlock); /* lock */
            bar_entry->valid = G_FALSE;
            ros_rwlock_write_unlock(&bar_entry->rwlock); /* unlock */

            /* Free res */
            Res_Free(bar_head->res_no, 0, tmp_index);
        }
    }

    return EN_COMM_ERRNO_OK;
}

uint32_t fp_msg_bar_mod(comm_msg_ie_t *ie)
{
    uint32_t cnt = 0;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    fp_bar_table *bar_head = fp_bar_table_get();
    fp_bar_entry *bar_entry = NULL;
    comm_msg_bar_ie_data *ie_data = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ie_data = (comm_msg_bar_ie_data *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t tmp_index = ntohl(ie_data[cnt].index);

        LOG(FASTPASS, RUNNING, "modify bar entry %u.", tmp_index);
        /* Check index */
        if (tmp_index >= bar_head->entry_max) {
            LOG(FASTPASS, ERR, "modify entry index: %u overflow.", tmp_index);
            continue;
        }

        /* Check alloc status */
        if (!Res_IsAlloced(bar_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "modify entry index: %u invaild.", tmp_index);
            continue;
        }

        bar_entry = fp_bar_entry_get(tmp_index);

        /* Copy entry config */
        ros_rwlock_write_lock(&bar_entry->rwlock); /* lock */
        fp_msg_bar_copy(&bar_entry->config, &ie_data[cnt].cfg);
        ros_rwlock_write_unlock(&bar_entry->rwlock); /* unlock */
    }

    return EN_COMM_ERRNO_OK;
}


uint32_t fp_msg_bar_sum()
{
    fp_bar_table        *bar_head;
    uint32_t            sum_num;

    bar_head = fp_bar_table_get();

    sum_num  = Res_GetAlloced(bar_head->res_no);

    LOG(FASTPASS, RUNNING, "GET total bar entry number %d.", sum_num);

    return sum_num;
}

uint32_t fp_msg_bar_get(void)
{
    uint32_t entry_num = 0;
    int32_t cur_index = -1;
    fp_bar_entry *bar_entry = NULL;
    fp_bar_table *bar_head = fp_bar_table_get();
    comm_msg_bar_ie_data *ie_data = NULL;
    comm_msg_header_t *msg;
    comm_msg_rules_ie_t *ie = NULL;
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len = 0;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_bar_ie_data);

    msg = fp_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd  = htons(EN_COMM_MSG_UPU_BAR_GET);
    ie_data  = (comm_msg_bar_ie_data *)ie->data;
    entry_num = 0;

    cur_index = Res_GetAvailableInBand(bar_head->res_no, cur_index + 1, bar_head->entry_max);
    while (-1 != cur_index) {
        bar_entry = fp_bar_entry_get(cur_index);
        if (!bar_entry->valid) {
            LOG(FASTPASS, ERR, "The bar entry %u is alloced, but invalid.", cur_index);
            cur_index = Res_GetAvailableInBand(bar_head->res_no, cur_index + 1, bar_head->entry_max);
            continue;
        }
        ie_data[entry_num].index = htonl(bar_entry->index);
        ros_rwlock_read_lock(&bar_entry->rwlock);
        fp_msg_bar_copy(&ie_data[entry_num].cfg, &bar_entry->config);
        ros_rwlock_read_unlock(&bar_entry->rwlock);
        ++entry_num;

        if (entry_num >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_bar_ie_data) * entry_num;
            ie->rules_num = htonl(entry_num);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > fp_msg_send((char *)buf, buf_len)) {
                LOG(UPC, ERR, "Send msg to spu failed.");
            }
            entry_num = 0;
        }

        cur_index = Res_GetAvailableInBand(bar_head->res_no, cur_index + 1, bar_head->entry_max);
    }

    if (entry_num > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_bar_ie_data) * entry_num;
        ie->rules_num = htonl(entry_num);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > fp_msg_send((char *)buf, buf_len)) {
            LOG(UPC, ERR, "Send msg to spu failed.");
        }
        entry_num = 0;
    }

    return EN_COMM_ERRNO_OK;
}


uint32_t fp_msg_bar_clr()
{
    return EN_COMM_ERRNO_UNSUPPORTED;
}

uint32_t fp_msg_bar_show(struct cli_def *cli,uint32_t bar_num)
{
    fp_bar_entry            *bar_entry;
    fp_bar_table            *bar_head;
    bar_head = fp_bar_table_get();

    /* Check index */
    if (bar_num >= bar_head->entry_max) {
        cli_print(cli,"  entry error!\n"
               "  beyond entry max, should be less than %d\n",
               bar_head->entry_max);
        return -1;
    }
    bar_entry = fp_bar_entry_get(bar_num);
    if (bar_entry->valid) {
        cli_print(cli,"bar index      %d\n",bar_entry->index);
        cli_print(cli,"bar id         %d\n",bar_entry->config.bar_id);
        cli_print(cli,"Delay          %d\n",bar_entry->config.notify_delay);
        cli_print(cli,"max pkts       %d\n",bar_entry->config.pkts_max);
        cli_print(cli,"max time       %d\n",bar_entry->config.time_max);
        cli_print(cli,"current pkts   %d\n",ros_atomic32_read(&bar_entry->container.pkts_count));
        cli_print(cli,"start time     %d\n",ros_atomic32_read(&bar_entry->container.time_start));
    } else {
        cli_print(cli,"  not find bar table\n");
        return -1;
    }

    return 0;
}

uint32_t fp_msg_qer_add(comm_msg_ie_t *ie)
{
#ifdef ENABLE_FP_QER
    uint32_t cnt = 0;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    fp_qer_table *qer_head = fp_qer_table_get();
    fp_qer_entry *qer_entry = NULL;
    comm_msg_qer_ie_data *ie_data = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ie_data = (comm_msg_qer_ie_data *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t tmp_index = ntohl(ie_data[cnt].index);

        LOG(FASTPASS, RUNNING, "add qer entry %u to table.", tmp_index);
        /* Check index */
        if (tmp_index >= qer_head->entry_max) {
            LOG(FASTPASS, ERR, "The qer entry index overflow,"
                " entry num: %u.", tmp_index);
            continue;
        }

        if (G_SUCCESS != Res_AllocTarget(qer_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "The qer entry is existing,"
                " entry num: %u.", tmp_index);
            continue;
        }

        qer_entry = fp_qer_entry_get(tmp_index);

        ros_rwlock_write_lock(&qer_entry->qos_lock); /* lock */

        /* copy config */
        fp_msg_qer_copy(&qer_entry->qer_cfg, &ie_data[cnt].cfg);

        /* make config effective */
        fp_qer_launch(qer_entry);

        /* enable entry */
        qer_entry->valid = G_TRUE;

        ros_rwlock_write_unlock(&qer_entry->qos_lock); /* unlock */
    }
#endif

    return EN_COMM_ERRNO_OK;
}

static uint32_t fp_msg_qer_del_proc(uint32_t index)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    fp_qer_table            *qer_head = fp_qer_table_get();
    fp_qer_entry            *qer_entry;

    /* Check index */
    if (index >= qer_head->entry_max) {
        ret = EN_COMM_ERRNO_ITEM_NUM_OVERFLOW;
        return ret;
    }

    /* Check alloc status */
    if (!Res_IsAlloced(qer_head->res_no, 0, index)) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    qer_entry = fp_qer_entry_get(index);
    ros_rwlock_write_lock(&qer_entry->qos_lock); /* lock */
    qer_entry->valid = G_FALSE;
    ros_rwlock_write_unlock(&qer_entry->qos_lock); /* unlock */

    /* Free res */
    Res_Free(qer_head->res_no, 0, index);

    return ret;
}

uint32_t fp_msg_qer_del(comm_msg_ie_t *ie)
{
    uint32_t *index = NULL, cnt = 0;
    uint32_t ret = EN_COMM_ERRNO_OK;
    comm_msg_rules_ie_t *entry_ie = (comm_msg_rules_ie_t *)ie;

    index = (uint32_t *)entry_ie->data;

    LOG(FASTPASS, RUNNING, "del qer entry number %u.", entry_ie->rules_num);

    for (cnt = 0; cnt < entry_ie->rules_num; ++cnt) {
        ret = fp_msg_qer_del_proc(ntohl(index[cnt]));
    }

    return ret;
}

uint32_t fp_msg_qer_mod(comm_msg_ie_t *ie)
{
    uint32_t cnt = 0;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    fp_qer_table *qer_head = fp_qer_table_get();
    fp_qer_entry *qer_entry = NULL;
    comm_msg_qer_ie_data *ie_data = NULL;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ie_data = (comm_msg_qer_ie_data *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t tmp_index = ntohl(ie_data[cnt].index);

        LOG(FASTPASS, RUNNING, "modify qer entry %u.", tmp_index);
        /* Check index */
        if (tmp_index >= qer_head->entry_max) {
            LOG(FASTPASS, ERR, "modify entry index: %u overflow.", tmp_index);
            continue;
        }

        /* Check alloc status */
        if (!Res_IsAlloced(qer_head->res_no, 0, tmp_index)) {
            LOG(FASTPASS, ERR, "modify entry index: %u invaild.", tmp_index);
            continue;
        }

        qer_entry = fp_qer_entry_get(tmp_index);

        ros_rwlock_write_lock(&qer_entry->qos_lock); /* lock */

        /* copy entry config */
        fp_msg_qer_copy(&qer_entry->qer_cfg, &ie_data[cnt].cfg);

        /* make config effective */
        fp_qer_launch(qer_entry);

        ros_rwlock_write_unlock(&qer_entry->qos_lock); /* unlock */
    }

    return EN_COMM_ERRNO_OK;
}

uint32_t fp_msg_qer_sum()
{
    fp_qer_table        *qer_head;
    uint32_t            sum_num;

    qer_head = fp_qer_table_get();
    sum_num  = Res_GetAlloced(qer_head->res_no);

    LOG(FASTPASS, RUNNING, "GET total qer entry number %d.", sum_num);

    return sum_num;
}

uint32_t fp_msg_qer_get(void)
{
    uint32_t entry_num = 0;
    int32_t cur_index = -1;
    fp_qer_entry *qer_entry = NULL;
    fp_qer_table *qer_head = fp_qer_table_get();
    comm_msg_qer_ie_data *ie_data = NULL;
    comm_msg_header_t *msg;
    comm_msg_rules_ie_t *ie = NULL;
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len = 0;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_qer_ie_data);

    msg = fp_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd   = htons(EN_COMM_MSG_UPU_QER_GET);
    ie_data   = (comm_msg_qer_ie_data *)ie->data;
    entry_num = 0;

    cur_index = Res_GetAvailableInBand(qer_head->res_no, cur_index + 1, qer_head->entry_max);
    while (-1 != cur_index) {
        qer_entry = fp_qer_entry_get(cur_index);
        if (!qer_entry->valid) {
            LOG(FASTPASS, ERR, "The qer entry %u is alloced, but invalid.", cur_index);
            cur_index = Res_GetAvailableInBand(qer_head->res_no, cur_index + 1, qer_head->entry_max);
            continue;
        }
        ie_data[entry_num].index = htonl(qer_entry->index);
        ros_rwlock_write_lock(&qer_entry->qos_lock); /* lock */
        fp_msg_qer_copy(&ie_data[entry_num].cfg, &qer_entry->qer_cfg);
        ros_rwlock_write_unlock(&qer_entry->qos_lock); /* unlock */
        ++entry_num;

        if (entry_num >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_qer_ie_data) * entry_num;
            ie->rules_num = htonl(entry_num);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > fp_msg_send((char *)buf, buf_len)) {
                LOG(UPC, ERR, "Send msg to spu failed.");
            }
            entry_num = 0;
        }

        cur_index = Res_GetAvailableInBand(qer_head->res_no, cur_index + 1, qer_head->entry_max);
    }

    if (entry_num > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_qer_ie_data) * entry_num;
        ie->rules_num = htonl(entry_num);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > fp_msg_send((char *)buf, buf_len)) {
            LOG(UPC, ERR, "Send msg to spu failed.");
        }
        entry_num = 0;
    }

    return EN_COMM_ERRNO_OK;
}

uint32_t fp_msg_qer_clr()
{
    return EN_COMM_ERRNO_UNSUPPORTED;
}

static uint32_t fp_msg_qer_prss(comm_msg_ie_t *ie)
{
    fp_qer_table        *qer_head = fp_qer_table_get();
    fp_qer_entry        *qer_entry = NULL;
    comm_msg_qer_prss_t *ie_data = NULL;
    comm_msg_qer_prss_t *resp_data = NULL;
    comm_msg_header_t   *msg;
    comm_msg_ie_t       *resp_ie = NULL;
    uint32_t            qer_index;
    uint8_t             buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t            buf_len = 0;

    if (NULL == ie) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p).", ie);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    qer_index = ie->index;
    ie_data = (comm_msg_qer_prss_t *)ie->data;

    LOG(FASTPASS, RUNNING, "Get qer %u packet rate status surplus.", qer_index);
    /* Check index */
    if (qer_index >= qer_head->entry_max) {
        LOG(FASTPASS, ERR, "entry index: %u overflow.", qer_index);
        return EN_COMM_ERRNO_ITEM_NUM_OVERFLOW;
    }

    /* Check alloc status */
    if (!Res_IsAlloced(qer_head->res_no, 0, qer_index)) {
        LOG(FASTPASS, ERR, "entry index: %u invaild.", qer_index);
        return EN_COMM_ERRNO_NO_SUCH_ITEM;
    }

    qer_entry = fp_qer_entry_get(qer_index);

    msg = fp_fill_msg_header(buf);
    resp_ie = COMM_MSG_GET_IE(msg);
    resp_ie->cmd = htons(EN_COMM_MSG_UPU_QER_PRS);
    resp_ie->index = htonl(ie->index);
    resp_data = (comm_msg_qer_prss_t *)resp_ie->data;

    resp_data->up_seid = ie_data->up_seid;
    resp_data->cp_seid = ie_data->cp_seid;
    resp_data->seq_num = ie_data->seq_num;
    resp_data->msg_type = ie_data->msg_type;
    resp_data->node_index = ie_data->node_index;

    ros_rwlock_read_lock(&qer_entry->qos_lock); /* lock */
    if (ros_getime() > qer_entry->ul_meter.valid_cycle) {
        resp_data->validity_time = 0;
    } else {
        resp_data->validity_time = htonl(qer_entry->ul_meter.valid_cycle);
    }
    resp_data->ul_pkts = htons((uint16_t)ros_atomic32_read(&qer_entry->ul_meter.pkt_num));
    resp_data->dl_pkts = htons((uint16_t)ros_atomic32_read(&qer_entry->dl_meter.pkt_num));
    resp_data->s.f_dp = qer_entry->qer_cfg.flag.s.f_dp;
    resp_data->s.f_up = qer_entry->qer_cfg.flag.s.f_up;
    ros_rwlock_read_unlock(&qer_entry->qos_lock); /* unlock */

    buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_qer_prss_t);
    resp_ie->len = htons(buf_len);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    if (0 > fp_msg_send((char *)buf, buf_len)) {
        LOG(FASTPASS, ERR, "Send msg to spu failed.");
        return EN_COMM_ERRNO_SEND_MSG_ERROR;
    }

    return EN_COMM_ERRNO_OK;
}

uint32_t fp_msg_qer_show(struct cli_def *cli,uint32_t qer_num)
{
    fp_qer_entry            *qer_entry;
    fp_qer_table            *qer_head;
    qer_head = fp_qer_table_get();

    /* Check index */
    if (qer_num >= qer_head->entry_max) {
        cli_print(cli,"  entry error!\n"
               "  beyond entry max, should be less than %d\n",
               qer_head->entry_max);
        return -1;
    }
    qer_entry = fp_qer_entry_get(qer_num);
    if (qer_entry->valid) {
        cli_print(cli,"index        %d\n",qer_entry->index);
        cli_print(cli,"ul_mbr       %d\n",qer_entry->qer_cfg.ul_mbr);
        cli_print(cli,"ul_gbr       %d\n",qer_entry->qer_cfg.ul_gbr);
        cli_print(cli,"ul_pkt_max   %d\n",qer_entry->qer_cfg.ul_pkt_max);
        cli_print(cli,"dl_mbr       %d\n",qer_entry->qer_cfg.dl_mbr);
        cli_print(cli,"dl_gbr       %d\n",qer_entry->qer_cfg.dl_gbr);
        cli_print(cli,"dl_pkt_max   %d\n",qer_entry->qer_cfg.dl_pkt_max);
        cli_print(cli,"valid_time   %d\n",qer_entry->qer_cfg.valid_time);
        cli_print(cli,"ul_gate      %d\n",qer_entry->qer_cfg.ul_gate);
        cli_print(cli,"dl_gate      %d\n",qer_entry->qer_cfg.dl_gate);
        cli_print(cli,"ext_len      %d\n",qer_entry->qer_cfg.gtpu_ext.ext_len);
    } else {
        cli_print(cli,"  not find qer table\n");
        return -1;
    }
    return 0;
}

static uint32_t fp_msg_dns_add(comm_msg_ie_t *ie)
{
    uint32_t cnt = 0;
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    fp_dns_table *tbl = fp_dns_table_get_public();
    uint32_t *ie_data = NULL;

    if (NULL == ie || NULL == tbl) {
        LOG(FASTPASS, ERR, "parameter is invalid, ie(%p), dns_table(%p).",
            ie, tbl);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ie_data = (uint32_t *)rule_ie->data;

    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        ie_data[cnt] = ntohl(ie_data[cnt]);
    }

    return fp_dns_update2sp(ie_data, rule_ie->rules_num);
}

uint32_t fp_msg_dns_del(comm_msg_ie_t *ie)
{
    uint32_t *index = NULL, cnt = 0;
    uint32_t ret = EN_COMM_ERRNO_OK;
    comm_msg_rules_ie_t *entry_ie = (comm_msg_rules_ie_t *)ie;

    index = (uint32_t *)entry_ie->data;

    LOG(FASTPASS, RUNNING, "del dns entry number %u.", entry_ie->rules_num);

    for (cnt = 0; cnt < entry_ie->rules_num; ++cnt) {
        ret = fp_dns_table_del(ntohl(index[cnt]));
    }

    return ret;
}


uint32_t fp_msg_dns_sum()
{
    fp_dns_table       *head;
    uint32_t            sum_num;

    head = fp_dns_table_get_public();
    if (NULL == head) {
        return 0;
    }

    sum_num = Res_GetAlloced(head->res_no);

    LOG(FASTPASS, RUNNING, "GET total dns entry number %d.", sum_num);

    return sum_num;
}

uint32_t fp_msg_dns_get(void)
{
    uint32_t entry_num = 0;
    int32_t cur_index = -1;
    fp_dns_cache_node *dns_entry = NULL;
    fp_dns_table *dns_head = fp_dns_table_get_public();
    comm_msg_dns_ie_data *ie_data = NULL;
    comm_msg_header_t *msg;
    comm_msg_rules_ie_t *ie = NULL;
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t buf_len = 0;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_dns_ie_data);

    msg = fp_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd  = htons(EN_COMM_MSG_UPU_DNS_GET);
    ie_data  = (comm_msg_dns_ie_data *)ie->data;
    entry_num = 0;

    cur_index = Res_GetAvailableInBand(dns_head->res_no, cur_index + 1, dns_head->entry_max);
    while (-1 != cur_index) {
        dns_entry = fp_dns_node_get_public(cur_index);

        ie_data[entry_num].index = htonl(dns_entry->index);
        ros_memcpy(&ie_data[entry_num].cfg, &dns_entry->dns_cfg,
            sizeof(comm_msg_dns_config));
        fp_dns_config_hton(&ie_data[entry_num].cfg);
        ++entry_num;

        if (entry_num >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_dns_ie_data) * entry_num;
            ie->rules_num = htonl(entry_num);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > fp_msg_send((char *)buf, buf_len)) {
                LOG(UPC, ERR, "Send msg to spu failed.");
            }
            entry_num = 0;
        }

        cur_index = Res_GetAvailableInBand(dns_head->res_no, cur_index + 1, dns_head->entry_max);
    }

    if (entry_num > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_dns_ie_data) * entry_num;
        ie->rules_num = htonl(entry_num);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > fp_msg_send((char *)buf, buf_len)) {
            LOG(UPC, ERR, "Send msg to spu failed.");
        }
        entry_num = 0;
    }

    return EN_COMM_ERRNO_OK;
}


uint32_t fp_msg_dns_clr()
{
    return EN_COMM_ERRNO_UNSUPPORTED;
}

uint32_t fp_msg_dns_show(struct cli_def *cli,uint32_t index)
{
    fp_dns_cache_node *dns_entry;
    fp_dns_table *dns_head = fp_dns_table_get_public();
    uint32_t cnt;

    /* Check index */
    if (index >= dns_head->entry_max) {
        cli_print(cli,"  entry error!\n"
               "  beyond entry max, should be less than %d\n",
               dns_head->entry_max);
        return -1;
    }
    if (G_FALSE == Res_IsAlloced(dns_head->res_no, 0, index)) {
        cli_print(cli,"  not find dns table\n");
        return -1;
    }
    dns_entry = fp_dns_node_get_public(index);

    cli_print(cli,"index    : %d\n",dns_entry->index);
    cli_print(cli,"name     : %s\n",dns_entry->dns_cfg.name);
    cli_print(cli,"expire   : %u\n",dns_entry->dns_cfg.expire);
    for (cnt = 0; cnt < dns_entry->dns_cfg.ipaddr_num; ++cnt) {
        if (dns_entry->dns_cfg.ipaddr[cnt].ip_ver == EN_DNS_IPV4) {
            cli_print(cli,"IPv4 : 0x%08x\n",
                dns_entry->dns_cfg.ipaddr[cnt].ip.ipv4);
        } else {
            cli_print(cli,"IPv6 : 0x%08x %08x %08x %08x\n",
                *(uint32_t *)&dns_entry->dns_cfg.ipaddr[cnt].ip.ipv6[0],
                *(uint32_t *)&dns_entry->dns_cfg.ipaddr[cnt].ip.ipv6[4],
                *(uint32_t *)&dns_entry->dns_cfg.ipaddr[cnt].ip.ipv6[8],
                *(uint32_t *)&dns_entry->dns_cfg.ipaddr[cnt].ip.ipv6[12]);
        }
    }

    return 0;
}

static uint32_t fp_msg_collect_status()
{
    comm_msg_fpu_stat   *stat;
    comm_msg_header_t   *msg;
    comm_msg_ie_t       *ie;
    uint8_t             buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t            buf_len;

    msg = fp_fill_msg_header(buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd     = htons(EN_COMM_MSG_COLLECT_STATUS);
    ie->index   = htonl(0);
    stat        = (comm_msg_fpu_stat *)ie->data;

    ros_memset(stat, 0, sizeof(comm_msg_fpu_stat));
    fp_collect_status(stat);

    buf_len     = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_fpu_stat);
    ie->len     = htons(buf_len);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    if (0 > fp_msg_send((char *)buf, buf_len)) {
        LOG(FASTPASS, ERR, "Send msg to spu failed.");
        return EN_COMM_ERRNO_SEND_MSG_ERROR;
    }

    return EN_COMM_ERRNO_OK;
}

static inline void fp_msg_resp(comm_msg_ie_t *ie, uint32_t ret)
{
    comm_msg_header_t *msg;
    comm_msg_resp_ie_t  *resp_ie;
    uint8_t             buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t            buf_len;

    msg = fp_fill_msg_header(buf);
    resp_ie = COMM_MSG_GET_RESP_IE(msg);

    resp_ie->cmd   = htons(ie->cmd);
    resp_ie->index = htonl(ie->index);
    resp_ie->ret   = htonl(ret);
    resp_ie->flag_key = htonll(fp_be_get_flag_key());

    buf_len = COMM_MSG_IE_LEN_RESP;
    resp_ie->len   = htons(buf_len);
    buf_len += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    fp_msg_send((char *)buf, buf_len);
}

static inline uint32_t fp_msg_sigtrace_set(comm_msg_ie_t *ie)
{
    comm_msg_sigtrace_ie_t  *sigtrace_ie = (comm_msg_sigtrace_ie_t *)ie;
    char cmdstr[256];

    if (fpu_sig_trace_ueip.ueip != 0) {
        sprintf(cmdstr, "rm %s", COMM_SIGNALING_TRACE_FILE_NAME);
        ros_system(cmdstr);
    }

    fpu_sig_trace_ueip.ueip = ntohl(sigtrace_ie->ueip);
    LOG(FASTPASS, RUNNING, "set sig trace, ueip %x.", fpu_sig_trace_ueip.ueip);

    return EN_COMM_ERRNO_OK;
}

uint32_t fp_msg_proc(void *trans_mng, comm_msg_ie_t *ie)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    //int fd = (uint64_t)trans_mng;

    switch(ie->cmd)
    {
        case EN_COMM_MSG_UPU_ENTR_ADD:
            break;

        case EN_COMM_MSG_UPU_ENTR_DEL:
            ret = fp_msg_entry_del(ie);
            break;

        case EN_COMM_MSG_UPU_ENTR_INS:
            break;

        case EN_COMM_MSG_UPU_ENTR_REM:
            break;

        case EN_COMM_MSG_UPU_ENTR_MOD:
            ret = fp_msg_entry_mod(ie);
            break;

        case EN_COMM_MSG_UPU_ENTR_GET:
            ret = fp_msg_entry_get(ie);
            break;

        case EN_COMM_MSG_UPU_ENTR_SUM:
            ret = fp_msg_entry_sum(ie);
            fp_msg_resp(ie, ret);
            break;

        case EN_COMM_MSG_UPU_ENTR_CLR:
            ret = fp_msg_entry_clr(ie);
            break;

        case EN_COMM_MSG_UPU_CHNL_SET_MOD:
            break;

        case EN_COMM_MSG_UPU_QER_ADD:
            ret = fp_msg_qer_add(ie);
            break;

        case EN_COMM_MSG_UPU_QER_DEL:
            ret = fp_msg_qer_del(ie);
            break;

        case EN_COMM_MSG_UPU_QER_MOD:
            ret = fp_msg_qer_mod(ie);
            break;

        case EN_COMM_MSG_UPU_QER_GET:
            ret = fp_msg_qer_get();
            break;

        case EN_COMM_MSG_UPU_QER_SUM:
            ret = fp_msg_qer_sum();
            fp_msg_resp(ie, ret);
            break;

        case EN_COMM_MSG_UPU_QER_CLR:
            ret = fp_msg_qer_clr();
            break;

        case EN_COMM_MSG_UPU_QER_VAL:
            {
                fp_qer_table *qer_head = fp_qer_table_get();

                ret = fp_msg_rules_val(qer_head->res_no, EN_COMM_MSG_UPU_QER_VAL, qer_head->entry_max);
            }
            break;

        case EN_COMM_MSG_UPU_QER_PRS:
            ret = fp_msg_qer_prss(ie);
            break;

        case EN_COMM_MSG_UPU_INST_ADD:
            ret = fp_msg_inst_add(ie);
            break;

        case EN_COMM_MSG_UPU_INST_DEL:
            ret = fp_msg_inst_del(ie);
            break;

        case EN_COMM_MSG_UPU_INST_INS:
            ret = fp_msg_inst_ins(ie);
            break;

        case EN_COMM_MSG_UPU_INST_MOD:
            ret = fp_msg_inst_mod(ie);
            break;

        case EN_COMM_MSG_UPU_INST_GET:
            ret = fp_msg_inst_get();
            break;

        case EN_COMM_MSG_UPU_INST_SUM:
            ret = fp_msg_inst_sum();
            fp_msg_resp(ie, ret);
            break;

        case EN_COMM_MSG_UPU_INST_CLR:
            ret = fp_msg_inst_clr();
            break;

        case EN_COMM_MSG_UPU_INST_VALIDITY:
            {
                fp_inst_table *inst_head = fp_inst_table_get();

                ret = fp_msg_rules_val(inst_head->res_no, EN_COMM_MSG_UPU_INST_VALIDITY, inst_head->entry_max);
            }
            break;

        case EN_COMM_MSG_UPU_INST_LIGHT:
            ret = fp_msg_inst_light_mod(ie);
            break;

		case EN_COMM_MSG_UPU_INST_THRES:
            ret = fp_msg_inst_thres_mod(ie);
            break;

        case EN_COMM_MSG_UPU_FAR_ADD:
            ret = fp_msg_far_add(ie);
            break;

        case EN_COMM_MSG_UPU_FAR_DEL:
            ret = fp_msg_far_del(ie);
            break;

        case EN_COMM_MSG_UPU_FAR_MOD:
            ret = fp_msg_far_mod(ie);
            break;

        case EN_COMM_MSG_UPU_FAR_GET:
            ret = fp_msg_far_get();
            break;

        case EN_COMM_MSG_UPU_FAR_SUM:
            ret = fp_msg_far_sum();
            fp_msg_resp(ie, ret);
            break;

        case EN_COMM_MSG_UPU_FAR_CLR:
            ret = fp_msg_far_clr();
            break;

        case EN_COMM_MSG_UPU_FAR_VAL:
            {
                fp_far_table *far_head = fp_far_table_get();

                ret = fp_msg_rules_val(far_head->res_no, EN_COMM_MSG_UPU_FAR_VAL, far_head->entry_max);
            }
            break;

        case EN_COMM_MSG_UPU_BAR_ADD:
            ret = fp_msg_bar_add(ie);
            break;

        case EN_COMM_MSG_UPU_BAR_DEL:
            ret = fp_msg_bar_del(ie);
            break;

        case EN_COMM_MSG_UPU_BAR_MOD:
            ret = fp_msg_bar_mod(ie);
            break;

        case EN_COMM_MSG_UPU_BAR_GET:
            ret = fp_msg_bar_get();
            break;

        case EN_COMM_MSG_UPU_BAR_SUM:
            ret = fp_msg_bar_sum();
            fp_msg_resp(ie, ret);
            break;

        case EN_COMM_MSG_UPU_BAR_CLR:
            ret = fp_msg_bar_clr();
            break;

        case EN_COMM_MSG_UPU_BAR_VAL:
            {
                fp_bar_table *bar_head = fp_bar_table_get();

                ret = fp_msg_rules_val(bar_head->res_no, EN_COMM_MSG_UPU_BAR_VAL, bar_head->entry_max);
            }
            break;

        case EN_COMM_MSG_UPU_DNS_ADD:
            ret = fp_msg_dns_add(ie);
            break;

        case EN_COMM_MSG_UPU_DNS_DEL:
            ret = fp_msg_dns_del(ie);
            break;

        case EN_COMM_MSG_UPU_DNS_GET:
            ret = fp_msg_dns_get();
            break;

        case EN_COMM_MSG_UPU_DNS_SUM:
            ret = fp_msg_dns_sum();
            fp_msg_resp(ie, ret);
            break;

        case EN_COMM_MSG_UPU_DNS_CLR:
            ret = fp_msg_dns_clr();
            break;

        case EN_COMM_MSG_UPU_DNS_VAL:
            {
                fp_dns_table *dns_head = fp_dns_table_get_public();

                ret = fp_msg_rules_val(dns_head->res_no, EN_COMM_MSG_UPU_DNS_VAL, dns_head->entry_max);
            }
            break;

        case EN_COMM_MSG_UPU_SIGTRACE_SET:
            ret = fp_msg_sigtrace_set(ie);
            break;

        case EN_COMM_MSG_COLLECT_STATUS:
            ret = fp_msg_collect_status();
            break;

        case EN_COMM_MSG_BACKEND_HB:
            fp_be_reset_hb_cnt_public();
            break;

        case EN_COMM_MSG_BACKEND_CONFIG:
            fp_start_proc_reset();
            ret = fp_start_proc_config(ie);
            fp_be_active();
            fp_start_proc_start();
            break;

        case EN_COMM_MSG_BACKEND_SHUTDOWN:
            kill(getpid(), SIGINT);
            break;

        case EN_COMM_MSG_BACKEND_RE_REGIS:
            {
                fp_backend_config *be_cfg = fp_be_get_config_public();

                be_cfg->flag_key = ros_rdtsc() ^ (uint64_t)rand();
            }
            break;

        case EN_COMM_MSG_BACKEND_RESET_LBMAC:
            {
                comm_msg_heartbeat_config *hb_fg = (comm_msg_heartbeat_config *)ie->data;
                fp_backend_config *be_cfg = fp_be_get_config_public();

                memcpy((void *)be_cfg->loadbalancer_mac, (void *)hb_fg->mac, EN_PORT_BUTT * ETH_ALEN);
            }
            break;

        default:
            LOG(FASTPASS, ERR, "Unknown ie cmd 0x%04x.", ie->cmd);
            break;
    }

    return ret;
}

int fp_msg_send(char *buf, uint32_t len)
{
    return comm_msg_channel_client_send(fp_be_get_channel_cli(), buf, len);
}

inline void *fp_fast_entry_get(fp_fast_table *head, uint32_t index)
{
    return (void *)((uint8_t *)head->entry + (index<<FP_CACHE_LINE_BIT));
}

inline void *fp_fast_shadow_get(fp_fast_table *head, uint32_t index)
{
    return &(head->shadow[index]);
}

inline fp_inst_entry *fp_inst_entry_get(uint32_t index)
{
    fp_inst_table *head = fp_inst_table_get();
    if (index >= head->entry_max) {
        return NULL;
    }

    return &(head->entry[index]);
}

inline fp_far_entry *fp_far_entry_get(uint32_t index)
{
    fp_far_table *head = fp_far_table_get();
    if (index >= head->entry_max) {
        return NULL;
    }

    return &(head->entry[index]);
}

inline fp_bar_entry *fp_bar_entry_get(uint32_t index)
{
    fp_bar_table *head = fp_bar_table_get();
    if (index >= head->entry_max) {
        return NULL;
    }

    return &(head->entry[index]);
}

inline fp_qer_entry *fp_qer_entry_get(uint32_t index)
{
    fp_qer_table *head = fp_qer_table_get();
    if (index >= head->entry_max) {
        return NULL;
    }

    return &(head->entry[index]);
}

fp_fast_entry *
fp_fast_table_add(fp_fast_table *head, fp_fast_entry *entry,
    uint32_t hash_key, uint32_t aux_info)
{
    fp_fast_entry  *entry_tmp;
    fp_fast_bucket *bucket;

    LOG(FASTPASS, RUNNING,
        "add fast entry %d to hash %x tree!", entry->index, hash_key);

    bucket = &(head->bucket[hash_key & head->bucket_mask]);

    LOG(FASTPASS, RUNNING, "hash value %x, aux value %x, bucket %p, tree %p.",
        (hash_key & head->bucket_mask), aux_info, bucket, bucket->hash_tree);

    ros_rwlock_write_lock(&bucket->rwlock);

    /* Check if item exist in table */
    entry_tmp = (fp_fast_entry *)avluint_search(bucket->hash_tree, aux_info);
    if (entry_tmp) {

        ros_rwlock_write_unlock(&bucket->rwlock);
        return NULL;
    }

    entry->aux_info = aux_info;
    if (OK != avluint_insert(&bucket->hash_tree, (AVLU_NODE *)entry)){

        ros_rwlock_write_unlock(&bucket->rwlock);
        return NULL;
    }
    ros_rwlock_write_unlock(&bucket->rwlock);

    return entry;
}

static uint32_t fp_fast_table_del(fp_fast_table *head, uint32_t entry_no,
    uint32_t aux_info)
{
    fp_fast_entry           *entry;
    fp_fast_shadow          *shadow;
    fp_fast_bucket          *bucket;
    AVLU_NODE               *node;
    comm_msg_fast_cfg       *entry_cfg;
    fp_fast_table           *tmphead;

    LOG(FASTPASS, RUNNING, "entry_no %d!", entry_no);
    if (entry_no >= head->entry_max)
    {
        LOG(FASTPASS, ERR, "entry_no(%d) overflow!", entry_no);
        goto err;
    }

    shadow = &(head->shadow[entry_no]);
    entry  = fp_fast_entry_get(head, entry_no);
    entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);

    /* Check out inst queue */
    fp_fast_link_del(entry_cfg->inst_index, shadow);

    ros_rwlock_write_lock(&shadow->rwlock);
    tmphead = shadow->head;
    bucket  = &(tmphead->bucket[(shadow->key & tmphead->bucket_mask)]);

    LOG(FASTPASS, RUNNING, "tree %p, bucket %p, aux value %x.",
        bucket->hash_tree, bucket, aux_info);

    node = (AVLU_NODE *)avluint_delete(&bucket->hash_tree, aux_info);
    if (unlikely(!node))
    {
        ros_rwlock_write_unlock(&shadow->rwlock);
        LOG(FASTPASS, ERR, "del node from tree failed.");
        return EN_COMM_ERRNO_OTHER_ERROR;
    }
    entry->valid = G_FALSE;

    ros_rwlock_write_unlock(&shadow->rwlock);

    Res_Free(head->res_no, 0, entry_no);

err:
    return EN_COMM_ERRNO_OK;
}

fp_fast_entry *fp_fast_table_test(uint32_t hash_key, uint32_t aux_info)
{
    fp_fast_entry *entry;
    fp_fast_table *fast_head = (fp_fast_table *)fp_fast_table_get(COMM_MSG_FAST_IPV4);

    /* Alloc a entry in local */
    entry = fp_fast_alloc(fast_head);
    if (unlikely(!entry)) {
        LOG(FASTPASS, RUNNING, "alloc fast entry failed(head %p)!", fast_head);
        return NULL;
    }
    else {
        comm_msg_fast_cfg *entry_cfg;
        fp_fast_shadow *shadow;

        /* enqueue */
        shadow = fp_fast_shadow_get(fast_head, entry->index);
        shadow->head = fast_head;
        shadow->key  = hash_key;

        /* Set entry number to 1(in default) */
        entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);

        /* Set tmp flag */
        entry_cfg->temp_flag  = G_TRUE;
        entry_cfg->inst_index = COMM_MSG_ORPHAN_NUMBER;

        /* Put in hash tree */
        if (NULL == fp_fast_table_add(fast_head, entry, hash_key, aux_info))
        {
            LOG(FASTPASS, RUNNING,
                "put fast entry %d in tree %p IPV4 pool failed!",
                entry->index, fast_head);
            fp_fast_free(fast_head, entry->index);

            return NULL;
        }
        shadow->entry = entry;

        fp_fast_link_add(COMM_MSG_ORPHAN_NUMBER, shadow);
    }

    return entry;
}


uint32_t fp_fast_link_add(uint32_t inst_index, fp_fast_shadow *shadow)
{
    fp_inst_table           *inst_head;
    fp_inst_entry           *inst_entry;

    /* get inst entry */
    inst_head  = fp_inst_table_get();
    if (inst_index >= inst_head->entry_max) {
        LOG(FASTPASS, ERR,
            "add fast entry %d to inst %d list, but inst_index failed!",
            shadow->index, inst_index);

        /* Don't check other action bit */
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    inst_entry = fp_inst_entry_get(inst_index);
    if ((!inst_entry)||(!(inst_entry->valid))) {
        LOG(FASTPASS, ERR,
            "add fast entry %d to inst %d list, but get inst entry failed!",
            shadow->index, inst_index);

        /* Don't check other action bit */
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ros_rwlock_write_lock(&inst_entry->lstlock);
    lstAdd(&inst_entry->lstfast, (NODE *)shadow);
    ros_rwlock_write_unlock(&inst_entry->lstlock);

    LOG(FASTPASS, RUNNING, "add fast entry %d to inst %d list success.",
        shadow->index, inst_index);

    return EN_COMM_ERRNO_OK;
}

static uint32_t fp_fast_link_del(uint32_t inst_index, fp_fast_shadow *shadow)
{
    fp_inst_entry           *inst_entry;

    LOG(FASTPASS, RUNNING, "index %d!", inst_index);

    /* get inst entry */
    inst_entry = fp_inst_entry_get(inst_index);
    if (!inst_entry) {
        LOG(FASTPASS, ERR,
            "del fast entry %d from inst %d list, but get inst entry failed!",
            shadow->index, inst_index);

        /* Don't check other action bit */
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    ros_rwlock_write_lock(&inst_entry->lstlock);
    lstDelete(&inst_entry->lstfast, (NODE *)shadow);
    ros_rwlock_write_unlock(&inst_entry->lstlock);

    LOG(FASTPASS, RUNNING, "del fast entry %d from inst %d list success.",
        shadow->index, inst_index);

    return EN_COMM_ERRNO_OK;
}

static uint32_t fp_fast_send_buff_pkt(fp_fast_shadow *shadow)
{
    fp_cblk_entry       *cblk;
    fp_fast_entry       *entry;
    uint32_t            handle_count = 0;
    int                 trace_flag = G_FALSE;
    fp_packet_info      pkt_info;
    struct packet_desc  desc;
    uint8_t             *field_ofs = pkt_info.match_key.field_offset;

    entry = fp_fast_entry_get(shadow->head, shadow->index);
    if ((!entry)||(!entry->valid)) {
        LOG(FASTPASS, ERR,
            "get fast entry %d error!", shadow->index);
        fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    /* Flush shadow queue */
    ros_rwlock_write_lock(&shadow->rwlock);
    cblk = (fp_cblk_entry *)lstGet(&(shadow->list));
    ros_rwlock_write_unlock(&shadow->rwlock);

    LOG(FASTPASS, RUNNING,
        "get fast entry %d blk list, first is %p!", shadow->index, cblk);

    while (cblk) {
        /* for nic, need transfer block to wqe. do nothing on dpdk version */
#ifdef ENABLE_OCTEON_III
        fp_transfer_tmp_buf(cblk);
#endif

#ifdef RECORD_FAST_INFO_NEW_VER

#ifdef CONFIG_FP_DPDK_PORT
        pkt_buf_set_len(cblk->buf, pkt_buf_data_len(cblk->buf) - RECORD_FAST_INFO_LEN);
#endif
        cblk->len -= RECORD_FAST_INFO_LEN;

#endif

        pkt_info.arg = cblk->buf;
        pkt_info.buf = cblk->pkt;
        pkt_info.len = cblk->len;
        desc.buf = cblk->pkt;
        desc.len = cblk->len;
        desc.offset = 0;

        LOG(FASTPASS, RUNNING,
            "handle buf %p, pkt %p, len %d, cblk(%p) index %d, port %d!",
            cblk->buf, cblk->pkt, cblk->len, cblk, cblk->index, cblk->port);

        /* send out by action */
        if (unlikely(packet_dissect(&desc, &pkt_info.match_key) < 0)) {
            LOG(FASTPASS, ERR, "packet dissect failed!");
#ifdef CONFIG_FP_DPDK_PORT
            cblk->port = EN_PORT_BUTT; /* Let the applicant release */
            fp_dpdk_add_cblk_buf(cblk);
#else
            /* free buffer */
            fp_free_pkt(cblk->buf);
            cblk->buf = NULL;
            fp_cblk_free(cblk);
#endif
            fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
            return -1;
        }

        if (likely(0 == FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_ETHERNET_DL))) {
            /* Ethernet II should be >= 1536(0x0600) */

            if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV4))) {
                struct pro_ipv4_hdr *ip_hdr = FlowGetL1Ipv4Header(&pkt_info.match_key);

                /* ipv4 package */
                switch (cblk->port) {
                    case EN_PORT_N6:
                        switch (cblk->port) {
                            case IP_PRO_UDP:
                            case IP_PRO_TCP:
                            case IP_PRO_SCTP:
                                trace_flag = fp_check_signal_trace(ip_hdr->source, ip_hdr->dest,
                                    ((struct tp_port *)(ip_hdr + 1))->source,
                                    ((struct tp_port *)(ip_hdr + 1))->dest, ip_hdr->protocol);
                                break;

                            default:
                                trace_flag = fp_check_signal_trace(ip_hdr->source, ip_hdr->dest,
                                    0, 0, ip_hdr->protocol);
                                break;
                        }

                        fp_pkt_match_n6_ipv4(&pkt_info, shadow->head,
                            entry, cblk, trace_flag);

                        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N6 buff packet process success.");
                        break;

                    default:
                        /* N3 and N4 */
                        switch (FlowGetL2IpVersion(&pkt_info.match_key)) {
                            case 4:
                                {
                                    struct pro_ipv4_hdr *l2_hdr = FlowGetL2Ipv4Header(&pkt_info.match_key);

                                    switch (cblk->port) {
                                        case IP_PRO_UDP:
                                        case IP_PRO_TCP:
                                        case IP_PRO_SCTP:
                                            trace_flag = fp_check_signal_trace(l2_hdr->source, l2_hdr->dest,
                                                ((struct tp_port *)(l2_hdr + 1))->source,
                                                ((struct tp_port *)(l2_hdr + 1))->dest, l2_hdr->protocol);
                                            break;

                                        default:
                                            trace_flag = fp_check_signal_trace(l2_hdr->source, l2_hdr->dest,
                                                0, 0, l2_hdr->protocol);
                                            break;
                                    }

                                    fp_pkt_match_n3_ipv4(&pkt_info, shadow->head,
                                        entry, cblk, trace_flag);

                                    LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 buff packet process success.");
                                }
                                break;

                            case 6:
                                {
                                    //struct pro_ipv6_hdr *ipv6_l2 = FlowGetL2Ipv6Header(&pkt_info.match_key);

                                    fp_pkt_match_l1v4_l2v6(&pkt_info, shadow->head,
                                        entry, cblk, trace_flag, cblk->port);

                                    LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 buff packet process success.");
                                }
                                break;

                            default:
#ifdef ETHERNET_SIMPLE_PROC
                                fp_pkt_match_n3_eth_and_nonip(&pkt_info, shadow->head, entry, cblk, trace_flag);
#else
                                if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_ETHERNET_LLC)) {
                                    /* Ethernet 802.3 */
                                    LOG(FASTPASS, RUNNING, "N3 Ethernet 802.3 packet process success.");
                                    fp_pkt_match_n3_eth(&pkt_info, shadow->head, entry, cblk, trace_flag);
                                } else {
                                    /* Non-IP */
                                    LOG(FASTPASS, DEBUG, "N3 Non-IP packet process success.");
                                    fp_pkt_match_n3_nonip(&pkt_info, shadow->head, entry, cblk, trace_flag);
                                }
#endif
                                break;
#if 0
#ifdef CONFIG_FP_DPDK_PORT
                                cblk->port = EN_PORT_BUTT; /* Let the applicant release */
                                fp_dpdk_add_cblk_buf(cblk);
#else
                                /* free buffer */
                                fp_free_pkt(cblk->buf);
                                cblk->buf = NULL;
                                fp_cblk_free(cblk);
#endif
                                fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

                                LOG(FASTPASS, ERR, "Unsupported packet, unable to get inner header!\r\n");
                                LOG(FASTPASS, ERR, "l1_hdr->src:%08x, l1_hdr->dst: %08x.",
                                    l1_hdr->source, l1_hdr->dest);
                                LOG(FASTPASS, ERR, "udp_hdr->src:%d, udp_hdr->dst: %d.",
                                    udp_hdr->source, udp_hdr->dest);
                                LOG(FASTPASS, ERR, "gtp_hdr->msg_type:%d, gtp_hdr->length:%d, gtp_hdr->teid:%u.",
                                    gtp_hdr->msg_type, gtp_hdr->length, gtp_hdr->teid);
                                break;
#endif
                        }
                        break;
                }
            }
            else if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_IPV6)) {
                switch (cblk->port) {
                    case EN_PORT_N6:
                        fp_pkt_match_n6_ipv6(&pkt_info, shadow->head,
                            entry, cblk, trace_flag);

                        LOG(FASTPASS, RUNNING, "N6 buff ipv6 packet process success.");
                        break;

                    default:
                        {
                            switch (FlowGetL2IpVersion(&pkt_info.match_key)) {
                                case 4:
                                    {
                                        struct pro_ipv4_hdr *l2_hdr = FlowGetL2Ipv4Header(&pkt_info.match_key);

                                        switch (cblk->port) {
                                            case IP_PRO_UDP:
                                            case IP_PRO_TCP:
                                            case IP_PRO_SCTP:
                                                trace_flag = fp_check_signal_trace(l2_hdr->source, l2_hdr->dest,
                                                    ((struct tp_port *)(l2_hdr + 1))->source,
                                                    ((struct tp_port *)(l2_hdr + 1))->dest, l2_hdr->protocol);
                                                break;

                                            default:
                                                trace_flag = fp_check_signal_trace(l2_hdr->source, l2_hdr->dest,
                                                    0, 0, l2_hdr->protocol);
                                                break;
                                        }

                                        fp_pkt_match_n3_ipv4(&pkt_info, shadow->head,
                                            entry, cblk, trace_flag);

                                        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 buff packet process success.");
                                    }
                                    break;

                                case 6:
                                    {
                                        //struct pro_ipv6_hdr *ipv6_l2 = FlowGetL2Ipv6Header(&pkt_info.match_key);

                                        fp_pkt_match_n3_ipv6(&pkt_info, shadow->head,
                                            entry, cblk, trace_flag, cblk->port);

                                        LOG(FASTPASS, RUNNING, "N3 buff packet process success.");
                                    }
                                    break;

                                default:
#ifdef ETHERNET_SIMPLE_PROC
                                    fp_pkt_match_n3_eth_and_nonip(&pkt_info, shadow->head, entry, cblk, trace_flag);
#else
                                    if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_ETHERNET_LLC)) {
                                        /* Ethernet 802.3 */
                                        LOG(FASTPASS, RUNNING, "N3 Ethernet 802.3 packet process success.");
                                        fp_pkt_match_n3_eth(&pkt_info, shadow->head, entry, cblk, trace_flag);
                                    } else {
                                        /* Non-IP */
                                        LOG(FASTPASS, DEBUG, "N3 Non-IP packet process success.");
                                        fp_pkt_match_n3_nonip(&pkt_info, shadow->head, entry, cblk, trace_flag);
                                    }
#endif
                                    break;
#if 0
#ifdef CONFIG_FP_DPDK_PORT
                                    cblk->port = EN_PORT_BUTT; /* Let the applicant release */
                                    fp_dpdk_add_cblk_buf(cblk);
#else
                                    /* free buffer */
                                    fp_free_pkt(cblk->buf);
                                    cblk->buf = NULL;
                                    fp_cblk_free(cblk);
#endif
                                    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

                                    LOG(FASTPASS, ERR, "Unsupported packet, unable to get inner header!\r\n");
                                    LOG(FASTPASS, ERR, "l1_hdr->src:%08x, l1_hdr->dst: %08x.",
                                        l1_hdr->source, l1_hdr->dest);
                                    LOG(FASTPASS, ERR, "udp_hdr->src:%d, udp_hdr->dst: %d.",
                                        udp_hdr->source, udp_hdr->dest);
                                    LOG(FASTPASS, ERR, "gtp_hdr->msg_type:%d, gtp_hdr->length:%d, gtp_hdr->teid:%u.",
                                        gtp_hdr->msg_type, gtp_hdr->length, gtp_hdr->teid);
                                    break;
#endif
                            }
                        }
                        break;
                }
            } else {
                LOG(FASTPASS, ERR,"buff or nocp pkt is not a ipv4 or ipv6  packet!");
                /* if fail, free cblk or mbuf */
#ifdef CONFIG_FP_DPDK_PORT
                cblk->port = EN_PORT_BUTT; /* Let the applicant release */
                fp_dpdk_add_cblk_buf(cblk);
#else
                /* free buffer */
                fp_free_pkt(cblk->buf);
                cblk->buf = NULL;
                fp_cblk_free(cblk);
#endif
                fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
            }

        }
        else {
            /* 802.3 should be <= 1500 */

            fp_pkt_match_n6_eth(&pkt_info, shadow->head, entry, cblk, trace_flag);
        }

        handle_count++;

        /* get next packet */
        ros_rwlock_write_lock(&shadow->rwlock);
        cblk = (fp_cblk_entry *)lstGet(&(shadow->list));
        ros_rwlock_write_unlock(&shadow->rwlock);
    }

    /* Set list to null */
    ros_rwlock_write_lock(&shadow->rwlock);
    lstInit(&shadow->list);
    ros_rwlock_write_unlock(&shadow->rwlock);
    LOG(FASTPASS, RUNNING, "handler fast entry %d buffered pkts(%d)!",
        shadow->index, handle_count);

    return EN_COMM_ERRNO_OK;
}

static uint32_t fp_fast_free_buff_chain(fp_fast_shadow *shadow)
{
    fp_cblk_entry       *cblk;
    fp_fast_entry       *entry;
    uint32_t            handle_count = 0;

    entry = fp_fast_entry_get(shadow->head, shadow->index);
    if ((!entry)||(!entry->valid)) {
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    /* Flush shadow queue */
    ros_rwlock_write_lock(&shadow->rwlock);
    cblk = (fp_cblk_entry *)lstGet(&(shadow->list));
    ros_rwlock_write_unlock(&shadow->rwlock);
    while (cblk) {

        LOG(FASTPASS, RUNNING,
            "free buf %p, pkt %p, len %d, cblk(%p) index %d!",
            cblk->buf, cblk->pkt, cblk->len, cblk, cblk->index);

        /* Block will be free in fp_cblk_free */
#ifdef CONFIG_FP_DPDK_PORT
        cblk->port = EN_PORT_BUTT; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
#else
        /* free buffer */
        fp_free_pkt(cblk->buf);
        cblk->buf = NULL;
        fp_cblk_free(cblk);
#endif

        /* We will consider that every cblk is full in this case */
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);

        handle_count++;

        /* get next packet */
        ros_rwlock_write_lock(&shadow->rwlock);
        cblk = (fp_cblk_entry *)lstGet(&(shadow->list));
        ros_rwlock_write_unlock(&shadow->rwlock);
    }

    /* Set list to null */
    ros_rwlock_write_lock(&shadow->rwlock);
    lstInit(&shadow->list);
    ros_rwlock_write_unlock(&shadow->rwlock);

    LOG(FASTPASS, RUNNING,
        "free fast entry %d buffered pkts(%d)!",
        shadow->index, handle_count);

    return EN_COMM_ERRNO_OK;
}

fp_fast_entry *fp_fast_alloc(fp_fast_table *head)
{
    fp_fast_entry  *entry;
    uint64_t       ret64;
    uint32_t       key = 0, index;

    if (!head) {
        return NULL;
    }

    ret64 = Res_Alloc(head->res_no, &key, &index, EN_RES_ALLOC_MODE_OC);
    if (ret64 != G_SUCCESS) {
        return NULL;
    }
    entry = fp_fast_entry_get(head, index);
    entry->index = index;
    entry->valid = G_TRUE;
    entry->count = 0;
    entry->tcp_seg_mgmt = NULL;

    return entry;
}

uint32_t fp_fast_free(fp_fast_table *head, uint32_t index)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    fp_fast_entry           *entry;
    fp_fast_shadow          *shadow;
    fp_cblk_entry           *cblk;

    if (!head) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    /* Check index */
    if (index >= head->entry_max) {
        ret = EN_COMM_ERRNO_ITEM_NUM_OVERFLOW;
        return ret;
    }

    /* Get entry */
    entry = fp_fast_entry_get(head, index);
    if (!entry->valid) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    if(entry->tcp_seg_mgmt)
        fp_tcp_segment_free(&entry->tcp_seg_mgmt);

    /* Remove it from hash tree */
    fp_fast_table_del(head, entry->index, entry->aux_info);

    entry->valid = G_FALSE;

    /* Check alloc status */
    if (Res_IsAlloced(head->res_no, 0, index)) {
        Res_Free(head->res_no, 0, index);
    }

    /* Flush shadow queue */
    shadow = &(head->shadow[index]);
    ros_rwlock_write_lock(&shadow->rwlock);
    cblk = (fp_cblk_entry *)lstGet(&(shadow->list));
    while (cblk) {

        /* Block will be free in fp_cblk_free */
#ifdef CONFIG_FP_DPDK_PORT
        cblk->port = EN_PORT_BUTT; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
#else
        /* free buffer */
        fp_free_pkt(cblk->buf);
        cblk->buf = NULL;
        fp_cblk_free(cblk);
#endif

        /* We will consider that every cblk is full in this case */
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);

        /* Get next */
        cblk = (fp_cblk_entry *)lstGet(&(shadow->list));
    }
    lstInit(&shadow->list);
    ros_rwlock_write_unlock(&shadow->rwlock);

    LOG(FASTPASS, RUNNING, "rem entry %d from tree.", entry->index);

    return ret;
}

uint32_t fp_fast_clear(uint32_t type)
{
    uint32_t ret = EN_COMM_ERRNO_OK;
    uint32_t index, bucket_no, bucket_num;
    fp_fast_entry           *entry;
    fp_fast_table           *head;
    fp_fast_shadow          *shadow;
    fp_cblk_entry           *cblk;
    comm_msg_fast_cfg       *entry_cfg;

    LOG(FASTPASS, RUNNING,
        "clr table(type %d).", type);

    head = fp_fast_table_get(type);
    if (!head) {
        ret = EN_COMM_ERRNO_NO_SUCH_ITEM;
        return ret;
    }

    /* Clear bucket */
    bucket_num = head->bucket_mask + 1;
    for (bucket_no = 0; bucket_no < bucket_num; bucket_no++) {
        ros_rwlock_write_lock(&head->bucket[bucket_no].rwlock);
        head->bucket[bucket_no].hash_tree = NULL;
        head->bucket[bucket_no].node_count = 0;
        ros_rwlock_write_unlock(&head->bucket[bucket_no].rwlock);
    }

    /* Clear entry */
    for (index = 0; index < head->entry_max; index++) {
        if (G_FALSE == Res_IsAlloced(head->res_no, 0, index)) {
            continue;
        }

        /* Reset fast entry */
        entry = fp_fast_entry_get(head, index);
        entry->valid = G_FALSE;

        /* Get shadow */
        shadow = fp_fast_shadow_get(head, index);

        if (entry->tcp_seg_mgmt) {
            fp_tcp_segment_free(&entry->tcp_seg_mgmt);
        }
        /* Release buffered packets */
        ros_rwlock_write_lock(&shadow->rwlock);
        cblk = (fp_cblk_entry *)lstGet(&(shadow->list));
        while (cblk) {

            /* Block will be free in fp_cblk_free */
#ifdef CONFIG_FP_DPDK_PORT
            cblk->port = EN_PORT_BUTT; /* Let the applicant release */
            fp_dpdk_add_cblk_buf(cblk);
#else
            /* free buffer */
            fp_free_pkt(cblk->buf);
            cblk->buf = NULL;
            fp_cblk_free(cblk);
#endif

            /* We will consider that every cblk is full in this case */
            fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

            /* Get next */
            cblk = (fp_cblk_entry *)lstGet(&(shadow->list));
        }
        ros_rwlock_write_unlock(&shadow->rwlock);
        entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);

        /* Check out inst queue */
        fp_fast_link_del(entry_cfg->inst_index, shadow);

        /* Reset shadow entry */
        lstInit(&shadow->list);

        /* Release resource */
        Res_Free(head->res_no, 0, index);
    }

    return ret;
}

void fp_get_action_str(uint8_t action_val, char *action_str)
{
    comm_msg_far_action_t action;

    action_str[0] = 0;
    action.value = action_val;

    if (action.d.drop) {
        strcat(action_str, "drop ");
    }
    if (action.d.forw) {
        strcat(action_str, "forw ");
    }
    if (action.d.buff) {
        strcat(action_str, "buff ");
    }
    if (action.d.nocp) {
        strcat(action_str, "nocp ");
    }
    if (action.d.dupl) {
        strcat(action_str, "dupl ");
    }
}

static uint32_t fp_msg_inst_param_check(comm_msg_inst_config *inst_config)
{
    uint32_t            far_index;
    uint32_t            qer_index;
    uint32_t            index;
    uint32_t            ret = EN_COMM_ERRNO_OK;
    fp_far_entry        *far_entry;
    fp_qer_entry        *qer_entry;

    if (inst_config->choose.d.flag_far1) {
        far_index = ntohl(inst_config->far_index1);
        far_entry = fp_far_entry_get(far_index);
        if ((!far_entry)||(!far_entry->valid)) {
            LOG(FASTPASS, ERR, "far entry(%d) invalid.", far_index);
            ret = EN_COMM_ERRNO_PARAM_INVALID;
            return ret;
        }
    }
    if (inst_config->choose.d.flag_far2) {
        far_index = ntohl(inst_config->far_index2);
        far_entry = fp_far_entry_get(far_index);
        if ((!far_entry)||(!far_entry->valid)) {
            LOG(FASTPASS, ERR, "far entry(%d) invalid.", far_index);
            ret = EN_COMM_ERRNO_PARAM_INVALID;
            return ret;
        }
    }

    for (index = 0; index < inst_config->qer_number; index++) {
        qer_index = ntohl(inst_config->qer_index[index]);
        qer_entry = fp_qer_entry_get(qer_index);
        if ((!qer_entry)||(!qer_entry->valid)) {
            LOG(FASTPASS, ERR, "qer entry(%d) invalid.", qer_index);
            ret = EN_COMM_ERRNO_PARAM_INVALID;
            return ret;
        }
    }

    return ret;
}

void fp_msg_fast_copy(comm_msg_fast_cfg *entry_cfg,
    comm_msg_fast_cfg *input_cfg)
{
    /* copy mac */
    ros_memcpy(entry_cfg->dst_mac, input_cfg->dst_mac, 6);

    /* copy PDR SI */
    entry_cfg->pdr_si = input_cfg->pdr_si;

    /* copy inst index */
    entry_cfg->inst_index = ntohl(input_cfg->inst_index);

    /* copy temp flag */
    entry_cfg->temp_flag = input_cfg->temp_flag;

    /* copy far index */
    entry_cfg->far_index = ntohl(input_cfg->far_index);

	if((entry_cfg->head_enrich_flag >> 31) == 0)
		entry_cfg->head_enrich_flag = (ntohl(input_cfg->head_enrich_flag)) & 0x7fffffff;

    return;
}

static void fp_msg_inst_copy(comm_msg_inst_config *dst, comm_msg_inst_config *src)
{
    uint32_t index;

    /* Copy content */
    dst->choose.value = src->choose.value;

    dst->rm_outh.type = src->rm_outh.type;
    dst->rm_outh.flag = src->rm_outh.flag;

    dst->far_index1 = ntohl(src->far_index1);
    dst->far_index2 = ntohl(src->far_index2);

    dst->urr_number = src->urr_number;
    dst->qer_number = src->qer_number;

    for (index = 0; index < dst->urr_number; index++) {
        dst->urr_index[index] = ntohl(src->urr_index[index]);
    }

    for (index = 0; index < dst->qer_number; index++) {
        dst->qer_index[index] = ntohl(src->qer_index[index]);
    }
    dst->inact = src->inact;
    dst->max_act = src->max_act;
    dst->immediately_act = src->immediately_act;

    if (dst->choose.d.flag_ueip_type == 0) {
	    dst->ueip.ipv4 = ntohl(src->ueip.ipv4);
    } else {
        ros_memcpy(dst->ueip.ipv6, src->ueip.ipv6, IPV6_ALEN);
    }

	ros_memcpy(&(dst->user_info),&(src->user_info),sizeof(comm_msg_user_info_t));
	for (index = 0; index < MAX_UE_IP_NUM; ++index) {
        if (dst->user_info.ue_ipaddr[index].ueip_flag.d.v4) {
		    dst->user_info.ue_ipaddr[index].ipv4_addr =
                ntohl(dst->user_info.ue_ipaddr[index].ipv4_addr);
        }
    }
	dst->user_info.rat_type.enterprise_id = ntohs(dst->user_info.rat_type.enterprise_id);
	dst->user_info.user_local_info.enterprise_id =
        ntohs(dst->user_info.user_local_info.enterprise_id);
	dst->collect_thres = ntohll(src->collect_thres);
}

static void fp_msg_far_copy(comm_msg_far_config *dst, comm_msg_far_config *src)
{
    comm_msg_far_config     *entry_far, *input_far;
#ifdef FAR_DUPL_ENABLE
    comm_msg_dupl_config    *entry_dupl, *input_dupl;
    uint32_t                dupl_loop, dupl_max;
#endif

    input_far = src;
    entry_far = dst;

    entry_far->far_id = htonl(input_far->far_id);

    entry_far->action.value = input_far->action.value;
    entry_far->forw_if      = input_far->forw_if;
    entry_far->choose.value = htons(input_far->choose.value);

    /* Don't change byte order */
    ros_memcpy(&entry_far->forw_redirect, &input_far->forw_redirect, sizeof(session_redirect_server));
    switch (entry_far->choose.d.flag_redirect) {
        case 1:
            entry_far->forw_redirect.ipv4_addr = htonl(entry_far->forw_redirect.ipv4_addr);
            break;

        case 5:
            entry_far->forw_redirect.v4_v6.ipv4 = htonl(entry_far->forw_redirect.v4_v6.ipv4);
            break;
    }

    entry_far->forw_trans.tos  = input_far->forw_trans.tos;
    entry_far->forw_trans.mask = input_far->forw_trans.mask;

    entry_far->forw_cr_outh.type.value =
        htons(input_far->forw_cr_outh.type.value);
    entry_far->forw_cr_outh.port = htons(input_far->forw_cr_outh.port);
    entry_far->forw_cr_outh.teid = htonl(input_far->forw_cr_outh.teid);
    entry_far->forw_cr_outh.ipv4 = htonl(input_far->forw_cr_outh.ipv4);
    ros_memcpy(entry_far->forw_cr_outh.ipv6.s6_addr,
        input_far->forw_cr_outh.ipv6.s6_addr, IPV6_ALEN);
    entry_far->forw_cr_outh.ctag.vlan_flag.value = input_far->forw_cr_outh.ctag.vlan_flag.value;
    entry_far->forw_cr_outh.ctag.vlan_value.data =
        htons(input_far->forw_cr_outh.ctag.vlan_value.data);
    entry_far->forw_cr_outh.stag.vlan_flag.value = input_far->forw_cr_outh.stag.vlan_flag.value;
    entry_far->forw_cr_outh.stag.vlan_value.data =
        htons(input_far->forw_cr_outh.stag.vlan_value.data);

    entry_far->bar_index = htonl(input_far->bar_index);

#ifdef FAR_DUPL_ENABLE
    if (MAX_DUPL_PARAM_NUM <= entry_far->choose.d.section_dupl_num) {
        LOG(FASTPASS, ERR,
            "far(%d) duplication parameter number(%d) over max(%d), keep first %d.",
            entry_far->far_id, entry_far->choose.d.section_dupl_num,
            MAX_DUPL_PARAM_NUM, MAX_DUPL_PARAM_NUM);
        dupl_max = MAX_DUPL_PARAM_NUM;
        entry_far->choose.d.section_dupl_num = dupl_max;
    }
    else {
        dupl_max = entry_far->choose.d.section_dupl_num;
    }

    for (dupl_loop = 0; dupl_loop < dupl_max; dupl_loop++) {

        entry_dupl = &(entry_far->dupl_cfg[dupl_loop]);
        input_dupl = &(input_far->dupl_cfg[dupl_loop]);

        entry_dupl->dupl_if    = input_dupl->dupl_if;
        entry_dupl->trans.tos  = input_dupl->trans.tos;
        entry_dupl->trans.mask = input_dupl->trans.mask;

        entry_dupl->cr_outh.type.value =
            htons(input_dupl->cr_outh.type.value);
        entry_dupl->cr_outh.port = htons(input_dupl->cr_outh.port);
        entry_dupl->cr_outh.teid = htonl(input_dupl->cr_outh.teid);
        entry_dupl->cr_outh.ipv4 = htonl(input_dupl->cr_outh.ipv4);
        ros_memcpy(entry_dupl->cr_outh.ipv6.s6_addr,
            input_dupl->cr_outh.ipv6.s6_addr, IPV6_ALEN);
        entry_dupl->cr_outh.ctag.vlan_flag.value = input_dupl->cr_outh.ctag.vlan_flag.value;
        entry_dupl->cr_outh.ctag.vlan_value.data =
            htons(input_dupl->cr_outh.ctag.vlan_value.data);
        entry_dupl->cr_outh.stag.vlan_flag.value = input_dupl->cr_outh.stag.vlan_flag.value;
        entry_dupl->cr_outh.stag.vlan_value.data =
            htons(input_dupl->cr_outh.stag.vlan_value.data);
    }
#endif

    entry_far->forw_enrich.name_length = ntohs(input_far->forw_enrich.name_length);
    if (entry_far->forw_enrich.name_length) {
        ros_memcpy(entry_far->forw_enrich.name, input_far->forw_enrich.name,
            entry_far->forw_enrich.name_length);
    }

    entry_far->forw_enrich.value_length = ntohs(input_far->forw_enrich.value_length);
    if (entry_far->forw_enrich.value_length) {
        ros_memcpy(entry_far->forw_enrich.value, input_far->forw_enrich.value,
            entry_far->forw_enrich.value_length);
    }
    return;
}

void fp_msg_copy_volume(comm_msg_urr_volume_t *dst, comm_msg_urr_volume_t *src)
{
    dst->flag       = src->flag;
    dst->downlink   = src->downlink;
    dst->total      = src->total;
    dst->uplink     = src->uplink;
    ros_memcpy(dst->resv, src->resv, 7);
}

static void fp_msg_bar_copy(comm_msg_bar_config *dst, comm_msg_bar_config *src)
{
    dst->notify_delay = src->notify_delay;
    dst->bar_id   = src->bar_id;
    dst->time_max = htonl(src->time_max);
    dst->pkts_max = htons(src->pkts_max);

    return;
}

void fp_msg_urr_copy(comm_msg_urr_config *dst, comm_msg_urr_config *src)
{
    return;
}

static void fp_msg_qer_copy(comm_msg_qer_config *dst, comm_msg_qer_config *src)
{
    dst->flag.data  = src->flag.data;
    dst->ul_mbr     = ntohll(src->ul_mbr);
    dst->ul_gbr     = ntohll(src->ul_gbr);
    dst->ul_pkt_max = ntohl(src->ul_pkt_max);

    dst->dl_mbr     = ntohll(src->dl_mbr);
    dst->dl_gbr     = ntohll(src->dl_gbr);
    dst->dl_pkt_max = ntohl(src->dl_pkt_max);

    dst->valid_time = ntohl(src->valid_time);

    dst->ul_gate    = src->ul_gate;
    dst->dl_gate    = src->dl_gate;

    dst->gtpu_ext.ext_len = src->gtpu_ext.ext_len;
    memcpy(dst->gtpu_ext.content.data, src->gtpu_ext.content.data,
        sizeof(src->gtpu_ext.content.data));

    LOG(FASTPASS, RUNNING, "ul_gate: %d, dl_gate: %d.", dst->ul_gate, dst->dl_gate);
    LOG(FASTPASS, RUNNING, "ul_mbr: %lu, ul_gbr: %lu, ul_pkt_max: %u.",
        dst->ul_mbr, dst->ul_gbr, dst->ul_pkt_max);
    LOG(FASTPASS, RUNNING, "dl_mbr: %lu, dl_gbr: %lu, dl_pkt_max: %u.",
        dst->dl_mbr, dst->dl_gbr, dst->dl_pkt_max);
    LOG(FASTPASS, RUNNING, "valid_time: %u.", dst->valid_time);
    LOG(FASTPASS, RUNNING, "ext_len: %u, data: %02x, %02x, %02x, %02x.",
        dst->gtpu_ext.ext_len,
        dst->gtpu_ext.content.data[0],
        dst->gtpu_ext.content.data[1],
        dst->gtpu_ext.content.data[2],
        dst->gtpu_ext.content.data[3]);

    dst->qer_id = ntohl(src->qer_id);
    dst->ul_flag = src->ul_flag;
    dst->dl_flag = src->dl_flag;

    return;
}

int fp_write_wireshark(char *buf, int len)
{
    FILE*fp;
    int ret = 0;
    struct pcap_pkthdr pcap;
    struct timeval tv;

    gettimeofday(&tv,NULL);
    pcap.caplen = len;
    pcap.len = len;
    pcap.sec = (uint32_t)tv.tv_sec;
    pcap.usec = (uint32_t)tv.tv_usec;

    if (access(COMM_SIGNALING_TRACE_FILE_NAME, F_OK) != 0) {
        write_wireshark_head(COMM_SIGNALING_TRACE_FILE_NAME);
        pcap.sec = (uint32_t)tv.tv_sec;
    }

    if((fp=fopen(COMM_SIGNALING_TRACE_FILE_NAME, "a+"))==NULL) {
        LOG(FASTPASS, ERR, "fopen error");
        return -1;
    }

    ret = fwrite((char *)&pcap, sizeof(pcap), 1, fp);
    if(ret < 0)
    {
        LOG(FASTPASS, ERR, "fwrite error, ret %d", ret);
        fclose(fp);
        return -1;
    }

    ret = fwrite(buf, len, 1, fp);
    if(ret < 0)
    {
        LOG(FASTPASS, ERR, "fwrite error, ret %d", ret);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    return 0;
}

