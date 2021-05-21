/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session.h"
#include "session_instance.h"
#include "session_msg.h"
#include "session_mgmt.h"
#include "far_mgmt.h"
#include "bar_mgmt.h"
#include "urr_mgmt.h"
#include "qer_mgmt.h"
#include "mar_mgmt.h"
#include "sp_backend_mgmt.h"
#include "session_audit.h"
#include "local_parse.h"
#include "urr_proc.h"

struct session_inst_cb sess_instance_cb;
struct fsm_audit session_inst_audit_4am;
struct fsm_audit session_inst_audit_simple;

void session_instance_config_show(comm_msg_inst_config *inst_config)
{
    uint32_t cnt = 0;

    LOG(SESSION, RUNNING, "immediately_act:  %d", inst_config->immediately_act);
    LOG(SESSION, RUNNING, "choose value:  %d",
        inst_config->choose.value);
    LOG(SESSION, RUNNING, "rm_outh type:  %d",
        inst_config->rm_outh.type);
    LOG(SESSION, RUNNING, "rm_outh flag:  %d",
        inst_config->rm_outh.flag);
    LOG(SESSION, RUNNING, "far index1:  %u", inst_config->far_index1);
    LOG(SESSION, RUNNING, "far index2:  %u", inst_config->far_index2);
    LOG(SESSION, RUNNING, "urr number:  %u", inst_config->urr_number);
    for (cnt = 0; cnt < inst_config->urr_number; ++cnt) {
        LOG(SESSION, RUNNING, "urr index:  %u",
            inst_config->urr_index[cnt]);
    }

    LOG(SESSION, RUNNING, "qer number:  %u", inst_config->qer_number);
    for (cnt = 0; cnt < inst_config->qer_number; ++cnt) {
        LOG(SESSION, RUNNING, "qer index:  %u",
            inst_config->qer_index[cnt]);
    }
    LOG(SESSION, RUNNING, "inact:  %u", inst_config->inact);
    LOG(SESSION, RUNNING, "max act:  %u", inst_config->max_act);
}

inline uint32_t session_instance_max(void)
{
    return sess_instance_cb.max_inst_num;
}

struct session_inst_entry *session_instance_get_entry(uint32_t entry_num)
{
    if (entry_num < sess_instance_cb.max_inst_num)
        return &sess_instance_cb.inst_entry[entry_num];
    else
        return NULL;
}

inline struct session_inst_cb *session_instance_get_table(void)
{
    return &sess_instance_cb;
}

inline struct fsm_audit *session_instance_audit_simple(void)
{
    return &session_inst_audit_simple;
}

inline struct fsm_audit *session_instance_audit_4am(void)
{
    return &session_inst_audit_4am;
}

struct session_inst_entry *session_instance_get_orphan(void)
{
    return &sess_instance_cb.inst_entry[COMM_MSG_ORPHAN_NUMBER];
}

inline void session_instance_config_hton(comm_msg_inst_config *inst_config)
{
    uint8_t cnt = 0;

    inst_config->far_index1 = htonl(inst_config->far_index1);
    inst_config->far_index2 = htonl(inst_config->far_index2);
    for (cnt = 0; cnt < inst_config->urr_number; ++cnt) {
        inst_config->urr_index[cnt] = htonl(inst_config->urr_index[cnt]);
    }
    for (cnt = 0; cnt < inst_config->qer_number; ++cnt) {
        inst_config->qer_index[cnt] = htonl(inst_config->qer_index[cnt]);
    }
    if (inst_config->choose.d.flag_ueip_type == 0) {
        inst_config->ueip.ipv4 = htonl(inst_config->ueip.ipv4);
    }

    for (cnt = 0; cnt < inst_config->urr_number; ++cnt) {
        if (inst_config->user_info.ue_ipaddr[cnt].ueip_flag.d.v4) {
    		inst_config->user_info.ue_ipaddr[cnt].ipv4_addr =
                htonl(inst_config->user_info.ue_ipaddr[cnt].ipv4_addr);
        }
	}

    inst_config->collect_thres = htonll(inst_config->collect_thres);
}

inline void session_instance_config_ntoh(comm_msg_inst_config *inst_config)
{
    uint8_t cnt;

    inst_config->far_index1 = ntohl(inst_config->far_index1);
    inst_config->far_index2 = ntohl(inst_config->far_index2);
    for (cnt = 0; cnt < inst_config->urr_number; ++cnt) {
        inst_config->urr_index[cnt] = ntohl(inst_config->urr_index[cnt]);
    }
    for (cnt = 0; cnt < inst_config->qer_number; ++cnt) {
        inst_config->qer_index[cnt] = ntohl(inst_config->qer_index[cnt]);
    }
    if (inst_config->choose.d.flag_ueip_type == 0) {
        inst_config->ueip.ipv4 = ntohl(inst_config->ueip.ipv4);
    }

    for (cnt = 0; cnt < inst_config->urr_number; ++cnt) {
        if (inst_config->user_info.ue_ipaddr[cnt].ueip_flag.d.v4) {
    		inst_config->user_info.ue_ipaddr[cnt].ipv4_addr =
                ntohl(inst_config->user_info.ue_ipaddr[cnt].ipv4_addr);
        }
	}

    inst_config->collect_thres = ntohll(inst_config->collect_thres);
}

int session_instance_fill_far(struct session_t *sess,
    struct pdr_table *pdr_tbl, comm_msg_inst_config *inst_config)
{
    if ((NULL == sess) || (NULL == pdr_tbl) || (NULL == inst_config)) {
        LOG(SESSION, ERR,
            "parameter is invalid, sess(%p), pdr_tbl(%p), inst_config(%p).",
            sess, pdr_tbl, inst_config);
        return -1;
    }

    if (pdr_tbl->pdr.far_present) {

        inst_config->choose.d.flag_far1 = 1;
        inst_config->choose.d.flag_far2 = 0;
        inst_config->far_index1 = pdr_tbl->pdr_pri.far_index;
        LOG(SESSION, RUNNING, "Fill far index success.");
    } else if (pdr_tbl->pdr.mar_present) {
        if (0 > mar_fill_far_index(sess, pdr_tbl->pdr_pri.mar_index,
            inst_config)) {
            LOG(SESSION, ERR, "Fill far index failed.");
            return -1;
        }
        LOG(SESSION, RUNNING, "Fill the MAR's FAR index success.");
    }

    return 0;
}

int session_instance_fill_urr(struct session_t *sess, uint8_t urr_number,
    uint32_t *urr_array, comm_msg_inst_config *inst_config, struct session_inst_control *inst_ctrl)
{
    uint8_t cnt = 0;
    struct urr_table *urr_tbl = NULL;
    uint32_t inact_time = 0, thr_quo_time = 0;
	uint64_t min_thres = -1;

    if ((NULL == sess) || (NULL == inst_config)) {
        LOG(SESSION, ERR, "parameter is invalid, sess: 0x%p,"
            " far_id: %u, inst_config: 0x%p.", sess, urr_number, inst_config);
        return -1;
    }

    inst_config->urr_number = urr_number;
    for (cnt = 0; cnt < urr_number; ++cnt) {
        urr_tbl = urr_table_search(sess, urr_array[cnt]);
        if (NULL == urr_tbl) {
            LOG(SESSION, ERR, "far table search failed, urr_id %u.",
                urr_array[cnt]);
            return -1;
        }

		/* Take the minimum threshold of all URRS */
		if (urr_tbl->urr.vol_thres.flag.d.dlvol) {
			if (min_thres > urr_tbl->urr.vol_thres.downlink)
				min_thres = urr_tbl->urr.vol_thres.downlink;
		}
		if (urr_tbl->urr.vol_thres.flag.d.ulvol) {
			if (min_thres > urr_tbl->urr.vol_thres.uplink)
				min_thres = urr_tbl->urr.vol_thres.uplink;
		}
		if (urr_tbl->urr.vol_thres.flag.d.tovol) {
			if (min_thres > urr_tbl->urr.vol_thres.total)
				min_thres = urr_tbl->urr.vol_thres.total;
		}

        inst_config->choose.d.flag_urr = 1;
        inst_config->urr_index[cnt] = urr_tbl->index;

        inact_time = inact_time < urr_tbl->urr.inact_detect ? urr_tbl->urr.inact_detect : inact_time;

        if (urr_tbl->urr.tim_quota > urr_tbl->urr.tim_thres) {
            thr_quo_time = thr_quo_time < urr_tbl->urr.tim_quota ? urr_tbl->urr.tim_quota : thr_quo_time;
        } else {
            thr_quo_time = thr_quo_time < urr_tbl->urr.tim_thres ? urr_tbl->urr.tim_thres : thr_quo_time;
        }
        inst_config->immediately_act = urr_tbl->urr.measu_info.d.istm ? 1 : inst_config->immediately_act;

        /* Classification according to pre-and post-qos */
        if (urr_tbl->urr.measu_info.d.mbqe) {
            inst_ctrl->urr_bqos[inst_ctrl->urr_bnum] = urr_tbl->index;
            inst_ctrl->urr_bnum++;
        } else {
            inst_ctrl->urr_aqos[inst_ctrl->urr_anum] = urr_tbl->index;
            inst_ctrl->urr_anum++;
        }

        inst_ctrl->urr_drop[inst_ctrl->urr_dnum] = urr_tbl->index;
        inst_ctrl->urr_dnum++;
    }

    inst_config->inact = inact_time + 1; /* One more judgment is used to trigger */
    inst_config->max_act = thr_quo_time + 1; /* One more judgment is used to trigger */
    inst_ctrl->light = COMM_MSG_LIGHT_GREEN;

	/*没有门限不进行精确上报
	精确上报一秒最多200次，触发条件最小为500字节*/
	if (-1 == min_thres) {
		inst_config->collect_thres = -1;
	}
	else {
		inst_config->collect_thres = min_thres/2;
	}

    return 0;
}

int session_instance_fill_qer(struct session_t *sess, uint8_t qer_number,
    uint32_t *qer_array, comm_msg_inst_config *inst_config)
{
    uint8_t cnt = 0;
    struct qer_table *qer_tbl = NULL;

    if ((NULL == sess) || (NULL == inst_config)) {
        LOG(SESSION, ERR, "parameter is invalid, sess: 0x%p,"
            " far_id: %u, inst_config: 0x%p.", sess, qer_number, inst_config);
        return -1;
    }


    inst_config->qer_number = qer_number;
    for (cnt = 0; cnt < qer_number; ++cnt) {
        qer_tbl = qer_table_search(sess, qer_array[cnt]);
        if (NULL == qer_tbl) {
            LOG(SESSION, ERR, "far table search failed, qer_id %u.",
                qer_array[cnt]);
            return -1;
        }

        inst_config->choose.d.flag_qer = 1;
        inst_config->qer_index[cnt] = qer_tbl->index;
    }

    return 0;
}

int session_instance_fill_user_info(struct session_t *sess, struct pdr_table *pdr_tbl,
	comm_msg_inst_config *inst_config)
{
	uint8_t i=0;

	if ((NULL == sess) || (NULL == inst_config)) {
		LOG(SESSION, ERR, "parameter is invalid, sess: 0x%p,"
			"inst_config: 0x%p.", sess, inst_config);
		return -1;
	}

	ros_memcpy(&inst_config->user_info.user_id,&sess->session.user_id,sizeof(session_user_id));
	for(i=0;i<MAX_UE_IP_NUM;i++)
	{
		ros_memcpy(&(inst_config->user_info.ue_ipaddr[i]),
					&(pdr_tbl->pdr.pdi_content.ue_ipaddr[i].ueip),sizeof(session_ue_ip));
	}
	ros_memcpy(&inst_config->user_info.apn_dnn, &sess->session.apn_dnn,
        sizeof(session_apn_dnn));
	inst_config->user_info.rat_type = sess->session.rat_type;

	return 0;
}

int session_instance_fp_add_or_mod(uint32_t *index_arr, uint32_t index_num, uint8_t is_add, int fd)
{
    uint8_t                     buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                    buf_len = 0;
    comm_msg_header_t           *msg;
    comm_msg_rules_ie_t         *ie = NULL;
    struct session_inst_entry   *entry = NULL;
    uint32_t                    cnt = 0, data_cnt = 0;
    comm_msg_inst_ie_data       *ie_data = NULL;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_inst_ie_data);

    if (unlikely(0 == index_num)) {
        LOG(SESSION, ERR, "parameter is invalid, index number: %u.",
            index_num);
        return -1;
    }

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    if (is_add) {
        ie->cmd = htons(EN_COMM_MSG_UPU_INST_ADD);
    } else {
        ie->cmd = htons(EN_COMM_MSG_UPU_INST_MOD);
    }
    ie_data     = (comm_msg_inst_ie_data *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        entry = session_instance_get_entry(index_arr[cnt]);
        if (NULL == entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", index_arr[cnt]);
            continue;
        }

        ie_data[data_cnt].index = htonl(entry->index);
        ros_memcpy(&ie_data[data_cnt].cfg, &entry->inst_config, sizeof(comm_msg_inst_config));
        session_instance_config_hton(&ie_data[data_cnt].cfg);
        ++data_cnt;

        if (data_cnt >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_inst_config) * data_cnt;
            ie->rules_num = htonl(data_cnt);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > session_msg_send_to_fp((char *)buf, buf_len, fd)) {
                LOG(UPC, ERR, "Send buffer to backend failed.");
                return -1;
            }
            data_cnt = 0;
        }
    }

    if (data_cnt > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_inst_config) * data_cnt;
        ie->rules_num = htonl(data_cnt);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > session_msg_send_to_fp((char *)buf, buf_len, fd)) {
            LOG(UPC, ERR, "Send buffer to backend failed.");
            return -1;
        }
        data_cnt = 0;
    }

    return 0;
}

int session_instance_add(uint32_t index, comm_msg_inst_config *entry_cfg,
    uint8_t fp_sync, struct session_inst_control *inst_ctrl)
{
    struct session_inst_entry *entry = NULL;
    struct session_inst_cb *inst_table = session_instance_get_table();

    if (index >= session_instance_max() || (NULL == entry_cfg)) {
        LOG(SESSION, ERR, "parameter is invalid, index: %u, "
            "entry cfg point: 0x%p.", index, entry_cfg);
        return -1;
    }

    entry = session_instance_get_entry(index);
    if (!entry) {
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return -1;
    }
    ros_rwlock_write_lock(&entry->rwlock);// lock
    if (entry->valid) {
        ros_rwlock_write_unlock(&entry->rwlock);// unlock
        LOG(SESSION, ERR,
            "The entry already exists, entry num: %u.", index);
        return -1;
    }

    ros_memcpy(&entry->inst_config, entry_cfg, sizeof(comm_msg_inst_config));
    ros_memcpy(&entry->control, inst_ctrl, sizeof(struct session_inst_control));
    ros_memset(&entry->stat, 0, sizeof(comm_msg_urr_stat_t));

    entry->valid = G_TRUE;
    ros_atomic32_add(&inst_table->use_entry_num, 1);

    ros_rwlock_write_unlock(&entry->rwlock);// unlock

    if (fp_sync) {
        return session_instance_fp_add_or_mod(&index, 1, 1, MB_SEND2BE_BROADCAST_FD);
    } else {
        return 0;
    }
}

int session_instance_del(uint32_t index, uint8_t fp_sync)
{
    struct session_inst_entry *entry = NULL;
    struct session_inst_cb  *inst_table = session_instance_get_table();

    if (index >= session_instance_max() || index == 0) {
        LOG(SESSION, ERR, "parameter is invalid, index: %u.",
            index);
        return -1;
    }

    entry = session_instance_get_entry(index);
    if (!entry) {
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return -1;
    }
    ros_rwlock_write_lock(&entry->rwlock);/* lock */
    if (!entry->valid) {
        ros_rwlock_write_unlock(&entry->rwlock);/* unlock */
        LOG(SESSION, ERR, "The entry is invalid,"
            " index: %u.", index);
        return -1;
    }

    entry->valid = G_FALSE;
    ros_atomic32_sub(&inst_table->use_entry_num, 1);
    ros_rwlock_write_unlock(&entry->rwlock);/* unlock */

    if (fp_sync) {
        return rules_fp_del(&index, 1, EN_COMM_MSG_UPU_INST_DEL, MB_SEND2BE_BROADCAST_FD);
    } else {
        return 0;
    }
}

int session_instance_modify(uint32_t index, comm_msg_inst_config *inst_config,
    uint8_t fp_sync, struct session_inst_control *inst_ctrl)
{
    struct session_inst_entry *entry = NULL;

    if (index >= session_instance_max() || (NULL == inst_config)) {
        LOG(SESSION, ERR, "parameter is invalid, index: %u, "
            "inst_config point: 0x%p.", index, inst_config);
        return -1;
    }

    entry = session_instance_get_entry(index);
    if (!entry) {
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return -1;
    }
    ros_rwlock_write_lock(&entry->rwlock);// lock
    if (!entry->valid) {
        ros_rwlock_write_unlock(&entry->rwlock);// unlock
        LOG(SESSION, ERR, "The entry is invalid, index: %u.", index);
        return -1;
    }

    ros_memcpy(&entry->inst_config, inst_config, sizeof(comm_msg_inst_config));
    ros_memcpy(&entry->control, inst_ctrl, sizeof(struct session_inst_control));

    ros_rwlock_write_unlock(&entry->rwlock);// unlock

    if (fp_sync) {
        return session_instance_fp_add_or_mod(&index, 1, 0, MB_SEND2BE_BROADCAST_FD);
    } else {
        return 0;
    }
}

int session_instance_modify_far(uint32_t index, uint32_t far_index, uint8_t fp_sync)
{
    struct session_inst_entry *entry = NULL;

    if (index >= session_instance_max()) {
        LOG(SESSION, ERR, "parameter is invalid, index: %u.", index);
        return -1;
    }

    entry = session_instance_get_entry(index);
    if (!entry) {
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return -1;
    }
    ros_rwlock_write_lock(&entry->rwlock);// lock
    if (!entry->valid) {
        ros_rwlock_write_unlock(&entry->rwlock);// unlock
        LOG(SESSION, ERR, "The entry is invalid, index: %u.", index);
        return -1;
    }

    entry->inst_config.far_index1 = far_index;

    ros_rwlock_write_unlock(&entry->rwlock);// unlock

    if (fp_sync) {
        return session_instance_fp_add_or_mod(&index, 1, 0, MB_SEND2BE_BROADCAST_FD);
    } else {
        return 0;
    }
}

int session_instance_get(uint32_t index, comm_msg_inst_config *inst_config)
{
    struct session_inst_entry *entry = NULL;

    entry = session_instance_get_entry(index);
    if (!entry) {
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return -1;
    }
    ros_rwlock_read_lock(&entry->rwlock);// lock
    if (!entry->valid) {
        ros_rwlock_read_unlock(&entry->rwlock);// unlock
        LOG(SESSION, ERR, "The entry is invalid, entry num: %u.", index);
        return -1;
    }
    ros_memcpy(inst_config, &entry->inst_config, sizeof(comm_msg_inst_config));
    ros_rwlock_read_unlock(&entry->rwlock);// unlock

    return 0;
}

uint32_t session_instance_sum(void)
{
    struct session_inst_cb *inst_table = session_instance_get_table();
    uint32_t entry_sum = 0;

    entry_sum = ros_atomic32_read(&inst_table->use_entry_num);

    return entry_sum;
}

uint32_t session_instance_check_all(comm_msg_ie_t *ie, int fd)
{
    comm_msg_rules_ie_t *rule_ie = (comm_msg_rules_ie_t *)ie;
    struct session_inst_entry *entry = NULL;
    comm_msg_inst_ie_data *ie_data = NULL;
    uint32_t cnt = 0;
    uint32_t mod_arr[ONCE_CHANGE_NUMBER_MAX], mod_num = 0;

    if (NULL == ie) {
        LOG(SESSION, ERR, "parameter is invalid, ie(%p).",
            ie);
        return -1;
    }

    ie_data = (comm_msg_inst_ie_data *)rule_ie->data;
    for (cnt = 0; cnt < rule_ie->rules_num; ++cnt) {
        uint32_t index = ntohl(ie_data[cnt].index);

        session_instance_config_ntoh(&ie_data[cnt].cfg);

        entry = session_instance_get_entry(index);
        if (!entry) {
            LOG(SESSION, ERR, "Entry index error, index: %u.", index);
            continue;
        }
        ros_rwlock_read_lock(&entry->rwlock);/* lock */
        if (G_FALSE == entry->valid) {
            /* spu和fpu表项有效性不一致的4am审计不去处理，simple审计会去处理，各司其职 */
            ros_rwlock_read_unlock(&entry->rwlock);/* unlock */
            LOG(SESSION, ERR, "entry is invalid, index: %u.",
                index);
            continue;
        }

        if (ros_memcmp(&ie_data[cnt].cfg, &entry->inst_config, sizeof(comm_msg_inst_config))) {
            ros_rwlock_read_unlock(&entry->rwlock);/* unlock */
            if (mod_num >= ONCE_CHANGE_NUMBER_MAX) {
                if (0 > session_instance_fp_add_or_mod(mod_arr, mod_num, 0, fd)) {
                    ros_rwlock_read_unlock(&entry->rwlock);/* unlock */
                    LOG(SESSION, ERR, "Modify fpu entry failed.");
                    return -1;
                }
                mod_num = 0;
            }
            mod_arr[mod_num] = index;
            ++mod_num;
        } else {
            ros_rwlock_read_unlock(&entry->rwlock);/* unlock */
        }
    }

    if (mod_num > 0) {
        if (0 > session_instance_fp_add_or_mod(mod_arr, mod_num, 0, fd)) {
            LOG(SESSION, ERR, "Modify fpu entry failed.");
            return -1;
        }
    }

    return 0;
}

int session_instance_check_table_validity(comm_msg_entry_val_config_t *fp_val_cfg, int fd)
{
    uint32_t field_num = 0, cnt = 0, fp_del = 0, fp_add = 0, diff = 0;
    uint32_t remainder = 0;
    uint32_t del_arr[ONCE_CHANGE_NUMBER_MAX], del_num = 0;
    uint32_t add_arr[ONCE_CHANGE_NUMBER_MAX], add_num = 0;
    uint8_t val_data[SERVICE_BUF_TOTAL_LEN];
    comm_msg_entry_val_config_t *sp_val_cfg = (comm_msg_entry_val_config_t *)val_data;

    LOG(SESSION, RUNNING, "validity action start.");

    if (NULL == fp_val_cfg) {
        LOG(SESSION, ERR, "Abnormal parameter, fp_val_cfg(%p).", fp_val_cfg);
        return -1;
    }

    if (0 > session_val_ntoh(fp_val_cfg)) {
        LOG(SESSION, ERR, "Abnormal parameters, invalid 'val config'.");
        return -1;
    }

    if (G_SUCCESS != Res_GetRangeField(pdr_get_pool_id(), 0,
        fp_val_cfg->start, fp_val_cfg->entry_num, sp_val_cfg->data)) {
        LOG(SESSION, ERR, "Get range field failed, start: %u, entry_num: %u.",
            fp_val_cfg->start, fp_val_cfg->entry_num);
        return -1;
    }

    field_num = fp_val_cfg->entry_num >> RES_PART_LEN_BIT;
    LOG(SESSION, RUNNING, "field_num: %u.", field_num);
    for (cnt = 0; cnt < field_num; ++cnt) {
        diff = sp_val_cfg->data[cnt] ^ fp_val_cfg->data[cnt];
        if (diff) {
            uint32_t start_bit = fp_val_cfg->start + (cnt << RES_PART_LEN_BIT);

            fp_add = (sp_val_cfg->data[cnt] & diff) ^ diff;
            fp_del = (fp_val_cfg->data[cnt] & diff) ^ diff;

            if (fp_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_INST_DEL, fd);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_del,
                    del_arr, &del_num);
            }
            if (fp_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    session_instance_fp_add_or_mod(add_arr, add_num, 1, fd);
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_add,
                    add_arr, &add_num);
            }
        }
    }

    remainder = fp_val_cfg->entry_num & RES_PART_LEN_MASK;
    if (remainder) {
        diff = sp_val_cfg->data[cnt] ^ fp_val_cfg->data[cnt];
        diff &= ~((1 << (RES_PART_LEN - remainder)) - 1);
        if (diff) {
            uint32_t start_bit = fp_val_cfg->start + (cnt << RES_PART_LEN_BIT);

            fp_add = (sp_val_cfg->data[cnt] & diff) ^ diff;
            fp_del = (fp_val_cfg->data[cnt] & diff) ^ diff;

            if (fp_del) {
                if (del_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_INST_DEL, fd);
                    del_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_del,
                    del_arr, &del_num);
            }
            if (fp_add) {
                if (add_num > (ONCE_CHANGE_NUMBER_MAX - RES_PART_LEN)) {
                    session_instance_fp_add_or_mod(add_arr, add_num, 1, fd);
                    add_num = 0;
                }
                comm_msg_val_bit2index(start_bit, fp_add,
                    add_arr, &add_num);
            }
        }
    }

    if (del_num > 0) {
        rules_fp_del(del_arr, del_num, EN_COMM_MSG_UPU_INST_DEL, fd);
    }
    if (add_num > 0) {
        session_instance_fp_add_or_mod(add_arr, add_num, 1, fd);
    }

    return 0;
}

/* init session instance table */
int64_t session_instance_init(uint32_t sess_num)
{
    uint32_t max_num = sess_num * MAX_PDR_NUM;
    int64_t size = sizeof(struct session_inst_entry) * max_num;
    struct session_inst_entry *inst_entry = NULL;
    comm_msg_inst_config orphan_inst_core = {0};
    int cnt = 0;
    struct session_inst_control inst_ctrl = {0};

    if (0 == max_num) {
        LOG(SESSION, ERR, "init failed, max_num:%u.", max_num);
        return -1;
    }

    inst_entry = ros_malloc(size);
    if (NULL == inst_entry) {
        LOG(SESSION, ERR,
            "init failed, no enough memory, max_num:%u.", max_num);
        return -1;
    }
    memset(inst_entry, 0, size);
    sess_instance_cb.max_inst_num = max_num;
    sess_instance_cb.inst_entry   = inst_entry;
    ros_atomic32_set(&sess_instance_cb.use_entry_num, 0);
    ros_rwlock_init(&sess_instance_cb.rwlock);

    /* init entry */
    for (cnt = 0; cnt < max_num; ++cnt) {
        inst_entry[cnt].index = cnt;
        inst_entry[cnt].valid = G_FALSE;
        ros_rwlock_init(&inst_entry[cnt].rwlock);
    }

    /* add orphan instance table */
    orphan_inst_core.choose.d.flag_far1 = 1;
    orphan_inst_core.far_index1 = 0;
    if (0 > session_instance_add(COMM_MSG_ORPHAN_NUMBER,
        &orphan_inst_core, 0, &inst_ctrl)) {
        LOG(SESSION, ERR, "add orphan instance table failed.");
        return -1;
    }

    /* init 4am audit */
    if (0 > audit_4am_init(&session_inst_audit_4am, EN_INST_AUDIT)) {
        LOG(SESSION, ERR, "audit_4am_init failed.");
        return -1;
    }

    /* init sample audit */
    if (0 > audit_simple_init(&session_inst_audit_simple, EN_INST_AUDIT)) {
        LOG(SESSION, ERR, "Simple audit init failed.");
        return -1;
    }

    LOG(SESSION, MUST, "session instance init success.");
    return size;
}

static inline void session_instance_stat_show(struct cli_def *cli, comm_msg_urr_stat_t *stat)
{
    cli_print(cli, "forward packets:    %lu", stat->forw_pkts);
    cli_print(cli, "forward bytes:      %lu", stat->forw_bytes);
    cli_print(cli, "drop packets:       %lu", stat->drop_pkts);
    cli_print(cli, "drop bytes:         %lu", stat->drop_bytes);
    cli_print(cli, "error count:        %lu", stat->err_cnt);
}

int session_instance_stats_show(struct cli_def *cli, int argc, char **argv)
{
    struct session_inst_entry *entry = NULL;
    struct pdr_table_head *pdr_head = pdr_get_head();

    if (argc < 1) {
        cli_print(cli, "Parameters too few...\n");
        goto help;
    }

    if (strcasecmp(argv[0], "all")) {
        int32_t cur_index = -1;

        cur_index = Res_GetAvailableInBand(pdr_head->pool_id, cur_index + 1, pdr_head->max_num);
        while (-1 != (cur_index = Res_GetAvailableInBand(pdr_head->pool_id, cur_index + 1, pdr_head->max_num))) {
            entry = session_instance_get_entry(cur_index);

            cli_print(cli, "\n---------- instance index %d ----------", cur_index);
            session_instance_stat_show(cli, &entry->stat);
        }
    } else if (strcasecmp(argv[0], "help")) {
        goto help;
    } else {
        int index = atoi(argv[0]);

        entry = session_instance_get_entry(index);

        cli_print(cli, "\n---------- instance index %d ----------", index);
        session_instance_stat_show(cli, &entry->stat);
    }

    return 0;

help:
    cli_print(cli, "\ninst_stat <instance index | all>");
    cli_print(cli, "\te.g. inst_stat 1");
    cli_print(cli, "\te.g. inst_stat all");

    return 0;
}

