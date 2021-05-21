/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "session_msg.h"
#include "session_audit.h"
#include "far_mgmt.h"
#include "urr_mgmt.h"
#include "pdr_mgmt.h"
#include "urr_proc.h"

#include "local_parse.h"

struct urr_table_head urr_tbl_head;

void urr_table_show(struct urr_table *urr_tbl)
{
    uint32_t cnt = 0;

    LOG(SESSION, RUNNING, "--------------urr--------------");
    LOG(SESSION, RUNNING, "index: %u", urr_tbl->index);
    LOG(SESSION, RUNNING, "urr id: 0x%08x", urr_tbl->urr.urr_id);
    LOG(SESSION, RUNNING, "method value: %d", urr_tbl->urr.method.value);
    LOG(SESSION, RUNNING, "trigger value: %u", urr_tbl->urr.trigger.value);

    LOG(SESSION, RUNNING, "period: %u", urr_tbl->urr.period);
    LOG(SESSION, RUNNING, "vol_thres flag value: %u",
        urr_tbl->urr.vol_thres.flag.value);
    LOG(SESSION, RUNNING, "vol_thres downlink: %lu",
        urr_tbl->urr.vol_thres.downlink);
    LOG(SESSION, RUNNING, "vol_thres uplink: %lu",
        urr_tbl->urr.vol_thres.uplink);
    LOG(SESSION, RUNNING, "vol_thres total: %lu",
        urr_tbl->urr.vol_thres.total);

    LOG(SESSION, RUNNING, "vol_quota flag value: %u",
        urr_tbl->urr.vol_quota.flag.value);
    LOG(SESSION, RUNNING, "vol_quota downlink: %lu",
        urr_tbl->urr.vol_quota.downlink);
    LOG(SESSION, RUNNING, "vol_quota uplink: %lu",
        urr_tbl->urr.vol_quota.uplink);
    LOG(SESSION, RUNNING, "vol_quota total: %lu",
        urr_tbl->urr.vol_quota.total);
    LOG(SESSION, RUNNING, "eve thres: %u", urr_tbl->urr.eve_thres);
    LOG(SESSION, RUNNING, "eve quota: %u", urr_tbl->urr.eve_quota);
    LOG(SESSION, RUNNING, "tim thres: %u", urr_tbl->urr.tim_thres);
    LOG(SESSION, RUNNING, "tim quota: %u", urr_tbl->urr.tim_quota);
    LOG(SESSION, RUNNING, "quota hold: %u", urr_tbl->urr.quota_hold);
    LOG(SESSION, RUNNING, "drop_thres flag value: %d",
        urr_tbl->urr.drop_thres.flag.value);
    LOG(SESSION, RUNNING, "drop_thres packets: %lu",
        urr_tbl->urr.drop_thres.packets);
    LOG(SESSION, RUNNING, "drop_thres bytes: %lu",
        urr_tbl->urr.drop_thres.bytes);

    LOG(SESSION, RUNNING, "mon_time: %u", urr_tbl->urr.mon_time);
    LOG(SESSION, RUNNING, "sub_vol_thres flag value: %u",
        urr_tbl->urr.sub_vol_thres.flag.value);
    LOG(SESSION, RUNNING, "sub_vol_thres downlink: %lu",
        urr_tbl->urr.sub_vol_thres.downlink);
    LOG(SESSION, RUNNING, "sub_vol_thres uplink: %lu",
        urr_tbl->urr.sub_vol_thres.uplink);
    LOG(SESSION, RUNNING, "sub_vol_thres total: %lu",
        urr_tbl->urr.sub_vol_thres.total);

    LOG(SESSION, RUNNING, "sub_tim_thres: %u",
        urr_tbl->urr.sub_tim_thres);

    LOG(SESSION, RUNNING, "sub_vol_quota flag value: %u",
        urr_tbl->urr.sub_vol_quota.flag.value);
    LOG(SESSION, RUNNING, "sub_vol_quota downlink: %lu",
        urr_tbl->urr.sub_vol_quota.downlink);
    LOG(SESSION, RUNNING, "sub_vol_quota uplink: %lu",
        urr_tbl->urr.sub_vol_quota.uplink);
    LOG(SESSION, RUNNING, "sub_vol_quota total: %lu",
        urr_tbl->urr.sub_vol_quota.total);

    LOG(SESSION, RUNNING, "sub_tim_quota: %u",
        urr_tbl->urr.sub_tim_quota);
    LOG(SESSION, RUNNING, "sub_eve_thres: %u",
        urr_tbl->urr.sub_eve_thres);
    LOG(SESSION, RUNNING, "sub_eve_quota: %u",
        urr_tbl->urr.sub_eve_quota);
    LOG(SESSION, RUNNING, "inact_detect: %u", urr_tbl->urr.inact_detect);
    LOG(SESSION, RUNNING, "measu_info value: %d",
        urr_tbl->urr.measu_info.value);

    LOG(SESSION, RUNNING, "quota_far: %u", urr_tbl->urr.quota_far);
    LOG(SESSION, RUNNING, "eth_inact_time: %u",
        urr_tbl->urr.eth_inact_time);

    LOG(SESSION, RUNNING, "linked urr number: %d",
        urr_tbl->urr.linked_urr_number);
    for (cnt = 0; cnt < urr_tbl->urr.linked_urr_number; ++cnt) {
        LOG(SESSION, RUNNING, "linked urr[%u]: %u",
            cnt, urr_tbl->urr.linked_urr[cnt]);
    }
    LOG(SESSION, RUNNING, "add mon time number: %d",
        urr_tbl->urr.add_mon_time_number);

	LOG(SESSION, RUNNING, "container flag value: %d",
        urr_tbl->container.flag.value);

	LOG(SESSION, RUNNING, "container vol_total: %ld",
        ros_atomic64_read(&urr_tbl->container.vol_total));

	LOG(SESSION, RUNNING, "container vol_ulink: %ld",
        ros_atomic64_read(&urr_tbl->container.vol_ulink));

	LOG(SESSION, RUNNING, "container vol_dlink: %ld",
        ros_atomic64_read(&urr_tbl->container.vol_dlink));

    for (cnt = 0; cnt < urr_tbl->urr.add_mon_time_number; ++cnt) {
        LOG(SESSION, RUNNING, "------------add mon time[%u]------------",
            cnt);

        LOG(SESSION, RUNNING, "mon_time: %u",
            urr_tbl->urr.add_mon_time[cnt].mon_time);
        LOG(SESSION, RUNNING, "sub_vol_thres flag value: %u",
            urr_tbl->urr.sub_vol_thres.flag.value);
        LOG(SESSION, RUNNING, "sub_vol_thres downlink: %lu",
            urr_tbl->urr.add_mon_time[cnt].sub_vol_thres.downlink);
        LOG(SESSION, RUNNING, "sub_vol_thres uplink: %lu",
            urr_tbl->urr.add_mon_time[cnt].sub_vol_thres.uplink);
        LOG(SESSION, RUNNING, "sub_vol_thres total: %lu",
            urr_tbl->urr.add_mon_time[cnt].sub_vol_thres.total);

        LOG(SESSION, RUNNING, "sub_tim_thres: %u",
            urr_tbl->urr.add_mon_time[cnt].sub_tim_thres);

        LOG(SESSION, RUNNING, "sub_vol_quota flag value: %u",
            urr_tbl->urr.sub_vol_quota.flag.value);
        LOG(SESSION, RUNNING, "sub_vol_quota downlink: %lu",
            urr_tbl->urr.add_mon_time[cnt].sub_vol_quota.downlink);
        LOG(SESSION, RUNNING, "sub_vol_quota uplink: %lu",
            urr_tbl->urr.add_mon_time[cnt].sub_vol_quota.uplink);
        LOG(SESSION, RUNNING, "sub_vol_quota total: %lu",
            urr_tbl->urr.add_mon_time[cnt].sub_vol_quota.total);

        LOG(SESSION, RUNNING, "sub_tim_quota: %u",
            urr_tbl->urr.add_mon_time[cnt].sub_tim_quota);
        LOG(SESSION, RUNNING, "sub_eve_thres: %u",
            urr_tbl->urr.add_mon_time[cnt].sub_eve_thres);
        LOG(SESSION, RUNNING, "sub_eve_quota: %u",
            urr_tbl->urr.add_mon_time[cnt].sub_eve_quota);
    }
}

inline struct urr_table_head *urr_get_head(void)
{
    return &urr_tbl_head;
}

struct urr_table *urr_get_table(uint32_t index)
{
    if (index < urr_tbl_head.max_num)
        return &urr_tbl_head.urr_table[index];
    else
        return NULL;
}

inline uint16_t urr_get_pool_id(void)
{
    return urr_tbl_head.pool_id;
}

inline uint32_t urr_get_max(void)
{
    return urr_tbl_head.max_num;
}

int urr_id_compare(struct rb_node *node, void *key)
{
    struct urr_table *urr_node = (struct urr_table *)node;
    uint32_t id = *(uint32_t *)key;

    if (id < urr_node->urr.urr_id) {
        return -1;
    }
    else if (id > urr_node->urr.urr_id) {
        return 1;
    }

    return 0;
}

int urr_id_compare_externel(struct rb_node *node, void *key)
{
    return urr_id_compare(node,key);
}

struct urr_table *urr_table_search(struct session_t *sess, uint32_t id)
{
    struct urr_table *urr_tbl = NULL;
    uint32_t urr_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    ros_rwlock_read_lock(&sess->lock);// lock
    urr_tbl = (struct urr_table *)rbtree_search(&sess->session.urr_root,
        &urr_id, urr_id_compare);
    ros_rwlock_read_unlock(&sess->lock);// unlock
    if (NULL == urr_tbl) {
        LOG(SESSION, ERR,
            "The entry with id %u does not exist.", urr_id);
        return NULL;
    }

    return urr_tbl;
}

struct urr_table *urr_table_create(struct session_t *sess, uint32_t id)
{
    struct urr_table_head *urr_head = urr_get_head();
    struct urr_table *urr_tbl = NULL;
    uint32_t key = 0, index = 0, urr_id = id;

    if (NULL == sess) {
        LOG(SESSION, ERR, "sess is NULL.");
        return NULL;
    }

    if (G_FAILURE == Res_Alloc(urr_head->pool_id, &key, &index,
        EN_RES_ALLOC_MODE_OC)) {
        LOG(SESSION, ERR,
            "create failed, Resource exhaustion, pool id: %d.",
            urr_head->pool_id);
        return NULL;
    }

    ros_rwlock_write_lock(&sess->lock);// lock
    urr_tbl = urr_get_table(index);
    if (!urr_tbl) {
        Res_Free(urr_head->pool_id, key, index);
        ros_rwlock_write_unlock(&sess->lock);// unlock
        LOG(SESSION, ERR, "Entry index error, index: %u.", index);
        return NULL;
    }
    memset(&urr_tbl->urr, 0, sizeof(comm_msg_urr_config));
    urr_tbl->urr.urr_id = urr_id;
    urr_tbl->sess = sess;

    /* insert node to session tree root*/
    if (rbtree_insert(&sess->session.urr_root, &urr_tbl->urr_node,
        &urr_id, urr_id_compare) < 0) {
        ros_rwlock_write_unlock(&sess->lock);// unlock
        Res_Free(urr_head->pool_id, key, index);
        LOG(SESSION, ERR,
            "rb tree insert failed, id: %u.", urr_id);
        return NULL;
    }
    ros_rwlock_write_unlock(&sess->lock);// unlock

    ros_atomic32_add(&urr_head->use_num, 1);

    return urr_tbl;
}

int urr_insert(struct session_t *sess, void *parse_urr_arr,
    uint32_t urr_num, uint32_t *fail_id)
{
    struct urr_table *urr_tbl = NULL;
    uint32_t index_cnt = 0;

    if (NULL == sess || (NULL == parse_urr_arr && urr_num)) {
        LOG(SESSION, ERR, "insert failed, sess(%p), parse_urr_arr(%p),"
			" urr_num: %u.", sess, parse_urr_arr, urr_num);
        return -1;
    }

    for (index_cnt = 0; index_cnt < urr_num; ++index_cnt) {

        urr_tbl = urr_add(sess, parse_urr_arr, index_cnt, fail_id);
        if (NULL == urr_tbl) {
            LOG(SESSION, ERR, "urr add failed.");
            return -1;
        }

        /* Config URR */
        urr_tbl->container.mon_cfg.mon_time = urr_tbl->urr.mon_time;
        ros_memcpy(&urr_tbl->container.mon_cfg.sub_vol_thres,
            &urr_tbl->urr.vol_thres, sizeof(comm_msg_urr_volume_t));
        ros_memcpy(&urr_tbl->container.mon_cfg.sub_vol_quota,
            &urr_tbl->urr.vol_quota, sizeof(comm_msg_urr_volume_t));
        urr_tbl->container.mon_cfg.sub_tim_thres =
            urr_tbl->urr.tim_thres;
		urr_tbl->container.mon_cfg.sub_tim_thres_fixed =
            urr_tbl->urr.tim_thres;
        urr_tbl->container.mon_cfg.sub_tim_quota =
            urr_tbl->urr.tim_quota;
        urr_tbl->container.mon_cfg.sub_eve_thres =
            urr_tbl->urr.eve_thres;
        urr_tbl->container.mon_cfg.sub_eve_quota =
            urr_tbl->urr.eve_quota;

        LOG(SESSION, RUNNING, "mon_time = %u!",
            urr_tbl->container.mon_cfg.mon_time);
        LOG(SESSION, RUNNING,
            "sub_vol_thres flag = %d!",
            urr_tbl->container.mon_cfg.sub_vol_thres.flag.value);
        LOG(SESSION, RUNNING,
            "sub_vol_thres total = %lu!",
            urr_tbl->container.mon_cfg.sub_vol_thres.total);
        LOG(SESSION, RUNNING,
            "sub_vol_thres down = %lu!",
            urr_tbl->container.mon_cfg.sub_vol_thres.downlink);
        LOG(SESSION, RUNNING,
            "sub_vol_thres up = %lu!",
            urr_tbl->container.mon_cfg.sub_vol_thres.uplink);
        LOG(SESSION, RUNNING,
            "sub_tim_thres = %u!",
            urr_tbl->container.mon_cfg.sub_tim_thres);

        /* Init urr */
        urr_container_init(urr_tbl->index);
    }

    return 0;
}

int urr_remove(struct session_t *sess, uint32_t *id_arr, uint8_t id_num, uint32_t *ret_index_arr, uint32_t *fail_id)
{
    struct urr_table *urr_tbl = NULL;
    struct urr_table_head *urr_head = urr_get_head();
	uint32_t index_cnt = 0;

    if (NULL == sess || (NULL == id_arr && id_num)) {
        LOG(SESSION, ERR, "remove failed, sess(%p), id_arr(%p),"
			" id_num: %d.", sess, id_arr, id_num);
        return -1;
    }

	for (index_cnt = 0; index_cnt < id_num; ++index_cnt) {
	    ros_rwlock_write_lock(&sess->lock);// lock
	    urr_tbl = (struct urr_table *)rbtree_delete(&sess->session.urr_root,
			&id_arr[index_cnt], urr_id_compare);
	    ros_rwlock_write_unlock(&sess->lock);// unlock
	    if (NULL == urr_tbl) {
	        LOG(SESSION, ERR, "remove failed, not exist, id: %u.",
				id_arr[index_cnt]);
            if (fail_id)
                *fail_id = id_arr[index_cnt];
            return -1;
	    }

        /* Start urr charging if exist */
        urr_container_destroy(urr_tbl->index);

	    Res_Free(urr_head->pool_id, 0, urr_tbl->index);
	    ros_atomic32_sub(&urr_head->use_num, 1);
	}

    return 0;
}

int urr_modify(struct session_t *sess, void *parse_urr_arr,
    uint32_t urr_num, uint32_t *fail_id)
{
    struct urr_table *urr_tbl = NULL;
    uint32_t index_cnt = 0;

    if (NULL == sess || (NULL == parse_urr_arr && urr_num)) {
        LOG(SESSION, ERR, "modify failed, sess(%p), parse_urr_arr(%p),"
			" urr_num: %u.", sess, parse_urr_arr, urr_num);
        return -1;
    }

	for (index_cnt = 0; index_cnt < urr_num; ++index_cnt) {

        urr_tbl = urr_update(sess, parse_urr_arr, index_cnt, fail_id);
        if (NULL == urr_tbl) {
            LOG(SESSION, ERR, "urr update failed.");
            return -1;
        }
        urr_container_destroy(urr_tbl->index);

        /* Config URR */
        urr_tbl->container.mon_cfg.mon_time = urr_tbl->urr.mon_time;
        ros_memcpy(&urr_tbl->container.mon_cfg.sub_vol_thres,
            &urr_tbl->urr.vol_thres, sizeof(comm_msg_urr_volume_t));
        ros_memcpy(&urr_tbl->container.mon_cfg.sub_vol_quota,
            &urr_tbl->urr.vol_quota, sizeof(comm_msg_urr_volume_t));
        urr_tbl->container.mon_cfg.sub_tim_thres =
            urr_tbl->urr.tim_thres;
		urr_tbl->container.mon_cfg.sub_tim_thres_fixed =
            urr_tbl->urr.tim_thres;
        urr_tbl->container.mon_cfg.sub_tim_quota =
            urr_tbl->urr.tim_quota;
        urr_tbl->container.mon_cfg.sub_eve_thres =
            urr_tbl->urr.eve_thres;
        urr_tbl->container.mon_cfg.sub_eve_quota =
            urr_tbl->urr.eve_quota;

        LOG(SESSION, RUNNING,
            "conf->vol_thres.flag.value = %d!",
            urr_tbl->container.mon_cfg.sub_vol_thres.flag.value);
        LOG(SESSION, RUNNING,
            "conf->vol_thres.flag.value = %d!",
            urr_tbl->container.mon_cfg.sub_vol_thres.resv[6]);
        LOG(SESSION, RUNNING,
            "conf->vol_thres.flag.value = %d!",
            urr_tbl->urr.vol_thres.flag.value);
        LOG(SESSION, RUNNING,
            "conf->vol_thres.flag.value = %ld!",
            urr_tbl->container.mon_cfg.sub_vol_thres.uplink);

        /* Init urr */
        urr_container_init(urr_tbl->index);

    }

    return 0;
}

uint32_t urr_sum(void)
{
    struct urr_table_head *urr_head = urr_get_head();
    uint32_t entry_sum = 0;

    entry_sum = ros_atomic32_read(&urr_head->use_num);

    return entry_sum;
}

void md_urr_fill_value(struct urr_table *urr_entry, session_md_usage_report *report)
{
    urr_container        *cont;          /* resource container */
	comm_msg_urr_mon_time_t *monitor;

    cont = &urr_entry->container;
	monitor = &urr_entry->container.mon_cfg;

	if (urr_entry->urr.method.d.volum) {
        report->vol_meas.flag.value = urr_entry->container.flag.value;

		LOG(SESSION, RUNNING, "vol_ulink %ld, vol_dlink %ld, vol_total %ld",
			cont->vol_ulink.cnt, cont->vol_dlink.cnt, cont->vol_total.cnt);

		report->vol_meas.uplink = cont->vol_ulink.cnt;
		report->vol_meas.downlink = cont->vol_dlink.cnt;
		report->vol_meas.total = cont->vol_total.cnt;

		ros_atomic64_init(&cont->vol_dlink);
		ros_atomic64_init(&cont->vol_ulink);
		ros_atomic64_init(&cont->vol_total);
    }

    if (urr_entry->urr.method.d.durat) {
        if (urr_entry->container.tim_status & URR_STATUS_NORMAL) {
			if (monitor->sub_tim_thres) {
            	report->duration = (monitor->sub_tim_thres - cont->time.cnt);
			}
			else {
				report->duration = (monitor->sub_tim_quota - cont->time.cnt);
			}
        }
        else {
			if (!monitor->sub_tim_quota) {
				report->duration = monitor->sub_tim_thres;
			}
			else {
				report->duration = (monitor->sub_tim_quota - cont->time.cnt);
			}
		}
    }

}

static void session_delete_urr_content_copy(struct urr_table *urr_tbl, session_emd_response *resp)
{
	urr_container           *cont = NULL;
	uint32_t 				report_num = 0;

	cont = &urr_tbl->container;
	report_num = resp->usage_report_num;

	if (report_num >= MAX_URR_NUM) {
		LOG(SESSION, ERR, "report_num(%d) is error.", report_num);
        return ;
	}

	resp->usage_report[report_num].trigger.d.termr = G_TRUE;
    resp->usage_report[report_num].start_time      = cont->start_time.cnt;
    resp->usage_report[report_num].end_time        = ros_getime();
    resp->usage_report[report_num].first_pkt_time  = cont->first_pkt.cnt;
    resp->usage_report[report_num].last_pkt_time   = cont->last_pkt.cnt;
	resp->usage_report[report_num].urr_id		   = urr_tbl->urr.urr_id;
	resp->usage_report[report_num].ur_seqn		   = urr_tbl->urr.ur_seqn;
	++resp->usage_report_num;

    md_urr_fill_value(urr_tbl, &resp->usage_report[report_num]);

    if (resp->usage_report[report_num].start_time) {
        resp->usage_report[report_num].member_flag.d.start_time_present = 1;
    }
    if (resp->usage_report[report_num].end_time) {
        resp->usage_report[report_num].member_flag.d.end_time_present = 1;
    }

    if (resp->usage_report[report_num].vol_meas.flag.value) {
        resp->usage_report[report_num].member_flag.d.vol_meas_present = 1;
    }

    if (resp->usage_report[report_num].duration) {
        resp->usage_report[report_num].member_flag.d.duration_present = 1;
    }


    if (resp->usage_report[report_num].first_pkt_time) {
        resp->usage_report[report_num].member_flag.d.first_pkt_time_present = 1;
    }

    if (resp->usage_report[report_num].last_pkt_time) {
        resp->usage_report[report_num].member_flag.d.last_pkt_time_present = 1;
    }

    if (resp->usage_report[report_num].usage_info.value) {
        resp->usage_report[report_num].member_flag.d.usage_info_present = 1;
    }

    if (resp->usage_report[report_num].query_urr_ref) {
        resp->usage_report[report_num].member_flag.d.query_urr_ref_present = 1;
    }

}

/* clear all urr rules releated the current pfcp session */
int urr_clear(struct session_t *sess,
	uint8_t fp_sync, struct session_rules_index * rules, session_emd_response *resp)
{
    struct urr_table *urr_tbl = NULL;
    struct urr_table_head *urr_head = urr_get_head();
    uint32_t id = 0;

    if (NULL == sess || (0 == fp_sync && NULL == rules)) {
        LOG(SESSION, ERR, "clear failed, sess is null.");
        return -1;
    }

    resp->usage_report_num = 0;
    ros_rwlock_write_lock(&sess->lock);// lock
    urr_tbl = (struct urr_table *)rbtree_first(&sess->session.urr_root);
    while (NULL != urr_tbl) {
        id = urr_tbl->urr.urr_id;

        urr_tbl = (struct urr_table *)rbtree_delete(&sess->session.urr_root,
            &id, urr_id_compare);
        if (NULL == urr_tbl) {
            LOG(SESSION, ERR, "clear failed, id: %u.", id);
            urr_tbl = (struct urr_table *)rbtree_next(&urr_tbl->urr_node);
            continue;
        }

		session_delete_urr_content_copy(urr_tbl, resp);

        /* Start urr charging if exist */
        urr_container_destroy(urr_tbl->index);

        Res_Free(urr_head->pool_id, 0, urr_tbl->index);
        ros_atomic32_sub(&urr_head->use_num, 1);

        urr_tbl = (struct urr_table *)rbtree_next(&urr_tbl->urr_node);
    }
    ros_rwlock_write_unlock(&sess->lock);// unlock

    return 0;
}

int64_t urr_table_init(uint32_t session_num)
{
    uint32_t index = 0;
    int pool_id = -1;
    struct urr_table *urr_tbl = NULL;
    uint32_t max_num = 0;
    int64_t size = 0;

    if (0 == session_num) {
        LOG(SESSION, ERR,
            "Abnormal parameter, session_num: %u.", session_num);
        return -1;
    }

    max_num = session_num * MAX_URR_NUM;
    LOG(SESSION, RUNNING,
            "init urr, sizeof(urr): %lu  max_num: %u.",
            sizeof(struct urr_table), max_num);
    size = sizeof(struct urr_table) * max_num;
    urr_tbl = ros_malloc(size);
    if (NULL == urr_tbl) {
        LOG(SESSION, ERR,
            "init pdr failed, no enough memory, max number: %u ="
            " session_num: %u * %d.", max_num,
            session_num, MAX_URR_NUM);
        return -1;
    }
    ros_memset(urr_tbl, 0, sizeof(struct urr_table) * max_num);

    for (index = 0; index < max_num; ++index) {
        urr_tbl[index].index = index;
        ros_rwlock_init(&urr_tbl[index].lock);
    }

    pool_id = Res_CreatePool();
    if (pool_id < 0) {
        return -1;
    }
    if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        return -1;
    }

    urr_tbl_head.pool_id = pool_id;
    urr_tbl_head.urr_table = urr_tbl;
    urr_tbl_head.max_num = max_num;
	ros_rwlock_init(&urr_tbl_head.lock);
    ros_atomic32_set(&urr_tbl_head.use_num, 0);

    LOG(SESSION, MUST, "urr init success.");
    return size;
}

