/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "session_mgmt.h"
#include "pdr_mgmt.h"
#include "far_mgmt.h"
#include "bar_mgmt.h"
#include "urr_mgmt.h"
#include "qer_mgmt.h"
#include "session_teid.h"
#include "urr_proc.h"

#include "local_parse.h"
#include "session_report.h"
#include "upc_session.h"

/* session report buffer length */
#define UPU_REPORT_BUF_LEN			(2048)

/* session report */
ros_atomic32_t sequece_number = {-1};

static int session_report_publish(session_report_request *sess_req)
{
    if (sess_req == NULL) {
        LOG(SESSION, ERR, "abnormal parameter, sess_rep: %p.", sess_req);
        return -1;
    }

	sess_req->msg_header.seq_num = ros_atomic32_add_return(&sequece_number, 1);
	sess_req->msg_header.msg_type = SESS_SESSION_REPORT_REQUEST;

    LOG(SESSION, RUNNING, "seqence number: %d.", sess_req->msg_header.seq_num);

    upc_report_proc(sess_req, sizeof(session_report_request));

	return 0;
}

static void session_report_fill_nocp_info(struct pdr_table *pdr_tbl,
    session_report_request *report)
{
    session_dl_data_report *dd_report = &report->dl_data_report;
	comm_msg_urr_report_t   ur_report[MAX_URR_NUM];
	struct session_t 	   *sess;
	struct qer_table *qer_tbl;
	struct urr_table *urr_tbl;
	struct far_table *far_tbl;
	uint32_t  cnt = 0, report_num = 0;
	//urr_container           *cont = NULL;

	memset(ur_report, 0, sizeof(ur_report));
    report->report_type.d.DLDR = 1;

	sess = pdr_tbl->session_link;
    dd_report->pdr_id_arr[0] = pdr_tbl->pdr.pdr_id;
    dd_report->dl_data_service[0].ddsi_flag.d.ppi = 1;
    dd_report->dl_data_service[0].ddsi_flag.d.qfii = 1;
    dd_report->dl_data_service[0].ppi_value = 0;
    dd_report->dl_data_service[0].qfi = 0;
	dd_report->pdr_id_num = 1;

	far_tbl = far_table_search(sess, pdr_tbl->pdr.far_id);
	if(NULL == far_tbl) {
        LOG(SESSION, ERR, "far table search failed, far_id %u.",
           pdr_tbl->pdr.far_id);
        return;
    }
	/*ppi取dscp的值*/
	if(far_tbl->far_cfg.choose.d.flag_transport_level1) {
		dd_report->dl_data_service[0].ppi_value = (far_tbl->far_cfg.forw_trans.tos & far_tbl->far_cfg.forw_trans.mask) >> 2;
	}

	//取第一条带GBR的QER表
	if(pdr_tbl->pdr.qer_list_number) {

		#if 0
		for(cnt=0; cnt<pdr_tbl->pdr.qer_list_number; cnt++) {
			qer_tbl = qer_table_search(sess, pdr_tbl->pdr.qer_id_array[cnt]);
			if(NULL == qer_tbl) {
	            LOG(SESSION, ERR, "qer table search failed, qer_id %u.",
	                pdr_tbl->pdr.qer_id_array[cnt]);
	            return;
	        }
			if(qer_tbl->qer.dl_gbr) {
				break;
			}
		}
		#else
			/*暂时直接取第一条QER的QFI*/
			qer_tbl = qer_table_search(sess, pdr_tbl->pdr.qer_id_array[0]);
			if(NULL == qer_tbl) {
	            LOG(SESSION, ERR, "qer table search failed, qer_id %u.",
	                pdr_tbl->pdr.qer_id_array[0]);
	            return;
	        }
		#endif

		if(cnt < pdr_tbl->pdr.qer_list_number) {

			if(qer_tbl->qer_priv.qfi) {
				dd_report->dl_data_service[0].ddsi_flag.d.qfii = 1;
				dd_report->dl_data_service[0].qfi = qer_tbl->qer_priv.qfi;
			}
			/*ppi获取dscp的值，不用QER表中的ppi*/
			#if 0
			if(qer_tbl->qer_priv.paging_policy_indic) {
				dd_report->dl_data_service[0].ddsi_flag.d.ppi = 1;
				dd_report->dl_data_service[0].ppi_value = qer_tbl->qer_priv.paging_policy_indic;
			}
			#endif
		}
	}


	for(cnt=0; cnt< pdr_tbl->pdr.urr_list_number; cnt++) {

		report->report_type.d.USAR = 1;

		urr_tbl = urr_table_search(sess, pdr_tbl->pdr.urr_id_array[cnt]);
		if(NULL == urr_tbl) {
            LOG(SESSION, ERR, "urr table search failed, urr_id %u.",
               pdr_tbl->pdr.urr_id_array[cnt]);
            return;
        }
		//cont = &urr_tbl->container;
		ur_report[report_num].urr_id  = urr_tbl->urr.urr_id;
		ur_report[report_num].urr_index  = urr_tbl->index;
		ur_report[report_num].trigger.d.termr = 1;
		ur_report[report_num].ur_seqn = urr_tbl->urr.ur_seqn++;

		//目前只有第一个包会触发下行链路上报，先填当前时间
		ur_report[report_num].start_time      = ros_getime();
        ur_report[report_num].end_time        = ros_getime();
        ur_report[report_num].first_pkt_time  = ros_getime();
        ur_report[report_num].last_pkt_time   = ros_getime();
		urr_fill_value(urr_tbl, &ur_report[report_num]);
		ur_report[report_num].urr_id = urr_tbl->urr.urr_id;
		++report_num;
		report_num = urr_get_link_report(&ur_report[0], urr_tbl, report_num);
		if(-1 == report_num) {
			LOG(SESSION, ERR, "urr_get_link_report error.");
			return;
		}
		report->usage_report_num = report_num;
	}
	for(cnt = 0; cnt<report_num; cnt++) {
		session_report_urr_content_copy(&report->usage_report_arr[cnt], &ur_report[cnt]);
	}

}

void session_report_nocp(void *tim, uint64_t para)
{
    struct session_t *session = NULL;
    struct pdr_table *pdr_tbl = NULL;
    session_report_request report_req = {{0}};

    if (!para) {
        LOG(SESSION, ERR, "abnormal parameter, para is NULL.");
        return;
    }

    pdr_tbl = (struct pdr_table *)para;
    session = pdr_tbl->session_link;
    if (unlikely(NULL == session)) {
        LOG(SESSION, ERR, "Pdr linked session error.\r\n");
        return;
    }

	report_req.local_seid = session->session.local_seid;
	report_req.cp_seid = session->session.cp_seid;
	report_req.msg_header.node_id_index = session->session.node_index;
    session_report_fill_nocp_info(pdr_tbl, &report_req);

    if (0 > session_report_publish(&report_req)) {
		LOG(SESSION, ERR, "publish report info to smu failed.");
	}

}

int session_start_nocp_timer(struct session_t *session, struct pdr_table *pdr_tbl, uint32_t far_index)
{
    struct far_table *far_tbl = NULL;

    if (NULL == session || NULL == pdr_tbl) {
        LOG(SESSION, ERR, "abnormal parameter, session(%p), pdr_tbl(%p).",
            session, pdr_tbl);
        return -1;
    }

    /* search far table */
    far_tbl = far_get_table(far_index);
    if (NULL == far_tbl) {
        LOG(SESSION, ERR, "far table search failed, far_index %u.", far_index);
        return -1;
    }
    LOG(SESSION, RUNNING,
        "far action  spare: %d, dupl: %d, nocp: %d, buff: %d,"
        " forw: %d, drop: %d.", far_tbl->far_cfg.action.d.spar,
        far_tbl->far_cfg.action.d.dupl, far_tbl->far_cfg.action.d.nocp,
        far_tbl->far_cfg.action.d.buff, far_tbl->far_cfg.action.d.forw,
        far_tbl->far_cfg.action.d.drop);

    /* forwarding parameters */
    if ((far_tbl->far_cfg.action.d.buff) && (far_tbl->far_cfg.action.d.nocp)) {
        session_up_features up_features = {.value = upc_get_up_features()};

        if (up_features.d.DDND) {
            struct bar_table *bar_tbl = NULL;

            LOG(SESSION, RUNNING, "downlink data notification delay.");
            /* search bar table */
            bar_tbl = bar_table_search(session, far_tbl->far_priv.bar_id);
            if (NULL == bar_tbl) {
                LOG(SESSION, ERR, "bar table not found, bar_id %u.", far_tbl->far_priv.bar_id);
                return -1;
            }

            /* 现在定时器的时间单位为10ms, notify的延时单位为50ms */
            if (bar_tbl->bar.notify_delay) {
                /* 如果延迟时间不为0就去启定时器 */
                uint16_t delay = bar_tbl->bar.notify_delay * 5;

                ros_timer_reset(pdr_tbl->nocp_report_timer,
                    delay, ROS_TIMER_MODE_ONCE, (uint64_t)pdr_tbl, session_report_nocp);

                LOG(SESSION, RUNNING, "notify timer ready start.");

            } else {
                /* 如果延迟时间为0就直接发送报文，不启动定时器 */

                LOG(SESSION, RUNNING, "notify delay is 0, immediate send packet to UPC.");
                session_report_nocp(NULL, (uint64_t)pdr_tbl);
            }
        } else {

            LOG(SESSION, RUNNING, "DDND not support, immediate report to UPC.");
            session_report_nocp(NULL, (uint64_t)pdr_tbl);
        }

    }

    return 0;
}

void session_urr_report_htonl(comm_msg_urr_report_t *urr_rep)
{
	urr_rep->urr_id = htonl(urr_rep->urr_id);
	urr_rep->ur_seqn = htonl(urr_rep->ur_seqn);
	urr_rep->trigger.value = htonl(urr_rep->trigger.value);
	urr_rep->start_time = htonl(urr_rep->start_time);
	urr_rep->end_time = htonl(urr_rep->end_time);
	urr_rep->vol_meas.total = htonll(urr_rep->vol_meas.total);
	urr_rep->vol_meas.uplink = htonll(urr_rep->vol_meas.uplink);
	urr_rep->vol_meas.downlink = htonll(urr_rep->vol_meas.downlink);
	urr_rep->tim_meas = htonl(urr_rep->tim_meas);
	/* Too few parameters */
	urr_rep->app_detect.stub = htonl(urr_rep->app_detect.stub);
	urr_rep->ue_ip.ipv4 = htonl(urr_rep->ue_ip.ipv4);
	/* Too few parameters */
	urr_rep->network_instance = htonl(urr_rep->network_instance);
	urr_rep->first_pkt_time = htonl(urr_rep->first_pkt_time);
	urr_rep->last_pkt_time = htonl(urr_rep->last_pkt_time);
	urr_rep->query_urr_ref = htonl(urr_rep->query_urr_ref);
	urr_rep->eve_stamp = htonl(urr_rep->eve_stamp);
}

static void session_urr_report_ntohl(comm_msg_urr_report_t *urr_rep)
{
	urr_rep->urr_id = ntohl(urr_rep->urr_id);
	urr_rep->ur_seqn = ntohl(urr_rep->ur_seqn);
	urr_rep->trigger.value = ntohl(urr_rep->trigger.value);
	urr_rep->start_time = ntohl(urr_rep->start_time);
	urr_rep->end_time = ntohl(urr_rep->end_time);
	urr_rep->vol_meas.total = ntohll(urr_rep->vol_meas.total);
	urr_rep->vol_meas.uplink = ntohll(urr_rep->vol_meas.uplink);
	urr_rep->vol_meas.downlink = ntohll(urr_rep->vol_meas.downlink);
	urr_rep->tim_meas = ntohl(urr_rep->tim_meas);
	/* Too few parameters */
	urr_rep->app_detect.stub = ntohl(urr_rep->app_detect.stub);
	urr_rep->ue_ip.ipv4 = ntohl(urr_rep->ue_ip.ipv4);
	/* Too few parameters */
	urr_rep->network_instance = ntohl(urr_rep->network_instance);
	urr_rep->first_pkt_time = ntohl(urr_rep->first_pkt_time);
	urr_rep->last_pkt_time = ntohl(urr_rep->last_pkt_time);
	urr_rep->query_urr_ref = ntohl(urr_rep->query_urr_ref);
	urr_rep->eve_stamp = ntohl(urr_rep->eve_stamp);
}

static inline void session_show_urr_report(comm_msg_urr_report_t *urr_rep)
{
	time_t                  time_val;

	LOG(SESSION, DEBUG, "show urr report content:");
	LOG(SESSION, DEBUG, "  urr id           : %d",
		urr_rep->urr_id);
	LOG(SESSION, DEBUG, "  ur_seqn          : %d",
		urr_rep->ur_seqn);

	LOG(SESSION, DEBUG, "  trigger.perio    : %d",
		urr_rep->trigger.d.perio);
	LOG(SESSION, DEBUG, "  trigger.volth    : %d",
		urr_rep->trigger.d.volth);
	LOG(SESSION, DEBUG, "  trigger.timth    : %d",
		urr_rep->trigger.d.timth);
	LOG(SESSION, DEBUG, "  trigger.quhti    : %d",
		urr_rep->trigger.d.quhti);
	LOG(SESSION, DEBUG, "  trigger.start    : %d",
		urr_rep->trigger.d.start);
	LOG(SESSION, DEBUG, "  trigger.stopt    : %d",
		urr_rep->trigger.d.stopt);
	LOG(SESSION, DEBUG, "  trigger.droth    : %d",
		urr_rep->trigger.d.droth);
	LOG(SESSION, DEBUG, "  trigger.liusa    : %d",
		urr_rep->trigger.d.liusa);
	LOG(SESSION, DEBUG, "  trigger.volqu    : %d",
		urr_rep->trigger.d.volqu);
	LOG(SESSION, DEBUG, "  trigger.timqu    : %d",
		urr_rep->trigger.d.timqu);
	LOG(SESSION, DEBUG, "  trigger.envcl    : %d",
		urr_rep->trigger.d.envcl);
	LOG(SESSION, DEBUG, "  trigger.macar    : %d",
		urr_rep->trigger.d.macar);
	LOG(SESSION, DEBUG, "  trigger.envcl    : %d",
		urr_rep->trigger.d.envcl);
	LOG(SESSION, DEBUG, "  trigger.eveth    : %d",
		urr_rep->trigger.d.eveth);
	LOG(SESSION, DEBUG, "  trigger.evequ    : %d",
		urr_rep->trigger.d.evequ);
	LOG(SESSION, DEBUG, "  trigger.monit    : %d",
		urr_rep->trigger.d.monit);
	LOG(SESSION, DEBUG, "  trigger.termr    : %d",
		urr_rep->trigger.d.termr);

	time_val = urr_rep->start_time;
	LOG(SESSION, DEBUG, "  start_time       : %s", ctime(&time_val));
	time_val = urr_rep->end_time;
	LOG(SESSION, DEBUG, "  end_time         : %s", ctime(&time_val));
	LOG(SESSION, DEBUG, "  vol_meas.flag    : %d",
		urr_rep->vol_meas.flag.value);
	LOG(SESSION, DEBUG, "  vol_meas.downlink: %ld",
		urr_rep->vol_meas.downlink);
	LOG(SESSION, DEBUG, "  vol_meas.uplink  : %ld",
		urr_rep->vol_meas.uplink);
	LOG(SESSION, DEBUG, "  vol_meas.total   : %ld",
		urr_rep->vol_meas.total);
	LOG(SESSION, DEBUG, "  tim_meas         : %d",
		urr_rep->tim_meas);
	time_val = urr_rep->first_pkt_time;
	LOG(SESSION, DEBUG, "  first_pkt_time   : %s", ctime(&time_val));
	time_val = urr_rep->last_pkt_time;
	LOG(SESSION, DEBUG, "  last_pkt_time    : %s", ctime(&time_val));
	LOG(SESSION, DEBUG, "  usage_info.ube   : %d",
		urr_rep->usage_info.d.ube);
	LOG(SESSION, DEBUG, "  usage_info.uae   : %d",
		urr_rep->usage_info.d.uae);
	LOG(SESSION, DEBUG, "  usage_info.aft   : %d",
		urr_rep->usage_info.d.aft);
	LOG(SESSION, DEBUG, "  usage_info.bef   : %d\r\n",
		urr_rep->usage_info.d.bef);

#ifndef LOG_MODE_DEBUG
    (void)time_val;
#endif
}

void session_report_urr_content_copy(
    session_report_request_ur *urr_dst, comm_msg_urr_report_t *urr_src)
{
    urr_dst->urr_id = urr_src->urr_id;
    urr_dst->ur_seqn = urr_src->ur_seqn;
    urr_dst->trigger.value = urr_src->trigger.value;

    if (urr_src->start_time) {
        urr_dst->member_flag.d.start_time_present = 1;
        urr_dst->start_time = urr_src->start_time;
    }
    if (urr_src->end_time) {
        urr_dst->member_flag.d.end_time_present = 1;
        urr_dst->end_time = urr_src->end_time;
    }

    urr_dst->vol_meas.flag.value = urr_src->vol_meas.flag.value;
    if (urr_dst->vol_meas.flag.value) {
        urr_dst->member_flag.d.vol_meas_present = 1;
        urr_dst->vol_meas.total     = urr_src->vol_meas.total;
        urr_dst->vol_meas.uplink    = urr_src->vol_meas.uplink;
        urr_dst->vol_meas.downlink  = urr_src->vol_meas.downlink;
    }

    if (urr_src->tim_meas_present) {
        urr_dst->member_flag.d.duration_present = 1;
        urr_dst->duration = urr_src->tim_meas;
    }

    /* lost app detect */
    if (urr_src->app_detect.stub) {

    }

    urr_dst->ue_ip.ueip_flag.value = urr_src->ue_ip.type.value;
    if (urr_dst->ue_ip.ueip_flag.value) {
        urr_dst->member_flag.d.ue_ip_present = 1;
        urr_dst->ue_ip.ipv4_addr = urr_src->ue_ip.ipv4;
        ros_memcpy(urr_dst->ue_ip.ipv6_addr, &urr_src->ue_ip.ipv6, IPV6_ALEN);
        urr_dst->ue_ip.ipv6_prefix= urr_src->ue_ip.ipv6_prefix_bits;
    }

    /* lost network instance */
    if (urr_src->network_instance) {
        urr_dst->member_flag.d.network_instance_present = 1;
    }

    if (urr_src->first_pkt_time) {
        urr_dst->member_flag.d.first_pkt_time_present = 1;
        urr_dst->first_pkt_time = urr_src->first_pkt_time;
    }

    if (urr_src->last_pkt_time) {
        urr_dst->member_flag.d.last_pkt_time_present = 1;
        urr_dst->last_pkt_time = urr_src->last_pkt_time;
    }

    if (urr_src->usage_info.value) {
        urr_dst->member_flag.d.usage_info_present = 1;
        urr_dst->usage_info.value = urr_src->usage_info.value;
    }

    if (urr_src->query_urr_ref) {
        urr_dst->member_flag.d.query_urr_ref_present = 1;
        urr_dst->query_urr_ref = urr_src->query_urr_ref;
    }

    if (urr_src->eve_stamp) {
        urr_dst->member_flag.d.eve_stamp_present = 1;
        urr_dst->eve_stamp = urr_src->eve_stamp;
    }
}

int session_report_local_urr(comm_msg_urr_report_t *config, uint8_t usage_report_num, uint16_t trigger)
{
    session_report_request report_req = {{0}};
    struct urr_table *urr_entry;
	uint32_t          index;
	uint8_t	cnt;

    if (NULL == config) {
        LOG(SESSION, ERR, "Abnormal parameters, config(%p).", config);
        return -1;
    }
	if(usage_report_num > MAX_URR_NUM) {
		LOG(SESSION, ERR, "Abnormal parameters, usage_report_num(%d).", usage_report_num);
        return -1;
	}

	index = config[0].urr_index;
	for(cnt=0; cnt<usage_report_num; cnt++) {

		session_show_urr_report(&config[cnt]);

	    urr_entry = urr_get_table(config[cnt].urr_index);
	    if (NULL == urr_entry || NULL == urr_entry->sess) {
	        LOG(SESSION, ERR, "get urr session failed,"
	            " urr_entry(%p), session(%p), Not reported.",
	            urr_entry, urr_entry ? urr_entry->sess : NULL);
	        return -1;
	    }

	    /* filling SEID */
		report_req.local_seid = urr_entry->sess->session.local_seid;
		report_req.cp_seid	= urr_entry->sess->session.cp_seid;
	    report_req.msg_header.node_id_index = urr_entry->sess->session.node_index;
	    report_req.report_type.d.USAR = 1;
	    /* modify urr index to urr id */
	    config[cnt].urr_id = urr_entry->urr.urr_id;
	    session_report_urr_content_copy(&report_req.usage_report_arr[cnt], &config[cnt]);

	}
	report_req.usage_report_num = usage_report_num;

    /* send info to UPC */
	if (0 > session_report_publish(&report_req)) {
		LOG(SESSION, ERR, "publish report info to smu failed.");
		return -1;
	}

	urr_entry = urr_get_table(index);
	urr_entry->sess->msg_type = SESS_SESSION_REPORT_REQUEST;
	urr_entry->sess->urr_index_arr[0] = index;
	urr_entry->sess->trigger = trigger;

	//ros_timer_start(urr_entry->sess->timeout_timer);

    return 0;
}

int session_report_urr(comm_msg_ie_t *ie)
{
    comm_msg_urr_report_t *config = NULL;

    config = (comm_msg_urr_report_t *)(ie->data);
	session_urr_report_ntohl(config);
    LOG(SESSION, RUNNING, "get urr report, ie(%u).",
        ntohl(ie->index));

    return session_report_local_urr(config, 1,0xffff);
}

int session_report_teid_err(struct session_peer_fteid_entry *fteid_entry)
{
    session_report_request report_req = {{0}};
    session_error_indication_report *err_indic = NULL;

    if (NULL == fteid_entry) {
        LOG(SESSION, ERR, "Abnormal parameter, peer f-teid entry(%p).", fteid_entry);
        return -1;
    }

    /* filling SEID */
	report_req.local_seid   = fteid_entry->sess_cfg->local_seid;
	report_req.cp_seid	    = fteid_entry->sess_cfg->cp_seid;
    report_req.report_type.d.ERIR = 1;
	report_req.msg_header.node_id_index = fteid_entry->sess_cfg->node_index;
    /* fill remote f-teid */
    err_indic = &report_req.err_indic_report;
    err_indic->remote_f_teid_arr[0].teid = fteid_entry->fteid_key.teid;
    err_indic->remote_f_teid_arr[0].f_teid_flag.value = fteid_entry->ip_flag;
    if (SESSION_IP_V4 == fteid_entry->ip_flag) {
        err_indic->remote_f_teid_arr[0].ipv4_addr = fteid_entry->fteid_key.ipv4;
    } else {
        /* Default IPv6 */
        ros_memcpy(err_indic->remote_f_teid_arr[0].ipv6_addr, fteid_entry->fteid_key.ipv6, IPV6_ALEN);
    }
    err_indic->f_teid_num = 1;

    /* send info to UPC */
	if (0 > session_report_publish(&report_req)) {
		LOG(SESSION, ERR, "publish report info to smu failed.");
	}

    return 0;
}


int session_node_report_publish(session_node_report_request *node_req)
{
    if (node_req == NULL) {
        LOG(SESSION, ERR, "abnormal parameter, session_node_report_request: %p.", node_req);
        return -1;
    }

	node_req->msg_header.seq_num = ros_atomic32_add_return(&sequece_number, 1);
	node_req->msg_header.msg_type = SESS_NODE_REPORT_REQUEST;

    LOG(SESSION, RUNNING, "seqence number: %d.", node_req->msg_header.seq_num);

    upc_report_proc(node_req, sizeof(session_node_report_request));

	return 0;
}


int session_node_report_gtpu_err(struct session_gtpu_entry *gtpu_entry)
{
    session_node_report_request report_req = {{0}};
    session_up_path_failure_report *upfr = NULL;

    if (NULL == gtpu_entry) {
        LOG(SESSION, ERR, "Abnormal parameter, gtpu_entry(%p).", gtpu_entry);
        return -1;
    }

    /* filling node_req */
    report_req.node_report_type.d.UPFR = 1;
	report_req.msg_header.node_id_index = gtpu_entry->node_index;
    /* fill remote GTPU */
    upfr = &report_req.path_fail_report;

    switch (gtpu_entry->ip_flag) {
        case SESSION_IP_V4:
            upfr->gtpu_peer_arr[0].regtpr_flag.d.V4 = 1;
            upfr->gtpu_peer_arr[0].ipv4_addr = gtpu_entry->ip_addr.ipv4;
            LOG(SESSION, RUNNING, "upfr->gtpu_peer_arr[0].ipv4_addr is 0x%08x.",
                upfr->gtpu_peer_arr[0].ipv4_addr);
            break;

        case SESSION_IP_V6:
            upfr->gtpu_peer_arr[0].regtpr_flag.d.V6 = 1;
            ros_memcpy(upfr->gtpu_peer_arr[0].ipv6_addr,
                gtpu_entry->ip_addr.ipv6, IPV6_ALEN);
            LOG(SESSION, RUNNING,
    			"upfr->gtpu_peer_arr[0].ipv6_addr is : 0x%08x %08x %08x %08x.",
            ntohl(*(uint32_t *)(upfr->gtpu_peer_arr[0].ipv6_addr)),
            ntohl(*(uint32_t *)(upfr->gtpu_peer_arr[0].ipv6_addr + 4)),
            ntohl(*(uint32_t *)(upfr->gtpu_peer_arr[0].ipv6_addr + 8)),
            ntohl(*(uint32_t *)(upfr->gtpu_peer_arr[0].ipv6_addr + 12)));
            break;
    }

    upfr->gtpu_peer_arr[0].regtpr_flag.d.DI = 1;
    upfr->gtpu_peer_arr[0].des_if_len = 1;
    upfr->gtpu_peer_arr[0].dest_if = gtpu_entry->port;
    LOG(SESSION, RUNNING, "upfr->gtpu_peer_arr[0].dest_if is %d.",
            upfr->gtpu_peer_arr[0].dest_if);

    /*if (strlen(gtpu_entry->gtpu_cfg.network_inst)) {
        upfr->gtpu_peer_arr[0].regtpr_flag.d.NI = 1;
        upfr->gtpu_peer_arr[0].net_inst_len = strlen(gtpu_entry->gtpu_cfg.network_inst);
        strcpy(upfr->gtpu_peer_arr[0].net_instance, gtpu_entry->gtpu_cfg.network_inst);
        LOG(SESSION, RUNNING, "upfr->gtpu_peer_arr[0].net_instance is %s.",
			upfr->gtpu_peer_arr[0].net_instance);
    }*/

    upfr->gtpu_peer_num = 1;
    /* send info to UPC */
	if (0 > session_node_report_publish(&report_req)) {
		LOG(SESSION, ERR, "publish report info to smu failed.");
	}

    return 0;
}

int session_report_inactivity(struct session_t *sess)
{
	session_report_request report_req = {{0}};

	if (NULL == sess) {
		LOG(SESSION, ERR, "Abnormal parameter, sess(%p).", sess);
		return -1;
	}

	/* filling SEID */
	report_req.local_seid = sess->session.local_seid;
	report_req.cp_seid	= sess->session.cp_seid;
	report_req.msg_header.node_id_index = sess->session.node_index;
	report_req.report_type.d.UPIR = 1;

	/* send info to UPC */
	if (0 > session_report_publish(&report_req)) {
		LOG(SESSION, ERR, "publish report info to smu failed.");
	}

	return 0;
}


