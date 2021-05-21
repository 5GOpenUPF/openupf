/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"

#include "session_mgmt.h"
#include "session_msg.h"
#include "session_teid.h"

#include "far_mgmt.h"
#include "bar_mgmt.h"
#include "urr_mgmt.h"
#include "qer_mgmt.h"
#include "mar_mgmt.h"
#include "pdr_mgmt.h"
#include "session_instance.h"
#include "session_audit.h"
#include "sp_backend_mgmt.h"
#include "session_orphan.h"
#include "session_match.h"

#include "local_parse.h"

#include "session_report.h"
#include "traffic_endpoint_mgmt.h"
#include "pfd_mgmt.h"
#include "white_list.h"
#include "tuple_table.h"
#include "sp_dns_cache.h"
#include "session_ethernet.h"
#include "predefine_rule_mgmt.h"

#ifdef SUPPORT_REST_API
#include "ulfius.h"
#endif


/* SPU packets status */
ros_atomic64_t sess_pkt_stat[SESSION_PKT_STATUS_BUTT];

/* FPU latest statistics */
comm_msg_fpu_stat sess_recv_fpu_stat;
ros_rwlock_t sess_fpu_stat_lock = {.cnt = 0};
static uint32_t sess_fpu_last_ul_stat, sess_fpu_last_dl_stat;
static uint32_t sess_fpu_last_stat_time; /* in second */

#ifdef SUPPORT_REST_API
/* REST api instance */
struct _u_instance sess_restful_instance;
#endif

void session_pkt_status_add(int unit)
{
    if (unit < SESSION_PKT_STATUS_BUTT)
        ros_atomic64_add(&sess_pkt_stat[unit], 1);
    else
        LOG(SESSION, ERR, "Recording SPU status failed.\r\n");
}

int64_t session_pkt_status_read(int unit)
{
    if (unit < SESSION_PKT_STATUS_BUTT)
        return ros_atomic64_read(&sess_pkt_stat[unit]);
    else
        LOG(SESSION, ERR, "Recording SPU status failed.\r\n");

    return 0;
}

void session_pkt_status_init(void)
{
    int cnt;

    for (cnt = 0; cnt < SESSION_PKT_STATUS_BUTT; ++cnt)
        ros_atomic64_init(&sess_pkt_stat[cnt]);
}

void session_update_fpu_status(comm_msg_fpu_stat *fpu_stat)
{
    uint32_t iloop;

    ros_rwlock_write_lock(&sess_fpu_stat_lock); /* lock */
    sess_recv_fpu_stat.internal_send_stat = ntohl(fpu_stat->internal_send_stat);
    sess_recv_fpu_stat.internal_recv_stat = ntohl(fpu_stat->internal_recv_stat);
    for (iloop = 0; iloop < COMM_MSG_FP_STAT_BUTT; iloop++) {
        sess_recv_fpu_stat.external_stat[iloop] = ntohl(fpu_stat->external_stat[iloop]);
    }
    sess_recv_fpu_stat.fp_fast_stat     = ntohl(fpu_stat->fp_fast_stat);
    sess_recv_fpu_stat.fp_inst_stat     = ntohl(fpu_stat->fp_inst_stat);
    sess_recv_fpu_stat.fp_far_stat      = ntohl(fpu_stat->fp_far_stat);
    sess_recv_fpu_stat.fp_qer_stat      = ntohl(fpu_stat->fp_qer_stat);
    sess_recv_fpu_stat.fp_bar_stat      = ntohl(fpu_stat->fp_bar_stat);
    sess_recv_fpu_stat.fp_cblk_stat     = ntohl(fpu_stat->fp_cblk_stat);
    sess_recv_fpu_stat.fp_block_stat    = ntohl(fpu_stat->fp_block_stat);
    sess_recv_fpu_stat.fp_mac_stat      = ntohl(fpu_stat->fp_mac_stat);

    ros_rwlock_write_unlock(&sess_fpu_stat_lock); /* unlock */
}

void session_get_fpu_status(comm_msg_fpu_stat *stat)
{
    ros_rwlock_read_lock(&sess_fpu_stat_lock); /* lock */
    ros_memcpy(stat, &sess_recv_fpu_stat, sizeof(comm_msg_fpu_stat));
    ros_rwlock_read_unlock(&sess_fpu_stat_lock); /* unlock */
}

uint64_t session_mac_strtoll(uint8_t *mac)
{
    uint64_t mac_tmp = 0ULL;

    mac_tmp |= (uint64_t)mac[0] << 40;
    mac_tmp |= (uint64_t)mac[1] << 32;
    mac_tmp |= (uint64_t)mac[2] << 24;
    mac_tmp |= (uint64_t)mac[3] << 16;
    mac_tmp |= (uint64_t)mac[4] << 8;
    mac_tmp |= (uint64_t)mac[5];

    return mac_tmp;
}

inline void session_print_string(uint8_t *data, uint32_t data_len)
{
	uint32_t cnt = 0;

	printf("buffer len: %d\nbuffer: \n", data_len);
	for (cnt = 0; cnt < data_len; ++cnt) {
		printf("\\x%02x", (uint8_t)data[cnt]);
	}
	printf("\n");
}

int session_pkt_match_process(char *buf, int len, int fd)
{
    struct packet_desc  desc = {.buf = buf, .len = len, .offset = 0};
    struct filter_key   match_key;
    uint32_t            fast_tid;
    uint8_t             type;

    if (packet_dissect(&desc, &match_key) < 0) {
        LOG(SESSION, ERR, "packet dissect failed!");
        /* Keep going */
    }

#ifdef RECORD_FAST_INFO_NEW_VER
    len -= RECORD_FAST_INFO_LEN;

    fast_tid = GET_FAST_TID(&buf[len]);
    type = GET_FAST_TYPE(&buf[len]);
#else
    fast_tid = GET_FAST_TID(buf);
    type = GET_FAST_TYPE(buf);
#endif
    LOG(SESSION, RUNNING, "fast_tid: %u, fast_type: %d.", fast_tid, type);

    session_match(&match_key, fast_tid, type, fd);
    LOG(SESSION, RUNNING, "packet process finish!\n");
    session_pkt_status_add(SESSION_PKT_RECV_FORM_FPU);

    return 0;
}

void session_collect_fp_status(char *stat_str, comm_msg_fpu_stat *stat_data)
{
    uint32_t data_len = 0;
    uint32_t pkt_cnt = 0, stat_mod_cnt;
    char mod_name[128];
    uint32_t dorp_pkt;
    int stat_unit[] = {COMM_MSG_FP_STAT_UP_RECV,
                        COMM_MSG_FP_STAT_UP_FWD,
                        COMM_MSG_FP_STAT_UP_DROP,
                        COMM_MSG_FP_STAT_DOWN_RECV,
                        COMM_MSG_FP_STAT_DOWN_FWD,
                        COMM_MSG_FP_STAT_DOWN_DROP};
    int stat_max_unit = sizeof(stat_unit) / sizeof(stat_unit[0]);
    uint32_t cur_time = ros_getime();

    /*---------------internal status---------------*/
    data_len += sprintf(&stat_str[data_len], "# HELP fpu_internal_status Statistics of FPU in UPF.\n");
    data_len += sprintf(&stat_str[data_len], "# TYPE fpu_internal_status gauge\n");

    data_len += sprintf(&stat_str[data_len], "fpu_internal_status{name=\"all_core_send\"} %u\n",
        stat_data->internal_send_stat);
    data_len += sprintf(&stat_str[data_len], "fpu_internal_status{name=\"all_core_recv\"} %u\n",
        stat_data->internal_recv_stat);
    data_len = strlen(stat_str);

    for (stat_mod_cnt = 0; stat_mod_cnt < COMM_MSG_FP_STAT_BUTT; ++stat_mod_cnt) {
        switch (stat_mod_cnt) {
            case COMM_MSG_FP_STAT_N3_MATCH:
                sprintf(mod_name, "N3_MATCH");
                break;
            case COMM_MSG_FP_STAT_N3_NOMATCH:
                sprintf(mod_name, "N3_NOMATCH");
                break;
            case COMM_MSG_FP_STAT_N3_ECHO:
                sprintf(mod_name, "N3_ECHO");
                break;
            case COMM_MSG_FP_STAT_N6_MATCH:
                sprintf(mod_name, "N6_MATCH");
                break;
            case COMM_MSG_FP_STAT_N6_NOMATCH:
                sprintf(mod_name, "N6_NOMATCH");
                break;
            case COMM_MSG_FP_STAT_MOD_FAST:
                sprintf(mod_name, "MOD_FAST");
                break;
            case COMM_MSG_FP_STAT_FROM_SPU:
                sprintf(mod_name, "FROM_SPU");
                break;
            case COMM_MSG_FP_STAT_REPORT_REQ:
                sprintf(mod_name, "REPORT_REQ");
                break;
            case COMM_MSG_FP_STAT_ARP:
                sprintf(mod_name, "ARP");
                break;
            case COMM_MSG_FP_STAT_ROUTE:
                sprintf(mod_name, "ROUTE");
                break;
            case COMM_MSG_FP_STAT_UP_RECV:
                sprintf(mod_name, "UP_RECV");
                break;
            case COMM_MSG_FP_STAT_UP_FWD:
                sprintf(mod_name, "UP_FWD");
                break;
            case COMM_MSG_FP_STAT_UP_DROP:
                sprintf(mod_name, "UP_DROP");
                break;
            case COMM_MSG_FP_STAT_DOWN_RECV:
                sprintf(mod_name, "DOWN_RECV");
                break;
            case COMM_MSG_FP_STAT_DOWN_FWD:
                sprintf(mod_name, "DOWN_FWD");
                break;
            case COMM_MSG_FP_STAT_DOWN_DROP:
                sprintf(mod_name, "DOWN_DROP");
                break;
            case COMM_MSG_FP_STAT_UNSUPPORT_PKT:
                sprintf(mod_name, "UNSUPPORT_PKT");
                break;
            case COMM_MSG_FP_STAT_ERR_PROC:
                sprintf(mod_name, "ERR_PROC");
                break;

            default:
                sprintf(mod_name, "INDEX_%u", stat_mod_cnt);
                break;
        }

        data_len += sprintf(&stat_str[data_len], "fpu_internal_status{name=\"%s\"} %u\n",
            mod_name, stat_data->external_stat[stat_mod_cnt]);
    }

    /*---------------external status---------------*/
    data_len += sprintf(&stat_str[data_len], "# HELP fpu_external_status Statistics of FPU in UPF.\n");
    data_len += sprintf(&stat_str[data_len], "# TYPE fpu_external_status gauge\n");

    for (stat_mod_cnt = 0; stat_mod_cnt < stat_max_unit; ++stat_mod_cnt) {
        switch (stat_unit[stat_mod_cnt]) {
            case COMM_MSG_FP_STAT_UP_RECV:
                sprintf(mod_name, "UP_recv");
                break;
            case COMM_MSG_FP_STAT_UP_FWD:
                sprintf(mod_name, "UP_forward");
                break;
            case COMM_MSG_FP_STAT_UP_DROP:
                sprintf(mod_name, "UP_drop");
                break;
            case COMM_MSG_FP_STAT_DOWN_RECV:
                sprintf(mod_name, "DOWN_recv");
                break;
            case COMM_MSG_FP_STAT_DOWN_FWD:
                sprintf(mod_name, "DOWN_forward");
                break;
            case COMM_MSG_FP_STAT_DOWN_DROP:
                sprintf(mod_name, "DOWN_drop");
                break;

            default:
                sprintf(mod_name, "index_%u", stat_unit[stat_mod_cnt]);
                break;
        }

        data_len += sprintf(&stat_str[data_len], "fpu_external_status{name=\"%s\"} %u\n",
            mod_name, stat_data->external_stat[stat_unit[stat_mod_cnt]]);
    }

    /* UPlink packet loss rate */
    pkt_cnt = stat_data->external_stat[COMM_MSG_FP_STAT_UP_RECV];
    dorp_pkt = stat_data->external_stat[COMM_MSG_FP_STAT_UP_DROP];
    if (pkt_cnt)
        data_len += sprintf(&stat_str[data_len], "fpu_external_status{name=\"UP_loss_rate\"} %.4lf\n",
            (double)dorp_pkt/(double)pkt_cnt);
    else
        data_len += sprintf(&stat_str[data_len], "fpu_external_status{name=\"UP_loss_rate\"} 0\n");

    /* DOWNlink packet loss rate */
    pkt_cnt = stat_data->external_stat[COMM_MSG_FP_STAT_DOWN_RECV];
    dorp_pkt = stat_data->external_stat[COMM_MSG_FP_STAT_DOWN_DROP];
    if (pkt_cnt)
        data_len += sprintf(&stat_str[data_len], "fpu_external_status{name=\"DOWN_loss_rate\"} %.4lf\n",
            (double)dorp_pkt/(double)pkt_cnt);
    else
        data_len += sprintf(&stat_str[data_len], "fpu_external_status{name=\"DOWN_loss_rate\"} 0\n");

    /* pps */
    if (sess_fpu_last_stat_time && cur_time > sess_fpu_last_stat_time) {
        uint32_t diff_time = cur_time - sess_fpu_last_stat_time;
        double pps;

        /* uplink */
        if (stat_data->external_stat[COMM_MSG_FP_STAT_UP_RECV] &&
            sess_fpu_last_ul_stat < stat_data->external_stat[COMM_MSG_FP_STAT_UP_RECV]) {
            pps = (double)(stat_data->external_stat[COMM_MSG_FP_STAT_UP_RECV] - sess_fpu_last_ul_stat)
                / (double)diff_time;
            data_len += sprintf(&stat_str[data_len], "fpu_external_status{name=\"UL_kpps\"} %.4lf\n",
                pps/1000);
        } else {
            data_len += sprintf(&stat_str[data_len], "fpu_external_status{name=\"UL_kpps\"} 0\n");
        }

        /* downlink */
        if (stat_data->external_stat[COMM_MSG_FP_STAT_DOWN_RECV] &&
            sess_fpu_last_dl_stat < stat_data->external_stat[COMM_MSG_FP_STAT_DOWN_RECV]) {
            pps = (double)(stat_data->external_stat[COMM_MSG_FP_STAT_DOWN_RECV] - sess_fpu_last_dl_stat)
                / (double)diff_time;
            data_len += sprintf(&stat_str[data_len], "fpu_external_status{name=\"DL_kpps\"} %.4lf\n",
                pps/1000);
        } else {
            data_len += sprintf(&stat_str[data_len], "fpu_external_status{name=\"DL_kpps\"} 0\n");
        }
    }
    sess_fpu_last_ul_stat = stat_data->external_stat[COMM_MSG_FP_STAT_UP_RECV];
    sess_fpu_last_dl_stat = stat_data->external_stat[COMM_MSG_FP_STAT_DOWN_RECV];
    sess_fpu_last_stat_time = cur_time;

    /*---------------resource status---------------*/
    data_len += sprintf(&stat_str[data_len], "# HELP fpu_res_status Statistics of FPU in UPF.\n");
    data_len += sprintf(&stat_str[data_len], "# TYPE fpu_res_status gauge\n");

    data_len += sprintf(&stat_str[data_len], "fpu_res_status{name=\"fast_stat\"} %u\n",
        stat_data->fp_fast_stat);
    data_len += sprintf(&stat_str[data_len], "fpu_res_status{name=\"inst_stat\"} %u\n",
        stat_data->fp_inst_stat);
    data_len += sprintf(&stat_str[data_len], "fpu_res_status{name=\"far_stat\"} %u\n",
        stat_data->fp_far_stat);
    data_len += sprintf(&stat_str[data_len], "fpu_res_status{name=\"qer_stat\"} %u\n",
        stat_data->fp_qer_stat);
    data_len += sprintf(&stat_str[data_len], "fpu_res_status{name=\"bar_stat\"} %u\n",
        stat_data->fp_bar_stat);
    data_len += sprintf(&stat_str[data_len], "fpu_res_status{name=\"cblk_stat\"} %u\n",
        stat_data->fp_cblk_stat);
    data_len += sprintf(&stat_str[data_len], "fpu_res_status{name=\"block_stat\"} %u\n",
        stat_data->fp_block_stat);
    data_len += sprintf(&stat_str[data_len], "fpu_res_status{name=\"mac_stat\"} %u\n",
        stat_data->fp_mac_stat);
}

#ifdef SUPPORT_REST_API
static void session_update_status_timer_cb(void *tim, uint64_t para)
{
    comm_msg_header_t   *msg;
    comm_msg_rules_ie_t *ie = NULL;
    uint8_t buf[256];
    uint32_t buf_len;

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd         = htons(EN_COMM_MSG_COLLECT_STATUS);
    ie->rules_num   = 0;
    buf_len         = COMM_MSG_IE_LEN_COMMON;
    ie->len         = htons(buf_len);
    buf_len        += COMM_MSG_HEADER_LEN;
    msg->total_len  = htonl(buf_len);

    if (0 > session_msg_send_to_fp((char *)buf, buf_len, MB_SEND2BE_BROADCAST_FD)) {
        LOG(SESSION, ERR, "Send msg failed.");
    }
}

int session_update_status_to_promu(const struct _u_request *request,
    struct _u_response *response, void *user_data)
{
    char data[8192];
    uint32_t data_len = 0;
    uint32_t equ_flag = 0;
    struct session_mgmt_cb *sess_mgmt = session_mgmt_head();
    struct pdr_table_head *pdr_mgmt = pdr_get_head();
    struct far_table_head *far_mgmt = far_get_head();
    struct qer_table_head *qer_mgmt = qer_get_head();
    struct urr_table_head *urr_mgmt = urr_get_head();
    struct bar_table_head *bar_mgmt = bar_get_head();
    struct mar_table_head *mar_mgmt = mar_get_head();
    pfd_table_header *pfd_mgmt = pfd_get_table_header_public();
    tuple_table_head *tuple_mgmt = tuple_head_get_public();
    sp_dns_cache_table *dns_mgmt = sdc_get_table_public();
    char stat_name[32];
    comm_msg_fpu_stat stat_data;

    session_update_status_timer_cb(NULL, 0);

    sprintf(stat_name, "spu_res_status");
    data_len += sprintf(&data[data_len], "# HELP %s Statistics of SPU in UPF.\n", stat_name);
    data_len += sprintf(&data[data_len], "# TYPE %s gauge\n", stat_name);

    /* session resource */
    equ_flag = (Res_GetAlloced(sess_mgmt->pool_id) == ros_atomic32_read(&sess_mgmt->use_num));
    data_len += sprintf(&data[data_len], "%s{name=\"session\"} %u\n", stat_name,
        equ_flag ? Res_GetAlloced(sess_mgmt->pool_id) : (uint32_t)-1);

    /* pdr resource */
    equ_flag = (Res_GetAlloced(pdr_mgmt->pool_id) == ros_atomic32_read(&pdr_mgmt->use_num));
    data_len += sprintf(&data[data_len], "%s{name=\"pdr\"} %u\n", stat_name,
        equ_flag ? Res_GetAlloced(pdr_mgmt->pool_id) : (uint32_t)-1);

    /* far resource */
    equ_flag = (Res_GetAlloced(far_mgmt->pool_id) == ros_atomic32_read(&far_mgmt->use_num));
    data_len += sprintf(&data[data_len], "%s{name=\"far\"} %u\n", stat_name,
        equ_flag ? Res_GetAlloced(far_mgmt->pool_id) : (uint32_t)-1);

    /* qer resource */
    equ_flag = (Res_GetAlloced(qer_mgmt->pool_id) == ros_atomic32_read(&qer_mgmt->use_num));
    data_len += sprintf(&data[data_len], "%s{name=\"qer\"} %u\n", stat_name,
        equ_flag ? Res_GetAlloced(qer_mgmt->pool_id) : (uint32_t)-1);

    /* urr resource */
    equ_flag = (Res_GetAlloced(urr_mgmt->pool_id) == ros_atomic32_read(&urr_mgmt->use_num));
    data_len += sprintf(&data[data_len], "%s{name=\"urr\"} %u\n", stat_name,
        equ_flag ? Res_GetAlloced(urr_mgmt->pool_id) : (uint32_t)-1);

    /* bar resource */
    equ_flag = (Res_GetAlloced(bar_mgmt->pool_id) == ros_atomic32_read(&bar_mgmt->use_num));
    data_len += sprintf(&data[data_len], "%s{name=\"bar\"} %u\n", stat_name,
        equ_flag ? Res_GetAlloced(bar_mgmt->pool_id) : (uint32_t)-1);

    /* mar resource */
    equ_flag = (Res_GetAlloced(mar_mgmt->pool_id) == ros_atomic32_read(&mar_mgmt->use_num));
    data_len += sprintf(&data[data_len], "%s{name=\"mar\"} %u\n", stat_name,
        equ_flag ? Res_GetAlloced(mar_mgmt->pool_id) : (uint32_t)-1);

    /* pfd management resource */
    data_len += sprintf(&data[data_len], "%s{name=\"pfd\"} %u\n", stat_name,
        Res_GetAlloced(pfd_mgmt->pool_id));

    /* tuple table resource */
    data_len += sprintf(&data[data_len], "%s{name=\"tuple\"} %u\n", stat_name,
        Res_GetAlloced(tuple_mgmt->pool_id));

    /* dns table resource */
    data_len += sprintf(&data[data_len], "%s{name=\"dns\"} %u\n", stat_name,
        Res_GetAlloced(dns_mgmt->pool_id));

    /****************** SPU packet status *******************/
    sprintf(stat_name, "spu_pkt_status");
    data_len += sprintf(&data[data_len], "# HELP %s Statistics of SPU in UPF.\n", stat_name);
    data_len += sprintf(&data[data_len], "# TYPE %s gauge\n", stat_name);

    data_len += sprintf(&data[data_len], "%s{name=\"recv_form_fpu\"} %ld\n", stat_name,
        session_pkt_status_read(SESSION_PKT_RECV_FORM_FPU));
    data_len += sprintf(&data[data_len], "%s{name=\"send_fast_modify\"} %ld\n", stat_name,
        session_pkt_status_read(SESSION_PKT_MDF_FAST));

    session_get_fpu_status(&stat_data);
    session_collect_fp_status(&data[data_len], &stat_data);

    ulfius_set_string_body_response(response, 200, data);

    return U_CALLBACK_CONTINUE;
}

#endif

static void session_stop_all_audit_timer(void)
{
    uint32_t cnt;

    for (cnt = EN_AUDIT_HEAD; cnt < EN_AUDIT_BUTT; ++cnt) {
        rules_stop_audit(cnt);
    }
}

static void session_start_all_audit_timer(void)
{
    uint32_t cnt;

    for (cnt = EN_AUDIT_HEAD; cnt < EN_AUDIT_BUTT; ++cnt) {
        rules_start_audit(cnt);
    }
}

int session_init(upc_config_info *upc_conf)
{
    /* First add the memory used by ros_timer */
    int64_t total_mem = 0, ret = 0;

    ret = tuple_table_init(upc_conf->fast_num);
    if (ret < 0) {
        LOG(SESSION, ERR, "tuple_table_init failed, fast_num:%u,",
            upc_conf->fast_num);
        return -1;
    }
    total_mem += ret;

    ret = session_mgmt_init(upc_conf->session_num);
    if (ret < 0) {
        LOG(SESSION, ERR, "session_mgmt_init failed, session number: %u.", upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    set_audit_switch(upc_conf->audit_switch);
    set_audit_time(upc_conf->audit_period);

    ret = pdr_table_init(upc_conf->session_num);
    if (ret < 0) {
        LOG(SESSION, ERR, "pdr_table_init failed, session number: %u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    ret = traffic_endpoint_table_init(upc_conf->session_num);
    if (ret < 0) {
        LOG(SESSION, ERR, "traffic_endpoint_table_init failed, session number: %u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    ret = far_table_init(upc_conf->session_num);
    if (ret < 0) {
        LOG(SESSION, ERR, "far_table_init failed, session number: %u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    ret = bar_table_init(upc_conf->session_num);
    if (ret < 0) {
        LOG(SESSION, ERR, "bar_table_init failed, session number: %u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    ret = urr_table_init(upc_conf->session_num);
    if (ret < 0) {
        LOG(SESSION, ERR, "urr_table_init failed, session number: %u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    ret = qer_table_init(upc_conf->session_num);
    if (ret < 0) {
        LOG(SESSION, ERR, "qer_table_init failed, session number: %u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    ret = mar_table_init(upc_conf->session_num);
    if (ret < 0) {
        LOG(SESSION, ERR, "mar_table_init failed, session number: %u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

	ret = white_list_table_init(MAX_WHITE_LIST_TABLE);
	if (ret < 0) {
        LOG(SESSION, ERR, "white_list_table_init failed, white_list number: %u.",
            MAX_WHITE_LIST_TABLE);
        return -1;
    }
    total_mem += ret;

    /* Init predefined rules */
    ret = predef_rules_table_init(MAX_PREDEFINED_RULES_NUM);
	if (ret < 0) {
        LOG(SESSION, ERR, "Predefined rules init failed, number: %u.",
            MAX_PREDEFINED_RULES_NUM);
        return -1;
    }
    total_mem += ret;

    ret = session_instance_init(upc_conf->session_num);
    if (ret < 0){
        LOG(SESSION, ERR, "session_instance_init failed, session_num:%u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    ret = session_orphan_table_init(upc_conf->orphan_number);
    if (0 > ret) {
        LOG(SESSION, ERR, "orphan_table_init failed, orphan_number: %u.",
            upc_conf->orphan_number);
        return -1;
    }
    total_mem += ret;

    /* session teid init must be before session node init */
    ret = session_gtpu_init(upc_conf->session_num);
    if (0 > ret) {
        LOG(SESSION, ERR, "teid_init failed, session_num: %u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    ret = pfd_table_init(upc_conf->pfd_number);
    if (0 > ret) {
        LOG(SESSION, ERR, "pfd_table_init failed, pfd_number: %u.",
            upc_conf->pfd_number);
        return -1;
    }
    total_mem += ret;

    {
        extern CVMX_SHARED ST_RES_POOL    *gpstResPoolAssigner;

        LOG(UPC, MUST, "Resource pool uiTotal: %u, uiSecNum: %u, uiAlloced: %u",
            gpstResPoolAssigner->uiTotal, gpstResPoolAssigner->uiSecNum,
            gpstResPoolAssigner->uiAlloced);
    }

    ret = sdc_init(upc_conf->dns_num);
    if (0 > ret) {
        LOG(SESSION, ERR, "sdc_init failed, dns_num: %u.",
            upc_conf->dns_num);
        return -1;
    }
    total_mem += ret;

    ret = se_table_init(upc_conf->session_num);
    if (0 > ret) {
        LOG(SESSION, ERR, "Session ethernet table init failed, session_num: %u.",
            upc_conf->session_num);
        return -1;
    }
    total_mem += ret;

    session_start_all_audit_timer();

    LOG(SESSION, RUNNING, "inst size: %lu", sizeof(comm_msg_inst_config));
    LOG(SESSION, RUNNING, "far size: %lu", sizeof(comm_msg_far_config));
    LOG(SESSION, RUNNING, "qer size: %lu", sizeof(comm_msg_qer_config));
    LOG(SESSION, RUNNING, "bar size: %lu", sizeof(comm_msg_bar_config));
    LOG(SESSION, RUNNING, "urr size: %lu", sizeof(comm_msg_urr_config));
    LOG(SESSION, RUNNING, "report_request size: %lu\n", sizeof(session_report_request));
    LOG(SESSION, RUNNING, "session_content_create size: %lu\n", sizeof(session_content_create));
    LOG(SESSION, RUNNING, "session_content_modify size: %lu\n", sizeof(session_content_modify));

    LOG(SESSION, MUST,
        "------init success(cost memory %ld M)------\n", total_mem >> 20);

    return total_mem;
}

void session_deinit(void)
{
#ifdef SUPPORT_REST_API
    ulfius_stop_framework(&sess_restful_instance);
    ulfius_clean_instance(&sess_restful_instance);
#endif
    session_stop_all_audit_timer();
}

int session_proc_qer_prss(comm_msg_ie_t *ie)
{
    comm_msg_qer_prss_t *qer_prss = (comm_msg_qer_prss_t *)ie->data;

    if (NULL == ie) {
        LOG(SESSION, ERR, "Parameter abnormal, ie(%p).", ie);
        return -1;
    }

    qer_prss->up_seid = ntohll(qer_prss->up_seid);
    qer_prss->cp_seid = ntohll(qer_prss->cp_seid);
    qer_prss->validity_time = ntohl(qer_prss->validity_time);
    qer_prss->ul_pkts = ntohs(qer_prss->ul_pkts);
    qer_prss->dl_pkts = ntohs(qer_prss->dl_pkts);
    qer_prss->seq_num = ntohl(qer_prss->seq_num);

    /* 这里失败的情况可能是session已经删除了 */
    if (0 > session_reply_timer_stop(qer_prss->up_seid, qer_prss->cp_seid)) {
        LOG(SESSION, RUNNING, "Stop session reply timeout timer failed, May have been deleted.");
        return 0;
    }

    switch (qer_prss->msg_type) {
        case SESS_SESSION_DELETION_RESPONSE:
            {
                session_emd_response resp = {{0,}};

                if (0 > session_delete(qer_prss->up_seid,
        			qer_prss->cp_seid, &resp, 1, NULL)) {
                    LOG(SESSION, ERR,
                        "session delete failed, local_seid: 0x%016lx cp_seid: 0x%016lx.",
                        qer_prss->up_seid, qer_prss->cp_seid);
                }
                session_fill_load_info(&resp);

                resp.msg_header.msg_type = SESS_SESSION_DELETION_RESPONSE;
                resp.msg_header.node_id_index = (uint8_t)qer_prss->node_index;
                resp.msg_header.seq_num = qer_prss->seq_num;

                resp.pkt_rate_status_report_num = 1;
                resp.pkt_rate_status_report[0].qer_id = ie->index;
                if (qer_prss->s.f_up) {
                    resp.pkt_rate_status_report[0].packet_rate_status.flag.d.UL = 1;
                    resp.pkt_rate_status_report[0].packet_rate_status.remain_ul_packets = qer_prss->ul_pkts;
                }
                if (qer_prss->s.f_dp) {
                    resp.pkt_rate_status_report[0].packet_rate_status.flag.d.DL = 1;
                    resp.pkt_rate_status_report[0].packet_rate_status.remain_dl_packets = qer_prss->dl_pkts;
                }
                resp.pkt_rate_status_report[0].packet_rate_status.rate_ctrl_status_time =
                    (uint64_t)qer_prss->validity_time << 32;

                LOG(SESSION, RUNNING, "res->local_seid\t\t0x%lx", resp.local_seid);
            	LOG(SESSION, RUNNING, "res->cp_seid\t\t0x%lx", resp.cp_seid);
            	LOG(SESSION, RUNNING, "res->cause\t\t%d", resp.cause);

                /*if (0 > session_publish_to_upc(&resp, sizeof(resp))) {
                    LOG(SESSION, ERR, "publish to redis failed.");
                }*/
            }
            break;

        case SESS_SESSION_REPORT_REQUEST:
            break;

        default:
            break;
    }

    return 0;
}

/* Query packet rate status of FPU */
uint32_t session_send_prs_cmd_to_fp(uint32_t qer_index, uint64_t up_seid, uint64_t cp_seid,
    uint32_t seq_num, uint8_t node_index, uint8_t msg_type)
{
    comm_msg_header_t   *msg;
    comm_msg_ie_t       *ie = NULL;
    comm_msg_qer_prss_t *config;
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    struct session_t *sess_tbl = NULL;
    struct session_key key = {.local_seid = up_seid, .cp_seid = cp_seid};
    uint32_t buf_len;

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd     = htons(EN_COMM_MSG_UPU_QER_PRS);
    ie->index   = htonl(qer_index);
    buf_len     = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_qer_prss_t);
    ie->len     = htons(buf_len);
    buf_len    += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);
    config      = (comm_msg_qer_prss_t *)ie->data;

    config->up_seid = htonll(up_seid);
    config->cp_seid = htonll(cp_seid);
    config->seq_num = htonl(seq_num);
    config->msg_type = msg_type;
    config->node_index = node_index;

    if (0 > session_msg_send_to_fp((char *)buf, buf_len, MB_SEND2BE_BROADCAST_FD)) {
        return EN_COMM_ERRNO_COMM_CHNL_ERROR;
    } else {
        sess_tbl = session_table_search(&key);
        if (NULL == sess_tbl) {
            LOG(SESSION, ERR, "search failed, no such session, seid:0x%016lx:0x%016lx.",
                key.local_seid, key.cp_seid);
            return EN_COMM_ERRNO_NO_SUCH_ITEM;
        }

        ros_timer_start(sess_tbl->timeout_timer);
    }

    return EN_COMM_ERRNO_OK;
}

uint32_t session_send_sigtrace_ueip_to_fp(struct session_t *sess_tbl)
{
    comm_msg_header_t           *msg;
    comm_msg_sigtrace_ie_t      *ie = NULL;
    uint8_t                     buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                    buf_len;
	struct pdr_table			*pdr_tbl = NULL;
	session_ue_ip				*sess_ueip = NULL;
	uint32_t					ueip = 0;

	if(1 == sess_tbl->session.user_id.sig_trace) {
		pdr_tbl = (struct pdr_table *)rbtree_first(&sess_tbl->session.pdr_root);
	    while (NULL != pdr_tbl) {
			if (EN_COMM_SRC_IF_CORE == pdr_tbl->pdr.pdi_content.si) {
				//暂时只考虑ipv4跟单ueip
				sess_ueip = &pdr_tbl->pdr.pdi_content.ue_ipaddr[0].ueip;
				if(sess_ueip->ueip_flag.d.s_d && sess_ueip->ueip_flag.d.v4) {
					ueip = sess_ueip[0].ipv4_addr;
					break;
				}
			}
	        pdr_tbl = (struct pdr_table *)rbtree_next(&pdr_tbl->pdr_node);
	    }
	}
	LOG(SESSION, ERR, "sig trace open, send ueip to fp ueip %x.", ueip);

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_SIGTRACE_IE(msg);
    ie->cmd     = htons(EN_COMM_MSG_UPU_SIGTRACE_SET);
    ie->index   = 0;
    buf_len     = COMM_MSG_IE_LEN_SIGTRACE_SET;
    ie->len     = htons(buf_len);
	ie->ueip	= htonl(ueip);
    buf_len     += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    return session_msg_send_to_fp((char *)buf, buf_len, MB_SEND2BE_BROADCAST_FD);
}

int rules_fp_del(uint32_t *index_arr, uint32_t index_num, uint16_t cmd, int fd)
{
    comm_msg_header_t           *msg;
    comm_msg_rules_ie_t         *ie = NULL;
    uint8_t buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t *ie_data = NULL, cnt = 0, data_cnt = 0;
    uint32_t buf_len;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(uint32_t);

    if (unlikely(0 == index_num)) {
        LOG(SESSION, ERR, "parameter is invalid, index number: %u.", index_num);
        return -1;
    }

    msg = upc_fill_msg_header(buf);

    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd = htons(cmd);
    ie_data = (uint32_t *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        ie_data[data_cnt] = htonl(index_arr[cnt]);
        ++data_cnt;

        if (data_cnt >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(uint32_t) * data_cnt;
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
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(uint32_t) * data_cnt;
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

uint32_t session_send_simple_cmd_to_fp(uint16_t cmd, int fd)
{
    comm_msg_header_t   *msg;
    comm_msg_ie_t       *ie = NULL;
    uint8_t             buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t            buf_len;

    msg = upc_fill_msg_header(buf);
    ie = COMM_MSG_GET_IE(msg);
    ie->cmd     = htons(cmd);
    ie->index   = htonl(0);
    buf_len     = COMM_MSG_IE_LEN_COMMON;
    ie->len     = htons(buf_len);
    buf_len     += COMM_MSG_HEADER_LEN;
    msg->total_len = htonl(buf_len);

    return session_msg_send_to_fp((char *)buf, buf_len, fd);
}

int session_sig_trace_proc(session_sig_trace *sess_st)
{
	struct session_key key = {0,};
	struct session_t *sess_tbl = NULL;

	key.local_seid  = sess_st->local_seid;
	key.cp_seid     = sess_st->cp_seid;

	sess_tbl = session_table_search(&key);
	if (NULL == sess_tbl) {
		LOG(SESSION, ERR,
			"session table search failed, seid:0x%lx:0x%lx.",
			key.local_seid, key.cp_seid);
		return -1;
	}

	sess_tbl->session.user_id.sig_trace = sess_st->sigtrace_flag;

	session_send_sigtrace_ueip_to_fp(sess_tbl);

	return 0;
}


