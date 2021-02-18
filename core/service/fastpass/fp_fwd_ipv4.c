/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "fp_msg.h"
#include "fp_urr.h"
#include "fp_qer.h"
#include "fp_dns.h"

#ifndef ENABLE_OCTEON_III
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include "dpdk.h"
#endif
#include "fp_fwd_common.h"
#include "fp_fwd_ipv6.h"
#include "fp_fwd_eth.h"
#include "fp_fwd_nonip.h"
#include "fp_frag.h"
#include "fp_fwd_ipv4.h"


extern CVMX_SHARED uint32_t fp_net_n6_local_ip;
extern CVMX_SHARED uint32_t fp_net_n3_local_ip;
extern CVMX_SHARED uint32_t fp_net_n4_local_ip;
extern uint16_t	fp_extension_type;
extern uint8_t	fp_head_enrich_enable;

static inline void
fp_pkt_redirect_ipv4(struct pro_udp_hdr *udp_out_hdr,
    struct pro_ipv4_hdr *ip_hdr, comm_msg_redirect_ipv4_t *redir)
{
    struct pro_udp_hdr  *udp_hdr;
    struct pro_tcp_hdr  *tcp_hdr;
    uint32_t redirip = htonl(redir->ipv4);

    /* Fix inner udp/tcp checksum */
    if (ip_hdr->protocol == IP_PRO_UDP) {

        /* Get header */
        udp_hdr = (struct pro_udp_hdr *)((uint8_t *)ip_hdr + (ip_hdr->ihl << 2));
        if (unlikely(!udp_hdr)) {
            return;
        }

        /* Fix checksum */
        calc_fix_sum((uint8_t *)&udp_hdr->check, (uint8_t *)&ip_hdr->dest, 4,
            (uint8_t *)&redirip, 4);
    }
    else if (ip_hdr->protocol == IP_PRO_TCP) {

        /* Get header */
        tcp_hdr = (struct pro_tcp_hdr *)((uint8_t *)ip_hdr + (ip_hdr->ihl << 2));
        if (unlikely(!tcp_hdr)) {
            return;
        }

        /* Fix checksum */
        calc_fix_sum((uint8_t *)&tcp_hdr->check, (uint8_t *)&ip_hdr->dest, 4,
            (uint8_t *)&redirip, 4);
    }

    /* Fix inner ip checksum */
    calc_fix_sum((uint8_t *)&ip_hdr->check, (uint8_t *)&ip_hdr->dest, 4,
        (uint8_t *)&redirip, 4);

    /* Fix outer udp checksum */
    if (udp_out_hdr != NULL) {
        calc_fix_sum((uint8_t *)&udp_out_hdr->check, (uint8_t *)&ip_hdr->dest, 4,
            (uint8_t *)&redirip, 4);
    }

    /* Replace inner dest ip address */
    ip_hdr->dest = redirip;
}

static inline void fp_pkt_enrich_ipv4(char *pkt, int *enrich_len,
        comm_msg_header_enrichment_t *enrich)
{
    struct pro_ipv4_hdr         *ip_hdr;
    struct pro_tcp_hdr          *tcp_hdr;
    uint32_t                    content_len;
    char                        *tcp_payload;
    char                        *copy_pos;
    char                        *http_line; /* request line or status line */
    uint32_t                    http_line_len;

    ip_hdr = (struct pro_ipv4_hdr *)pkt;
    tcp_hdr = (struct pro_tcp_hdr *)((char *)pkt + (ip_hdr->ihl << 2));
    tcp_payload = (char *)tcp_hdr + (tcp_hdr->doff << 2);

    *enrich_len = enrich->name_length + enrich->value_length + 4; /* include ": " and "\r\n" */

    /* tcp payload length */
    content_len = ntohs(ip_hdr->tot_len) -
        (tcp_hdr->doff << 2) - (ip_hdr->ihl << 2);

    /* Check whether it is an HTTP packet */
    http_line = strstr(tcp_payload, "\r\n");
    if (NULL == http_line) {
        return;
    }
    http_line_len = http_line + 2 - tcp_payload; /* add \r\n */
    http_line[0] = '\0';
    if (NULL == strstr(tcp_payload, "HTTP/1.")) {
        http_line[0] = '\r';
        return;
    }
    http_line[0] = '\r';

    LOG(FASTPASS, RUNNING,
        "content_len = %d, enrich name_length = %d, enrich value_length = %d",
        content_len, enrich->name_length, enrich->value_length);
    tcp_payload += http_line_len; /* Offset to header field */

    /* new position for tcp_payload */
    copy_pos = tcp_payload + *enrich_len;

    /* copy payload to new pos */
    ros_memmove(copy_pos, tcp_payload, content_len - http_line_len);

    /* copy enrich name */
    ros_memcpy(tcp_payload, enrich->name, enrich->name_length);
    tcp_payload[enrich->name_length] = ':';
    tcp_payload[enrich->name_length + 1] = ' ';

    /* copy enrich value */
    ros_memcpy(tcp_payload + enrich->name_length + 2,
        enrich->value, enrich->value_length);
    copy_pos[-2] = '\r';
    copy_pos[-1] = '\n';

    ip_hdr->tot_len = htons(ntohs(ip_hdr->tot_len) + *enrich_len);
    ip_hdr->check   = 0;
    ip_hdr->check   = calc_crc_ip(ip_hdr);

    tcp_hdr->check = 0;
    tcp_hdr->check = calc_crc_tcp(tcp_hdr, ip_hdr);
    return;
}

static inline void fp_pkt_enrich_user_info(char *pkt, int *enrich_len,comm_msg_inst_config *config,
	uint32_t head_enrich_flag)
{
	struct pro_ipv4_hdr    	*ip_hdr;
    struct pro_tcp_hdr    	*tcp_hdr;
	struct timeval 			tv;
    char                   	*tcp_payload;
	uint8_t					tls_pro_type;
	uint16_t				tls_total_len;
	uint32_t				handshake_type;
	uint16_t				offset = 0,ip_total_len=0;
	char                   	*total_len_ptr = NULL, *hello_ptr = NULL;
	char                   	*increase_ptr = NULL, *extension_total_len_ptr=NULL;
	uint16_t				increase_len=0,apn_dnn_len = 0;
	uint64_t				_64bitvalue=0;
	char					rat_type[10][20]={"UTRAN","GERAN","WLAN","GAN","HSPA","EUTRAN","Virtual","EUTRAN-NB-IoT","LTE-M","NR"};
	uint8_t					rat_type_len=0, last_5byte_flag=1;
	char					last_5byte[5]={0};

    ip_hdr = (struct pro_ipv4_hdr *)pkt;
    tcp_hdr = (struct pro_tcp_hdr *)((char *)pkt + (ip_hdr->ihl << 2));
    tcp_payload = (char *)tcp_hdr + (tcp_hdr->doff << 2);
	*enrich_len = 0;

	//https协议,只增强handshake(22)的client hello(1)消息
	if (htons(tcp_hdr->dest) == 443)
	{
		offset = 0;
		tls_pro_type = tcp_payload[offset];
		offset += 3;	//tls content type和version

		if(tls_pro_type == TLS_CONTENT_TYPE_HANDSHAKE)
		{
			total_len_ptr = tcp_payload+offset;
			tls_total_len = ntohs(*((uint16_t *)total_len_ptr));
			offset += 2;	//length
			hello_ptr = tcp_payload+offset;
			handshake_type = ntohl(*((uint32_t *)hello_ptr));

			if(((handshake_type>>24)&0xff) == TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
			{
				if(pkt_parse_https_client_hello(tcp_payload,tls_total_len,&offset,NULL,0,NULL)<0)
				{
			        LOG(FASTPASS, ERR,"pkt_parse_https_client_hello decode failed!");
					*enrich_len = 0;
			        return ;
			    }

				//最后五个字节是0x(xa),0x(xa),0x0,0x1,0x0, 头增强需要放在它们前面
				if(((*(tcp_payload+offset-1))==0) && ((*(tcp_payload+offset-2))==1) && ((*(tcp_payload+offset-3))==0))
				{
					ros_memcpy(last_5byte,(tcp_payload+offset-5),5);
					last_5byte_flag = 1;
			        offset-=5;
			    }

				increase_ptr = tcp_payload+offset;
				*((uint16_t *)increase_ptr) = htons(fp_extension_type);
				increase_len += 2;
				extension_total_len_ptr = increase_ptr+increase_len;
				*((uint16_t *)extension_total_len_ptr) = 0;	//total-length暂时设置为0
				increase_len += 2;

				//以下为添加子扩展头
				if((head_enrich_flag&TLS_SUB_EXTENSION_TYPE_PHONENUM) && (config->user_info.user_id.msisdn_len > 0))
				{
					*(increase_ptr+increase_len) = 1;//手机号码
					increase_len += 1;
					*((uint16_t *)(increase_ptr+increase_len)) = htons(15);//手机号码长度
					increase_len += 2;
					_64bitvalue = bcd_to_int64(config->user_info.user_id.msisdn,8,1);
					ros_memcpy((increase_ptr+increase_len),"msisdn-",7);
					*((uint64_t *)(increase_ptr+increase_len+7)) = htonll(_64bitvalue);
					increase_len += 15;//手机号码
				}

				if((head_enrich_flag&TLS_SUB_EXTENSION_TYPE_UEIP) && (config->user_info.ue_ipaddr[0].ipv4_addr > 0))
				{
					*(increase_ptr+increase_len) = 2;//用户源ip(ueip)
					increase_len += 1;
					*((uint16_t *)(increase_ptr+increase_len)) = htons(4);//用户源ip长度
					increase_len += 2;
					*((uint32_t *)(increase_ptr+increase_len)) = htonl(config->user_info.ue_ipaddr[0].ipv4_addr);
					increase_len += 4;//用户源ip
				}

				if((head_enrich_flag&TLS_SUB_EXTENSION_TYPE_SUPI) && (config->user_info.user_id.imsi_len > 0))
				{
					*(increase_ptr+increase_len) = 3;//imsi
					increase_len += 1;
					*((uint16_t *)(increase_ptr+increase_len)) = htons(13);//imsi长度
					increase_len += 2;
					_64bitvalue = bcd_to_int64(config->user_info.user_id.imsi,8,1);
					ros_memcpy((increase_ptr+increase_len),"imsi-",5);
					*((uint64_t *)(increase_ptr+increase_len+5)) = htonll(_64bitvalue);
					increase_len += 13;//imsi
				}

				if((head_enrich_flag&TLS_SUB_EXTENSION_TYPE_PEI) && (config->user_info.user_id.imei_len > 0))
				{
					*(increase_ptr+increase_len) = 4;//imei
					increase_len += 1;
					*((uint16_t *)(increase_ptr+increase_len)) = htons(13);//imei长度
					increase_len += 2;
					_64bitvalue = bcd_to_int64(config->user_info.user_id.imei,8,1);
					ros_memcpy((increase_ptr+increase_len),"imei-",5);
					*((uint64_t *)(increase_ptr+increase_len+5)) = htonll(_64bitvalue);
					increase_len += 13;//imei
				}

				if((head_enrich_flag&TLS_SUB_EXTENSION_TYPE_TIMESTAMP))
				{
					gettimeofday(&tv,NULL);
					*(increase_ptr+increase_len) = 8;//时间戳
					increase_len += 1;
					*((uint16_t *)(increase_ptr+increase_len)) = htons(8);//时间戳
					increase_len += 2;
					*((uint32_t *)(increase_ptr+increase_len)) = 0;
					*((uint32_t *)(increase_ptr+increase_len+4)) = htonl((uint32_t)tv.tv_sec);
					increase_len += 8;//时间戳
				}

				if((head_enrich_flag&TLS_SUB_EXTENSION_TYPE_RATTYPE) &&
					((config->user_info.rat_type.rat_type>=1) && (config->user_info.rat_type.rat_type<=10)))
				{
					rat_type_len = strlen(rat_type[config->user_info.rat_type.rat_type-1]);
					*(increase_ptr+increase_len) = 9;//rat_type
					increase_len += 1;
					*((uint16_t *)(increase_ptr+increase_len)) = htons(rat_type_len);//rat_type长度
					increase_len += 2;
					ros_memcpy((increase_ptr+increase_len),rat_type[config->user_info.rat_type.rat_type-1],rat_type_len);
					increase_len += rat_type_len;//rat_type
				}

				apn_dnn_len = strlen(config->user_info.apn_dnn.value);
				if((head_enrich_flag&TLS_SUB_EXTENSION_TYPE_DNN) && (apn_dnn_len > 0))
				{
					*(increase_ptr+increase_len) = 0xa;//APN/DNN
					increase_len += 1;
					*((uint16_t *)(increase_ptr+increase_len)) = htons(apn_dnn_len);//APN/DNN
					increase_len += 2;
					ros_memcpy((increase_ptr+increase_len),
						config->user_info.apn_dnn.value,apn_dnn_len);
					increase_len += apn_dnn_len;//APN/DNN
				}

				if(last_5byte_flag)
				{
					ros_memcpy((increase_ptr+increase_len),last_5byte,5);
				}

				*((uint16_t *)extension_total_len_ptr) = htons(increase_len-4);
				*((uint16_t *)total_len_ptr) = htons(tls_total_len + increase_len);
				*((uint32_t *)hello_ptr) = htonl(handshake_type + increase_len);

				*enrich_len = increase_len;

				ip_total_len = ntohs(ip_hdr->tot_len);
				ip_total_len+=increase_len;
				ip_hdr->tot_len = htons(ip_total_len);
			    ip_hdr->check   = 0;
			    ip_hdr->check   = calc_crc_ip(ip_hdr);
			    tcp_hdr->check = calc_crc_tcp(tcp_hdr, ip_hdr);
			}
		}
	}

	return ;
}

inline void fp_pkt_match_n3_ipv4(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag)
{
    void                    *mbuf = pkt_info->arg;
    char                    *pkt = pkt_info->buf;
    int                     len = pkt_info->len;
    uint8_t                 *field_ofs = pkt_info->match_key.field_offset;
    int                     count_len = len - field_ofs[FLOW_FIELD_GTP_CONTENT];
    comm_msg_fast_cfg       *entry_cfg;
    struct pro_eth_hdr      *eth_hdr;
    int                     efflen = len;
    char                    *pktforw = pkt;
    fp_inst_entry           *inst_entry = NULL;
    comm_msg_inst_config    *inst_config;
    fp_far_entry            *far_entry;
    int                     enrich_len = 0;
    char                    action_str[64];
    pkt_buf_struct          *m = (pkt_buf_struct *)mbuf;
    int                     len_diff;
    struct pro_ipv4_hdr     *l2_hdr = FlowGetL2Ipv4Header(&pkt_info->match_key);
#ifdef ENABLE_IP_FRAG
	char                    *resam_buf = NULL;
#endif

    /* Get configuration */
    entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "handle packet, buf %p, pkt %p, len %d, queue(%d, %d), fast entry %d, "
        "dst mac %02x:%02x:%02x:%02x:%02x:%02x, "
        "src mac %02x:%02x:%02x:%02x:%02x:%02x, ",
        mbuf, pkt, len, head->port_no, head->port_type, entry->index,
        *(uint8_t *)(pkt + 0), *(uint8_t *)(pkt + 1), *(uint8_t *)(pkt + 2),
        *(uint8_t *)(pkt + 3), *(uint8_t *)(pkt + 4), *(uint8_t *)(pkt + 5),
        *(uint8_t *)(pkt + 6), *(uint8_t *)(pkt + 7), *(uint8_t *)(pkt + 8),
        *(uint8_t *)(pkt + 9), *(uint8_t *)(pkt + 10), *(uint8_t *)(pkt + 11));

    if (unlikely((NULL == cblk) && entry_cfg->tcp_push)) {
        struct pro_tcp_hdr *tcp_hdr = FlowGetL2TcpHeader(&pkt_info->match_key);
#ifdef ENABLE_IP_FRAG
		fp_tcp_segment_mgmt	*tcp_seg_mgmt = NULL;
		int buf_len;
#endif

        if (tcp_hdr && tcp_hdr->psh) {
#ifdef ENABLE_IP_FRAG
			if (((ntohs(tcp_hdr->dest) == 80) || (ntohs(tcp_hdr->dest) == 8080) || (ntohs(tcp_hdr->dest) == 443)) &&
				unlikely(fp_check_http_head_is_full(pkt_info->buf, pkt_info->len) < 0))
			{
				if (unlikely(fp_tcp_segment_process(&entry->tcp_seg_mgmt, pkt_info->buf,
					pkt_info->arg, pkt_info->len, tcp_hdr) < 0))
				{
			        LOG_TRACE(FASTPASS, DEBUG, trace_flag, "fp_tcp_fegment_process(%p %d %x) failed!",
			        pkt_info->buf, pkt_info->len, ntohl(tcp_hdr->seq));
			        goto err;
			    }

				tcp_seg_mgmt = (fp_tcp_segment_mgmt *)entry->tcp_seg_mgmt;
				if (likely((tcp_seg_mgmt) && (tcp_seg_mgmt->num > 1) &&
					(tcp_seg_mgmt->seg_total_len == tcp_seg_mgmt->meat_total_len)))
				{
					if (unlikely((resam_buf=fp_tcp_segment_reasm(tcp_seg_mgmt,&buf_len)) == NULL))
					{
						if(entry->tcp_seg_mgmt)
							fp_tcp_segment_free(&entry->tcp_seg_mgmt);
						LOG_TRACE(FASTPASS, ERR, trace_flag, "fp_tcp_fegment_process reasm(%p) failed!",
				        resam_buf);
				        goto err;
					}
					else
					{
						if ((fp_check_http_head_is_full(resam_buf, buf_len) == 0))
						{
							fp_forward_pkt_buf_to_sp(resam_buf, buf_len, entry, trace_flag, FAST_TBL_IPV4);
							if(entry->tcp_seg_mgmt)
								fp_tcp_segment_free(&entry->tcp_seg_mgmt);
							entry_cfg->tcp_push = G_FALSE;
							//分片重组的包不进行头增强
							entry_cfg->head_enrich_flag = TLS_NOT_HEAD_ENRICH;
						}
						ros_free(resam_buf);
					}
				}
			}
			else
			{
	            entry_cfg->tcp_push = G_FALSE;
#ifdef RECORD_FAST_INFO_NEW_VER
#else
	            fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV4);
#endif
			}
			entry_cfg->temp_flag = G_TRUE;
            fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);
#else
            entry_cfg->tcp_push = G_FALSE;
            entry_cfg->temp_flag = G_TRUE;
#ifdef RECORD_FAST_INFO_NEW_VER
#else
	        fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV4);
#endif
            fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);
#endif
        }

    }

    /* If temp status, buffer it */
    if (unlikely(entry_cfg->temp_flag)) {
        if (likely(0 == fp_pkt_temp_buffer(pkt_info, head,
            entry, EN_PORT_N3, trace_flag))) {
            /* Don't check other action bit */
            /* Exit 1, temp branch. Queue mbuf, no cblk in this case, update 2 stats */
            return;
        } else {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "Packet temp buffer failed.");

            goto err;
        }
    }

    /* Get inst entry */
    inst_entry = fp_inst_entry_get(entry_cfg->inst_index);
    if (unlikely((!inst_entry)||(!inst_entry->valid))) {
        LOG_TRACE(FASTPASS, ERR, trace_flag, "get inst entry(%d) failed!", entry_cfg->inst_index);

        goto err;
    }
    inst_config  = &(inst_entry->config);

    /* when get inst_entry, first thing is check light */
    if (unlikely(inst_entry->control.light == COMM_MSG_LIGHT_RED)){
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get inst entry(%d) light(%d), drop!",
            entry_cfg->inst_index, inst_entry->control.light);

        goto drop;
    }

    /* Get configuration */
    if (likely(inst_config->choose.d.flag_far1 || inst_config->choose.d.flag_far2)) {
        far_entry = fp_far_entry_get(entry_cfg->far_index);
        if ((!far_entry)||(!far_entry->valid)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "get far entry failed!");

            goto err;
        }
    }
    else {
        /* If no far, should drop it */
        goto err;
    }

    /* when get far_entry, first thing is check drop flag */
    if (unlikely(far_entry->config.action.d.drop)){
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get far entry(%d) action(%d), drop!",
            entry_cfg->far_index, far_entry->config.action.d.drop);

        goto drop;
    }

    /* get read lock, keep no reading when writing */
    ros_rwlock_write_lock(&inst_entry->rwlock);
    fp_get_action_str(far_entry->config.action.value, action_str);
    LOG_TRACE(FASTPASS, RUNNING, trace_flag, "action: %s", action_str);

    /* If forw */
    if (likely(far_entry->config.action.d.forw)) {
        char *extension = NULL;
        comm_msg_outh_rm_t      *outh_rm;
        comm_msg_far_choose_t   *far_choose;

        far_choose = &(far_entry->config.choose);

        /* redirect */
        if (unlikely(far_choose->d.flag_redirect1)) {
            fp_pkt_redirect_ipv4(FlowGetL1UdpHeader(&pkt_info->match_key),
                l2_hdr, &(far_entry->config.forw_redirect));
        }

#ifdef ENABLE_DNS_CACHE
        /* handle udp dns request, if match local cache, reply it directly */
        if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L2_UDP)) {
            struct pro_udp_hdr *udp_header = FlowGetL2UdpHeader(&pkt_info->match_key);

            if (udp_header->dest == FLOW_DNS_PORT) {
                if (fp_pkt_ipv4_reply_dns(pkt_info, udp_header) == OK) {

					/* update stat */
					//fp_pkt_stat_forw(inst_entry, len);

					ros_rwlock_write_unlock(&inst_entry->rwlock);

                    /* send out */
#ifdef CONFIG_FP_DPDK_PORT
                    if (cblk) {
                        cblk->port = EN_PORT_N3;
                        fp_dpdk_add_cblk_buf(cblk);
                    }
                    else
#endif
                    {
                        fp_fwd_snd_to_n3_phy(m);
                        if (cblk)
                            fp_cblk_free(cblk);
                    }
                    fp_packet_stat_count(COMM_MSG_FP_STAT_UP_FWD);

                    LOG(FASTPASS, RUNNING,
                        "reply dns query(ipv4) packet(len %d) to n3!", pkt_buf_data_len(m));

                    /* Exit 0, reply dns */
                    return;
                }
            }
        }
#endif

        /* forwarding policy */
        if (unlikely(far_choose->d.flag_forward_policy1)) {
        }

		if (unlikely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L2_TCP) &&
			((entry_cfg->head_enrich_flag&0x7fffffff) != 0) && fp_head_enrich_enable)) {
            struct pro_tcp_hdr *tcp_hdr;
            tcp_hdr = FlowGetL2TcpHeader(&pkt_info->match_key);
            if (htons(tcp_hdr->dest) == 443) {
				fp_pkt_enrich_user_info((char *)l2_hdr, &enrich_len,
                    inst_config, entry_cfg->head_enrich_flag);
				pkt_buf_set_len(m, (pkt_buf_data_len(m) + enrich_len));

				LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                    "https header enrich, length is %d.", enrich_len);
            }
		}

        /* header enrichment */
        if (unlikely(far_choose->d.flag_header_enrich &&
            FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L2_TCP))) {
            struct pro_tcp_hdr *tcp_hdr = FlowGetL2TcpHeader(&pkt_info->match_key);

            /* get inner header */
            if (tcp_hdr->psh){
                pkt[len] = 0; /* 防止使用strstr的时候越界 */
                fp_pkt_enrich_ipv4((char *)l2_hdr, &enrich_len,
                    &(far_entry->config.forw_enrich));

                pkt_buf_set_len(m, (pkt_buf_data_len(m) + enrich_len));

                LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                    "Header enrich, length is %d.", enrich_len);
            }
        }

        /* outer header removal */
        if (likely(inst_config->choose.d.flag_rm_header)) {
            outh_rm = (comm_msg_outh_rm_t *)&(inst_entry->config.rm_outh);

            pktforw = fp_pkt_outer_header_remove(pkt_info, outh_rm);

            /* set pkt start position */
            efflen -= (pktforw - pkt);
        } else {
            pktforw += ETH_HLEN;
            efflen -= ETH_HLEN;
        }

        /* outer header creation */
        if (unlikely(far_choose->d.flag_out_header1)) {
            pktforw = fp_pkt_outer_header_create(pktforw, &efflen, m,
                &(far_entry->config.forw_cr_outh), inst_config, extension,
                NULL, far_entry->config.forw_if);

            LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                "effective length(after add outer header) is %d, pkt start %p.",
                efflen, pktforw);
        } else {
            pktforw -= 2;
            *(uint16_t *)pktforw = FLOW_ETH_PRO_IP;
        }

        /* set mac header */
        eth_hdr  = (struct pro_eth_hdr *)(pktforw - ETH_ALEN - ETH_ALEN);

        ros_memcpy(eth_hdr->dest, entry_cfg->dst_mac, ETH_ALEN);
        fp_pkt_fill_outer_src_mac(eth_hdr, far_entry->config.forw_if);

        /* transport level marking */
        /* put it on outer header if have */
        if (unlikely(far_choose->d.flag_transport_level1)) {
            fp_pkt_set_transport_level((uint8_t *)eth_hdr,
                &far_entry->config.forw_trans);
        }

        /* send to the port that FAR given */
        /* Set data off */
        len_diff = (char *)eth_hdr - pkt;
        pkt_buf_data_off(m) += len_diff;
        pkt_buf_set_len(m, pkt_buf_data_len(m) - len_diff);

		/* in forw case, check QER first */
#ifdef ENABLE_FP_QER
		if (inst_config->choose.d.flag_qer) {
            if (0 > fp_pkt_qer_process(inst_config, NULL, EN_PORT_N3, count_len, trace_flag)) {
                ros_rwlock_write_unlock(&inst_entry->rwlock);
                /* Color red */
                goto drop;
            }
        }
#endif

        /* update stat */
        fp_pkt_stat_forw(inst_entry, count_len, entry_cfg);

		/* tracking */
		fp_trace_capture_packet(trace_flag, m);
    }

    /* If buff and nocp, buffer it */
    /* only download flow support BUFF and NOCP, refer to 3gpp 25244-5.2.3.1 */

    /* Transmit branch */
    ros_rwlock_write_unlock(&inst_entry->rwlock);

    /* Send buffer */
    fp_pkt_send2phy(m, cblk, far_entry->config.forw_if);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "forward ipv4 packet(len %d) to interface %d!",
        pkt_buf_data_len(m), far_entry->config.forw_if);

    /* Exit 2, forward branch. Queue mbuf, queue(dpdk mode) or free(nic mode) cblk, update 2 stats */
    return;

drop:

    fp_packet_stat_count(COMM_MSG_FP_STAT_UP_DROP);
    /* update stat */
    fp_pkt_stat_drop(inst_entry, count_len);

    /* if fail, free cblk or mbuf */
#ifdef CONFIG_FP_DPDK_PORT
    if (cblk) {
        cblk->port = EN_PORT_BUTT; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
    } else {
        /* free buffer */
        fp_free_pkt(mbuf);
    }
#else
    /* free buffer */
    fp_free_pkt(mbuf);

    if (cblk)
        fp_cblk_free(cblk);
#endif

    /* Exit 3, drop branch. Free mbuf and cblk, update 2 stats */
    return;

err:
    /* for debug, count by error types and core id */
    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

    /* update stat for showing */
    fp_pkt_stat_err(inst_entry);

    /* if fail, free cblk or mbuf */
#ifdef CONFIG_FP_DPDK_PORT
    if (cblk) {
        cblk->port = EN_PORT_BUTT; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
    } else {
        /* free buffer */
        fp_free_pkt(mbuf);
    }
#else
    /* free buffer */
    fp_free_pkt(mbuf);

    if (cblk)
        fp_cblk_free(cblk);
#endif

    /* Exit 4, error branch. Free mbuf, cblk, update 2 stats */
    return;
}

inline void fp_pkt_match_n6_ipv4(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag)
{
    void                    *mbuf = pkt_info->arg;
    char                    *pkt = pkt_info->buf;
    int                     len = pkt_info->len;
    uint8_t                 *field_ofs = pkt_info->match_key.field_offset;
	int						count_len = len - ETH_HLEN;
    comm_msg_fast_cfg       *entry_cfg;
    struct pro_eth_hdr      *eth_hdr;
    int                     efflen = len;
    char                    *pktforw = pkt;
    fp_inst_entry           *inst_entry = NULL;
    comm_msg_inst_config    *inst_config;
    fp_far_entry            *far_entry;
    char                    action_str[64];
    pkt_buf_struct          *m = (pkt_buf_struct *)mbuf;
    int                     len_diff;
#ifdef ENABLE_FP_QER
    comm_msg_qer_gtpu_ext   *gtpu_ext = NULL;   /* init gtpu extension, don't remove */
#endif
#ifdef ENABLE_OCTEON_III
    char *localbuf;
#endif
    struct pro_ipv4_hdr     *l1_hdr = FlowGetL1Ipv4Header(&pkt_info->match_key);

    /* Get configuration */
    entry_cfg = (comm_msg_fast_cfg *)&(entry->cfg_data);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "handle packet, buf %p, pkt %p, len %d, queue(%d, %d), fast entry %d, "
        "dst mac %02x:%02x:%02x:%02x:%02x:%02x, "
        "src mac %02x:%02x:%02x:%02x:%02x:%02x, ",
        mbuf, pkt, len, head->port_no, head->port_type, entry->index,
        *(uint8_t *)(pkt + 0), *(uint8_t *)(pkt + 1), *(uint8_t *)(pkt + 2),
        *(uint8_t *)(pkt + 3), *(uint8_t *)(pkt + 4), *(uint8_t *)(pkt + 5),
        *(uint8_t *)(pkt + 6), *(uint8_t *)(pkt + 7), *(uint8_t *)(pkt + 8),
        *(uint8_t *)(pkt + 9), *(uint8_t *)(pkt + 10), *(uint8_t *)(pkt + 11));

    if (unlikely((NULL == cblk) && entry_cfg->tcp_push)) {
        struct pro_tcp_hdr *tcp_hdr = FlowGetL1TcpHeader(&pkt_info->match_key);

        if (tcp_hdr->psh) {
            entry_cfg->tcp_push = G_FALSE;
            entry_cfg->temp_flag = G_TRUE;
#ifdef RECORD_FAST_INFO_NEW_VER
#else
	        fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV4);
#endif

            fp_packet_stat_count(COMM_MSG_FP_STAT_N6_NOMATCH);
        }
    }

    /* If temp status, buffer it */
    if (unlikely(entry_cfg->temp_flag)) {
        if (likely(0 == fp_pkt_temp_buffer(pkt_info, head,
            entry, EN_PORT_N6, trace_flag))) {
            /* Don't check other action bit */
            /* Exit 1, temp branch. Queue mbuf, no cblk in this case, update 2 stats */
            return;
        } else {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "Packet temp buffer failed.");

            goto err;
        }
    }

    /* Get inst entry */
    inst_entry = fp_inst_entry_get(entry_cfg->inst_index);
    if (unlikely((!inst_entry)||(!inst_entry->valid))) {

        LOG_TRACE(FASTPASS, ERR, trace_flag, "get inst entry %u failed!", entry_cfg->inst_index);

        goto err;
    }
    inst_config  = &(inst_entry->config);
    if (unlikely(inst_entry->control.light == COMM_MSG_LIGHT_RED)) {
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get inst entry(%d) light(%d), drop!",
            entry_cfg->inst_index, inst_entry->control.light);

        goto drop;
    }

    /* Get configuration */
    if (likely(inst_config->choose.d.flag_far1 || inst_config->choose.d.flag_far2)) {
        far_entry = fp_far_entry_get(entry_cfg->far_index);
        if ((!far_entry)||(!far_entry->valid)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "get far entry(%d) failed!", entry_cfg->far_index);

            goto err;
        }
    }
    else {
        /* If no far, should drop it */
        goto err;
    }

    /* when get far_entry, first thing is check drop flag */
    if (unlikely(far_entry->config.action.d.drop)){
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get far entry(%d) action(%d), drop!",
            entry_cfg->far_index, far_entry->config.action.d.drop);

        goto drop;
    }

    /* get read lock, keep no reading when writing */
    ros_rwlock_write_lock(&inst_entry->rwlock);
    fp_get_action_str(far_entry->config.action.value, action_str);
    LOG_TRACE(FASTPASS, RUNNING, trace_flag, "action: %s", action_str);

    /* If forw */
    if (likely(far_entry->config.action.d.forw)) {
        comm_msg_far_choose_t   *far_choose;

#ifdef ENABLE_DNS_CACHE
        /* Learn dns info */
        if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_UDP)) {
            struct pro_udp_hdr *udp_header = FlowGetL1UdpHeader(&pkt_info->match_key);

            if (udp_header->source == FLOW_DNS_PORT) {
                comm_msg_dns_ip dns_ip = {.ip_ver = EN_DNS_IPV4, .ip.ipv4 = l1_hdr->source};

                if (fp_dns_credible_master_switch() || 0 == fp_dns_credible_match(&dns_ip)) {
                    uint16_t payload_len = (uint16_t)(len - field_ofs[FLOW_FIELD_L1_UDP] - UDP_HLEN);

                    /* For dns response, save as cache */
                    if (fp_dns_handle_response((uint8_t *)(udp_header + 1), payload_len) == OK) {
                        /* match local dns cache */
                        LOG(FASTPASS, RUNNING, "Udp dns response.");
                    }
                }
            }
        }
#endif

        /* in forw case, check QER first */
#ifdef ENABLE_FP_QER
        if (inst_config->choose.d.flag_qer) {
            if (0 > fp_pkt_qer_process(inst_config, &gtpu_ext, EN_PORT_N6, count_len, trace_flag)) {
                ros_rwlock_write_unlock(&inst_entry->rwlock);
                /* Color red */
                goto drop;
            }
        }
#endif

        far_choose = &(far_entry->config.choose);

        /* redirect */
        if (unlikely(far_choose->d.flag_redirect1)) {
            fp_pkt_redirect_ipv4(NULL, l1_hdr, &(far_entry->config.forw_redirect));
        }

        /* forwarding policy */
        if (unlikely(far_choose->d.flag_forward_policy1)) {
        }

        /* header enrichment */
        /* only up flow support header enrichment, refer to 3gpp 29244-8.2.25.1 */

        /* outer header removal */
        if (inst_config->choose.d.flag_rm_header) {
            comm_msg_outh_rm_t *outh_rm = (comm_msg_outh_rm_t *)&inst_entry->config.rm_outh;

            pktforw = fp_pkt_outer_header_remove(pkt_info, outh_rm);

            /* set pkt start position */
            efflen -= (pktforw - pkt);
        } else {
            pktforw += ETH_HLEN;
            efflen -= ETH_HLEN;
        }

        /* outer header creation */
        if (likely(far_choose->d.flag_out_header1)) {
            pktforw = fp_pkt_outer_header_create(pktforw, &efflen, m,
                &(far_entry->config.forw_cr_outh), inst_config, NULL,
#ifdef ENABLE_FP_QER
                gtpu_ext, far_entry->config.forw_if);
#else
                NULL, far_entry->config.forw_if);
#endif

            LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                "effective length(after add outer header) is %d, pkt start %p.",
                efflen, pktforw);
        } else {
            pktforw -= 2;
            *(uint16_t *)pktforw = FLOW_ETH_PRO_IP;
        }

        /* set mac header */
        eth_hdr  = (struct pro_eth_hdr *)(pktforw - ETH_ALEN - ETH_ALEN);

        ros_memcpy(eth_hdr->dest, entry_cfg->dst_mac, ETH_ALEN);
        fp_pkt_fill_outer_src_mac(eth_hdr, far_entry->config.forw_if);

        /* transport level marking */
        /* put it on outer header if have */
        if (unlikely(far_choose->d.flag_transport_level1)) {
            fp_pkt_set_transport_level((uint8_t *)eth_hdr,
                &far_entry->config.forw_trans);
        }

        /* send to the port that FAR given */
        /* Set data off */
        len_diff = (char *)eth_hdr - pkt;
        pkt_buf_data_off(m) += len_diff;
        pkt_buf_set_len(m, pkt_buf_data_len(m) - len_diff);

        /* update stat */
        fp_pkt_stat_forw(inst_entry, count_len, entry_cfg);

        /* tracking */
		fp_trace_capture_packet(trace_flag, m);
    }
    /* If buff and nocp, buffer it */
    else if (unlikely((far_entry->config.action.d.buff)
      || (far_entry->config.action.d.nocp))) {
        if (likely(0 == fp_pkt_buffer_action_process(pkt_info, head, entry,
                &far_entry->config, EN_PORT_N6, trace_flag))) {

            /* Don't check other action bit */
            ros_rwlock_write_unlock(&inst_entry->rwlock);

            /* if cblk exist, free it */
            if (cblk)
                fp_cblk_free(cblk);

            /* Exit 2, buff and nocp branch. Queue mbuf, free cblk, update 2 stats */
            return;
        } else {
            ros_rwlock_write_unlock(&inst_entry->rwlock);

            goto err;
        }
    }

    /* Transmit branch */
    ros_rwlock_write_unlock(&inst_entry->rwlock);

    /* Send buffer */
    fp_pkt_send2phy(m, cblk, far_entry->config.forw_if);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "forward ipv4 packet(len %d) to interface %d!",
        pkt_buf_data_len(m), far_entry->config.forw_if);

    /* Exit 3, forw branch. Queue mbuf, queue(dpdk mode) or free(nic mode) cblk, update 2 stats */
    return;


drop:

    fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_DROP);

    /* update stat */
    fp_pkt_stat_drop(inst_entry, count_len);

    /* if fail, free cblk or mbuf */
#ifdef CONFIG_FP_DPDK_PORT
    if (cblk) {
        cblk->port = EN_PORT_BUTT; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
    } else {
        /* free buffer */
        fp_free_pkt(mbuf);
    }
#else
    /* free buffer */
    fp_free_pkt(mbuf);

    if (cblk)
        fp_cblk_free(cblk);
#endif

    /* Exit 4, drop branch. Free mbuf and cblk, update 2 stats */
    return;


err:
    /* for debug, count by error types and core id */
    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);

    /* update stat for showing */
    fp_pkt_stat_err(inst_entry);

    /* if fail, free cblk or mbuf */
#ifdef CONFIG_FP_DPDK_PORT
    if (cblk) {
        cblk->port = EN_PORT_BUTT; /* Let the applicant release */
        fp_dpdk_add_cblk_buf(cblk);
    } else {
        /* free buffer */
        fp_free_pkt(mbuf);
    }
#else
    /* free buffer */
    fp_free_pkt(mbuf);

    if (cblk)
        fp_cblk_free(cblk);
#endif

    /* Exit 5, error branch. Free mbuf, cblk, update 2 stats */
    return;
}

void fp_pkt_inner_ipv4_proc(fp_packet_info *pkt_info)
{
    uint32_t hash_key, aux_info;
    fp_fast_entry  *entry;
    int trace_flag = G_FALSE;
    fp_fast_table *head = fp_fast_table_get(COMM_MSG_FAST_IPV4);
    uint8_t *field_ofs = pkt_info->match_key.field_offset;
    struct pro_ipv4_hdr *ip_l2 = FlowGetL2Ipv4Header(&pkt_info->match_key);
    struct pro_gtp_hdr *gtp_hdr = FlowGetGtpuHeader(&pkt_info->match_key);
    struct tp_port *tp_inner = (struct tp_port *)(ip_l2 + 1);

    /* Calc hash key */
    switch (ip_l2->protocol) {
        case IP_PRO_UDP:
        case IP_PRO_TCP:
        case IP_PRO_SCTP:
        	hash_key = fp_calc_hash_ipv4(PktGetIpv4Long(ip_l2),
            	PktGetPortInt(tp_inner) ^ gtp_hdr->teid,
            	(EN_COMM_SRC_IF_ACCESS<<8)|ip_l2->protocol, &aux_info);

        	trace_flag = fp_check_signal_trace(ip_l2->source, ip_l2->dest,
            	tp_inner->source,
            	tp_inner->dest, ip_l2->protocol);
            break;

        default:
            hash_key = fp_calc_hash_ipv4(PktGetIpv4Long(ip_l2),
                gtp_hdr->teid, (EN_COMM_SRC_IF_ACCESS<<8)|ip_l2->protocol, &aux_info);

            trace_flag = fp_check_signal_trace(ip_l2->source, ip_l2->dest, 0, 0, ip_l2->protocol);
            break;
    }

    /* tracking */
	fp_trace_capture_packet(trace_flag, pkt_info->arg);

    LOG_TRACE(FASTPASS, RUNNING, trace_flag,
        "N3 fast table match(d:%08x,s:%08x,p:%d) (dp:%d,s:%d),"
        " key %x len %d!",
        ntohl(ip_l2->dest), ntohl(ip_l2->source), ip_l2->protocol,
        tp_inner ? ntohs(tp_inner->dest) : 0, tp_inner ? ntohs(tp_inner->source) : 0,
        hash_key, pkt_info->len);

    /* Match fast table */
    aux_info = (ip_l2->source ^ ip_l2->dest);
    entry = fp_table_match_fast_entry(head, hash_key, aux_info);

    /* Entry exist, handle packet by entry content */
    if (likely(entry != NULL)) {
        /* Match success, forwarding */
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 fast table match success");

        /* send out by action */
        fp_pkt_match_n3_ipv4(pkt_info, head, entry, NULL, trace_flag);

        fp_packet_stat_count(COMM_MSG_FP_STAT_N3_MATCH);
    }
    /* Match failed, transfer to slow plane */
    else {

        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 fast table match failed");

        /* Alloc new entry */
        entry = fp_pkt_no_match(pkt_info,
            FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L2_TCP),
            head, hash_key, aux_info, EN_PORT_N3, trace_flag);
        if (unlikely(!entry)) {
            LOG_TRACE(FASTPASS, ERR, trace_flag, "Alloc fast entry failed.");
            fp_free_pkt(pkt_info->arg);
            fp_packet_stat_count(COMM_MSG_FP_STAT_UP_DROP);
            return;
        }
        fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV4);

        fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);

        /* pkt have been buffered, don't free here */
        /* fp_free_pkt(arg); */
    }
}

void fp_pkt_ipv4_entry(fp_packet_info *pkt_info)
{
    fp_fast_entry       *entry;
    uint32_t            hash_key, aux_info;
    int                 trace_flag = G_FALSE;
    fp_fast_table       *head = fp_fast_table_get(COMM_MSG_FAST_IPV4);
    uint8_t             *field_ofs = pkt_info->match_key.field_offset;
    struct pro_ipv4_hdr *ipheader = FlowGetL1Ipv4Header(&pkt_info->match_key);

    /* 1. L1 dest ip match n3 ip, work as n3 */
    /* ipheader->dest == fp_net_n3_local_ip */
    if (likely(!(ipheader->dest ^ fp_net_n3_local_ip))) {

        LOG(FASTPASS, RUNNING, "Recv N3 ipv4 packet----");

        /* N3 traffic */
        if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_GTP_T_PDU))) {
            fp_packet_stat_count(COMM_MSG_FP_STAT_UP_RECV);

            switch (FlowGetL2IpVersion(&pkt_info->match_key)) {
                case 4:
                    fp_pkt_inner_ipv4_proc(pkt_info);
                    break;

                case 6:
                    fp_pkt_inner_ipv6_proc(pkt_info);
                    break;

                default:
                    /* Maybe Ethernet or Non-IP bearer */
#ifdef ETHERNET_SIMPLE_PROC
                    fp_pkt_inner_eth_nonip_proc(pkt_info);
#else
                    if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_ETHERNET_LLC)) {
                        /* Ethernet 802.3 */
                        LOG(FASTPASS, RUNNING, "Treat as Ethernet 802.3 process.");
                        fp_pkt_inner_ethernet_proc(pkt_info);
                    } else {
                        /* Non-IP */
                        LOG(FASTPASS, RUNNING, "Treat as non-IP process.");
                        fp_pkt_inner_non_ip_proc(pkt_info);
                    }
#endif
                    break;

                    /*fp_free_pkt(arg);
                    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
                    LOG(FASTPASS, ERR, "Unsupported packet, unable to get inner header!\r\n");
                    return;*/
            }
        }
        else {
            fp_free_pkt(pkt_info->arg);
            fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
            LOG(FASTPASS, RUNNING, "Unsupported N3 packet.\r\n");
            return;
        }
    }
    /* 3.L1 dest ip match N6 ip, work as N6 */
    /* Filter PFCP packets */
    /* Filter router packets */
    else if (!(ipheader->dest ^ fp_net_n6_local_ip)) {
        LOG(FASTPASS, RUNNING, "Recv router packet----");

        /* Parse OSPF or BGP */
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);

        fp_free_pkt(pkt_info->arg);
        return;
    }
    /* 4.All other packets, consider as N6 */
    else {
        /* 1. If packet dest ip is not local ip, it is from N6, no tunnel */
        /* So just check outer header, don't check innner */

        LOG(FASTPASS, RUNNING, "Recv N6 ipv4 packet----");
        fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_RECV);

        /* Calc hash key */
        switch (ipheader->protocol) {
            case IP_PRO_UDP:
            case IP_PRO_TCP:
            case IP_PRO_SCTP:
                hash_key = fp_calc_hash_ipv4(PktGetIpv4Long(ipheader),
                    PktGetPortInt((struct tp_port *)(ipheader + 1)),
                    (EN_COMM_SRC_IF_CORE<<8)|ipheader->protocol, &aux_info);

                trace_flag = fp_check_signal_trace(ipheader->source, ipheader->dest,
                    ((struct tp_port *)(ipheader + 1))->source,
                    ((struct tp_port *)(ipheader + 1))->dest, ipheader->protocol);
                break;

            default:
                hash_key = fp_calc_hash_ipv4(PktGetIpv4Long(ipheader),
                    0, (EN_COMM_SRC_IF_CORE<<8)|ipheader->protocol, &aux_info);

                trace_flag = fp_check_signal_trace(ipheader->source, ipheader->dest,
                    0, 0, ipheader->protocol);
                break;
        }

		/* tracking */
		fp_trace_capture_packet(trace_flag, pkt_info->arg);

        LOG_TRACE(FASTPASS, RUNNING, trace_flag,
            "N6 fast table match(d:%08x,s:%08x,p:%d), key 0x%08x aux 0x%08x len %d!",
            ntohl(ipheader->dest), ntohl(ipheader->source), ipheader->protocol,
            hash_key, aux_info, pkt_info->len);

        /* Match fast table */
        aux_info = (ipheader->source ^ ipheader->dest);
        entry = fp_table_match_fast_entry(head, hash_key, aux_info);

        /* Match failed, transfer to slow plane */
        if (unlikely(!entry)) {
            LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N6 fast table match failed");

            /* Alloc new entry */
            entry = fp_pkt_no_match(pkt_info,
                FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_TCP),
                head, hash_key, aux_info, EN_PORT_N6, trace_flag);
            if (unlikely(!entry)) {
                LOG_TRACE(FASTPASS, ERR, trace_flag,
                    "Alloc fast entry failed.");
                fp_free_pkt(pkt_info->arg);
                fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_DROP);
                return;
            }
            fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV4);

            fp_packet_stat_count(COMM_MSG_FP_STAT_N6_NOMATCH);

            /* pky have been buffered, don't free here */
            /* fp_free_pkt(arg); */
        }
        else {   /* Entry exist, handle packet by entry content */
            /* Match success, forwarding */
            LOG_TRACE(FASTPASS, RUNNING, trace_flag, "fast table match success");

            /* send out by action */
            fp_pkt_match_n6_ipv4(pkt_info, head, entry, NULL, trace_flag);

            fp_packet_stat_count(COMM_MSG_FP_STAT_N6_MATCH);
        }
    }
}

void fp_pkt_ipv4_n4_entry(fp_packet_info *pkt_info)
{
    fp_fast_entry  *entry;
    uint32_t hash_key, aux_info;
    int trace_flag = G_FALSE;
    uint8_t *field_ofs = pkt_info->match_key.field_offset;
    struct pro_ipv4_hdr *ipheader = FlowGetL1Ipv4Header(&pkt_info->match_key);

	if (likely(!(ipheader->dest ^ fp_net_n4_local_ip))) {

        LOG(FASTPASS, RUNNING, "Recv N4 ipv4 packet----");

        if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_GTP_T_PDU))) {
            struct pro_gtp_hdr *gtp_hdr = FlowGetGtpuHeader(&pkt_info->match_key);

            fp_packet_stat_count(COMM_MSG_FP_STAT_UP_RECV);

            switch (FlowGetL2IpVersion(&pkt_info->match_key)) {
                case 4:
                    {
                        fp_fast_table       *head = fp_fast_table_get(COMM_MSG_FAST_IPV4);
                        struct pro_ipv4_hdr *ip_l2 = FlowGetL2Ipv4Header(&pkt_info->match_key);
                        struct tp_port      *tp_inner = (struct tp_port *)(
                            ip_l2 + pkt_info->match_key.field_length[FLOW_FIELD_L2_IPV4]);

                        /* Calc hash key */
                        switch (ip_l2->protocol) {
                            case IP_PRO_UDP:
                            case IP_PRO_TCP:
                            case IP_PRO_SCTP:
                            	hash_key = fp_calc_hash_ipv4(PktGetIpv4Long(ip_l2),
                                	PktGetPortInt(tp_inner) ^ gtp_hdr->teid,
                                	(EN_COMM_SRC_IF_ACCESS<<8)|ip_l2->protocol, &aux_info);

                            	trace_flag = fp_check_signal_trace(ip_l2->source, ip_l2->dest,
                                	tp_inner->source,
                                	tp_inner->dest, ip_l2->protocol);
                                break;

                            default:
                                hash_key = fp_calc_hash_ipv4(PktGetIpv4Long(ip_l2),
                                    gtp_hdr->teid, (EN_COMM_SRC_IF_ACCESS<<8)|ip_l2->protocol, &aux_info);

                                trace_flag = fp_check_signal_trace(ip_l2->source, ip_l2->dest, 0, 0, ip_l2->protocol);
                                break;
                        }

                        LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                            "N4 fast table match(d:%08x,s:%08x,p:%d) (dp:%d,s:%d),"
                            " key %x len %d!",
                            ntohl(ip_l2->dest), ntohl(ip_l2->source), ip_l2->protocol,
                            tp_inner ? ntohs(tp_inner->dest) : 0, tp_inner ? ntohs(tp_inner->source) : 0,
                            hash_key, pkt_info->len);

                        /* Match fast table */
                        entry = fp_table_match_fast_entry(head, hash_key, aux_info);

                        /* Entry exist, handle packet by entry content */
                        if (likely(entry != NULL))
        				{
                            /* Match success, forwarding */
                            LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N4 fast table match success");

                            /* send out by action */
                            fp_pkt_match_l1v4_l2v6(pkt_info, head, entry, NULL, trace_flag, EN_PORT_N4);
                            fp_packet_stat_count(COMM_MSG_FP_STAT_N3_MATCH);
                        }
                        /* Match failed, transfer to slow plane */
                        else {
                            LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N4 fast table match failed");

                            /* Alloc new entry */
                            entry = fp_pkt_no_match(pkt_info,
                                FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L2_TCP), head,
                                hash_key, aux_info, EN_PORT_N4, trace_flag);
                            if (unlikely(NULL == entry)) {
                                LOG_TRACE(FASTPASS, ERR, trace_flag, "Alloc fast entry failed.");
                                fp_free_pkt(pkt_info->arg);
                                fp_packet_stat_count(COMM_MSG_FP_STAT_UP_DROP);
                                return;
                            }

                            fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV6);
                            fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);
                    	}
                    }
                    break;

                case 6:
                    {
                        fp_fast_table *head = fp_fast_table_get(COMM_MSG_FAST_IPV6);
                        struct pro_ipv6_hdr *ipv6_l2 = FlowGetL2Ipv6Header(&pkt_info->match_key);
                        uint32_t label = ipv6_l2->vtc_flow.d.flow_lbl;
                        uint64_t *ip_u64 = (uint64_t *)(ipv6_l2->saddr);
                        struct tp_port *tp_inner = (struct tp_port *)(
                            (char *)ipv6_l2 + pkt_info->match_key.field_length[FLOW_FIELD_L2_IPV6]);

                        /* Calc hash key */
                        switch (ipv6_l2->nexthdr) {
                            case IP_PRO_UDP:
                            case IP_PRO_TCP:
                            case IP_PRO_SCTP:
                                hash_key = fp_calc_hash_ipv6(ip_u64, PktGetPortInt(tp_inner) ^ gtp_hdr->teid,
                                    label,(EN_COMM_SRC_IF_ACCESS<<8)|ipv6_l2->nexthdr, &aux_info);

                        		LOG_TRACE(FASTPASS, RUNNING, G_FALSE, "sip:%lx:%lx,dip:%lx:%lx,label:%x,hash_key:%x",
                                    ip_u64[0], ip_u64[1], ip_u64[2], ip_u64[3], label, hash_key);
                                break;

                            default:
                                hash_key = fp_calc_hash_ipv6(ip_u64, gtp_hdr->teid, label,
                                    (EN_COMM_SRC_IF_ACCESS<<8)|ipv6_l2->nexthdr, &aux_info);
                                break;
                        }

                        LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                            "N4 fast table match(L2 dip: 0x%08x %08x %08x %08x) "
                            "(L2 sip: 0x%08x %08x %08x %08x, protocol: %d)  (dp:%d sp:%d),"
                            " key 0x%x, len %d!",
                            *(uint32_t *)&ipv6_l2->daddr[0], *(uint32_t *)&ipv6_l2->daddr[4],
                            *(uint32_t *)&ipv6_l2->daddr[8], *(uint32_t *)&ipv6_l2->daddr[12],
                            *(uint32_t *)&ipv6_l2->saddr[0], *(uint32_t *)&ipv6_l2->saddr[4],
                            *(uint32_t *)&ipv6_l2->saddr[8], *(uint32_t *)&ipv6_l2->saddr[12],
                            ntohs(tp_inner->dest), ntohs(tp_inner->source),
                            ipv6_l2->nexthdr, hash_key, pkt_info->len);


                        /* Match fast table */
                        entry = fp_table_match_fast_entry(head, hash_key, aux_info);

                        /* Entry exist, handle packet by entry content */
                        if (likely(entry != NULL))
        				{
                            /* Match success, forwarding */
                            LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                                "N4 fast table match sucess");

                            /* send out by action */
                            fp_pkt_match_l1v4_l2v6(pkt_info, head, entry, NULL, trace_flag, EN_PORT_N4);
                            fp_packet_stat_count(COMM_MSG_FP_STAT_N3_MATCH);
                        }
                        /* Match failed, transfer to slow plane */
                        else {
                            LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                                "N4 fast table match failed");
                            /* Alloc new entry */
                            entry = fp_pkt_no_match(pkt_info,
                                FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L2_TCP), head,
                                hash_key, aux_info, EN_PORT_N4, trace_flag);
                            if (unlikely(NULL == entry)) {
                                LOG_TRACE(FASTPASS, ERR, G_FALSE, "Alloc fast entry failed.");
                                fp_free_pkt(pkt_info->arg);
                                fp_packet_stat_count(COMM_MSG_FP_STAT_UP_DROP);
                                return;
                            }

                            fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV6);
                            fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);
                    	}
                    }
                    break;

                default:
                    /* Maybe Ethernet or Non-IP bearer(N4 except) */
#if 0
                    if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_ETHERNET_LLC)) {
                        /* Ethernet 802.3 */
                        LOG(FASTPASS, RUNNING, "Treat as Ethernet 802.3 process.");
                        fp_pkt_inner_ethernet_proc(pkt_info);
                    } else {
                        /* Non-IP */
                        LOG(FASTPASS, RUNNING, "Treat as non-IP process.");
                        fp_pkt_inner_non_ip_proc(pkt_info);
                    }
                    break;
#else
                    fp_free_pkt(pkt_info->arg);
                    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
                    LOG(FASTPASS, ERR, "Unsupported packet, unable to get inner header!\r\n");
                    return;
#endif
            }
        }
	    else {
            fp_free_pkt(pkt_info->arg);
            fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
            LOG(FASTPASS, RUNNING, "n4 ip address, but not gtp pdu packet!\r\n");
            return;
        }
    }
	else {
        fp_free_pkt(pkt_info->arg);
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
        LOG(FASTPASS, RUNNING, "n4 ip address, but ip not n4 ip!\r\n");
        return;
   }

}


