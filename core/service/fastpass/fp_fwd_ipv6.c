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
#include "fp_fwd_nonip.h"
#include "fp_fwd_ipv4.h"
#include "fp_fwd_eth.h"
#include "fp_frag.h"
#include "fp_fwd_ipv6.h"

extern CVMX_SHARED uint8_t  fp_host_n3_local_ipv6[IPV6_ALEN];
extern CVMX_SHARED uint8_t  fp_host_n4_local_ipv6[IPV6_ALEN];

static inline void
fp_pkt_redirect_ipv6(struct pro_udp_hdr *udp_out_hdr,
    struct pro_ipv6_hdr *ip_hdr,comm_msg_redirect_ipv6_t *redir)
{

    struct pro_udp_hdr  *udp_hdr;
    struct pro_tcp_hdr  *tcp_hdr;
    unsigned char redirip[IPV6_ALEN];

	memcpy(redirip, redir->ipv6.s6_addr, IPV6_ALEN);

    /* Fix inner udp/tcp checksum */
    if (ip_hdr->nexthdr== IP_PRO_UDP) {

        /* Get header */
         udp_hdr = (struct pro_udp_hdr *)((uint8_t *)ip_hdr + (ip_hdr->payload_len));
        if (unlikely(!udp_hdr)) {
            return;
        }

        /* Fix checksum */
		calc_fix_sum((uint8_t *)&udp_hdr->check, (uint8_t *)ip_hdr->daddr, 16,
            (uint8_t *)redirip, 16);
    }
    else if (ip_hdr->nexthdr== IP_PRO_TCP) {

        /* Get header */
         tcp_hdr = (struct pro_tcp_hdr *)((uint8_t *)ip_hdr + (ip_hdr->payload_len));
        if (unlikely(!tcp_hdr)) {
            return;
        }

        /* Fix checksum */
        calc_fix_sum((uint8_t *)&tcp_hdr->check, (uint8_t *)ip_hdr->daddr, 16,
            (uint8_t *)redirip, 16);
    }

    /* Fix outer udp checksum */
    calc_fix_sum((uint8_t *)&udp_out_hdr->check, (uint8_t *)ip_hdr->daddr, 16,
        (uint8_t *)redirip, 16);

    /* Replace inner dest ip address */
	memcpy(ip_hdr->daddr,redirip,sizeof(struct in6_addr));
}

inline void fp_pkt_match_n3_ipv6(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag, int src_intface)
{
    void                    *mbuf = pkt_info->arg;
    char                    *pkt = pkt_info->buf;
    int                     len = pkt_info->len;
    uint8_t                 *field_ofs = pkt_info->match_key.field_offset;
    int                     count_len = len - field_ofs[FLOW_FIELD_GTP_CONTENT];
	comm_msg_fast_cfg		*entry_cfg;
	struct pro_eth_hdr		*eth_hdr;
	int 					efflen = len;
	char					*pktforw = pkt;
	fp_inst_entry			*inst_entry = NULL;
	comm_msg_inst_config	*inst_config;
	fp_far_entry			*far_entry;
	int 					enrich_len = 0;
	char					action_str[64];
	pkt_buf_struct			*m = (pkt_buf_struct *)mbuf;
	int 					len_diff;
    struct pro_ipv6_hdr     *l2_hdr = FlowGetL2Ipv6Header(&pkt_info->match_key);

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

        if (tcp_hdr->psh) {
            entry_cfg->tcp_push = G_FALSE;
            entry_cfg->temp_flag = G_TRUE;
#ifdef RECORD_FAST_INFO_NEW_VER
#else
	        fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV6);
#endif

            fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);
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
	if (likely(inst_config->choose.d.flag_far1)) {
		far_entry = fp_far_entry_get(entry_cfg->far_index);
		if ((!far_entry)||(!far_entry->valid)) {
			LOG_TRACE(FASTPASS, ERR, trace_flag, "get far entry failed!");

			goto err;
		}
	}
	else {
		/* If no far, should use predefined rules */
		//fp_pkt_predefine_rule(mbuf, pkt, len);
		goto err;
	}

	/* when get far_entry, first thing is check drop flag */
	if (unlikely(far_entry->config.action.d.drop)){
		LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get far entry(%d) action(%d), drop!",
			entry_cfg->far_index, far_entry->config.action.d.drop);

		goto drop;
	}

	/* get read lock, keep no reading when writing */
	ros_rwlock_read_lock(&inst_entry->rwlock);
	fp_get_action_str(far_entry->config.action.value, action_str);
	LOG_TRACE(FASTPASS, RUNNING, trace_flag, "action: %s", action_str);

	/* If forw */
	if (likely(far_entry->config.action.d.forw)) {
		char *extension = NULL;
		comm_msg_outh_rm_t		*outh_rm;
		comm_msg_far_choose_t	*far_choose;

		LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get far entry(%d) action(%d), forw!",
			entry_cfg->far_index, far_entry->config.action.d.forw);

		far_choose = &(far_entry->config.choose);

		/* redirect */
		if (unlikely(far_choose->d.flag_redirect1)) {
			fp_pkt_redirect_ipv6(FlowGetL1UdpHeader(&pkt_info->match_key),
                l2_hdr, &(far_entry->config.forw_redirect_ipv6));
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

		/* header enrichment */
		if (unlikely(far_choose->d.flag_header_enrich)) {
			/* get inner header */
			if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L2_TCP)){
				//fp_pkt_enrich_ipv4((char *)l2_hdr, &enrich_len,&(far_entry->config.forw_enrich));

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
		if (likely(far_choose->d.flag_out_header1)) {
            pktforw = fp_pkt_outer_header_create(pktforw, &efflen, m,
                &(far_entry->config.forw_cr_outh), inst_config, extension,
                NULL, far_entry->config.forw_if);

			LOG_TRACE(FASTPASS, RUNNING, trace_flag,
				"effective length(after add outer header) is %d, pkt start %p, extension:%s",
				efflen, pktforw, extension);
		} else {
            pktforw -= 2;
            *(uint16_t *)pktforw = FLOW_ETH_PRO_IPV6;
        }

		/* set mac header */
		eth_hdr = (struct pro_eth_hdr *)(pktforw - ETH_ALEN - ETH_ALEN);

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
	}

	/* If buff and nocp, buffer it */
	/* only download flow support BUFF and NOCP, refer to 3gpp 25244-5.2.3.1 */

	/* Transmit branch */
	ros_rwlock_read_unlock(&inst_entry->rwlock);

	/* Send buffer */
    fp_pkt_send2phy(m, cblk, far_entry->config.forw_if);

	LOG_TRACE(FASTPASS, RUNNING, trace_flag,
		"forward ipv6 packet(len %d) to interface %d!",
		pkt_buf_data_len(m), far_entry->config.forw_if);

	/* Exit 2, forward branch. Queue mbuf, queue(dpdk mode) or free(nic mode) cblk, update 2 stats */
	return;

drop:
	LOG_TRACE(FASTPASS, RUNNING, trace_flag, "match ipv6 packet drop!");

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
	LOG_TRACE(FASTPASS, RUNNING, trace_flag, "match ipv6 packet err!");

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

inline void fp_pkt_match_n6_ipv6(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag)
{
    void                    *mbuf = pkt_info->arg;
    char                    *pkt = pkt_info->buf;
    int                     len = pkt_info->len;
    uint8_t                 *field_ofs = pkt_info->match_key.field_offset;
    int						count_len = len - field_ofs[FLOW_FIELD_L1_IPV6];
	comm_msg_fast_cfg		*entry_cfg;
	struct pro_eth_hdr		*eth_hdr;
	int 					efflen = len;
	char					*pktforw = pkt;
	fp_inst_entry			*inst_entry = NULL;
	comm_msg_inst_config	*inst_config;
	fp_far_entry			*far_entry;
	char					action_str[64];
	pkt_buf_struct			*m = (pkt_buf_struct *)mbuf;
	int 					len_diff;
#ifdef ENABLE_FP_QER
	comm_msg_qer_gtpu_ext	*gtpu_ext = NULL;	/* init gtpu extension, don't remove */
#endif
#ifdef ENABLE_OCTEON_III
	char *localbuf;
#endif
    struct pro_ipv6_hdr     *l1_hdr = FlowGetL1Ipv6Header(&pkt_info->match_key);

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
	        fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV6);
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
		LOG_TRACE(FASTPASS, RUNNING, trace_flag, "ipv6 n6 get inst entry(%d) light(%d), drop!",
			entry_cfg->inst_index, inst_entry->control.light);

		goto drop;
	}

	/* Get configuration */
	if (likely(inst_config->choose.d.flag_far1)) {
		far_entry = fp_far_entry_get(entry_cfg->far_index);
		if ((!far_entry)||(!far_entry->valid)) {
			LOG_TRACE(FASTPASS, ERR, trace_flag, "ipv6 n6 get far entry failed!");

			goto err;
		}
	}
	else {
		/* If no far, should use predefined rules */
		//fp_pkt_predefine_rule(mbuf, pkt, len);
		goto err;
	}

	/* when get far_entry, first thing is check drop flag */
	if (unlikely(far_entry->config.action.d.drop)){
		LOG_TRACE(FASTPASS, RUNNING, trace_flag, "ipv6 n6 get far entry(%d) action(%d), drop!",
			entry_cfg->far_index, far_entry->config.action.d.drop);

		goto drop;
	}

	/* get read lock, keep no reading when writing */
	ros_rwlock_read_lock(&inst_entry->rwlock);
	fp_get_action_str(far_entry->config.action.value, action_str);
	LOG_TRACE(FASTPASS, RUNNING, trace_flag, "action: %s", action_str);

	/* If forw */
	if (likely(far_entry->config.action.d.forw)) {
		comm_msg_far_choose_t	*far_choose;

#ifdef ENABLE_DNS_CACHE
        /* Learn dns info */
        if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_UDP)) {
            struct pro_udp_hdr *udp_header = FlowGetL1UdpHeader(&pkt_info->match_key);

            if (udp_header->source == FLOW_DNS_PORT) {
                comm_msg_dns_ip dns_ip;

                dns_ip.ip_ver = EN_DNS_IPV6;
                ros_memcpy(dns_ip.ip.ipv6, l1_hdr->saddr, IPV6_ALEN);

                if (fp_dns_credible_master_switch() || 0 == fp_dns_credible_match(&dns_ip)) {
                    uint16_t payload_len = len - (uint16_t)(len - field_ofs[FLOW_FIELD_L1_UDP] - UDP_HLEN);

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
			fp_pkt_redirect_ipv6(NULL, l1_hdr, &(far_entry->config.forw_redirect_ipv6));
		}

		/* forwarding policy */
		if (unlikely(far_choose->d.flag_forward_policy1)) {
		}

		/* header enrichment */
		/* only up flow support header enrichment, refer to 3gpp 25244-8.2.25.1 */

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
            *(uint16_t *)pktforw = FLOW_ETH_PRO_IPV6;
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
	ros_rwlock_read_unlock(&inst_entry->rwlock);

	/* Send buffer */
    fp_pkt_send2phy(m, cblk, far_entry->config.forw_if);

	LOG_TRACE(FASTPASS, RUNNING, trace_flag,
		"forward N6 ipv6 packet(len %d) to interface %d!",
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

void fp_pkt_match_l1v4_l2v6(fp_packet_info *pkt_info, fp_fast_table *head,
    fp_fast_entry *entry, fp_cblk_entry *cblk, int trace_flag, int src_intface)
{
    void                    *mbuf = pkt_info->arg;
    char                    *pkt = pkt_info->buf;
    int                     len = pkt_info->len;
    uint8_t                 *field_ofs = pkt_info->match_key.field_offset;
    int                     count_len = len - field_ofs[FLOW_FIELD_GTP_CONTENT];
	comm_msg_fast_cfg		*entry_cfg;
	struct pro_eth_hdr		*eth_hdr;
	int 					efflen = len;
	char					*pktforw = pkt;
	fp_inst_entry			*inst_entry = NULL;
	comm_msg_inst_config	*inst_config;
	fp_far_entry			*far_entry;
	int 					enrich_len = 0;
	char					action_str[64];
	pkt_buf_struct			*m = (pkt_buf_struct *)mbuf;
	int 					len_diff;
    struct pro_ipv6_hdr     *l2_hdr = FlowGetL2Ipv6Header(&pkt_info->match_key);

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

	/* If temp status, buffer it */
	if (unlikely(entry_cfg->temp_flag)) {
        if (likely(0 == fp_pkt_temp_buffer(pkt_info, head,
            entry, src_intface == EN_PORT_N4 ? EN_PORT_N4 : EN_PORT_N3, trace_flag))) {
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
	if (likely(inst_config->choose.d.flag_far1)) {
		far_entry = fp_far_entry_get(entry_cfg->far_index);
		if ((!far_entry)||(!far_entry->valid)) {
			LOG_TRACE(FASTPASS, ERR, trace_flag, "get far entry failed!");

			goto err;
		}
	}
	else {
		/* If no far, should use predefined rules */
		//fp_pkt_predefine_rule(mbuf, pkt, len);
		goto err;
	}

	/* when get far_entry, first thing is check drop flag */
	if (unlikely(far_entry->config.action.d.drop)){
		LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get far entry(%d) action(%d), drop!",
			entry_cfg->far_index, far_entry->config.action.d.drop);

		goto drop;
	}

	/* get read lock, keep no reading when writing */
	ros_rwlock_read_lock(&inst_entry->rwlock);
	fp_get_action_str(far_entry->config.action.value, action_str);
	LOG_TRACE(FASTPASS, RUNNING, trace_flag, "action: %s", action_str);

	/* If forw */
	if (likely(far_entry->config.action.d.forw)) {
		char *extension = NULL;
		comm_msg_outh_rm_t		*outh_rm;
		comm_msg_far_choose_t	*far_choose;

		LOG_TRACE(FASTPASS, RUNNING, trace_flag, "get far entry(%d) action(%d), forw!",
			entry_cfg->far_index, far_entry->config.action.d.forw);

		far_choose = &(far_entry->config.choose);

		/* redirect */
		if (unlikely(far_choose->d.flag_redirect1)) {
			fp_pkt_redirect_ipv6(FlowGetL1UdpHeader(&pkt_info->match_key),
                l2_hdr,&(far_entry->config.forw_redirect_ipv6));
		}

		/* forwarding policy */
		if (unlikely(far_choose->d.flag_forward_policy1)) {
		}

		/* header enrichment */
		if (unlikely(far_choose->d.flag_header_enrich)) {
			/* get inner header */
			if (FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L2_TCP)){
				//fp_pkt_enrich_ipv4((char *)l2_hdr, &enrich_len,&(far_entry->config.forw_enrich));

				pkt_buf_set_len(m, (pkt_buf_data_len(m) + enrich_len));

				LOG_TRACE(FASTPASS, RUNNING, trace_flag,
					"Header enrich, length is %d.", enrich_len);
			}
		}

		/* outer header removal */
		if (likely(inst_config->choose.d.flag_rm_header)) {
            outh_rm = (comm_msg_outh_rm_t *)&inst_entry->config.rm_outh;

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
                NULL, far_entry->config.forw_if);

			LOG_TRACE(FASTPASS, RUNNING, trace_flag,
				"N3 package  add head effective length(after add outer header) is %d, pkt start %p, extension:%s",
				efflen, pktforw, extension);
		} else {
            pktforw -= 2;
            *(uint16_t *)pktforw = FLOW_ETH_PRO_IPV6;
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
            if (0 > fp_pkt_qer_process(inst_config, NULL, EN_PORT_N4, count_len, trace_flag)) {
                ros_rwlock_write_unlock(&inst_entry->rwlock);
                /* Color red */
                goto drop;
            }
        }
#endif

		/* update stat */
		fp_pkt_stat_forw(inst_entry, count_len, entry_cfg);
	}

	/* If buff and nocp, buffer it */
	/* only download flow support BUFF and NOCP, refer to 3gpp 25244-5.2.3.1 */

	/* Transmit branch */
	ros_rwlock_read_unlock(&inst_entry->rwlock);

	/* Send buffer */
    fp_pkt_send2phy(m, cblk, far_entry->config.forw_if);

	LOG_TRACE(FASTPASS, RUNNING, trace_flag,"forward  packet(len %d) to interface %d!",
        pkt_buf_data_len(m), far_entry->config.forw_if);

	/* Exit 2, forward branch. Queue mbuf, queue(dpdk mode) or free(nic mode) cblk, update 2 stats */
	return;

drop:
	LOG_TRACE(FASTPASS, RUNNING, trace_flag,"match ipv6 packet drop!");

	/* free buffer */
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
	LOG_TRACE(FASTPASS, RUNNING, trace_flag,"match ipv6 packet err!");

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

void fp_pkt_inner_ipv6_proc(fp_packet_info *pkt_info)
{
    uint32_t label;
    uint64_t *ip_u64;
    fp_fast_entry  *entry;
    uint32_t hash_key, aux_info;
    int trace_flag = G_FALSE;
    fp_fast_table *head = fp_fast_table_get(COMM_MSG_FAST_IPV6);
    struct tp_port *tp_inner;
    uint8_t *field_ofs = pkt_info->match_key.field_offset;
    struct pro_ipv6_hdr *ipv6_l2 = FlowGetL2Ipv6Header(&pkt_info->match_key);
    struct pro_gtp_hdr *gtp_hdr = FlowGetGtpuHeader(&pkt_info->match_key);

    /* ICMP neighbor NDP  */
	if (unlikely(ipv6_l2->nexthdr == IP_PRO_ICMPV6)){
		struct pro_icmpv6_hdr *icmpv6_hdr = (struct pro_icmpv6_hdr  *)(ipv6_l2 + 1);

		LOG(FASTPASS, RUNNING, "Recv N3 ipv6 icmpv6 packet----type:%d",icmpv6_hdr->type);

		if (likely((icmpv6_hdr->type == 135) || (icmpv6_hdr->type == 136))){
			/*if (ERROR == fp_send_to_chn_port(FP_SOCK_TO_SPU_N3_ARP, pkt_info->arg)) {
                LOG(FASTPASS, ERR,
                    "ipv6 neighbor packet, forward to gwu n3 channel, but failed(errno %d)!\r\n",errno);
                fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
            }*/
            fp_free_pkt(pkt_info->arg);
			return;
		}
	}

	label = ipv6_l2->vtc_flow.d.flow_lbl;
    ip_u64 = (uint64_t *)(ipv6_l2->saddr);
    tp_inner = (struct tp_port *)((char *)ipv6_l2 + pkt_info->match_key.field_length[FLOW_FIELD_L2_IPV6]);

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
        "N3 fast table match (L2 dip: 0x%08x %08x %08x %08x) "
        "(L2 sip: 0x%08x %08x %08x %08x, pro: %d)  (dp:%d sp:%d),"
        " key 0x%x, len %d!",
        *(uint32_t *)&ipv6_l2->daddr[0], *(uint32_t *)&ipv6_l2->daddr[4],
        *(uint32_t *)&ipv6_l2->daddr[8], *(uint32_t *)&ipv6_l2->daddr[12],
        *(uint32_t *)&ipv6_l2->saddr[0], *(uint32_t *)&ipv6_l2->saddr[4],
        *(uint32_t *)&ipv6_l2->saddr[8], *(uint32_t *)&ipv6_l2->saddr[12],
        ipv6_l2->nexthdr, ntohs(tp_inner->dest), ntohs(tp_inner->source),
        hash_key, pkt_info->len);

    /* Match fast table */
    entry = fp_table_match_fast_entry(head, hash_key, aux_info);

    /* Entry exist, handle packet by entry content */
    if (likely(entry != NULL))
	{
        /* Match success, forwarding */
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 fast table match success.");

        /* send out by action */
        fp_pkt_match_l1v4_l2v6(pkt_info,
            head, entry, NULL, trace_flag, EN_PORT_N3);
        fp_packet_stat_count(COMM_MSG_FP_STAT_N3_MATCH);
    }
    /* Match failed, transfer to slow plane */
    else {
        LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 fast table match fail");

        /* Alloc new entry */
        entry = fp_pkt_no_match(pkt_info, FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L2_TCP),
            head, hash_key, aux_info, EN_PORT_N3, trace_flag);
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

void fp_pkt_ipv6_entry(fp_packet_info *pkt_info)
{
    fp_fast_table       *head = fp_fast_table_get(COMM_MSG_FAST_IPV6);
    uint32_t            hash_key, aux_info;
    int                 trace_flag = G_FALSE;
	fp_fast_entry       *entry;
    uint8_t             *field_ofs = pkt_info->match_key.field_offset;
    struct pro_ipv6_hdr *ipv6header = FlowGetL1Ipv6Header(&pkt_info->match_key);
	uint8_t             n3mcastipv6[IPV6_ALEN]={0xff,0x2,0,0,0,0,0,0,0,0,0,0x1,0xff,0,0,0};

	memcpy(&n3mcastipv6[13], &fp_host_n3_local_ipv6[13], 3);

	/* N3  ipv6  package */
	if (likely(0 == memcmp(ipv6header->daddr, fp_host_n3_local_ipv6, IPV6_ALEN))) {
        LOG(FASTPASS, RUNNING, "Recv N3 ipv6 package----");

		/* icmp  neighbor NDP  */
		if (unlikely(ipv6header->nexthdr == IP_PRO_ICMPV6)){
			struct pro_icmpv6_hdr *icmpv6_hdr = (struct pro_icmpv6_hdr  *)(ipv6header + 1);

			LOG(FASTPASS, RUNNING, "Recv N3 ipv6 icmpv6 packet----type: %d", icmpv6_hdr->type);

			if (likely((icmpv6_hdr->type == 135) || (icmpv6_hdr->type== 136))){
				/*if (ERROR == fp_send_to_chn_port(FP_SOCK_TO_SPU_N3_ARP, pkt_info->arg)) {
                    LOG(FASTPASS, ERR,
                        "ipv6 neighbor packet, forward to gwu n3 channel, but failed(errno %d)!\r\n",errno);
                    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
                }*/
                fp_free_pkt(pkt_info->arg);
				return;
			}
		}

        /* check protocol and port, just gtp packet can be handled */
        if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_GTP_T_PDU))) {
            struct pro_gtp_hdr *gtp_hdr = FlowGetGtpuHeader(&pkt_info->match_key);

            fp_packet_stat_count(COMM_MSG_FP_STAT_UP_RECV);

            /* N3 traffic */
            switch (FlowGetL2IpVersion(&pkt_info->match_key)) {
                case 4:
                    fp_pkt_inner_ipv4_proc(pkt_info);
                    break;

                case 6:
                    {
                        struct pro_ipv6_hdr *ipv6_l2 = FlowGetL2Ipv6Header(&pkt_info->match_key);
                        struct tp_port *tp_inner = (struct tp_port *)(
                                (char *)ipv6_l2 + pkt_info->match_key.field_length[FLOW_FIELD_L2_IPV6]);
                        uint32_t label = ipv6_l2->vtc_flow.d.flow_lbl;
        				uint64_t *ipv6_sa_da = (uint64_t *)ipv6_l2->saddr;

                        /* Calc hash key */
                        switch (ipv6_l2->nexthdr) {
                            case IP_PRO_UDP:
                            case IP_PRO_TCP:
                            case IP_PRO_SCTP:
                                hash_key = fp_calc_hash_ipv6(ipv6_sa_da,
                                    PktGetPortInt(tp_inner) ^ gtp_hdr->teid, label,
                                    (EN_COMM_SRC_IF_ACCESS<<8)|ipv6_l2->nexthdr, &aux_info);
                				LOG_TRACE(FASTPASS, RUNNING, trace_flag, "label:%x,hash_key:%x", label, hash_key);
                                break;

                            default:
                                hash_key = fp_calc_hash_ipv6(ipv6_sa_da, gtp_hdr->teid, label,
                                    (EN_COMM_SRC_IF_ACCESS<<8)|ipv6_l2->nexthdr, &aux_info);
                                break;
                        }

                        LOG_TRACE(FASTPASS, RUNNING, trace_flag,
                            "N3 fast table match(L1 dip: 0x%08x %08x %08x %08x)"
                            "(L1 sip: 0x%08x %08x %08x %08x, protocol: %d) "
                            "(L2 dip: 0x%08x %08x %08x %08x) "
                            "(L2 sip: 0x%08x %08x %08x %08x, protocol: %d)  (dp:%d sp:%d),"
                            " key 0x%x, len %d!",
                            *(uint32_t *)&ipv6header->daddr[0], *(uint32_t *)&ipv6header->daddr[4],
                            *(uint32_t *)&ipv6header->daddr[8], *(uint32_t *)&ipv6header->daddr[12],
                            *(uint32_t *)&ipv6header->saddr[0], *(uint32_t *)&ipv6header->saddr[4],
                            *(uint32_t *)&ipv6header->saddr[8], *(uint32_t *)&ipv6header->saddr[12],
                            ipv6header->nexthdr,
                            *(uint32_t *)&ipv6_l2->daddr[0], *(uint32_t *)&ipv6_l2->daddr[4],
                            *(uint32_t *)&ipv6_l2->daddr[8], *(uint32_t *)&ipv6_l2->daddr[12],
                            *(uint32_t *)&ipv6_l2->saddr[0], *(uint32_t *)&ipv6_l2->saddr[4],
                            *(uint32_t *)&ipv6_l2->saddr[8], *(uint32_t *)&ipv6_l2->saddr[12],
                            ntohs(tp_inner->dest), ntohs(tp_inner->source),
                            ipv6_l2->nexthdr, hash_key, pkt_info->len);

                        /* Match fast table */
                        entry = fp_table_match_fast_entry(head, hash_key, aux_info);

                        /* Entry exist, handle packet by entry content */
                        if (likely(entry != NULL)) {
                            /* Match success, forwarding */
                            LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N3 fast table match success");

                            /* send out by action */
                            fp_pkt_match_n3_ipv6(pkt_info, head, entry, NULL, G_FALSE,EN_PORT_N3);

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
                            fp_forward_pkt_to_sp(pkt_info, entry, G_FALSE, FAST_TBL_IPV6);

                            fp_packet_stat_count(COMM_MSG_FP_STAT_N3_NOMATCH);

                            /* pkt have been buffered, don't free here */
                            /* fp_free_pkt(arg); */
                        }
                    }
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
            LOG(FASTPASS, PERIOD, "Not GTP-U packet, Don't deal with it!\r\n");
            return;
        }
    }
	else if (likely(0 == ros_memcmp(ipv6header->daddr, n3mcastipv6, IPV6_ALEN))) {
		if (likely(ipv6header->nexthdr == IP_PRO_ICMPV6)) {
			struct pro_icmpv6_hdr *icmpv6_hdr=(struct pro_icmpv6_hdr *)(
                ipv6header + pkt_info->match_key.field_length[FLOW_FIELD_L1_IPV6]);

			LOG(FASTPASS, RUNNING, "Recv N3 macast ipv6 icmpv6 packet----type:%d",icmpv6_hdr->type);
			if (likely((icmpv6_hdr->type== 135) || (icmpv6_hdr->type== 136))){
				/*if (ERROR == fp_send_to_chn_port(FP_SOCK_TO_SPU_N3_ARP, pkt_info->arg)) {
                    LOG(FASTPASS, ERR,
                        "ipv6 neighbor packet, forward to gwu n3 channel, but failed(errno %d)!\r\n",errno);
                    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
                }*/
			}
		}
        fp_free_pkt(pkt_info->arg);
		return;
	}
	//  down stream N6 packages
	else{
        /* 1. If packet dest ip is not local ip, it is from N6, no tunnel */
        /* So just check outer header, don't check innner */
        uint32_t label = ipv6header->vtc_flow.d.flow_lbl;
		uint64_t *ip6_u64 = (uint64_t *)(&ipv6header->saddr[0]);
        struct tp_port *tp_inner = (struct tp_port *)(
            (char *)ipv6header + pkt_info->match_key.field_length[FLOW_FIELD_L1_IPV6]);

        LOG(FASTPASS, RUNNING, "Recv N6 ipv6 packet----");

		/* icmp  neighbor NDP  */
		if (unlikely(ipv6header->nexthdr == IP_PRO_ICMPV6)) {
			struct pro_icmpv6_hdr  *icmpv6_hdr=(struct pro_icmpv6_hdr  *)(ipv6header+1);
            LOG(FASTPASS, RUNNING, "Recv N6 ipv6 icmpv6 packet----type:%d",icmpv6_hdr->type);
			if (likely((icmpv6_hdr->type== 135) || (icmpv6_hdr->type== 136))){
				/*if (ERROR == fp_send_to_chn_port(FP_SOCK_TO_SPU_N6_ARP, pkt_info->arg)) {
                    LOG(FASTPASS, RUNNING,"ipv6 neighbor packet, forward to gwu n6 channel, but failed(errno %d)!\r\n",errno);
                    fp_packet_stat_count(COMM_MSG_FP_STAT_ERR_PROC);
                }*/
                fp_free_pkt(pkt_info->arg);
				return;
			}
		}

        fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_RECV);

        /* Calc hash key */
        switch (ipv6header->nexthdr) {
            case IP_PRO_UDP:
            case IP_PRO_TCP:
            case IP_PRO_SCTP:
                hash_key = fp_calc_hash_ipv6(ip6_u64, PktGetPortInt(tp_inner), label,
                    (EN_COMM_SRC_IF_CORE<<8)|ipv6header->nexthdr, &aux_info);

    			LOG_TRACE(FASTPASS, RUNNING, trace_flag, "label:%x, hash_key:%x", label, hash_key);
                break;

            default:
                hash_key = fp_calc_hash_ipv6(ip6_u64, 0, label,
                    (EN_COMM_SRC_IF_CORE<<8)|ipv6header->nexthdr, &aux_info);
                break;
        }

        LOG_TRACE(FASTPASS, RUNNING, trace_flag,
            "N6 fast table match(L1 dip: 0x%08x %08x %08x %08x)"
            "(L1 sip: 0x%08x %08x %08x %08x, protocol: %d) (dp:%d sp:%d),"
            " key 0x%x, len %d!",
            *(uint32_t *)&ipv6header->daddr[0], *(uint32_t *)&ipv6header->daddr[4],
            *(uint32_t *)&ipv6header->daddr[8], *(uint32_t *)&ipv6header->daddr[12],
            *(uint32_t *)&ipv6header->saddr[0], *(uint32_t *)&ipv6header->saddr[4],
            *(uint32_t *)&ipv6header->saddr[8], *(uint32_t *)&ipv6header->saddr[12],
            ipv6header->nexthdr, ntohs(tp_inner->dest), ntohs(tp_inner->source),
            hash_key, pkt_info->len);

        /* Match fast table */
        entry = fp_table_match_fast_entry(head, hash_key, aux_info);

        /* Match failed, transfer to slow plane */
        if (unlikely(NULL == entry)) {
            LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N6 fast table match failed");

            /* Alloc new entry */
            entry = fp_pkt_no_match(pkt_info,
                FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_L1_TCP),
                head, hash_key, aux_info, EN_PORT_N6, trace_flag);
            if (unlikely(NULL == entry)) {
                LOG_TRACE(FASTPASS, ERR, trace_flag, "Alloc fast entry failed.");
                fp_free_pkt(pkt_info->arg);
                fp_packet_stat_count(COMM_MSG_FP_STAT_DOWN_DROP);
                return;
            }
            fp_forward_pkt_to_sp(pkt_info, entry, trace_flag, FAST_TBL_IPV6);

            fp_packet_stat_count(COMM_MSG_FP_STAT_N6_NOMATCH);

            /* pky have been buffered, don't free here */
            /* fp_free_pkt(arg); */
        }
        else {   /* Entry exist, handle packet by entry content */
            /* Match success, forwarding */
            LOG_TRACE(FASTPASS, RUNNING, trace_flag, "fast table match success");

            /* send out by action */
            fp_pkt_match_n6_ipv6(pkt_info, head, entry, NULL, trace_flag);

            fp_packet_stat_count(COMM_MSG_FP_STAT_N6_MATCH);
        }
    }
}

void fp_pkt_ipv6_n4_entry(fp_packet_info *pkt_info)
{
    uint32_t                hash_key, aux_info;
    int                     trace_flag = G_FALSE;
	fp_fast_entry           *entry;
    uint8_t                 *field_ofs = pkt_info->match_key.field_offset;
    struct pro_ipv6_hdr     *ipv6header = FlowGetL1Ipv6Header(&pkt_info->match_key);

	/* N3  ipv6  package */
	if (likely(0 == ros_memcmp(ipv6header->daddr, fp_host_n4_local_ipv6, IPV6_ALEN))) {
        LOG(FASTPASS, RUNNING, "Recv N4 ipv6 package----");

        /* N3 traffic */
        if (likely(FLOW_MASK_FIELD_ISSET(field_ofs, FLOW_FIELD_GTP_T_PDU))) {
            struct pro_gtp_hdr *gtp_hdr = FlowGetGtpuHeader(&pkt_info->match_key);

            fp_packet_stat_count(COMM_MSG_FP_STAT_UP_RECV);

            /* Calc hash key */
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
                            "N4 fast table match(L1 dip: 0x%08x %08x %08x %08x)"
                            "(L1 sip: 0x%08x %08x %08x %08x, protocol: %d) "
                            "(L2 dip: 0x%08x %08x %08x %08x) "
                            "(L2 sip: 0x%08x %08x %08x %08x, protocol: %d)  (dp:%d sp:%d),"
                            " key 0x%x, len %d!",
                            *(uint32_t *)&ipv6header->daddr[0], *(uint32_t *)&ipv6header->daddr[4],
                            *(uint32_t *)&ipv6header->daddr[8], *(uint32_t *)&ipv6header->daddr[12],
                            *(uint32_t *)&ipv6header->saddr[0], *(uint32_t *)&ipv6header->saddr[4],
                            *(uint32_t *)&ipv6header->saddr[8], *(uint32_t *)&ipv6header->saddr[12],
                            ipv6header->nexthdr,
                            *(uint32_t *)&ipv6_l2->daddr[0], *(uint32_t *)&ipv6_l2->daddr[4],
                            *(uint32_t *)&ipv6_l2->daddr[8], *(uint32_t *)&ipv6_l2->daddr[12],
                            *(uint32_t *)&ipv6_l2->saddr[0], *(uint32_t *)&ipv6_l2->saddr[4],
                            *(uint32_t *)&ipv6_l2->saddr[8], *(uint32_t *)&ipv6_l2->saddr[12],
                            ipv6_l2->nexthdr, ntohs(tp_inner->dest), ntohs(tp_inner->source),
                            hash_key, pkt_info->len);


                        /* Match fast table */
                        entry = fp_table_match_fast_entry(head, hash_key, aux_info);

                        /* Entry exist, handle packet by entry content */
                        if (likely(entry != NULL))
        				{
                            /* Match success, forwarding */
                            LOG_TRACE(FASTPASS, RUNNING, trace_flag, "N4 fast table match sucess");

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
            LOG(FASTPASS, RUNNING, "n4 ipv6 address, but not gtp packet!\r\n");
            return;
        }
    }
	else{
        fp_free_pkt(pkt_info->arg);
        fp_packet_stat_count(COMM_MSG_FP_STAT_UNSUPPORT_PKT);
        LOG(FASTPASS, RUNNING, "not n4 ip address, drop it!\r\n");
        return;
    }
}


