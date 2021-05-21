/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "dpdk.h"
#include <getopt.h>
#include <rte_ip_frag.h>

#define DPDK_PCIDEVICE          "DPDK_PCIDEVICE"

#if (defined(PRODUCT_IS_fpu))
//#define DPDK_USED_RX_VMDQ         /* Use VMDq */
//#define DPDK_FLOW_REDIRECT        /* Enable flow redirect */
#endif

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t enabled_port_mask;
static int promiscuous_on = 1; /**< Ports set in promiscuous mode off by default. */

static volatile int force_quit;

static uint16_t nb_mempool = 0;

static struct rte_eth_conf port_conf = {
    .rxmode = {
        /* Generally the FPU is bound VF, and the LBU binds PF */
#if (defined(DPDK_USED_RX_VMDQ))
        /* The RSS feature is not supported by the VF, and only the VMDq can be used */
        .mq_mode    = ETH_MQ_RX_VMDQ_ONLY,
#else
        .mq_mode    = ETH_MQ_RX_RSS,
#endif
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .offloads = DEV_RX_OFFLOAD_CHECKSUM |
                    DEV_RX_OFFLOAD_JUMBO_FRAME,
    },
    .rx_adv_conf = {
#if (defined(DPDK_USED_RX_VMDQ))
        .vmdq_rx_conf = {
			.nb_queue_pools = ETH_8_POOLS,
			.enable_default_pool = 0,
			.default_pool = 0,
			.nb_pool_maps = ETH_8_POOLS,
			.pool_map = {{0, 0x1}, {1, 0x2}, {2, 0x4}, {3, 0x8},
			             {4, 0x10}, {5, 0x20}, {6, 0x40}, {7, 0x80},},
		},
#else
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP | ETH_RSS_SCTP,
        },
#endif
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
        .offloads = DEV_TX_OFFLOAD_IPV4_CKSUM \
                    |DEV_TX_OFFLOAD_UDP_CKSUM \
                    |DEV_TX_OFFLOAD_TCP_CKSUM \
                    |DEV_TX_OFFLOAD_SCTP_CKSUM \
                    |DEV_TX_OFFLOAD_MBUF_FAST_FREE,
    },
};

static dpdk_proc_eal_pthr_cb_t gfuncDpdkPacketHook = NULL;
static dpdk_proc_no_eal_pthr_cb_t gfuncDpdkExtraTaskHook = NULL;

static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];
static struct rte_mempool *pktmbuf_indirect_pool[NB_SOCKETS];
static struct lcore_conf dpdk_lcore_conf[RTE_MAX_LCORE];
static unsigned dpdk_nb_ports;

static EN_DPDK_INIT_STAT eDpdkLibInitStat = EN_DPDK_INIT_STAT_NULL;
/* System core info */
static volatile uint64_t dpdk_stat_send[COMM_MSG_MAX_DPDK_CORE_NUM];
static volatile uint64_t dpdk_stat_recv[COMM_MSG_MAX_DPDK_CORE_NUM];
uint32_t dpdk_mtu_size = 1500, dpdk_fragment_size = 1514; /* need to add sizeof(struct rte_ether_hdr) */

struct dpdk_config dpdk_cfg;

#if (defined(DPDK_USED_RX_VMDQ))
static struct dpdk_vmdq_config dpdk_vmdp_cfg[RTE_MAX_ETHPORTS];
#endif

EN_DPDK_INIT_STAT Dpdk_GetInitStat(void)
{
    return eDpdkLibInitStat;
}

void Dpdk_SetInitStat(EN_DPDK_INIT_STAT eStat)
{
    eDpdkLibInitStat = eStat;
}

uint8_t dpdk_get_first_core_id(void)
{
    return dpdk_cfg.cpus[1];
}

uint8_t *dpdk_get_cpus(void)
{
    return dpdk_cfg.cpus;
}

uint8_t dpdk_get_core_num(void)
{
    return dpdk_cfg.core_num;
}

uint8_t dpdk_get_port_num(void)
{
    return dpdk_nb_ports;
}

/*-----------------------------------------------------------------------------
 Name     : Dpdk_DpdkRegisterHook
 Descript : Configure deduplicate parameter by function interface
 Input    : deduplicate parameter
 Output   : NULL
 Return   : DPDK_ERROR or stream index
 Hint     :
 Example  : NULL
 -----------------------------------------------------------------------------*/
int Dpdk_RegisterHook(dpdk_proc_eal_pthr_cb_t funcHook, dpdk_proc_no_eal_pthr_cb_t extraHook)
{
    if (funcHook != 0)
    {
        gfuncDpdkPacketHook = funcHook;
        if (extraHook != NULL)
            gfuncDpdkExtraTaskHook = extraHook;

        return OK;
    }
    else
    {
        return ERROR;
    }
}

/* main processing loop */
static int Dpdk_LoopTask(__attribute__((unused)) void *dummy)
{
    unsigned lcore_id;
    int i, sent;
    uint8_t portid, queueid;
    struct lcore_conf *qconf;
    struct rte_mbuf *pkts_burst[DPDK_MAX_RX_PKT_BURST];
    struct rte_mbuf *m;
    uint64_t cur_tsc;
    uint64_t next_tsc = 0;
    int      j, nb_rx;
    char    *pPacket;
    const uint64_t drain_tsc =
        (rte_get_tsc_hz() + US_PER_S - 1) / (US_PER_S * BURST_TX_DRAIN_US);

    lcore_id = rte_lcore_id();
    qconf = &dpdk_lcore_conf[lcore_id];

    if (qconf->n_rx_queue == 0) {
        LOG(SERVER, ERR, "lcore %u has nothing to do", lcore_id);
        return 0;
    }

    LOG(SERVER, MUST, "entering main loop on lcore %u, qconf->n_rx_queue:%d",
                        lcore_id, qconf->n_rx_queue);

    for (i = 0; i < qconf->n_rx_queue; i++) {

        portid = qconf->rx_queue_list[i].port_id;
#if (defined(DPDK_USED_RX_VMDQ))
        qconf->rx_queue_list[i].queue_id += dpdk_vmdp_cfg[portid].vmdq_queue_base;
#endif
        queueid = qconf->rx_queue_list[i].queue_id;
        LOG(SERVER, MUST, "-- lcoreid=%u portid=%hhu RX queue id=%hhu",
            lcore_id, portid, queueid);
    }

    while (!force_quit) {
        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        if (unlikely(cur_tsc > next_tsc)) {
            if (gfuncDpdkExtraTaskHook)
                gfuncDpdkExtraTaskHook(lcore_id);

            for (i = 0; i < qconf->n_tx_port; ++i) {
                portid = qconf->tx_port_id[i];
                sent = rte_eth_tx_buffer_flush(portid,
                        qconf->tx_queue_id[portid],
                        qconf->tx_buffer[portid]);
                if (sent)
                    dpdk_stat_send[lcore_id] += sent;
            }
            next_tsc = cur_tsc + drain_tsc;
        }

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->n_rx_queue; ++i) {
            portid = qconf->rx_queue_list[i].port_id;
            queueid = qconf->rx_queue_list[i].queue_id;
            nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, DPDK_MAX_RX_PKT_BURST);

            dpdk_stat_recv[lcore_id] += nb_rx;
            for (j = 0; j < nb_rx; j++) {
                m = pkts_burst[j];
                pPacket = rte_pktmbuf_mtod(m, void *);
#if (defined(ENABLE_DPDK_DEBUG))
                m->dynfield1[EN_MBUF_CACHE_CORE] = lcore_id;
                dpdk_mbuf_record(m->buf_addr, __LINE__);
#endif
                rte_prefetch0(pPacket);
//LOG(SERVER, MUST, "Port: %d, queueid: %d, socketid: %d, mbuf nb: %d, Mbuf(%p)", portid, queueid, rte_lcore_to_socket_id(lcore_id), nb_rx, m);
                /* If registered hook, handle hook function */
                if (likely(gfuncDpdkPacketHook)) {
                    gfuncDpdkPacketHook(pPacket, rte_pktmbuf_data_len(m), portid, (void *)m);
                } else {
                    dpdk_free_mbuf(m);
                }
            }
        }
    }

    return 0;
}

static int Dpdk_InitMem(unsigned nb_mbuf)
{
    int socketid;
    unsigned lcore_id;
    char s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

#if (defined(DPDK_USED_RX_VMDQ))
        socketid = rte_socket_id();
#else
        socketid = rte_lcore_to_socket_id(lcore_id);
#endif
        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE,
                "Socket %d of lcore %u is out of range %d.",
                socketid, lcore_id, NB_SOCKETS);
        }
        if (pktmbuf_pool[socketid] == NULL) {
            LOG(SERVER, ERR,
                "Creating direct mempool on socket %i.", socketid);

            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            pktmbuf_pool[socketid] =
                rte_pktmbuf_pool_create(s, nb_mbuf,
                    MEMPOOL_CACHE_SIZE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE,
                    socketid);
            if (pktmbuf_pool[socketid] == NULL)
                rte_exit(EXIT_FAILURE,
                    "Cannot init mbuf pool on socket %d.",
                    socketid);
            ++nb_mempool;
        }
        if (pktmbuf_indirect_pool[socketid] == NULL) {
            LOG(SERVER, ERR,
                "Creating indirect mempool on socket %i.", socketid);

            snprintf(s, sizeof(s),
                "mbuf_pool_indirect_%i", socketid);

            pktmbuf_indirect_pool[socketid] = rte_pktmbuf_pool_create(s,
                nb_mbuf, 32, 0, 0, socketid);
            if (pktmbuf_indirect_pool[socketid] == NULL) {
                LOG(SERVER, ERR,
                    "Cannot create indirect mempool.");
                return -1;
            }
        }
    }
    return 0;
}

/**
 *  Check whether the specified port is linked
 *
 *  @return
 *   - (1) success.
 *   - (0) failed.
 */
int dpdk_port_linked(uint8_t port_id)
{
    struct rte_eth_link link;

    if (port_id >= dpdk_nb_ports) {
        return 0;
    }

    ros_memset(&link, 0, sizeof(link));
    rte_eth_link_get_nowait(port_id, &link);
    if (link.link_status == ETH_LINK_UP) {
        return 1;
    } else {
        return 0;
    }
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void Dpdk_CheckAllPortsLinkStatus(uint8_t port_num, uint32_t port_mask)
{
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= DPDK_MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;

        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if (force_quit)
                return;

            if ((port_mask & (1 << portid)) == 0)
                continue;

            ros_memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                        "Mbps - %s\n", (uint8_t)portid,
                        (unsigned)link.link_speed,
                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                    ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                        (uint8_t)portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(DPDK_CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (DPDK_MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}

struct rte_flow *dpdk_flow_redirect_queue(uint16_t port_id, uint16_t rx_queue,
        struct rte_ether_addr *local_mac, struct rte_flow_error *error)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[4];
	struct rte_flow_action action[4];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = rx_queue };
    struct rte_flow_item_eth eth_spec;
    struct rte_flow_item_eth eth_mask;
	int res;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (ETH).
	 */
    memset(&eth_spec, 0, sizeof(eth_spec));
    memset(&eth_mask, 0, sizeof(eth_mask));

    memcpy(&eth_spec.dst, &local_mac, sizeof(struct rte_ether_addr));
    memset(&eth_spec.src, 0x00, sizeof(struct rte_ether_addr));
    eth_spec.type = 0x0000;
    eth_spec.has_vlan = 0;
    memset(&eth_mask.dst, 0xFF, sizeof(struct rte_ether_addr));
    memset(&eth_mask.src, 0x00, sizeof(struct rte_ether_addr));
    eth_mask.type = 0x0000;
    eth_mask.has_vlan = 0;
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].spec = &eth_spec;
    pattern[0].mask = &eth_mask;

    /* the final level must be always type end */
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

    if (1) {
        struct rte_flow_item_ipv4 ip_spec;
	    struct rte_flow_item_ipv4 ip_mask;

        action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    	action[0].conf = NULL;

        memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    	ip_spec.hdr.dst_addr = htonl(0x0a080000);
    	ip_mask.hdr.dst_addr = 0xFFFF0000;
    	ip_spec.hdr.src_addr = htonl(0U);
    	ip_mask.hdr.src_addr = 0x0;
        pattern[0].spec = NULL;
        pattern[0].mask = NULL;
    	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    	pattern[1].spec = &ip_spec;
    	pattern[1].mask = &ip_mask;
        pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    }

	res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);

	return flow;
}

#if (defined(DPDK_USED_RX_VMDQ))
static int dpdk_vmdq_port_init(void)
{
    struct lcore_conf *qconf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    struct rte_eth_rxconf rxconf;
    int ret;
    uint16_t queueid, nb_tx_queue, nb_rx_queue;
    unsigned lcore_id;
    uint8_t portid, socketid;
    struct rte_eth_conf local_port_conf = port_conf;
    uint32_t max_nb_pools;
    struct dpdk_vmdq_config *vmdq_cfg;
    uint8_t *dpdk_cpus;

    /* The total number of cores also includes one core (control core) that is not used by dpdk */
    if ((dpdk_cfg.core_num - 1) > local_port_conf.rx_adv_conf.vmdq_rx_conf.nb_queue_pools) {
        LOG(SERVER, MUST,
            "The number of dpdk cores exceeds the hash range, see nb_queue_pools");
        return -1;
    }

    /* Set VMDq RX queue */
    portid = 0;
    dpdk_cpus = &dpdk_cfg.cpus[1]; /* Start with 1 */
    lcore_id = 0;
    for (queueid = 0; queueid < local_port_conf.rx_adv_conf.vmdq_rx_conf.nb_queue_pools; ++queueid) {
        qconf = &dpdk_lcore_conf[dpdk_cpus[lcore_id]];
        qconf->rx_queue_list[qconf->n_rx_queue].port_id = portid;
        qconf->rx_queue_list[qconf->n_rx_queue].queue_id = queueid; /* VMDq RX queue id */
        qconf->n_rx_queue++;
        portid = (portid + 1) % dpdk_nb_ports;
        lcore_id = (lcore_id + 1) % (dpdk_cfg.core_num - 1);
    }

    /* initialize all ports */
    for (portid = 0; portid < dpdk_nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            continue;
        }

        /* init port */
        fflush(stdout);

        ret = rte_eth_dev_info_get(portid, &dev_info);
        if (ret != 0) {
            LOG(SERVER, ERR, "Error during getting device (port %u) info: %s", portid, strerror(-ret));
            return -1;
        }
        local_port_conf.txmode.offloads &= dev_info.tx_offload_capa;
        if (local_port_conf.txmode.offloads != port_conf.txmode.offloads) {
            LOG(SERVER, MUST, "Port %u ask %lx tx offload feature, but just support %lx\n",
                portid,
                port_conf.txmode.offloads,
                local_port_conf.txmode.offloads);

            /* Reset RSS flags */
            port_conf.txmode.offloads = local_port_conf.txmode.offloads;
        }

        vmdq_cfg = &dpdk_vmdp_cfg[portid];

        vmdq_cfg->nb_queue_pools = local_port_conf.rx_adv_conf.vmdq_rx_conf.nb_queue_pools;
        max_nb_pools = (uint32_t)dev_info.max_vmdq_pools;
    	/*
    	 * We allow to process part of VMDQ pools specified by num_pools in
    	 * command line.
    	 */
        LOG(SERVER, MUST, "Port %d, nb_queue_pools %d, max_nb_pools %d\n",
            portid, vmdq_cfg->nb_queue_pools, max_nb_pools);
        if (vmdq_cfg->nb_queue_pools > max_nb_pools) {
            LOG(SERVER, ERR, "Port %d, nb_queue_pools %d > max_nb_pools %d\n",
                portid, vmdq_cfg->nb_queue_pools, max_nb_pools);
            return -1;
        }

        /*
    	 * NIC queues are divided into pf queues and vmdq queues.
    	 */
    	/* There is assumption here all ports have the same configuration! */
        /*if (dev_info.vmdq_queue_num > 0) {
            LOG(SERVER, MUST, "Abnormal situation, should not appear.");
            return -1;
        }*/
    	vmdq_cfg->num_pf_queues = dev_info.max_rx_queues - dev_info.vmdq_queue_num;
    	vmdq_cfg->queues_per_pool = dev_info.vmdq_queue_num / dev_info.max_vmdq_pools;
    	vmdq_cfg->num_vmdq_queues = vmdq_cfg->nb_queue_pools * vmdq_cfg->queues_per_pool;
    	vmdq_cfg->num_queues = vmdq_cfg->num_pf_queues + vmdq_cfg->num_vmdq_queues;
    	vmdq_cfg->vmdq_queue_base = dev_info.vmdq_queue_base;
    	vmdq_cfg->vmdq_pool_base  = dev_info.vmdq_pool_base;

    	LOG(SERVER, MUST, "pf queue num: %u, configured vmdq pool num: %u, each vmdq pool has %u queues",
    		vmdq_cfg->num_pf_queues, vmdq_cfg->nb_queue_pools, vmdq_cfg->queues_per_pool);
    	LOG(SERVER, MUST, "vmdq queue base: %d pool base %d vmdq queue num: %d",
    		vmdq_cfg->vmdq_queue_base, vmdq_cfg->vmdq_pool_base, dev_info.vmdq_queue_num);
        LOG(SERVER, MUST, "Port %d, max TX queues: %d, max RX queues: %d", portid,
    		(uint16_t)dev_info.max_tx_queues, (uint16_t)dev_info.max_rx_queues);

    	if (!rte_eth_dev_is_valid_port(portid))
    		return -1;

        LOG(SERVER, MUST, "Port %u RSS support: %#"PRIx64"", portid, dev_info.flow_type_rss_offloads);
        local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
        if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) {
            LOG(SERVER, MUST, "Port %u modified RSS hash function based on hardware support,"
                "requested:%#"PRIx64" configured:%#"PRIx64"\n",
                portid,
                port_conf.rx_adv_conf.rss_conf.rss_hf,
                local_port_conf.rx_adv_conf.rss_conf.rss_hf);

            /* Reset RSS flags*/
            port_conf.rx_adv_conf.rss_conf.rss_hf =
                local_port_conf.rx_adv_conf.rss_conf.rss_hf;
        }

        /*
    	 * Though in this example, we only receive packets from the first queue
    	 * of each pool and send packets through first rte_lcore_count() tx
    	 * queues of vmdq queues, all queues including pf queues are setup.
    	 * This is because VMDQ queues doesn't always start from zero, and the
    	 * PMD layer doesn't support selectively initialising part of rx/tx
    	 * queues.
    	 */
    	nb_rx_queue = (uint16_t)dev_info.max_rx_queues;
    	nb_tx_queue = (uint16_t)dev_info.max_tx_queues;

    	ret = rte_eth_dev_info_get(portid, &dev_info);
    	if (ret != 0) {
    		LOG(SERVER, ERR, "Error during getting device (port %u) info: %s\n", portid, strerror(-ret));
    		return -1;
    	}

        ret = rte_eth_dev_configure(portid, nb_rx_queue,
                    (uint16_t)nb_tx_queue, &local_port_conf);
        if (ret < 0) {
            LOG(SERVER, ERR, "Cannot configure device: err=%d, port=%d\n",
                ret, portid);
            return -1;
        }

    	/*ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &rxRingSize,
    				&txRingSize);
    	if (ret < 0) {
            LOG(SERVER, ERR, "rte_eth_dev_adjust_nb_rx_tx_desc: err=%d, port=%d\n",
                ret, portid);
            return -1;
        }
    	if (RTE_MAX(rxRingSize, txRingSize) > RTE_MAX(nb_rxd, nb_txd)) {
    		LOG(SERVER, ERR, "Mbuf pool has an insufficient size for port %u.\n",
    			portid);
    		return -1;
    	}*/

    	rxconf = dev_info.default_rxconf;
    	rxconf.rx_drop_en = 1;
    	txconf = dev_info.default_txconf;
    	txconf.offloads = local_port_conf.txmode.offloads;
        socketid = rte_socket_id();
        for (queueid = 0; queueid < nb_rx_queue; ++queueid) {
            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                    rte_eth_dev_socket_id(portid),
                    &rxconf,
                    pktmbuf_pool[socketid]);
            if (ret < 0) {
                LOG(SERVER, ERR, "rte_eth_rx_queue_setup: err=%d, port=%d!", ret, portid);
                return -1;
            }
        }

    	for (queueid = 0; queueid < nb_tx_queue; ++queueid) {
    		ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
    					rte_eth_dev_socket_id(portid),
    					&txconf);
            if (ret < 0) {
                LOG(SERVER, ERR, "rte_eth_tx_queue_setup: err=%d, port=%d!", ret, portid);
                return -1;
            }
    	}

        /* set the mtu to the maximum received packet size */
        local_port_conf.rxmode.max_rx_pkt_len = dpdk_get_mtu();
        ret = rte_eth_dev_set_mtu(portid,
            local_port_conf.rxmode.max_rx_pkt_len);
        if (ret < 0) {
            LOG(SERVER, ERR, "Set MTU failed: err=%d, port=%d\n",
                ret, portid);
            return -1;
        }

        ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        if (ret < 0) {
            LOG(SERVER, ERR, "rte_eth_macaddr_get: err=%d, port=%d\n", ret, portid);
            return -1;
        }

        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            /* Initialize TX buffers */
            qconf = &dpdk_lcore_conf[lcore_id];
            qconf->tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
                    RTE_ETH_TX_BUFFER_SIZE(DPDK_MAX_TX_PKT_BURST), 0,
                    rte_eth_dev_socket_id(portid));
            if (qconf->tx_buffer[portid] == NULL) {
                LOG(SERVER, ERR, "Can't allocate tx buffer for port %u!", (unsigned) portid);
                return -1;
            }

            rte_eth_tx_buffer_init(qconf->tx_buffer[portid], DPDK_MAX_TX_PKT_BURST);
        }

        /* init one TX queue per couple (lcore,port) */
        queueid = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;
            qconf = &dpdk_lcore_conf[lcore_id];
            socketid = rte_socket_id();

            fflush(stdout);

            qconf->direct_pool = pktmbuf_pool[socketid];
            qconf->indirect_pool  = pktmbuf_indirect_pool[socketid];

            qconf->tx_queue_id[portid] = queueid;
            queueid++;

            qconf->tx_port_id[qconf->n_tx_port] = portid;
            qconf->n_tx_port++;
        }

        LOG(SERVER, MUST,"Port %u, device name: %s, default MAC address: %02X:%02X:%02X:%02X:%02X:%02X",
                portid, dev_info.device->name,
                ports_eth_addr[portid].addr_bytes[0],
                ports_eth_addr[portid].addr_bytes[1],
                ports_eth_addr[portid].addr_bytes[2],
                ports_eth_addr[portid].addr_bytes[3],
                ports_eth_addr[portid].addr_bytes[4],
                ports_eth_addr[portid].addr_bytes[5]);
    }

    /* start ports */
    for (portid = 0; portid < dpdk_nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0) {
            LOG(SERVER, ERR, "rte_eth_dev_start: err=%d, port=%d!",
                                ret, portid);
            return -1;
        }

        /*
         * If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross-connected  ports of the
         * target machine.
         */
        if (promiscuous_on)
            rte_eth_promiscuous_enable(portid);
    }

    /*
	 * Set mac for each pool.
	 * There is no default mac for the pools in i40.
	 * Removes this after i40e fixes this issue.
	 */
	for (portid = 0; portid < dpdk_nb_ports; portid++) {
        vmdq_cfg = &dpdk_vmdp_cfg[portid];

    	for (queueid = 0; queueid < vmdq_cfg->nb_queue_pools; queueid++) {
    		struct rte_ether_addr mac;
    		mac = ports_eth_addr[portid];
    		mac.addr_bytes[4] = portid;
    		mac.addr_bytes[5] = queueid;
    		LOG(SERVER, MUST, "Port %u vmdq pool %u set mac %02x:%02x:%02x:%02x:%02x:%02x",
    			portid, queueid,
    			mac.addr_bytes[0], mac.addr_bytes[1],
    			mac.addr_bytes[2], mac.addr_bytes[3],
    			mac.addr_bytes[4], mac.addr_bytes[5]);
    		ret = rte_eth_dev_mac_addr_add(portid, &mac,
    				queueid + vmdq_cfg->vmdq_pool_base);
    		if (ret < 0) {
    			LOG(SERVER, MUST, "mac addr add failed at pool %d", queueid);
    			return -1;
    		}
    	}
	}

    return 0;
}
#else

static int dpdk_port_init(void)
{
    struct lcore_conf *qconf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    int ret;
    uint16_t queueid;
    unsigned lcore_id;
    uint8_t portid, nb_rx_queue, nb_tx_queue, socketid;
    uint8_t nb_rx_queue_list[RTE_MAX_ETHPORTS] = {0};
    struct rte_eth_conf local_port_conf = port_conf;

    portid = 0;
    for (lcore_id = 1; lcore_id < dpdk_cfg.core_num; ++lcore_id) {
        dpdk_lcore_conf[dpdk_cfg.cpus[lcore_id]].rx_queue_list[0].port_id = portid;
        dpdk_lcore_conf[dpdk_cfg.cpus[lcore_id]].rx_queue_list[0].queue_id = nb_rx_queue_list[portid]++;
        dpdk_lcore_conf[dpdk_cfg.cpus[lcore_id]].n_rx_queue++;
        portid = (portid + 1) % dpdk_nb_ports;
    }

    /* initialize all ports */
    for (portid = 0; portid < dpdk_nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            continue;
        }

        /* init port */
        fflush(stdout);

        nb_rx_queue = nb_rx_queue_list[portid];
#if (defined(PRODUCT_IS_fpu))
        /* The number of TX and Rx queues in each core of FPU is the same */
        nb_tx_queue = nb_rx_queue;
#else
        nb_tx_queue = dpdk_cfg.core_num - 1;
#endif

        ret = rte_eth_dev_info_get(portid, &dev_info);
        if (ret != 0) {
            LOG(SERVER, ERR, "Error during getting device (port %u) info: %s", portid, strerror(-ret));
            return -1;
        }
        local_port_conf.txmode.offloads &= dev_info.tx_offload_capa;
        if (local_port_conf.txmode.offloads != port_conf.txmode.offloads) {
            LOG(SERVER, MUST, "Port %u ask %lx tx offload feature, but just support %lx",
                portid,
                port_conf.txmode.offloads,
                local_port_conf.txmode.offloads);
        }

        local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
        LOG(SERVER, MUST, "Port %u RSS support: %#"PRIx64","
            "requested %#"PRIx64" The valid configuration is %#"PRIx64"",
            portid,
            dev_info.flow_type_rss_offloads,
            port_conf.rx_adv_conf.rss_conf.rss_hf,
            local_port_conf.rx_adv_conf.rss_conf.rss_hf);
        if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) {
            /* Reset RSS flags*/
            port_conf.rx_adv_conf.rss_conf.rss_hf =
                local_port_conf.rx_adv_conf.rss_conf.rss_hf;
        }

        ret = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &local_port_conf);
        if (ret < 0) {
            LOG(SERVER, ERR, "Cannot configure device: err=%d, port=%d\n", ret, portid);
            return -1;
        }

        /* set the mtu to the maximum received packet size */
        local_port_conf.rxmode.max_rx_pkt_len = dpdk_get_mtu();
        ret = rte_eth_dev_set_mtu(portid, local_port_conf.rxmode.max_rx_pkt_len);
        if (ret < 0) {
            LOG(SERVER, ERR, "Set MTU failed: err=%d, port=%d\n",
                ret, portid);
            return -1;
        }

        ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        if (ret < 0) {
            LOG(SERVER, ERR, "rte_eth_macaddr_get: err=%d, port=%d\n", ret, portid);
            return -1;
        }

#if (defined(PRODUCT_IS_fpu))
        /**
         *  The initialization of TX queue and Rx queue is processed together later.
         */
#else
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            /* Initialize TX buffers */
            qconf = &dpdk_lcore_conf[lcore_id];
            qconf->tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
                    RTE_ETH_TX_BUFFER_SIZE(DPDK_MAX_TX_PKT_BURST), 0,
                    rte_eth_dev_socket_id(portid));
            if (qconf->tx_buffer[portid] == NULL) {
                LOG(SERVER, ERR, "Can't allocate tx buffer for port %d!", portid);
                return -1;
            }
            rte_eth_tx_buffer_init(qconf->tx_buffer[portid], DPDK_MAX_TX_PKT_BURST);
        }

        /* init one TX queue per couple (lcore,port) */
        queueid = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;
            qconf = &dpdk_lcore_conf[lcore_id];
            socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);

            fflush(stdout);

            txconf = dev_info.default_txconf;
            txconf.offloads = local_port_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
                             rte_eth_dev_socket_id(portid), &txconf);
            if (ret < 0) {
                LOG(SERVER, ERR, "rte_eth_tx_queue_setup: err=%d, port=%d !", ret, portid);
                return -1;
            }

            qconf->direct_pool = pktmbuf_pool[socketid];
            qconf->indirect_pool  = pktmbuf_indirect_pool[socketid];

            qconf->tx_queue_id[portid] = queueid;
            queueid++;

            qconf->tx_port_id[qconf->n_tx_port] = portid;
            qconf->n_tx_port++;
        }
#endif

        LOG(SERVER, MUST,"Port %u, device name: %s, MAC address: %02X:%02X:%02X:%02X:%02X:%02X",
                portid, dev_info.device->name,
                ports_eth_addr[portid].addr_bytes[0],
                ports_eth_addr[portid].addr_bytes[1],
                ports_eth_addr[portid].addr_bytes[2],
                ports_eth_addr[portid].addr_bytes[3],
                ports_eth_addr[portid].addr_bytes[4],
                ports_eth_addr[portid].addr_bytes[5]);
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &dpdk_lcore_conf[lcore_id];
        fflush(stdout);
        /* init RX queues */
        for (queueid = 0; queueid < qconf->n_rx_queue; ++queueid) {
            portid = qconf->rx_queue_list[queueid].port_id;
            queueid = qconf->rx_queue_list[queueid].queue_id;
            socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);

            LOG(SERVER, MUST, "lcore_id: %u, port_id: %u, socketid: %d, RX queue_id: %u",
                lcore_id, portid, socketid, queueid);

            fflush(stdout);
            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                    rte_eth_dev_socket_id(portid), NULL,
                    pktmbuf_pool[socketid]);
            if (ret < 0) {
                LOG(SERVER, ERR, "rte_eth_rx_queue_setup: err=%d, port=%d!", ret, portid);
                return -1;
            }

#if (defined(PRODUCT_IS_fpu))
            /* Initialize TX buffers */
            qconf->tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
                    RTE_ETH_TX_BUFFER_SIZE(DPDK_MAX_TX_PKT_BURST), 0,
                    rte_eth_dev_socket_id(portid));
            if (qconf->tx_buffer[portid] == NULL) {
                LOG(SERVER, ERR, "Can't allocate tx buffer for port %d!", portid);
                return -1;
            }
            rte_eth_tx_buffer_init(qconf->tx_buffer[portid], DPDK_MAX_TX_PKT_BURST);

            /* init one TX queue per couple (lcore,port) */
            LOG(SERVER, MUST, "lcore_id: %u, port_id: %u, socketid: %d, TX queue_id: %u",
                lcore_id, portid, socketid, queueid);

            ret = rte_eth_dev_info_get(portid, &dev_info);
            if (ret != 0) {
                LOG(SERVER, ERR, "Error during getting device (port %u) info: %s", portid, strerror(-ret));
                return -1;
            }
            fflush(stdout);

            txconf = dev_info.default_txconf;
            txconf.offloads = local_port_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
                             rte_eth_dev_socket_id(portid), &txconf);
            if (ret < 0) {
                LOG(SERVER, ERR, "rte_eth_tx_queue_setup: err=%d, port=%d !", ret, portid);
                return -1;
            }

            qconf->direct_pool = pktmbuf_pool[socketid];
            qconf->indirect_pool  = pktmbuf_indirect_pool[socketid];

            qconf->tx_queue_id[portid] = queueid;

            qconf->tx_port_id[qconf->n_tx_port] = portid;
            qconf->n_tx_port++;
#endif
        }
    }

    /* start ports */
    for (portid = 0; portid < dpdk_nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0) {
            LOG(SERVER, ERR, "rte_eth_dev_start: err=%d, port=%d!", ret, portid);
            return -1;
        }

        /*
         * If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross-connected  ports of the
         * target machine.
         */
        if (promiscuous_on)
            rte_eth_promiscuous_enable(portid);
    }

#if (defined(DPDK_FLOW_REDIRECT))
    /* Add MAC address */
    for (portid = 0; portid < dpdk_nb_ports; portid++) {
        struct rte_ether_addr mac;

        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;

        nb_rx_queue = nb_rx_queue_list[portid];

        for (queueid = 0; queueid < nb_rx_queue; queueid++) {
            struct rte_flow *flow;
            struct rte_flow_error error;

            flow = dpdk_flow_redirect_queue(portid, queueid,
        				&mac,
        				&error);
            if (!flow) {
            	LOG(SERVER, ERR, "Flow can't be created %d message: %s\n",
            		error.type,
            		error.message ? error.message : "(no stated reason)");
                return -1;
            }
        }
	}
#endif

    return 0;
}
#endif

void Dpdk_LibExit(void)
{
    unsigned nb_ports;
    uint8_t portid;

    LOG(SERVER, ERR, "dpdk lib exit ...");
    force_quit = 1;

    nb_ports = rte_eth_dev_count_avail();

    for (portid = 0; portid < nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        LOG(SERVER, ERR, "Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        LOG(SERVER, ERR, "Done");
    }
    LOG(SERVER, ERR, "Bye...");

    Dpdk_SetInitStat(EN_DPDK_INIT_STAT_NULL);
    return;
}

void *Dpdk_LibTask(void *arg)
{
    int ret;
    unsigned nb_ports, nb_mbuf;
    unsigned lcore_id, nb_lcores;
    int argc = 0;
    const char *argv[256];
    uint32_t ulEthIndex;
    char     lcore_str[256], print_dev[256];
    char     mul_proc_str[128];
    int print_dev_len = 0;

    for (ulEthIndex = 0; ulEthIndex < dpdk_cfg.dev_num; ulEthIndex++) {
        print_dev_len += sprintf(&print_dev[print_dev_len], "%s ", dpdk_cfg.dev[ulEthIndex]);
    }
    LOG(SERVER, MUST, "dpdk dev:%s, dev_num: %d, core_num: %d",
        print_dev, dpdk_cfg.dev_num, dpdk_cfg.core_num);

    argc = 0;
    argv[argc++] = "upfdpdk";

    /* Set lcore */
    argv[argc++] = "-l";
    ros_memset(lcore_str, 0, sizeof(lcore_str));

    /* DPDK is used from the second CPU */
    sprintf(lcore_str, "%d", dpdk_cfg.cpus[1]);
    if (dpdk_cfg.core_num > 2) {
        uint8_t cnt, len_cnt = strlen(lcore_str);

        for (cnt = 2; cnt < dpdk_cfg.core_num; ++cnt) {
            len_cnt += sprintf(&lcore_str[len_cnt], ",%d", dpdk_cfg.cpus[cnt]);
        }
        LOG(SERVER, MUST, "DPDK bind cpus: %s", lcore_str);
    }
    argv[argc++] = lcore_str;

    /* Set pcie */
    /*
     * NOTE: The binding order of the white list cannot determine the order of the final port ID
     */
    for (ulEthIndex = 0; ulEthIndex < dpdk_cfg.dev_num; ulEthIndex++) {
        argv[argc++] = "-a";
        argv[argc++] = dpdk_cfg.dev[ulEthIndex];
    }

    /**
     *  Load external drivers.
     *  An argument can be a single shared object file,
     *  or a directory containing multiple driver shared objects.
     *  Multiple -d options are allowed.
     */
    argv[argc++] = "-d";
    argv[argc++] = "/opt/upf/lib/"; /* It's related to docker's workspace */

    /* Multiprocess */
    argv[argc++] = "--proc-type=primary";

    ros_memset(mul_proc_str, 0, sizeof(mul_proc_str));
#if (defined(PRODUCT_IS_fpu))
    sprintf(mul_proc_str, "--file-prefix=.upf_fpu_cfg_%s", dpdk_cfg.dev[0]);
#elif (defined(PRODUCT_IS_lbu))
    sprintf(mul_proc_str, "--file-prefix=.upf_lbu_cfg_%s", dpdk_cfg.dev[0]);
#endif
    argv[argc++] = mul_proc_str;

    force_quit = 0;

    /* init EAL */
    ret = rte_eal_init(argc, (char **)argv);
    if (ret < 0) {
        LOG(SERVER, ERR, "Invalid EAL parameters!");
        Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
        return G_NULL;
    }

    /* rte_eal_init will close the file description word of syslog, which needs to be reopened */
    openlog("UPF", LOG_CONS, LOG_USER);

    nb_ports = rte_eth_dev_count_avail();
    dpdk_nb_ports = nb_ports;

    if (dpdk_cfg.dev_num != nb_ports) {
        LOG(SERVER, ERR, "DPDK init fail, white-PCI number %d != dev_count_avail %u",
            dpdk_cfg.dev_num, nb_ports);
        Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
        return G_NULL;
    }

    enabled_port_mask = ((1 << nb_ports) - 1);

    /* Check cpu, Start with the second */
    for (lcore_id = 1; lcore_id < dpdk_cfg.core_num; lcore_id++) {
        if (!rte_lcore_is_enabled(dpdk_cfg.cpus[(uint8_t)lcore_id])) {
            LOG(SERVER, ERR, "error: cpu_id %hhu is not enabled in "
                "lcore mask", dpdk_cfg.cpus[(uint8_t)lcore_id]);
            Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
            return G_NULL;
        }
    }

    nb_lcores = rte_lcore_count();
    nb_ports = dpdk_nb_ports;

    /* init memory */
#if (defined(DPDK_USED_RX_VMDQ))
    nb_mbuf = RTE_MAX((nb_ports * (port_conf.rx_adv_conf.vmdq_rx_conf.nb_queue_pools * RTE_TEST_RX_DESC_DEFAULT + \
    	nb_lcores * DPDK_MAX_RX_PKT_BURST +			\
    	port_conf.rx_adv_conf.vmdq_rx_conf.nb_queue_pools * RTE_TEST_TX_DESC_DEFAULT +	\
    	nb_lcores * MEMPOOL_CACHE_SIZE)),			\
    	8192U);
#else
    nb_mbuf = RTE_MAX((nb_ports * (nb_lcores * RTE_TEST_RX_DESC_DEFAULT +	\
    	nb_lcores * DPDK_MAX_RX_PKT_BURST +			\
    	nb_lcores * RTE_TEST_TX_DESC_DEFAULT +	\
    	nb_lcores * MEMPOOL_CACHE_SIZE)),			\
    	8192U);
#endif
    ret = Dpdk_InitMem(nb_mbuf);
    if (ret < 0) {
        LOG(SERVER, ERR, "Dpdk_InitMem failed!");
        Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
        return G_NULL;
    }

#if (defined(DPDK_USED_RX_VMDQ))
    if (0 > dpdk_vmdq_port_init())
#else
    if (0 > dpdk_port_init())
#endif
    {
        LOG(SERVER, ERR, "DPDK port init failed.");
        Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
        return G_NULL;
    }

    Dpdk_CheckAllPortsLinkStatus((uint8_t)nb_ports, enabled_port_mask);

    Dpdk_SetInitStat(EN_DPDK_INIT_STAT_SUCCESS);

    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(Dpdk_LoopTask, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
            return G_NULL;
        }
    }

    return G_NULL;
}

uint64_t dpdk_get_tx_offload()
{
    return port_conf.txmode.offloads;
}

void dpdk_set_tx_offload(uint64_t offloads)
{
    port_conf.txmode.offloads = offloads;
}

uint64_t dpdk_get_rx_offload()
{
    return port_conf.rxmode.offloads;
}

void dpdk_set_rx_offload(uint64_t offloads)
{
    port_conf.rxmode.offloads = offloads;
}

void dpdk_dump_packet_1(uint8_t *buf, uint16_t buf_len, const char *func, uint32_t line)
{
    uint16_t cnt = 0;

    LOG(FASTPASS, MUST, "(%s)%u ", func, line);
    buf_len &= 0xFFF0;
    for (cnt = 0; cnt < buf_len; cnt += 16) {
        LOG(FASTPASS, MUST, "%02x %02x %02x %02x %02x %02x %02x %02x    %02x %02x %02x %02x %02x %02x %02x %02x",
            buf[cnt], buf[cnt + 1], buf[cnt + 2], buf[cnt + 3],
            buf[cnt + 4], buf[cnt + 5], buf[cnt + 6], buf[cnt + 7],
            buf[cnt + 8], buf[cnt + 9], buf[cnt + 10], buf[cnt + 11],
            buf[cnt + 12], buf[cnt + 13], buf[cnt + 14], buf[cnt + 15]);
    }
    LOG(FASTPASS, MUST, "");
}

void dpdk_send_packet(struct rte_mbuf *m, uint16_t port_id, const char *func, int line)
{
    unsigned lcore_id = rte_lcore_id();
    struct lcore_conf *qconf;
    int sent;

#if (defined(ENABLE_DPDK_DEBUG))
    dpdk_mbuf_del_record(m->buf_addr, __LINE__);

    if (lcore_id == LCORE_ID_ANY) {
        lcore_id = dpdk_get_first_core_id();
        LOG(SERVER, ERR, "Abnormal dpdk send core id, Should not fail to get coreid");
    } else if (m->dynfield1[EN_MBUF_CACHE_CORE] != lcore_id) {
        LOG(SERVER, ERR, "Free dpdk mbuf abnormal, record_id: %u != cur_id: %u.",
            m->dynfield1[EN_MBUF_CACHE_CORE], lcore_id);
    }
    m->dynfield1[EN_MBUF_CACHE_CORE] = 0; /* reset */
#endif

    qconf = &dpdk_lcore_conf[lcore_id];
    /* if we don't need to do any fragmentation */
    if (likely(dpdk_fragment_size >= m->pkt_len)) {
        sent = rte_eth_tx_buffer(port_id, qconf->tx_queue_id[port_id],
                    dpdk_lcore_conf[lcore_id].tx_buffer[port_id], m);
        if (sent)
            dpdk_stat_send[lcore_id] += sent;

        return;
    }
    else {
        uint64_t ol_flags = 0;
        /* Build transmission burst */
        uint32_t len = 0, i;
        int32_t  len2;

        /* Calc crc */
        if (likely(m->ol_flags & PKT_TX_IP_CKSUM)) {
            struct pro_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(m, struct pro_ipv4_hdr *,
                    (uint16_t)sizeof(struct rte_ether_hdr));
            ip_hdr->check = 0;
            ip_hdr->check = calc_crc_ip(ip_hdr);

            if (likely(m->ol_flags & PKT_TX_UDP_CKSUM)) {
                struct pro_udp_hdr *udp_hdr = (struct pro_udp_hdr *)((uint32_t *)ip_hdr + (ip_hdr->ihl));

                udp_hdr->check = 0;
                udp_hdr->check = calc_crc_udp(udp_hdr, ip_hdr);
            }
        }

        /* Remove the Ethernet header and trailer from the input packet */
        rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));

        /* if this is an IPv4 packet */
        if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
            /* Make fragments */
            len2 = rte_ipv4_fragment_packet(m,
                    &qconf->tx_mbufs[lcore_id].m_table[len],
                    (uint16_t)(DPDK_MBUF_TABLE_SIZE - len),
                    dpdk_mtu_size,
                    qconf->direct_pool, qconf->indirect_pool);

            /* request HW to regenerate IPv4 cksum */
            ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);

            /* If we fail to fragment the packet */
            if (unlikely (len2 < 0)) {
                LOG(SERVER, ERR, "IPv4 packet fragment failed, ret: %d", len2);
                /* Free input packet */
                rte_pktmbuf_free(m);
                return;
            }
        }
        else if (RTE_ETH_IS_IPV6_HDR(m->packet_type)) {
            /* Make fragments */
            len2 = rte_ipv6_fragment_packet(m,
                    &qconf->tx_mbufs[lcore_id].m_table[len],
                    (uint16_t)(DPDK_MBUF_TABLE_SIZE - len),
                    dpdk_mtu_size,
                    qconf->direct_pool, qconf->indirect_pool);

            /* If we fail to fragment the packet */
            if (unlikely (len2 < 0)) {
                LOG(SERVER, ERR, "IPv6 packet fragment failed, ret: %d", len2);
                rte_pktmbuf_free(m);
                return;
            }
        }
        /* else, just forward the packet */
        else {
            /* Don't update mac, send packet directly */
            LOG(SERVER, ERR, "Large packet of unknown type, packet_type: 0x%x", m->packet_type);
            sent = rte_eth_tx_buffer(port_id, qconf->tx_queue_id[port_id],
                        dpdk_lcore_conf[lcore_id].tx_buffer[0], m);
            if (sent)
                dpdk_stat_send[lcore_id] += sent;
            return;
        }

        /* Update mac, just for IPv4 and IPv6 */
        for (i = len; i < len + len2; i ++) {
            struct rte_mbuf *m_new;

            m_new = qconf->tx_mbufs[lcore_id].m_table[i];

            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)
                rte_pktmbuf_prepend(m_new, (uint16_t)sizeof(struct rte_ether_hdr));
            if (eth_hdr == NULL) {
                rte_panic("No headroom in mbuf.\n");
            }

            m_new->ol_flags |= ol_flags;
            m_new->l2_len = sizeof(struct rte_ether_hdr);

            rte_memcpy(eth_hdr,
                (char *)m->buf_addr + m->data_off - (uint16_t)sizeof(struct rte_ether_hdr),
                sizeof(struct rte_ether_hdr));

            /*if (unlikely(!(dpdk_get_tx_offload() & DEV_TX_OFFLOAD_IPV4_CKSUM))) {
                struct pro_ipv4_hdr *ip4_hdr = rte_pktmbuf_mtod_offset(m_new, struct pro_ipv4_hdr *,
                    (uint16_t)sizeof(struct rte_ether_hdr));

                ip4_hdr->check = calc_crc_ip(ip4_hdr);
            }*/

            sent = rte_eth_tx_buffer(port_id, qconf->tx_queue_id[port_id],
                        dpdk_lcore_conf[lcore_id].tx_buffer[0], m_new);
            if (sent)
                dpdk_stat_send[lcore_id] += sent;
        }
        rte_pktmbuf_free(m);

        return;
    }

    return;
}

#if (defined(ENABLE_DPDK_DEBUG))
struct rte_mbuf *__dpdk_alloc_mbuf(uint32_t line)
{
    struct rte_mbuf *m;
    unsigned lcore_id = rte_lcore_id();
    uint8_t  socketid;

    if (lcore_id == LCORE_ID_ANY) {
        LOG(SERVER, MUST, "This print should not appear.");
        lcore_id = dpdk_get_first_core_id();
    }
#if (defined(DPDK_USED_RX_VMDQ))
    socketid = (uint8_t)rte_socket_id();
#else
    socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
#endif

    /* Create new mbuf for the header. */
    m = rte_pktmbuf_alloc(pktmbuf_pool[socketid]);
    if (m) {
        m->dynfield1[EN_MBUF_CACHE_CORE] = lcore_id;
        dpdk_mbuf_record(m->buf_addr, line);
    }

    return m;
}
#else

struct rte_mbuf *dpdk_alloc_mbuf(void)
{
#if (defined(DPDK_USED_RX_VMDQ))
    uint8_t socketid = (uint8_t)rte_socket_id();
#else
    uint8_t socketid = (uint8_t)rte_lcore_to_socket_id(rte_lcore_id());
#endif

    /* Create new mbuf for the header. */
    return rte_pktmbuf_alloc(pktmbuf_pool[socketid]);
}
#endif

#if (defined(ENABLE_DPDK_DEBUG))
void __dpdk_free_mbuf(struct rte_mbuf *m, uint32_t line)
{
    if (likely(m != NULL)) {
        unsigned lcore_id = rte_lcore_id();

        dpdk_mbuf_del_record(m->buf_addr, line);

        if (lcore_id == LCORE_ID_ANY) {
            lcore_id = m->dynfield1[EN_MBUF_CACHE_CORE];
            LOG(SERVER, MUST, "This print should not appear.");
        } else if (m->dynfield1[EN_MBUF_CACHE_CORE] != lcore_id) {
            LOG(SERVER, ERR, "Free dpdk mbuf abnormal, record_id: %u != cur_id: %u.",
                m->dynfield1[EN_MBUF_CACHE_CORE], lcore_id);
        }
        m->dynfield1[EN_MBUF_CACHE_CORE] = 0; /* reset */

        rte_pktmbuf_free(m);
    }
    return;
}
#else

void dpdk_free_mbuf(struct rte_mbuf *m)
{
    rte_pktmbuf_free(m);
}
#endif

int32_t dpdk_init(struct pcf_file *conf, void *ssct1, void *extra_task)
{
    int ret;
    pthread_t ptid = 0;
    dpdk_proc_eal_pthr_cb_t ssct = ssct1;
    char result[32];
    char *device_name, *pci_addr, *token = NULL, *dev_token = NULL;

    dpdk_cfg.dev_num = 0;
    device_name = pcf_get_env(DPDK_PCIDEVICE);
    if (NULL == device_name) {
        LOG(SERVER, ERR, "Get DPDK env DPDK_PCIDEVICE fail.\n");
        return -1;
    }

    for (dev_token = strsep(&device_name, ","); dev_token != NULL; dev_token = strsep(&device_name, ",")) {
        if (*dev_token == 0) {
            continue;
        }
        pci_addr = pcf_get_env(dev_token);
        if (NULL == pci_addr) {
            LOG(SERVER, ERR, "Get DPDK PCI address fail.\n");
            return -1;
        }

        for (token = strsep(&pci_addr, ","); token != NULL; token = strsep(&pci_addr, ",")) {
            if (*token == 0) {
                continue;
            }

            strcpy(dpdk_cfg.dev[dpdk_cfg.dev_num++], token);
        }
    }

    /* effective cpus number */
    if (0 > ros_read_from_shell_cmd(result, sizeof(result), "nproc")) {
        LOG(SERVER, ERR, "ros_read_from_shell_cmd fail ");
        return -1;
    }
    dpdk_cfg.core_num = atoi(result);
    if (dpdk_cfg.core_num != ros_parse_cpuset_cpus(dpdk_cfg.cpus)) {
        LOG(SERVER, ERR, "Parse cpuset cpus fail.");
        return -1;
    }

#if (defined(PRODUCT_IS_fpu))
    if ((dpdk_cfg.core_num - 1) != dpdk_cfg.dev_num) {
        LOG(SERVER, ERR, "Illegal configuration. core numebr(%d - 1) != dev number(%d).",
            dpdk_cfg.core_num, dpdk_cfg.dev_num);
        return -1;
    }
    if ((dpdk_cfg.core_num - 1) > COMM_MSG_FPU_CORE_MAX) {
        LOG(SERVER, ERR, "The maximum number of cores that FPU can bind to dpdk is %d, but the configuration is %d.",
            COMM_MSG_FPU_CORE_MAX, (dpdk_cfg.core_num - 1));
        return -1;
    }
#endif

    /* Bind the control process to the control core */
    ret = pthread_create(&ptid, NULL, Dpdk_LibTask, (void *)conf);
    if (ret < 0) {
        LOG(SERVER, ERR, "pthread_create Dpdk_LibTask Fail!\n");
        return -1;
    }

    Dpdk_RegisterHook(ssct, extra_task);

    Dpdk_SetInitStat(EN_DPDK_INIT_STAT_ING);
    while (Dpdk_GetInitStat() == EN_DPDK_INIT_STAT_ING)
        sleep(1);

    if (Dpdk_GetInitStat() != EN_DPDK_INIT_STAT_SUCCESS)
    {
        LOG(SERVER, ERR, "dpdk init fail!\n");
        return -1;
    }

    LOG(SERVER, MUST, "dpdk init success!\n");
    return 0;
}

void dpdk_deinit(void)
{
    Dpdk_LibExit();
    return;
}

int dpdk_packet_stat(char *str)
{
    uint32_t iloop;
    static uint64_t s_last_count = 0;
    static uint32_t s_last_time;
    uint64_t new_count = 0;
    uint32_t current_time, pps_num;
    uint32_t pos = 0;
    uint64_t sent_total = 0, recv_total = 0;

    current_time = time((time_t *)NULL);
    for (iloop = 0; iloop < COMM_MSG_MAX_DPDK_CORE_NUM; iloop++) {
        if (rte_lcore_is_enabled(iloop) == 0)
            continue;
        new_count += dpdk_stat_send[iloop];
    }

    if ((current_time - s_last_time) != 0) {
        pps_num = (new_count - s_last_count)/(current_time - s_last_time);
    } else {
        pps_num = 0;
    }

    s_last_count = new_count;
    s_last_time  = current_time;

    for (iloop = 0; iloop < COMM_MSG_MAX_DPDK_CORE_NUM; iloop++) {
        if (rte_lcore_is_enabled(iloop) == 0)
            continue;
        if ((dpdk_stat_send[iloop])||(dpdk_stat_recv[iloop])) {
            pos += sprintf(str + pos, "core %u send: %lu\r\n", iloop, dpdk_stat_send[iloop]);
            pos += sprintf(str + pos, "core %u recv: %lu\r\n\r\n", iloop, dpdk_stat_recv[iloop]);
            sent_total += dpdk_stat_send[iloop];
            recv_total += dpdk_stat_recv[iloop];
        }
    }
    pos += sprintf(str + pos, "\r\nTotal send: %lu\r\n", sent_total);
    pos += sprintf(str + pos, "Total recv: %lu\r\n", recv_total);
    pos += sprintf(str + pos, "\r\npps: %u.%u K\r\n", pps_num/1000, pps_num%1000);

    return OK;
}

int dpdk_packet_stat_promu(comm_msg_fpu_stat *stat)
{
    uint32_t iloop;

    for (iloop = 0; iloop < COMM_MSG_MAX_DPDK_CORE_NUM; iloop++) {
        if (rte_lcore_is_enabled(iloop) == 0)
            continue;
        stat->internal_send_stat += htonl(dpdk_stat_send[iloop]);
        stat->internal_recv_stat += htonl(dpdk_stat_recv[iloop]);
    }

    return OK;
}

uint32_t dpdk_get_mtu()
{
    return dpdk_mtu_size;
}

void dpdk_set_mtu(uint32_t new_mtu)
{
    dpdk_mtu_size = new_mtu;
    dpdk_fragment_size = dpdk_mtu_size + (uint16_t)sizeof(struct rte_ether_hdr);
}

void dpdk_show_mempool_stat(struct cli_def *cli, int show_all)
{
    uint32_t port_id = 0, lcore_id;
    uint32_t show_index;
    uint32_t show_len;
    struct rte_eth_stats stats;
    struct rte_eth_xstat_name *xstats_names;
    uint64_t *values;
    int socketid;


    cli_print(cli,"\r\n----------------dpdk statistics for port %d----------------\r\n", port_id);

    if (show_all) {
        rte_eth_stats_get(port_id, &stats);

        cli_print(cli,"ipackets : %lu \r\n", stats.ipackets);
        cli_print(cli,"opackets : %lu \r\n", stats.opackets);
        cli_print(cli,"ibytes   : %lu \r\n", stats.ibytes);
        cli_print(cli,"obytes   : %lu \r\n", stats.obytes);
        cli_print(cli,"ierrors  : %lu \r\n", stats.ierrors);
        cli_print(cli,"oerrors  : %lu \r\n", stats.oerrors);
        cli_print(cli,"rx_nombuf: %lu \r\n\r\n", stats.rx_nombuf);

        for (show_index = 0; show_index < RTE_ETHDEV_QUEUE_STAT_CNTRS; ++show_index) {
            cli_print(cli,"q_ipackets[%d]: %lu \r\n", show_index, stats.q_ipackets[show_index]);
            cli_print(cli,"q_opackets[%d]: %lu \r\n", show_index, stats.q_opackets[show_index]);
            cli_print(cli,"q_ibytes[%d]  : %lu \r\n", show_index, stats.q_ibytes[show_index]);
            cli_print(cli,"q_obytes[%d]  : %lu \r\n", show_index, stats.q_obytes[show_index]);
            cli_print(cli,"q_errors[%d]  : %lu \r\n\r\n", show_index, stats.q_errors[show_index]);
        }
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
#if (defined(DPDK_USED_RX_VMDQ))
        socketid = rte_socket_id();
#else
        socketid = rte_lcore_to_socket_id(lcore_id);
#endif
        if (socketid >= NB_SOCKETS) {
            cli_print(cli, "Socket %d of lcore %u is out of range %d.",
                socketid, lcore_id, NB_SOCKETS);
            break;
        }

        cli_print(cli,"direct mempool_%u  : in use count: %u, avail count: %u\r\n", socketid,
            rte_mempool_in_use_count(pktmbuf_pool[socketid]),
            rte_mempool_avail_count(pktmbuf_pool[socketid]));

        cli_print(cli,"incirect mempool_%u: in use count: %u, avail count: %u\r\n", socketid,
            rte_mempool_in_use_count(pktmbuf_indirect_pool[socketid]),
            rte_mempool_avail_count(pktmbuf_indirect_pool[socketid]));

        /*cli_print(cli,"rx_queue [%u]:  %d\r\n", lcore_id,
            rte_eth_rx_queue_count(dpdk_lcore_conf[lcore_id].rx_queue_list[0].port_id,
            dpdk_lcore_conf[lcore_id].rx_queue_list[0].queue_id));*/
    }

    if (show_all) {
        show_len = rte_eth_xstats_get_names_by_id(0, NULL, 0, NULL);
        xstats_names = ros_malloc(show_len * sizeof(struct rte_eth_xstat_name));
        if (xstats_names == NULL) {
            return;
        }
        values = ros_malloc(show_len * sizeof(uint64_t));
        if (values == NULL) {
            ros_free(xstats_names);
            return;
        }

        if (show_len != rte_eth_xstats_get_names_by_id(port_id, xstats_names, show_len, NULL)) {
            cli_print(cli,"Cannot get xstat names\n");
            return;
        }

        cli_print(cli,"\r\n-----------NIC extended statistics for port %-2d-----------\r\n", port_id);
        rte_eth_xstats_get_by_id(port_id, NULL, values, show_len);

        for (show_index = 0; show_index < show_len; show_index++) {
            cli_print(cli,"%s: %lu \r\n", xstats_names[show_index].name, values[show_index]);
        }
        ros_free(xstats_names);
        ros_free(values);
    }
}

int dpdk_show_mempool(uint32_t ulCoreId, FILE *f)
{
    #define MAX_STRING_LEN 256
    uint64_t flags = 0;
    char s[64];
    char bdr_str[MAX_STRING_LEN];
    struct rte_mempool *ptr;
    struct rte_mempool_ops *ops;

    #define STATS_BDR_FMT "========================================"
    #define STATS_BDR_STR(w, s) fprintf(f,"%.*s%s%.*s\n", w, \
        STATS_BDR_FMT, s, w, STATS_BDR_FMT)

    extern uint64_t rte_get_tsc_hz(void);
    extern struct rte_mempool * rte_mempool_lookup(const char *name);
    snprintf(bdr_str, MAX_STRING_LEN, " show - MEMPOOL %ld",
            rte_get_tsc_hz());

    STATS_BDR_STR(10, bdr_str);

    snprintf(s, sizeof(s), "mbuf_pool_%d", ulCoreId);

    fprintf(f,"  MEMPOOL_CACHE_SIZE=%d\n",MEMPOOL_CACHE_SIZE);

    if (s != NULL) {
        ptr = rte_mempool_lookup(s);
        if (ptr != NULL) {
            flags = ptr->flags;
            fprintf(f,"  - Name: %s on socket %d\n"
                "  - flags:\n"
                "\t  -- No spread (%c)\n"
                "\t  -- No cache align (%c)\n"
                "\t  -- SP put (%c), SC get (%c)\n"
                "\t  -- Pool created (%c)\n"
                "\t  -- No IOVA config (%c)\n",
                ptr->name,
                ptr->socket_id,
                (flags & MEMPOOL_F_NO_SPREAD) ? 'y' : 'n',
                (flags & MEMPOOL_F_NO_CACHE_ALIGN) ? 'y' : 'n',
                (flags & MEMPOOL_F_SP_PUT) ? 'y' : 'n',
                (flags & MEMPOOL_F_SC_GET) ? 'y' : 'n',
                (flags & MEMPOOL_F_POOL_CREATED) ? 'y' : 'n',
                (flags & MEMPOOL_F_NO_IOVA_CONTIG) ? 'y' : 'n');
            fprintf(f,"  - Size %u Cache %u element %u\n"
                "  - header %u trailer %u\n"
                "  - private data size %u\n",
                ptr->size,
                ptr->cache_size,
                ptr->elt_size,
                ptr->header_size,
                ptr->trailer_size,
                ptr->private_data_size);
            fprintf(f,"  - memezone - socket %d\n",
                ptr->mz->socket_id);
            fprintf(f,"  - Count: avail (%u), in use (%u)\n",
                rte_mempool_avail_count(ptr),
                rte_mempool_in_use_count(ptr));

            DPDK_PRINTF_V(f,"%-30s:%d\n",ptr->ops_index);
            ops = rte_mempool_get_ops(ptr->ops_index);
            DPDK_PRINTF_NAME(f,ops->name);
            //DPDK_PRINTF_FUNC(f,ops->alloc);
            //DPDK_PRINTF_FUNC(f,ops->free);
            //DPDK_PRINTF_FUNC(f,ops->enqueue);
            //DPDK_PRINTF_FUNC(f,ops->dequeue);
            //DPDK_PRINTF_FUNC(f,ops->get_count);
            //DPDK_PRINTF_FUNC(f,ops->calc_mem_size);
            //DPDK_PRINTF_FUNC(f,ops->populate);
            //DPDK_PRINTF_FUNC(f,ops->get_info);
            //DPDK_PRINTF_FUNC(f,ops->dequeue_contig_blocks);
            STATS_BDR_STR(50, "");
            return 0;
        }
    }

    rte_mempool_list_dump(f);
    STATS_BDR_STR(50, "");
    return 0;
}

uint8_t *dpdk_get_mac(uint16_t portid)
{
    unsigned nb_ports = dpdk_nb_ports;

    if (nb_ports <= portid) {
        LOG(SERVER, ERR, "Abnormal Parameter, nb_ports %u, portid %u.", nb_ports, portid);
        return NULL;
    }

    return ports_eth_addr[portid].addr_bytes;
}

int dpdk_show_mac(FILE *f)
{
    int portid;
    struct rte_ether_addr *pstAddr;

    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0) {
            continue;
        }
        pstAddr = &ports_eth_addr[portid];
        fprintf(f, "Port [%d] = [%02x:%02x:%02x:%02x:%02x:%02x]\n", portid,
        pstAddr->addr_bytes[0],pstAddr->addr_bytes[1],
        pstAddr->addr_bytes[2],pstAddr->addr_bytes[3],
        pstAddr->addr_bytes[4],pstAddr->addr_bytes[5]);
    }

    return 0;
}


static void dpdk_collectd_resolve_cnt_type(char *cnt_type, size_t cnt_type_len,
                      const char *cnt_name)
{
    char *type_end = strrchr(cnt_name, '_');

    if ((type_end != NULL) &&
        (strncmp(cnt_name, "rx_", strlen("rx_")) == 0)) {
        if (strncmp(type_end, "_errors", strlen("_errors")) == 0)
            strncpy(cnt_type, "if_rx_errors", cnt_type_len);
        else if (strncmp(type_end, "_dropped", strlen("_dropped")) == 0)
            strncpy(cnt_type, "if_rx_dropped", cnt_type_len);
        else if (strncmp(type_end, "_bytes", strlen("_bytes")) == 0)
            strncpy(cnt_type, "if_rx_octets", cnt_type_len);
        else if (strncmp(type_end, "_packets", strlen("_packets")) == 0)
            strncpy(cnt_type, "if_rx_packets", cnt_type_len);
        else if (strncmp(type_end, "_placement",
                 strlen("_placement")) == 0)
            strncpy(cnt_type, "if_rx_errors", cnt_type_len);
        else if (strncmp(type_end, "_buff", strlen("_buff")) == 0)
            strncpy(cnt_type, "if_rx_errors", cnt_type_len);
        else
            /* Does not fit obvious type: use a more generic one */
            strncpy(cnt_type, "derive", cnt_type_len);
    } else if ((type_end != NULL) &&
        (strncmp(cnt_name, "tx_", strlen("tx_"))) == 0) {
        if (strncmp(type_end, "_errors", strlen("_errors")) == 0)
            strncpy(cnt_type, "if_tx_errors", cnt_type_len);
        else if (strncmp(type_end, "_dropped", strlen("_dropped")) == 0)
            strncpy(cnt_type, "if_tx_dropped", cnt_type_len);
        else if (strncmp(type_end, "_bytes", strlen("_bytes")) == 0)
            strncpy(cnt_type, "if_tx_octets", cnt_type_len);
        else if (strncmp(type_end, "_packets", strlen("_packets")) == 0)
            strncpy(cnt_type, "if_tx_packets", cnt_type_len);
        else
            /* Does not fit obvious type: use a more generic one */
            strncpy(cnt_type, "derive", cnt_type_len);
    } else if ((type_end != NULL) &&
           (strncmp(cnt_name, "flow_", strlen("flow_"))) == 0) {
        if (strncmp(type_end, "_filters", strlen("_filters")) == 0)
            strncpy(cnt_type, "operations", cnt_type_len);
        else if (strncmp(type_end, "_errors", strlen("_errors")) == 0)
            strncpy(cnt_type, "errors", cnt_type_len);
        else if (strncmp(type_end, "_filters", strlen("_filters")) == 0)
            strncpy(cnt_type, "filter_result", cnt_type_len);
    } else if ((type_end != NULL) &&
           (strncmp(cnt_name, "mac_", strlen("mac_"))) == 0) {
        if (strncmp(type_end, "_errors", strlen("_errors")) == 0)
            strncpy(cnt_type, "errors", cnt_type_len);
    } else {
        /* Does not fit obvious type, or strrchr error: */
        /* use a more generic type */
        strncpy(cnt_type, "derive", cnt_type_len);
    }
}
void dpdk_xstats_display(FILE *f, uint16_t port_id)
{
    struct rte_eth_xstat_name *xstats_names;
    uint64_t *values;
    int len, ret, i;
    static const char *nic_stats_border = "=================================";

    len = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
    if (len < 0) {
        fprintf(f,"Cannot get xstats count\n");
        return;
    }
    values = malloc(sizeof(*values) * len);
    if (values == NULL) {
        fprintf(f,"Cannot allocate memory for xstats\n");
        return;
    }

    xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
    if (xstats_names == NULL) {
        fprintf(f,"Cannot allocate memory for xstat names\n");
        free(values);
        return;
    }
    if (len != rte_eth_xstats_get_names_by_id(
            port_id, xstats_names, len, NULL)) {
        fprintf(f,"Cannot get xstat names\n");
        goto err;
    }

    fprintf(f,"###### NIC extended statistics for port %-2d #########\n",
               port_id);
    fprintf(f,"%s %d ========================================\n",nic_stats_border,port_id);
    ret = rte_eth_xstats_get_by_id(port_id, NULL, values, len);
    if (ret < 0 || ret > len)
    {
        fprintf(f,"Cannot get xstats\n");
        goto err;
    }

    for (i = 0; i < len; i++)
    {
        if (1)
        {
            char counter_type[MAX_STRING_LEN];
            dpdk_collectd_resolve_cnt_type(counter_type,
                          sizeof(counter_type),
                          xstats_names[i].name);
            fprintf(f,"dpdkstat-port.%u/%s-%s N:%"
                PRIu64"\n", port_id, counter_type,
                xstats_names[i].name, values[i]);

        } else
        {
            fprintf(f,"%s: %"PRIu64"\n", xstats_names[i].name,
                    values[i]);
        }
    }

    fprintf(f,"%s %d ========================================\n",nic_stats_border,port_id);
err:
    free(values);
    free(xstats_names);
}

uint8_t* dpdk_GetFuncNameByAddr(void * callAdrs)
{
    static uint8_t aucName[256];
    void * array[1];
    char **pscStrings;
    uint8_t *pStrBuf = aucName;

    array[0] = callAdrs;

    pscStrings = backtrace_symbols(array, 1);

    if(pscStrings)
    {
        memset(aucName,0,sizeof(aucName));
        sprintf((void*)aucName,"%s",pscStrings[0]);
        free(pscStrings);
        return pStrBuf;
    }
    return NULL;

}

struct lcore_conf * dpdk_get_conf(uint32_t coreid)
{
    if (rte_lcore_is_enabled(coreid))
        return &dpdk_lcore_conf[coreid];
    else
        return NULL;
}

int dpdk_show_info(FILE *f)
{
    uint32_t port_id;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_link link;
    struct rte_ether_addr *pstAddr;
    int ret;

    fprintf(f, "txmode.offloads=%lx \n", dpdk_get_tx_offload());
    fprintf(f, "rxmode.offloads=%lx \n\n", dpdk_get_rx_offload());

    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        if ((enabled_port_mask & (1 << port_id)) == 0) {
            continue;
        }

        ret = rte_eth_dev_info_get(port_id, &dev_info);
        if (ret != 0) {
            fprintf(f, "Error during getting device (port %u) info: %s\n", port_id, strerror(-ret));
            return -1;
        }

        ros_memset(&link, 0, sizeof(link));
        rte_eth_link_get_nowait(port_id, &link);

        fprintf(f, "Port %d\n", (uint8_t)port_id);

        if (link.link_status) {
            fprintf(f, "\tStatus: Link Up - speed %u Mbps - %s\n",
                (unsigned)link.link_speed,
                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));
        } else {
            fprintf(f, "\tStatus: Link Down\n");
        }

        fprintf(f, "\tDriver name: %s\n", dev_info.driver_name);
        fprintf(f, "\tDevice name: %s\n", dev_info.device->name);

        pstAddr = &ports_eth_addr[port_id];
        fprintf(f, "\tMac address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        pstAddr->addr_bytes[0],pstAddr->addr_bytes[1],
        pstAddr->addr_bytes[2],pstAddr->addr_bytes[3],
        pstAddr->addr_bytes[4],pstAddr->addr_bytes[5]);
    }

    return 0;
}

int dpdk_show_stat(FILE *f)
{
    uint32_t iloop;
    uint64_t ulRx = 0;

    fprintf(f, "%-30s : %ld\n", "rte_get_tsc_hz ", rte_get_tsc_hz());

    for (iloop = 0; iloop < RTE_MAX_LCORE; iloop++)
    {
        if (rte_lcore_is_enabled(iloop) == 0)
            continue;

        if (dpdk_stat_send[iloop] || dpdk_stat_recv[iloop]) {
            fprintf(f, "=====================core %d =====================\n", iloop);
            fprintf(f, "%-30s : %ld\n", "send", dpdk_stat_send[iloop]);
            fprintf(f, "%-30s : %ld\n", "recv", dpdk_stat_recv[iloop]);
            ulRx += dpdk_stat_recv[iloop];
        }
    }

    fprintf(f,"======================================================\n");
    fprintf(f,"%-30s : %ld\n", "all recv ", ulRx);
    fprintf(f,"======================================================\n");

    return 0;
}

void dpdk_clear_stat(void)
{
    uint32_t cnt;

    for (cnt = 0; cnt < COMM_MSG_MAX_DPDK_CORE_NUM; ++cnt) {
        if (dpdk_stat_send[cnt] || dpdk_stat_recv[cnt]) {
            dpdk_stat_send[cnt] = 0;
            dpdk_stat_recv[cnt] = 0;
        }
    }
    //rte_eth_xstats_reset(0);
}
