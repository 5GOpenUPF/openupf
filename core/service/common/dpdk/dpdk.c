/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "dpdk.h"
#include <getopt.h>
#include <rte_ip_frag.h>

#define DPDK_PCIDEVICE          "DPDK_PCIDEVICE"

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
        .mq_mode    = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .offloads = DEV_RX_OFFLOAD_CHECKSUM |
                    DEV_RX_OFFLOAD_JUMBO_FRAME,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
                ETH_RSS_TCP | ETH_RSS_SCTP,
        },
    },
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
        .offloads = DEV_TX_OFFLOAD_VLAN_INSERT \
                    |DEV_TX_OFFLOAD_IPV4_CKSUM \
                    |DEV_TX_OFFLOAD_UDP_CKSUM \
                    |DEV_TX_OFFLOAD_TCP_CKSUM \
                    |DEV_TX_OFFLOAD_SCTP_CKSUM \
                    |DEV_TX_OFFLOAD_QINQ_INSERT \
                    |DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM \
                    |DEV_TX_OFFLOAD_OUTER_UDP_CKSUM \
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
uint64_t dpdk_stat_send[COMM_MSG_MAX_DPDK_CORE_NUM];
uint64_t dpdk_stat_recv[COMM_MSG_MAX_DPDK_CORE_NUM];
uint32_t dpdk_mtu_size = 1500, dpdk_fragment_size = 1514; /* need to add sizeof(struct rte_ether_hdr) */

struct dpdk_config dpdk_cfg;

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
	int i;
	uint8_t portid, queueid;
	struct lcore_conf *qconf;
	struct rte_mbuf *pkts_burst[DPDK_MAX_RX_PKT_BURST];
	struct rte_mbuf *m;
	uint64_t diff_tsc, cur_tsc;
	uint64_t prev_tsc = 0;
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
		queueid = qconf->rx_queue_list[i].queue_id;
		LOG(SERVER, MUST, "-- lcoreid=%u portid=%hhu rxqueueid=%hhu",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {
		cur_tsc = rte_rdtsc();

        if (gfuncDpdkExtraTaskHook)
            gfuncDpdkExtraTaskHook(lcore_id);

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			for (i = 0; i < qconf->n_tx_port; ++i) {
				portid = qconf->tx_port_id[i];
				rte_eth_tx_buffer_flush(portid,
						qconf->tx_queue_id[portid],
						qconf->tx_buffer[portid]);
			}
			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, DPDK_MAX_RX_PKT_BURST);

			for (j = 0; j < nb_rx; j++)
			{
				m = pkts_burst[j];
                pPacket = rte_pktmbuf_mtod(m, void *);
#if (defined(ENABLE_DPDK_DEBUG))
                m->dynfield1[EN_MBUF_CACHE_CORE] = lcore_id;
#endif
                rte_prefetch0(pPacket);
                /* If registered hook, handle hook function */
				if (likely(gfuncDpdkPacketHook))
				    gfuncDpdkPacketHook(pPacket, rte_pktmbuf_data_len(m), portid, (void *)m);
                else
    				rte_pktmbuf_free(m);

                ++dpdk_stat_recv[lcore_id];
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

		socketid = rte_lcore_to_socket_id(lcore_id);
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
	struct lcore_conf *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	int ret;
	unsigned nb_ports, nb_lcores;
	uint16_t queueid;
	unsigned lcore_id;
	uint32_t n_tx_queue;
	uint8_t portid, nb_rx_queue, queue, socketid;
    int argc = 0;
    const char *argv[256];
    uint32_t ulEthIndex;
    uint32_t ulQueueIndex;
    char     lcore_str[256], print_dev[256];
    char     mul_proc_str[128];
    struct rte_eth_conf local_port_conf = port_conf;
    int print_dev_len = 0;


    for (ulEthIndex = 0; ulEthIndex < dpdk_cfg.dev_num; ulEthIndex++) {
        print_dev_len += sprintf(&print_dev[print_dev_len], "%s ", dpdk_cfg.dev[ulEthIndex]);
    }
    LOG(SERVER, MUST, "dpdk dev:%s, dev_num: %d, rx_queue:%d, tx_queue:%d, core_num: %d",
        print_dev, dpdk_cfg.dev_num, dpdk_cfg.rx_queue, dpdk_cfg.tx_queue, dpdk_cfg.core_num);

    argc = 0;
    argv[argc++] = "fpdpdk";

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
    for (ulEthIndex = 0; ulEthIndex < dpdk_cfg.dev_num; ulEthIndex++) {
        argv[argc++] = "-w";
        argv[argc++] = dpdk_cfg.dev[ulEthIndex];
    }

    /* Multiprocess */
    argv[argc++] = "--proc-type=primary";

    ros_memset(mul_proc_str, 0, sizeof(mul_proc_str));
#if (defined(PRODUCT_IS_fpu))
    sprintf(mul_proc_str, "--file-prefix=.upf_fpu_config%d", (uint8_t)(ros_rdtsc() % 256));
#elif (defined(PRODUCT_IS_lbu))
	sprintf(mul_proc_str, "--file-prefix=.upf_lbu_config%d", (uint8_t)(ros_rdtsc() % 256));
#endif
    argv[argc++] = mul_proc_str;

	force_quit = 0;

	/* init EAL */
	ret = rte_eal_init(argc, (char **)argv);
	if (ret < 0)
	{
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
    for (ulQueueIndex = 1; ulQueueIndex < dpdk_cfg.core_num; ulQueueIndex++)
    {
        if (!rte_lcore_is_enabled(dpdk_cfg.cpus[(uint8_t)ulQueueIndex])) {
    		LOG(SERVER, ERR, "error: cpu_id %hhu is not enabled in "
    			"lcore mask", dpdk_cfg.cpus[(uint8_t)ulQueueIndex]);
    		return G_NULL;
    	}
    }

    /* Init RX queue configure */
    for (ulEthIndex = 0; ulEthIndex < nb_ports; ulEthIndex++)
    {
        for (ulQueueIndex = 0; ulQueueIndex < dpdk_cfg.rx_queue; ulQueueIndex++)
        {
            dpdk_lcore_conf[dpdk_cfg.cpus[ulQueueIndex + 1]].rx_queue_list[ulEthIndex].port_id = ulEthIndex;
			dpdk_lcore_conf[dpdk_cfg.cpus[ulQueueIndex + 1]].rx_queue_list[ulEthIndex].queue_id = ulQueueIndex;
			dpdk_lcore_conf[dpdk_cfg.cpus[ulQueueIndex + 1]].n_rx_queue++;
        }
    }

	nb_lcores = rte_lcore_count();

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}

		/* init port */
		fflush(stdout);

		nb_rx_queue = dpdk_cfg.rx_queue;
		n_tx_queue = dpdk_cfg.tx_queue;

		rte_eth_dev_info_get(portid, &dev_info);
        local_port_conf.txmode.offloads &= dev_info.tx_offload_capa;
		if (local_port_conf.txmode.offloads != port_conf.txmode.offloads) {
			printf("Port %u ask %lx tx offload feature, but just support %lx\n",
				portid,
				port_conf.txmode.offloads,
				local_port_conf.txmode.offloads);

            /* Save data */
            port_conf.txmode.offloads = local_port_conf.txmode.offloads;
		}

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
			dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
				port_conf.rx_adv_conf.rss_conf.rss_hf) {
			printf("Port %u modified RSS hash function based on hardware support,"
				"requested:%#"PRIx64" configured:%#"PRIx64"\n",
				portid,
				port_conf.rx_adv_conf.rss_conf.rss_hf,
				local_port_conf.rx_adv_conf.rss_conf.rss_hf);

            /* Save data*/
            port_conf.rx_adv_conf.rss_conf.rss_hf =
                local_port_conf.rx_adv_conf.rss_conf.rss_hf;
		}

		ret = rte_eth_dev_configure(portid, nb_rx_queue,
					(uint16_t)n_tx_queue, &local_port_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%d\n",
				ret, portid);
		}

        /* set the mtu to the maximum received packet size */
        local_port_conf.rxmode.max_rx_pkt_len = dpdk_get_mtu();
		ret = rte_eth_dev_set_mtu(portid,
			local_port_conf.rxmode.max_rx_pkt_len);
		if (ret < 0) {
			printf("\n");
			rte_exit(EXIT_FAILURE, "Set MTU failed: "
				"err=%d, port=%d\n",
			ret, portid);
		}

		ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        if (ret < 0) {
			printf("\n");
			rte_exit(EXIT_FAILURE,
				"rte_eth_macaddr_get: err=%d, port=%d\n",
				ret, portid);
		}

		/* init memory */
		ret = Dpdk_InitMem(DPDK_NB_MBUF);
		if (ret < 0)
    	{
            LOG(SERVER, ERR, "Dpdk_InitMem failed!");
            Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
            return G_NULL;
    	}

		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			/* Initialize TX buffers */
			qconf = &dpdk_lcore_conf[lcore_id];
			qconf->tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
					RTE_ETH_TX_BUFFER_SIZE(DPDK_MAX_TX_PKT_BURST), 0,
					rte_eth_dev_socket_id(portid));
			if (qconf->tx_buffer[portid] == NULL)
        	{
                LOG(SERVER, ERR, "Can't allocate tx buffer for port %u!",
                                    (unsigned) portid);
                Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
                return G_NULL;
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

			rte_eth_dev_info_get(portid, &dev_info);
			txconf = &dev_info.default_txconf;
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     rte_eth_dev_socket_id(portid), txconf);
			if (ret < 0)
        	{
                LOG(SERVER, ERR, "rte_eth_tx_queue_setup: err=%d, port=%d !",
                                                ret, portid);
                Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
                return G_NULL;
        	}

        	qconf->direct_pool = pktmbuf_pool[socketid];
        	qconf->indirect_pool  = pktmbuf_indirect_pool[socketid];

			qconf->tx_queue_id[portid] = queueid;
			queueid++;

			qconf->tx_port_id[qconf->n_tx_port] = portid;
			qconf->n_tx_port++;
		}

        LOG(SERVER, MUST,"Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X",
				portid,
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
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
			fflush(stdout);

			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
					rte_eth_dev_socket_id(portid), NULL,
					pktmbuf_pool[socketid]);
			if (ret < 0)
        	{
                LOG(SERVER, ERR, "rte_eth_rx_queue_setup: err=%d, port=%d!",
                                ret, portid);
                Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
                return G_NULL;
        	}
		}
	}

	/* start ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
    	{
            LOG(SERVER, ERR, "rte_eth_dev_start: err=%d, port=%d!",
                                ret, portid);
            Dpdk_SetInitStat(EN_DPDK_INIT_STAT_FAIL);
            return G_NULL;
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

    if (rte_eal_process_type() == RTE_PROC_PRIMARY)
    	Dpdk_CheckAllPortsLinkStatus((uint8_t)nb_ports, enabled_port_mask);

    Dpdk_SetInitStat(EN_DPDK_INIT_STAT_SUCCESS);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(Dpdk_LoopTask, NULL, CALL_MASTER);

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return G_NULL;
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

#if (defined(ENABLE_DPDK_DEBUG))
    dpdk_mbuf_del_record(m->buf_addr, __LINE__);

    if (lcore_id == LCORE_ID_ANY) {
        lcore_id = dpdk_get_first_core_id();
        LOG(SERVER, ERR, "Abnormal dpdk send core id, Should not fail to get coreid");
    } else if (m->dynfield1[EN_MBUF_CACHE_CORE] != lcore_id) {
        LOG(SERVER, ERR, "Free dpdk mbuf abnormal, record_id: %lu != cur_id: %u.",
            m->dynfield1[EN_MBUF_CACHE_CORE], lcore_id);
    }
    m->dynfield1[EN_MBUF_CACHE_CORE] = 0; /* reset */
#endif

    qconf = &dpdk_lcore_conf[lcore_id];
    //port_id = qconf->tx_port_id[0];

    /* if we don't need to do any fragmentation */
    if (likely (dpdk_fragment_size >= m->pkt_len)) {
        rte_eth_tx_buffer(port_id, qconf->tx_queue_id[port_id],
                    dpdk_lcore_conf[lcore_id].tx_buffer[port_id], m);

        dpdk_stat_send[lcore_id]++;

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
                rte_pktmbuf_free(m);
                return;
            }
        }
        /* else, just forward the packet */
        else {
            /* Don't update mac, send packet directly */
            rte_eth_tx_buffer(port_id, qconf->tx_queue_id[port_id],
                        dpdk_lcore_conf[lcore_id].tx_buffer[0], m);

            dpdk_stat_send[lcore_id]++;
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


            rte_eth_tx_buffer(port_id, qconf->tx_queue_id[port_id],
                        dpdk_lcore_conf[lcore_id].tx_buffer[0], m_new);

            dpdk_stat_send[lcore_id]++;
        }
        rte_pktmbuf_free(m);

        return;
    }

    return;
}

#if (defined(ENABLE_DPDK_DEBUG))
struct rte_mbuf *__dpdk_alloc_mbuf(uint32_t line)
{
#if 1
    struct rte_mbuf *m;
    unsigned lcore_id = rte_lcore_id();
    uint8_t  socketid;

    if (lcore_id == LCORE_ID_ANY) {
        lcore_id = dpdk_get_first_core_id();
    }
    socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);

	/* Create new mbuf for the header. */
    m = rte_pktmbuf_alloc(pktmbuf_pool[socketid]);
    if (m) {
        m->dynfield1[EN_MBUF_CACHE_CORE] = lcore_id;
        dpdk_mbuf_record(m->buf_addr, line);
    }

    return m;
#else
    struct rte_mbuf *m;
    struct rte_mempool_cache *cache;
    unsigned lcore_id = rte_lcore_id();
    uint8_t  socketid;
    int ret;

    if (lcore_id == LCORE_ID_ANY) {
        lcore_id = dpdk_get_first_core_id();
    }
    socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);

	cache = rte_mempool_default_cache(pktmbuf_pool[socketid], lcore_id);
	ret = rte_mempool_generic_get(pktmbuf_pool[socketid], (void **)&m, 1, cache);
    if (ret < 0) {
		return NULL;
    } else {
        MBUF_RAW_ALLOC_CHECK(m);
        rte_pktmbuf_reset(m);
        m->dynfield1[EN_MBUF_CACHE_CORE] = lcore_id;
    }

    dpdk_mbuf_record(m->buf_addr, line);

    return m;
#endif
}
#else

struct rte_mbuf *dpdk_alloc_mbuf(void)
{
    uint8_t socketid = (uint8_t)rte_lcore_to_socket_id(rte_lcore_id());

	/* Create new mbuf for the header. */
    return rte_pktmbuf_alloc(pktmbuf_pool[socketid]);
}
#endif

#if (defined(ENABLE_DPDK_DEBUG))
void dpdk_free_mbuf(struct rte_mbuf *m)
{
#if 1
    if (likely(m != NULL)) {
        unsigned lcore_id = rte_lcore_id();

        if (lcore_id == LCORE_ID_ANY) {
            lcore_id = m->dynfield1[EN_MBUF_CACHE_CORE];
        } else if (m->dynfield1[EN_MBUF_CACHE_CORE] != lcore_id) {
            LOG(SERVER, ERR, "Free dpdk mbuf abnormal, record_id: %lu != cur_id: %u.",
                m->dynfield1[EN_MBUF_CACHE_CORE], lcore_id);
        }
        m->dynfield1[EN_MBUF_CACHE_CORE] = 0; /* reset */

        rte_pktmbuf_free(m);
    }
    return;
#else
    struct rte_mbuf *m_next;
    struct rte_mempool_cache *cache;
    unsigned lcore_id = rte_lcore_id();

    if (lcore_id == LCORE_ID_ANY) {
        lcore_id = m->dynfield1[EN_MBUF_CACHE_CORE];
    } else if (m->dynfield1[EN_MBUF_CACHE_CORE] != lcore_id) {
        LOG(SERVER, ERR, "Free dpdk mbuf abnormal, record_id: %lu != cur_id: %u.",
            m->dynfield1[EN_MBUF_CACHE_CORE], lcore_id);
    }
    m->dynfield1[EN_MBUF_CACHE_CORE] = 0; /* reset */

	if (m != NULL)
		__rte_mbuf_sanity_check(m, 1);

	while (m != NULL) {
		m_next = m->next;

		m = rte_pktmbuf_prefree_seg(m);
    	if (likely(m != NULL)) {
            RTE_ASSERT(RTE_MBUF_DIRECT(m));
        	RTE_ASSERT(rte_mbuf_refcnt_read(m) == 1);
        	RTE_ASSERT(m->next == NULL);
        	RTE_ASSERT(m->nb_segs == 1);
        	__rte_mbuf_sanity_check(m, 0);
            cache = rte_mempool_default_cache(m->pool, lcore_id);
        	rte_mempool_generic_put(m->pool, (void **)&m, 1, cache);
        }

		m = m_next;
	}
#endif
}
#else

void dpdk_free_mbuf(struct rte_mbuf *m)
{
    rte_pktmbuf_free(m);
}
#endif

void dpdk_init_pure_mbuf()
{
    char s[64];

    snprintf(s, sizeof(s), "mbuf_pool_%d", 0);

    pktmbuf_pool[0] = rte_pktmbuf_pool_create(s, 2048,
                        MEMPOOL_CACHE_SIZE, 0,
                        2048,
                        0);
    if (pktmbuf_pool[0] == NULL) {
        LOG(SERVER, ERR, "Cannot create direct mempool.");
        return;
    }

    pktmbuf_indirect_pool[0] = rte_pktmbuf_pool_create(s,
        2048, 32, 0, 0, 0);
    if (pktmbuf_indirect_pool[0] == NULL) {
        LOG(SERVER, ERR, "Cannot create indirect mempool.");
        return;
    }
}

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
    dpdk_cfg.rx_queue = dpdk_cfg.tx_queue = dpdk_cfg.core_num - 1;

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

    current_time = time((time_t *)NULL);
    for (iloop = 0; iloop < COMM_MSG_MAX_DPDK_CORE_NUM; iloop++) {
        if (rte_lcore_is_enabled(iloop) == 0)
		    continue;
        new_count += dpdk_stat_send[iloop];
    }

    if (current_time - s_last_time != 0) {
        pps_num = (new_count - s_last_count)/(current_time - s_last_time);
    }
    else {
        pps_num = 0;
    }

    s_last_count = new_count;
    s_last_time  = current_time;

    for (iloop = 0; iloop < COMM_MSG_MAX_DPDK_CORE_NUM; iloop++) {
        if (rte_lcore_is_enabled(iloop) == 0)
            continue;
        if ((dpdk_stat_send[iloop] != 0)&&(dpdk_stat_recv[iloop] != 0)) {
            pos += sprintf(str + pos, "core %d send: %ld\r\n", iloop, dpdk_stat_send[iloop]);
            pos += sprintf(str + pos, "core %d recv: %ld\r\n\r\n", iloop, dpdk_stat_recv[iloop]);
        }
    }
    pos += sprintf(str + pos, "\r\npps: %d.%d K\r\n", pps_num/1000, pps_num%1000);

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
    uint32_t port_id = 0;
    uint32_t show_index;
    uint32_t show_len;
	struct rte_eth_stats stats;
    struct rte_eth_xstat_name *xstats_names;
    uint64_t *values;


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

    for (show_index = 0; show_index < nb_mempool; ++show_index) {
        cli_print(cli,"direct mempool_%u  : in use count: %u, avail count: %u\r\n", show_index,
            rte_mempool_in_use_count(pktmbuf_pool[show_index]),
            rte_mempool_avail_count(pktmbuf_pool[show_index]));

        cli_print(cli,"incirect mempool_%u: in use count: %u, avail count: %u\r\n", show_index,
            rte_mempool_in_use_count(pktmbuf_indirect_pool[show_index]),
            rte_mempool_avail_count(pktmbuf_indirect_pool[show_index]));
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

    if ((enabled_port_mask & (1 << portid)) == 0) {
        LOG(SERVER, ERR, "Port id %u is down.", portid);
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

int dpdk_show_info(FILE *f,uint32_t ulFlag)
{
    uint32_t iloop,ulIndex;
    struct lcore_conf *pstDpdkCfg;
    char aucStr[128];
    struct rte_eth_dev_info dev_info;
    int rc;
    struct rte_eth_txq_info stTxQinfo;
    struct rte_eth_stats stStats;
    //struct rte_eth_dev   *pstDev;
    extern int i40e_dev_show_info(FILE *f,struct rte_eth_dev *dev);
    char fw_version[128]={0};
    struct rte_eth_rss_conf rss_conf;

    fprintf(f,"txmode.offloads=%lx \n",dpdk_get_tx_offload());
    fprintf(f,"rxmode.offloads=%lx \n",dpdk_get_rx_offload());

    for(ulIndex = 0; ulIndex < RTE_MAX_ETHPORTS; ulIndex++)
    {
        if ((enabled_port_mask & (1 << ulIndex)) == 0)
        {
            continue;
        }

        //pstDev = & rte_eth_devices[ulIndex];


        rte_eth_dev_info_get(ulIndex, &dev_info);

        rte_eth_dev_fw_version_get(ulIndex, fw_version,sizeof(fw_version));

        //DPDK_PRINTF_FUNC(f,pstDev->rx_pkt_burst);
        //DPDK_PRINTF_FUNC(f,pstDev->tx_pkt_burst);

        DPDK_PRINTF_V(f,"%-30s : %s\n",fw_version);
        DPDK_PRINTF_V(f,"%-30s : %s\n",dev_info.driver_name);

        if(ulFlag & 0x1)
        {
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.if_index); /**< Index to bound host interface, or 0 if none.
    		Use if_indextoname() to translate into an interface name. */
    	DPDK_PRINTF_V(f,"%-30s : %p\n",dev_info.dev_flags); /**< Device flags */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.min_rx_bufsize); /**< Minimum size of RX buffer. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.max_rx_pktlen); /**< Maximum configurable length of RX pkt. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.max_rx_queues); /**< Maximum number of RX queues. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.max_tx_queues); /**< Maximum number of TX queues. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.max_mac_addrs); /**< Maximum number of MAC addresses. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.max_hash_mac_addrs);
    	/** Maximum number of hash MAC addresses for MTA and UTA. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.max_vfs); /**< Maximum number of VFs. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.max_vmdq_pools); /**< Maximum number of VMDq pools. */
    	DPDK_PRINTF_V(f,"%-30s : %ld\n",dev_info.rx_offload_capa);
    	/**< All RX offload capabilities including all per-queue ones */
    	DPDK_PRINTF_V(f,"%-30s : %ld\n",dev_info.tx_offload_capa);
    	/**< All TX offload capabilities including all per-queue ones */
    	DPDK_PRINTF_V(f,"%-30s : %ld\n",dev_info.rx_queue_offload_capa);
    	/**< Device per-queue RX offload capabilities. */
    	DPDK_PRINTF_V(f,"%-30s : %ld\n",dev_info.tx_queue_offload_capa);
    	/**< Device per-queue TX offload capabilities. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.reta_size);
    	/**< Device redirection table size, the total number of entries. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.hash_key_size); /**< Hash key size in bytes */
    	/** Bit mask of RSS offloads, the bit offset also means flow type */
    	DPDK_PRINTF_V(f,"%-30s : %ld\n",dev_info.flow_type_rss_offloads);
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_rxconf.rx_thresh.pthresh); /**< Default RX configuration */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_rxconf.rx_thresh.hthresh); /**< Default RX configuration */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_rxconf.rx_thresh.wthresh); /**< Default RX configuration */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_rxconf.rx_free_thresh);
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_rxconf.rx_drop_en);
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_rxconf.rx_deferred_start);

    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_txconf.tx_thresh.pthresh);
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_txconf.tx_thresh.hthresh);
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_txconf.tx_thresh.wthresh);

    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_txconf.tx_rs_thresh); /**< Default TX configuration */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_txconf.tx_free_thresh); /**< Default TX configuration */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_txconf.tx_deferred_start); /**< Default TX configuration */
    	DPDK_PRINTF_V(f,"%-30s : %ld\n",dev_info.default_txconf.offloads); /**< Default TX configuration */

    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.vmdq_queue_base); /**< First queue ID for VMDQ pools. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.vmdq_queue_num);  /**< Queue number for VMDQ pools. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.vmdq_pool_base);  /**< First ID of VMDQ pools. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.rx_desc_lim.nb_max);
	    DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.rx_desc_lim.nb_min);   /**< Min allowed number of descriptors. */
	    DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.rx_desc_lim.nb_align); /**< Number of descriptors should be aligned to. */
	    DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.rx_desc_lim.nb_seg_max);
	    DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.rx_desc_lim.nb_mtu_seg_max);
	    DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.tx_desc_lim.nb_max);
	    DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.tx_desc_lim.nb_min);   /**< Min allowed number of descriptors. */
	    DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.tx_desc_lim.nb_align); /**< Number of descriptors should be aligned to. */
	    DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.tx_desc_lim.nb_seg_max);
	    DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.tx_desc_lim.nb_mtu_seg_max);

    	DPDK_PRINTF_V(f,"%-30s : %x\n",dev_info.speed_capa);  /**< Supported speeds bitmap (ETH_LINK_SPEED_). */
    	/** Configured number of rx/tx queues */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.nb_rx_queues); /**< Number of RX queues. */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.nb_tx_queues); /**< Number of TX queues. */
    	/** Rx parameter recommendations */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_rxportconf.burst_size);
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_rxportconf.ring_size);
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_rxportconf.nb_queues);
    	/** Tx parameter recommendations */
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_txportconf.burst_size);
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_txportconf.ring_size);
    	DPDK_PRINTF_V(f,"%-30s : %d\n",dev_info.default_txportconf.nb_queues);
    	/** Generic device capabilities (RTE_ETH_DEV_CAPA_). */
    	DPDK_PRINTF_V(f,"%-30s : %ld\n",dev_info.dev_capa);
    	/**
    	 * Switching information for ports on a device with a
    	 * embedded managed interconnect/switch.
    	 */
    	//struct rte_eth_switch_info switch_info;
        fprintf(f,"=================================================================\n");

        rte_eth_stats_get(ulIndex, &stStats);
        fprintf(f,"%-30s : %ld \n","TX-packets",stStats.opackets);
        fprintf(f,"%-30s : %ld \n","TX-dropped",stStats.oerrors);
        fprintf(f,"%-30s : %ld \n","TX-total",(stStats.opackets + stStats.oerrors));
        fprintf(f,"%-30s : %ld \n","RX-packets",stStats.ipackets);

        /**< Total of RX packets dropped by the HW,
	    * because there are no available buffer (i.e. RX queues are full).
	    */

        fprintf(f,"%-30s : %ld \n","RX-dropped",stStats.imissed);
        fprintf(f,"%-30s : %ld \n","RX-total",(stStats.ipackets + stStats.imissed));
        fprintf(f,"%-30s : %ld \n","RX-error",stStats.ierrors);
        fprintf(f,"%-30s : %ld \n","RX-rx_nombuf",stStats.rx_nombuf);
        #if 0
        for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++)
        {
            fprintf(f,"Q[%02d]%-25s : %ld \n",i,"TX-packets",stStats.q_opackets[i]);
            fprintf(f,"Q[%02d]%-25s : %ld \n",i,"TX-bytes",stStats.q_obytes[i]);
            fprintf(f,"Q[%02d]%-25s : %ld \n",i,"RX-packets",stStats.q_ipackets[i]);
            fprintf(f,"Q[%02d]%-25s : %ld \n",i,"RX-error",stStats.q_errors[i]);
            fprintf(f,"Q[%02d]%-25s : %ld \n",i,"RX-bytes",stStats.q_ibytes[i]);
		}
        #endif
        dpdk_xstats_display(f,ulIndex);

        rc = rte_eth_dev_rss_hash_conf_get(ulIndex, &rss_conf);
		if (rc == 0)
		{
			if (rss_conf.rss_key) {
				fprintf(f,"  - RSS\n");
				fprintf(f,"\t  -- RSS len %u key (hex):",
						rss_conf.rss_key_len);
				for (iloop = 0; iloop < rss_conf.rss_key_len; iloop++)
					fprintf(f," %x", rss_conf.rss_key[iloop]);
				fprintf(f,"\t  -- hf 0x%"PRIx64"\n",
						rss_conf.rss_hf);
			}
		}
        }

        if(0 == strcmp(dev_info.driver_name,"net_i40e"))
        {
            //i40e_dev_show_info(f,pstDev);
        }

    }

    if(ulFlag & 0x4)
    {

        for (iloop = 0; iloop < RTE_MAX_LCORE; iloop++)
        {
            if (rte_lcore_is_enabled(iloop) == 0)
                continue;

            pstDpdkCfg = &dpdk_lcore_conf[iloop];
            fprintf(f,"=====================core %d =====================\n",iloop);
            fprintf(f,"%-30s : %d\n", "n_rx_queue",pstDpdkCfg->n_rx_queue);

            for(ulIndex = 0; ((ulIndex < RTE_MAX_ETHPORTS)&& (ulIndex < pstDpdkCfg->n_rx_queue)); ulIndex++)
            {
                memset(aucStr,0,sizeof(aucStr));
                sprintf(aucStr,"rx_queue_list[%02d].port_id",ulIndex);
                fprintf(f,"%-30s : %d\n",aucStr,pstDpdkCfg->rx_queue_list[ulIndex].port_id);
                memset(aucStr,0,sizeof(aucStr));
                sprintf(aucStr,"rx_queue_list[%02d].queue_id",ulIndex);
                fprintf(f,"%-30s : %d\n",aucStr,pstDpdkCfg->rx_queue_list[ulIndex].queue_id);
            }

            fprintf(f,"%-30s : %d\n", "n_tx_port",pstDpdkCfg->n_tx_port);
            for(ulIndex = 0; ulIndex < RTE_MAX_ETHPORTS; ulIndex++)
            {
                if ((enabled_port_mask & (1 << ulIndex)) == 0)
                {
                    continue;
                }

                memset(aucStr,0,sizeof(aucStr));
                sprintf(aucStr,"tx_port_id[%02d]",ulIndex);
                fprintf(f,"%-30s : %d\n",aucStr,pstDpdkCfg->tx_port_id[ulIndex]);

                memset(aucStr,0,sizeof(aucStr));
                sprintf(aucStr,"tx_queue_id[%02d]",ulIndex);
                fprintf(f,"%-30s : %d\n",aucStr,pstDpdkCfg->tx_queue_id[ulIndex]);

                if(pstDpdkCfg->tx_buffer[ulIndex])
                {
                    memset(aucStr,0,sizeof(aucStr));
                    sprintf(aucStr,"tx_buffer[%02d].size",ulIndex);/**< Size of buffer for buffered tx */
                    fprintf(f,"%-30s : %d\n",aucStr,pstDpdkCfg->tx_buffer[ulIndex]->size);

                    memset(aucStr,0,sizeof(aucStr));
                    sprintf(aucStr,"tx_buffer[%02d].length",ulIndex);/**< Size of buffer for buffered tx */
                    fprintf(f,"%-30s : %d\n",aucStr,pstDpdkCfg->tx_buffer[ulIndex]->length);
                }

                rc = rte_eth_tx_queue_info_get(pstDpdkCfg->tx_port_id[ulIndex], pstDpdkCfg->tx_queue_id[ulIndex], &stTxQinfo);
            	if (rc == 0)
            	{
                	fprintf(f,"%-30s : %d\n","conf.tx_thresh.pthresh",stTxQinfo.conf.tx_thresh.pthresh);
                	fprintf(f,"%-30s : %d\n","conf.tx_thresh.hthresh",stTxQinfo.conf.tx_thresh.hthresh);
                	fprintf(f,"%-30s : %d\n","conf.tx_thresh.wthresh",stTxQinfo.conf.tx_thresh.wthresh);
                	fprintf(f,"%-30s : %d\n","conf.tx_rs_thresh",stTxQinfo.conf.tx_rs_thresh);
                	fprintf(f,"%-30s : %d\n","conf.tx_free_thresh",stTxQinfo.conf.tx_free_thresh);
                	fprintf(f,"%-30s : %s\n","conf.tx_deferred_start",((stTxQinfo.conf.tx_deferred_start != 0) ? "on" : "off"));
                	fprintf(f,"%-30s : %d\n","nb_desc",stTxQinfo.nb_desc);
            	}

            }

        }
    }
    return 0;
}

int dpdk_show_stat(FILE *f)
{
    uint32_t iloop;
    uint64_t ulRx = 0;

    fprintf(f,"%-30s : %ld\n","rte_get_tsc_hz ",rte_get_tsc_hz());

    for (iloop = 0; iloop < RTE_MAX_LCORE; iloop++)
    {
        if (rte_lcore_is_enabled(iloop) == 0)
            continue;
        fprintf(f,"=====================core %d =====================\n",iloop);
        fprintf(f,"%-30s : %ld\n","send",dpdk_stat_send[iloop]);
        fprintf(f,"%-30s : %ld\n","recv",dpdk_stat_recv[iloop]);
        ulRx += dpdk_stat_recv[iloop];
    }

    fprintf(f,"======================================================\n");
    fprintf(f,"%-30s : %ld\n","all recv ",ulRx);
    fprintf(f,"======================================================\n");

    return 0;
}

int dpdk_clear_stat(void)
{
    uint32_t iloop;

    for (iloop = 0; iloop < RTE_MAX_LCORE; iloop++)
    {
        if (rte_lcore_is_enabled(iloop) == 0)
            continue;
        dpdk_stat_send[iloop] = 0;
        dpdk_stat_recv[iloop] = 0;
    }

    rte_eth_xstats_reset(0);

    return 0;
}
