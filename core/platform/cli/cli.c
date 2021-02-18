/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "libcli.h"

static struct cli_def *g_cli=NULL;
int listen_fd = 0;

typedef struct cmdNode
{
	char *pCommand;
	char *pHelp;
	int privilege;
	int mode;
	int numChildren;
	struct cmdNode* pChildren;
	int (*pHandlers)(struct cli_def *cli, int, char **);
	struct cli_command *cmd_handle;
}cmdNode;

extern int cli_get_time(struct cli_def *cli, int argc, char **argv);
extern int git_version(struct cli_def *cli, int argc, char **argv);
extern int cli_show_version(struct cli_def *cli,int argc, char *argv[]);
extern int log_cli_show_log_switch(struct cli_def *cli,int argc, char **argv);
extern int log_cli_set_log_switch(struct cli_def *cli,int argc, char **argv);
extern int ros_show_mempool(struct cli_def *cli,int argc, char *argv[]);
extern void ros_set_task_name(const char *format, ...);
extern int cli_show_task(struct cli_def *cli,int argc, char **argv);
extern int ros_show_dpdk_lcore(struct cli_def *cli,int argc, char *argv[]);
extern int ros_show_mac(struct cli_def *cli,int argc, char *argv[]);
extern int ros_show_info(struct cli_def *cli,int argc, char *argv[]);


/* Override the default command prompt */
#if (defined(PRODUCT_IS_fpu))
char cli_prompt[16] = "fpu";
extern int cli_show_dpdk_stat(struct cli_def *cli, int argc, char **argv);
extern int fast_get_show(struct cli_def *cli, int argc, char **argv);
extern int inst_get_show(struct cli_def *cli, int argc, char **argv);
extern int far_get_show(struct cli_def *cli, int argc, char **argv);
extern int bar_get_show(struct cli_def *cli, int argc, char **argv);
extern int qer_get_show(struct cli_def *cli, int argc, char **argv);
extern int fp_get_start_config_show(struct cli_def *cli, int argc, char **argv);
extern int fp_ip_show(struct cli_def *cli, int argc, char **argv);
extern int fp_cli_start_sent_task(struct cli_def *cli, int argc, char **argv);
extern int fp_cli_stop_sent_task(struct cli_def *cli, int argc, char **argv);
extern int fp_cli_pkt_stat_start_task(struct cli_def *cli, int argc, char **argv);
extern int fp_cli_pkt_stat_stop_task(struct cli_def *cli, int argc, char **argv);
extern int fp_cli_pkt_stat_clear(struct cli_def *cli, int argc, char **argv);
extern int fp_cli_pkt_test_resend(struct cli_def *cli, int argc, char **argv);
extern int fp_show_signal_trace_ueip(struct cli_def *cli,int argc, char **argv);
extern int fp_set_head_enrich_flag(struct cli_def *cli, int argc, char **argv);

#elif (defined(PRODUCT_IS_lbu))
char cli_prompt[16] = "lbu";

#elif (defined(PRODUCT_IS_smu))
char cli_prompt[16] = "smu";
extern int cli_asso_setup(struct cli_def *cli,int argc, char **argv);
extern int cli_asso_update(struct cli_def *cli, int argc, char **argv);
extern int cli_asso_update_release(struct cli_def *cli, int argc, char **argv);
extern int cli_show_node(struct cli_def * cli, int argc, char * * argv);
extern int cli_user_sig_trace(struct cli_def *cli, int argc, char **argv);
extern int cli_show_up_features(struct cli_def * cli, int argc, char * * argv);
extern int upc_sig_trace_show(struct cli_def *cli, int argc, char **argv);
extern int cli_set_hb_time(struct cli_def * cli, int argc, char * * argv);
extern int cli_pf_rule(struct cli_def *cli, int argc, char **argv);
extern int cli_del_all_node(struct cli_def *cli, int argc, char **argv);
extern int cli_show_session(struct cli_def *cli, int argc, char **argv);
extern int cli_session_ip(struct cli_def *cli, int argc, char **argv);
extern int pf_rule_table_show(struct cli_def *cli, int argc, char **argv);
extern int cli_white_list(struct cli_def *cli, int argc, char **argv);
extern int pdr_show_activate_table(struct cli_def *cli, int argc, char **argv);

#elif (defined(PRODUCT_IS_stub))
char cli_prompt[16] = "stub";

#endif

//extern int ROS_DebugBlkMem(struct cli_def *cli, int argc, char **argv);
//extern int ROS_DebugMemSys(struct cli_def *cli, int argc, char **argv);


static cmdNode mShowChildren[] =
{
    { "version","display version",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_show_version,NULL },
    { "time","display time",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_get_time,NULL },
    { "mempool","display dpdk mempool",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,ros_show_mempool,NULL },
    { "task","display task",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_show_task,NULL },
    { "dpdklcore","display task",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,ros_show_dpdk_lcore,NULL },
    { "mac","display mac",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,ros_show_mac,NULL },
    { "info","display info",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,ros_show_info,NULL },
#if (defined(PRODUCT_IS_fpu))
    { "stat",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_show_dpdk_stat,NULL },
    { "fast",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fast_get_show,NULL },
    { "inst",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,inst_get_show,NULL },
    { "far",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,far_get_show,NULL },
    { "bar",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,bar_get_show,NULL },
    { "qer",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,qer_get_show,NULL },
    { "config",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_get_start_config_show,NULL },
    { "ip",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_ip_show,NULL },
    { "cblk",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_show_cblock_info,NULL },
#elif (defined(PRODUCT_IS_stub))
    //{ "ip",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,stub_show_ip_pair,NULL },
    //{ "stat",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,stub_show_stat,NULL },
    //{ "config",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,stub_show_config,NULL },
#endif
};

static cmdNode mLogChildren[] =
{
    { "show","show log_switch",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,log_cli_show_log_switch,NULL },
    { "set","set <type> <level> <value>",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,log_cli_set_log_switch,NULL },
};

#if (defined(PRODUCT_IS_fpu))

#elif (defined(PRODUCT_IS_stub))


#endif

#if (defined(PRODUCT_IS_smu))
static cmdNode mUpChildren[] =
{
	{ "configure",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,upc_set_features,NULL },
    { "show",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_show_up_features,NULL },
};

/*static cmdNode mSigTraceChildren[] =
{
	{ "enable",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_user_sig_trace,NULL },
    { "show",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,upc_sig_trace_show,NULL },
};*/
#endif

static cmdNode mRootChildren[] =
{
	{ "show",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, sizeof(mShowChildren)/sizeof(cmdNode),mShowChildren , NULL,NULL },
    { "log",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, sizeof(mLogChildren)/sizeof(cmdNode),mLogChildren , NULL,NULL },

#if (defined(PRODUCT_IS_fpu))
    { "res_stats","Show resource usage",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_stats_resource_info,NULL },
    { "stats","Display packet statistics",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_show_packet_stat,NULL },
    //{ "signal_trace_ueip",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_show_signal_trace_ueip,NULL },
    { "dns_test",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_dns_test,NULL },
    { "cap2spu","Legacy debugging function, not recommended",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_set_capture2spu_switch,NULL },
    { "dns_cdb","DNS creditable configuration",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_dns_credible_cmd,NULL },
	{ "head_enrich","Head enhancement",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_set_head_enrich_flag,NULL },
    { "vlan_set","VLAN configuration, It doesn't need to be set in FPU, but in LBU",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,fp_set_vlan,NULL },
#elif (defined(PRODUCT_IS_lbu))
    { "ass","Active standby switching",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,lb_ha_active_standby_switch,NULL },
    { "ha_status","Display active and standby working status",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,lb_ha_get_lbu_status,NULL },
    { "ngb_cache","Show neighbor cache table",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,lb_neighbor_cache_show,NULL },
    { "res_stat","Show resource usage",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,lb_show_resource_stats,NULL },
#elif (defined(PRODUCT_IS_smu))
    { "asso_setup","asso_setup [ip] [port]",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_asso_setup,NULL },
    { "asso_update","asso_update",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_asso_update,NULL },
    { "asso_update_release","asso_update_release [ip]",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_asso_update_release,NULL },
    { "del_all_node","del_all_node",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_del_all_node,NULL },
	{ "ass","Active standby switching",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,upc_ha_active_standby_switch,NULL },
    { "stats","Display packet statistics",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,upc_show_packet_stats,NULL },
    //{ "sig_trace",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, sizeof(mSigTraceChildren)/sizeof(cmdNode), mSigTraceChildren,NULL,NULL },

    { "show_node","Display node information",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_show_node,NULL },
    { "up_features","Configure UP features",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, sizeof(mUpChildren)/sizeof(cmdNode), mUpChildren,NULL,NULL },

    { "res_stat","Display resource statistic",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,upc_stats_resource_info,NULL },
    { "set_hb_time","Set heartbeat interval of node",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_set_hb_time,NULL },
    //{ "pf_rule","Configure predefined rules",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_pf_rule,NULL },
    { "asso_release","Release node",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,upc_node_release_cli,NULL },
    { "ha_status","Display active and standby working status",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,upc_show_working_status,NULL },

    { "show_session","Show session information",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_show_session,NULL },
    { "show_all_session","Show all session information",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,session_show_all_seid,NULL },
	{ "show_sess_ueip","Show UEIP of session",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_session_ip,NULL },
    { "pfd","Configure and query PFD rules",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,pfd_cli_process,NULL },
    { "pfrule_show","Show predefined rules",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,pf_rule_table_show,NULL },
    { "white_list","Configure white list",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,cli_white_list,NULL },
    { "pdr_show","Display PDR rule information",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,pdr_show_activate_table,NULL },
    { "dns_show","Show cached DNS",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,sdc_table_show,NULL },
    { "dns_aging","Configure DNS aging time",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,sdc_aging_time_set,NULL },
    { "dns_snf","Configure DNS sniffer",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,sdc_sniffer_cmd,NULL },
#elif (defined(PRODUCT_IS_stub))
    { "sess_perf","Simple UPF testing tool",PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,stub_session_test,NULL },
#endif
    //{ "mblk",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,ROS_DebugBlkMem,NULL },
    //{ "msys",NULL,PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 0, NULL,ROS_DebugMemSys,NULL },
};

cmdNode	mRootCmdNode = { NULL, NULL, 0, 0,sizeof(mRootChildren)/sizeof(cmdNode), mRootChildren, NULL, NULL };

void cmd_register(struct cli_def *cli,cmdNode* cmdNode,int numCmd,struct cli_command *cmd_parent)
{
	int i;
	for(i=0;i<numCmd;i++)
	{
		if(cmdNode[i].pCommand)
		{
			cmdNode[i].cmd_handle = cli_register_command(cli,cmd_parent,cmdNode[i].pCommand,cmdNode[i].pHandlers,
				cmdNode[i].privilege,cmdNode[i].mode, cmdNode[i].pHelp);
		}
		cmd_register(cli,cmdNode[i].pChildren,cmdNode[i].numChildren,cmdNode[i].cmd_handle);
	}
}

void cli_accept(int *p)
{
	int connectfd = *p;

	//int iret=-1;
	//int rv;
	//int maxfd;
	//fd_set rset;
	//struct timeval tv;
	//tv.tv_sec = 0;
    //tv.tv_usec = 100;

	g_cli->iIsPtyCmd = G_NO;
    set_input_mode(connectfd);
	cli_loop(g_cli, connectfd,connectfd);
	close(connectfd);
}

int cli_err(struct cli_def *cli, char *InvalidCmd,int iMsgCode)
{
    cli_print(cli, "msgcode(%03d)",iMsgCode);
    return 0;
}

void cli_drop_connect()
{
    //return ;
    int maxfd,rv,connectfd = 0;
	fd_set rset;
	struct sockaddr_in client;
	socklen_t addrlen;
    struct timeval tm;

	addrlen = sizeof(client);
    FD_ZERO(&rset);
	FD_SET(listen_fd, &rset);
	maxfd = listen_fd;

    tm.tv_sec = 0;
    tm.tv_usec = 1;
	rv =  select (maxfd + 1, &rset, NULL, NULL, &tm);
	if (rv <= 0)
	{
		return ;
	}

    if((connectfd = accept(listen_fd,(struct sockaddr *)&client, &addrlen)) != -1)
	{
		close(connectfd);
		return ;
	}
}


void *cli_task(void *arg)
{
    //struct cli_command *c;

    //int s, x;
    //int on = 1;
    //int attempt =0;
    //int i;
    //int iArgvLen;

    //char *pauArgvBuf[4] = {NULL};
    (void)arg;

	int connectfd = 0;
	struct sockaddr_in addr;
    struct sockaddr_in client;
	int soc_dummy=1;
	socklen_t addrlen;

    ros_set_task_name("cli_task");

	// create the listening socket
	if ( (listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
	{
		syslog(LOG_INFO, "can't open TCP socket for redundancy process.\n");
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

#if (defined(PRODUCT_IS_smu))
    addr.sin_port = htons(CLI_SMU_PORT);
#elif (defined(PRODUCT_IS_lbu))
    addr.sin_port = htons(CLI_LBU_PORT);
#elif (defined(PRODUCT_IS_fpu))
    addr.sin_port = htons(CLI_FPU_PORT);
#elif (defined(PRODUCT_IS_stub))
    addr.sin_port = htons(CLI_STUB_PORT);
#endif

	LOG(CLI, MUST, "cli_task port %u ",ntohs(addr.sin_port));
	if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,(char *)&soc_dummy, sizeof(soc_dummy))<0)
	{
        return NULL;
	}

	if(bind(listen_fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0)
	{
        return NULL;
	}

	if(listen(listen_fd, 1) == -1)
    {
       return NULL;
    }

    addrlen = sizeof(client);
	int rv;
	int maxfd;
	fd_set rset;

    while(1)
	{
		FD_ZERO(&rset);
		FD_SET(listen_fd, &rset);
		maxfd = listen_fd;

		rv =  select (maxfd + 1, &rset, NULL, NULL, NULL);
		if (rv < 0)
		{
			syslog(LOG_ERR, "select returned error %d\n", errno);
			continue;
		}

        if((connectfd=accept(listen_fd,(struct sockaddr *)&client, &addrlen))==-1)
		{
			perror("accept() error. \n");
			return NULL;
		}
		else
		{
			cli_accept(&connectfd);
		}
    }
}

uint64_t cli_parse_argv(int argc, char **argv)
{
    //const struct cli_table_entry *cmd_entry;
    //int rcode;

    /* The input parameter is empty and cannot be triggered. */
    if (argc <= 1)
        return G_FAILURE;

    cli_init();

    cli_no_pty_proc(g_cli,argc - 1, argv + 1);

    return G_SUCCESS;
}

uint64_t cli_init(void)
{
    int ret;
    pthread_t thread_id;

    if(g_cli)
    {
        return 0;
    }

    g_cli = cli_lib_init();
    g_cli->iIsPtyCmd = G_NO;
    g_cli->enCliLaguage = EN_CLI_LANGUAGE_CHS;
    g_cli->iOutSocket = 0;
    //printf("%s<%d> \r\n",__FUNCTION__,__LINE__);

    //cli_set_banner(cli,(char *)cli_prompt);
    //pcf_strname_add_upu_id(cli_prompt);
    cli_set_hostname(g_cli,(char *)cli_prompt);
    //cli_regular(cli, regular_callback);
    cli_regular_interval(g_cli, 5); // Defaults to 1 second
    cli_set_idle_timeout(g_cli, 0); // 60 second idle timeout
    //cli_register_command(cli, NULL, "exit", cmd_config_int_exit,PRIVILEGE_PRIVILEGED, MODE_CONFIG_INT,"Exit from interface configuration");
    //关闭密码验证
    //cli_set_auth_callback(cli, check_auth);
    //关闭特权模式
    //cli_set_enable_callback(cli, check_enable);

    //cli_checkalive(cli,cli_CheckAlive);

    //cli_set_error_callback(cli,(void*)cli_err);
	cmd_register(g_cli,&mRootCmdNode,1,NULL);

    ret = pthread_create(&thread_id, NULL, cli_task, NULL);
    if (ret != 0) {
        LOG(CLI, ERR, "pthread_create fail ");
        return G_FAILURE;
    }

    return G_SUCCESS;
}

uint64_t cli_exit(void)
{
    if(0 < listen_fd)
    {
        close(listen_fd);
    }
    return G_SUCCESS;
}

void cli_dump_args(int argc, char **argv)
{
    int i = 0;
    printf("argc:%d\n", argc);
    for (i = 0; i < argc; i++)
    {
        printf("idx:%d, argv:%s\n", i, argv[i]);
    }
}

void _dbg_printf(const char * pucFuncName,_U32 ulLine, char *format, ...)
{
    char g_auStrBuf[1024];
    va_list ap;
    va_start(ap, format);
    if((NULL == g_cli) || (0 >= g_cli->iOutSocket))
    {
        memset(g_auStrBuf,0,sizeof(g_auStrBuf));
        vsnprintf (g_auStrBuf,sizeof(g_auStrBuf), format, ap );
        printf("%s<%d> %s \n",pucFuncName,ulLine,g_auStrBuf);
    }
    else
    {
        _print(pucFuncName,ulLine,g_cli, PRINT_FILTERED, format, ap);
    }
    va_end(ap);
}

void main_loop()
{
    g_cli = cli_lib_init();
	cli_loop(g_cli, STDIN_FILENO,STDOUT_FILENO);
}

const char * cli_cmd_getinfo(const cmdDef * cmd, const char *name)
{
    return NULL;
}

int cli_cmd_help(const cmdDef *pCmd)
{
    return 0;
}

