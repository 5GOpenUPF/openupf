/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _ROS_H__
#define _ROS_H__

#ifdef __cplusplus
extern "C" {
#endif


#define ROS_CORE_NUM_MAX    5

#define ROS_MAX_CPUS_NUM    256

#define U64_TO_U32_H(ullValue) ((ullValue >> 32) & 0xFFFFFFFF)
#define U64_TO_U32_L(ullValue) (ullValue & 0xFFFFFFFF)

typedef double  _F64;

#define ROS_PKTS_TASK_IDLE       0
#define ROS_PKTS_TASK_RUNNING    1
#define ROS_PKTS_TASK_EXIT       2

struct ros_pkts_stat
{
    pthread_t tid;
    uint32_t ulRunSatus;
    uint32_t ulStartFlag;
    uint32_t ulPktCpyLen;
    uint64_t pkts_num;
    uint64_t total_pkts_num;
    uint64_t num_sec;
    _F64     max_rate;
    uint32_t starttime;
    uint32_t endtime;
    uint32_t tmptime;
    uint64_t pkts_len; //每次发送包的长度
    uint32_t ulResend;
    uint32_t pkts_error;
    uint64_t ullSpeed;
    uint64_t ullLastSpeed;
    uint32_t ulDelay;
    uint64_t drain_tsc;
    uint64_t cur_tsc;
	uint64_t prev_tsc;
	uint64_t pkt_byte_per_sec;

} __attribute__((aligned(64)));

#define EOS_TICKS_PER_SECOND    1

#define THREAD_NAME_LEN (128)
#define PROC_NAME_LEN (THREAD_NAME_LEN * 2)
#define MAX_LINE 2048

struct proc_info {
    struct proc_info *next;
    pid_t pid;
    pid_t tid;
    uid_t uid;
    gid_t gid;
    char name[PROC_NAME_LEN];
    char tname[THREAD_NAME_LEN];
    char state;
    long unsigned utime;
    long unsigned stime;
    long unsigned delta_utime;
    long unsigned delta_stime;
    long unsigned delta_time;
    long vss;
    long rss;
    int num_threads;
    char policy[32];
    int Cpus_allowed;
    char Cpus_allowed_list[THREAD_NAME_LEN];
};

extern void ros_pkts_stat_inc(struct ros_pkts_stat *pkts_stat,uint32_t pkt_len);
extern uint64_t ros_pkts_stat_init(struct ros_pkts_stat *pstPktStat,uint64_t total_pkts_num);
extern void ros_pkts_show_stat_top(void);
extern _F64 ros_pkts_stat_dump(char *prefix, struct ros_pkts_stat *pkts_stat, uint64_t pkts);
extern void ros_set_task_name(const char *format, ...);
extern uint64_t ros_pkts_stat_reset(struct ros_pkts_stat *pstPktStat);

extern uint32_t ros_app_run_time;
extern uint32_t ros_boottime;
extern uint32_t fp_msg_entry_show(struct cli_def *cli,uint32_t type_num,uint32_t index_num);
extern uint32_t fp_msg_inst_show(struct cli_def *cli,uint32_t inst_num);
extern uint32_t fp_msg_far_show(struct cli_def *cli,uint32_t far_num);
extern uint32_t fp_msg_bar_show(struct cli_def *cli,uint32_t bar_num);
extern uint32_t fp_msg_qer_show(struct cli_def *cli,uint32_t qer_num);
extern uint32_t fp_msg_dns_show(struct cli_def *cli,uint32_t index);
extern int fp_ip_show(struct cli_def *cli,int argc, char **argv);
extern void fp_start_config_show(struct cli_def *cli);
extern int fp_show_packet_stat(struct cli_def *cli,int argc, char **argv);
int fp_conf_signal_trace(struct cli_def *cli,int argc, char **argv);
extern int fp_stats_resource_info(struct cli_def *cli,int argc, char **argv);
extern int fp_show_cblock_info(struct cli_def *cli, int argc, char **argv);
extern int fp_dns_test(struct cli_def *cli, int argc, char **argv);
extern int fp_set_capture2spu_switch(struct cli_def *cli, int argc, char **argv);
extern int fp_dns_credible_cmd(struct cli_def *cli, int argc, char **argv);
extern int fp_set_vlan(struct cli_def *cli, int argc, char **argv);

extern int stub_build_session_pkt(struct cli_def *cli,int argc, char **argv);
extern int stub_build_pfd(struct cli_def *cli,int argc, char **argv);
extern int stub_build_assoc(struct cli_def *cli,int argc, char **argv);
extern int stub_session_test(struct cli_def *cli,int argc, char *argv[]);
extern int stub_show_recv_stat(struct cli_def *cli,int argc, char **argv);
extern int stub_test_predefined_rules(struct cli_def *cli, int argc, char *argv[]);

/* SMU */
extern int ueip_pool_show(struct cli_def *cli,int argc, char **argv);
extern int upc_cmd_teid(struct cli_def *cli,int argc, char **argv);
extern int upc_ha_active_standby_switch(struct cli_def *cli,int argc, char **argv);
extern int upc_show_working_status(struct cli_def *cli,int argc, char **argv);
extern int upc_show_packet_stats(struct cli_def *cli,int argc, char **argv);
extern int upc_stats_resource_info(struct cli_def *cli,int argc, char **argv);
extern void upc_node_create_node(uint8_t ipver, uint32_t ipv4,
        uint8_t *ipv6, uint16_t peer_port);
extern int upc_node_release_cli(struct cli_def *cli, int argc, char *argv[]);
extern int upc_set_features(struct cli_def *cli, int argc, char **argv);
extern int upc_configure_nat(struct cli_def *cli, int argc, char **argv);
extern int upc_configure_predefined_rules(struct cli_def *cli, int argc, char *argv[]);

extern int session_show_all_seid(struct cli_def *cli, int argc, char **argv);
extern int pfd_cli_process(struct cli_def *cli, int argc, char **argv);
extern int sdc_aging_time_set(struct cli_def *cli, int argc, char **argv);
extern int sdc_table_show(struct cli_def *cli, int argc, char **argv);
extern int sdc_sniffer_cmd(struct cli_def *cli, int argc, char **argv);
extern int session_instance_stats_show(struct cli_def *cli, int argc, char **argv);

extern int rqueue_test(int argc, char *argv[]);

/* LB */
extern int lb_ha_active_standby_switch(struct cli_def *cli,int argc, char **argv);
extern int lb_ha_get_lbu_status(struct cli_def *cli,int argc, char **argv);
extern int lb_neighbor_cache_show(struct cli_def *cli,int argc, char **argv);
extern int lb_show_resource_stats(struct cli_def *cli, int argc, char **argv);
extern int lb_show_packet_stat(struct cli_def *cli,int argc, char **argv);


#if (defined(__x86_64__))
#define	ros_mb()    _mm_mfence()
#define	ros_wmb()   _mm_sfence()
#define	ros_rmb()   _mm_lfence()
#elif (defined(_ARCH_PPC64))
#define	ros_mb()    asm volatile("sync" : : : "memory")
#define	ros_wmb()   asm volatile("lwsync" : : : "memory")
#define	ros_rmb()   asm volatile("lwsync" : : : "memory")
#else
#define	ros_mb()    __sync_synchronize()
#define	ros_wmb()   __sync_synchronize()
#define	ros_rmb()   __sync_synchronize()
#endif

int ros_read_from_shell_cmd(char *result, size_t sizeof_result, const char *command);
int ros_get_if_mac_addr(char *if_name, uint8_t *mac);
int ros_get_if_link_status(const char *if_name);
uint8_t ros_get_avail_core_num(void);
uint8_t ros_parse_cpuset_cpus(uint8_t cpus[]);
uint64_t ros_init(struct pcf_file *conf);
uint64_t ros_exit(void);
void ros_random_uuid(uint8_t *uuid);
/* 返回app运行时间，单位为s */
static inline uint32_t ros_getruntime(void)
{
    return ros_app_run_time;
}
/* 获取系统运行时间,从1900-01-01 00:00:00开始算，单位为s */
static inline uint32_t ros_getime(void)
{
    return ros_boottime + ros_app_run_time + 2208988800;
}

#define ROS_GET_TIME(time) (time = ros_app_run_time)
#define ROS_DIFF_TIME(starttime, endtime, timeuse) do { \
    ROS_GET_TIME(endtime);  \
    timeuse = ros_GetSecOffset(endtime,starttime);  \
} while (0)

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _ROS_H__ */
