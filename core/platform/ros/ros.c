/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "ros.h"
//#include <ctype.h>
#include <sys/prctl.h>
//#include <dirent.h>


#if (defined(PRODUCT_IS_fpu) || defined(PRODUCT_IS_lbu))
#include <rte_cycles.h>
#else
uint64_t rte_get_tsc_hz(void)
{
	return 0;
}
uint64_t rte_rdtsc(void)
{
    return 0;
}
#endif

#define UPF_VERSION_ENV         "UPF_VERSION"

uint32_t ros_app_run_time = 0;
uint32_t ros_boottime = 0;
pthread_t ros_checktime_thread;

extern int dpdk_show_stat(FILE *f);
extern int dpdk_clear_stat(void);
extern int dpdk_show_mac( FILE *f);
extern int dpdk_show_mempool(uint32_t ulCoreId, FILE *f);
extern int dpdk_show_info(FILE *f,uint32_t ulFlag);

void ros_set_task_name(const char *format, ...)
{
    int n,len;
    char buf[128];
	va_list ap;
    char* pStr=buf;

    memset((void *)buf, 0, sizeof(buf));

#if (defined(PRODUCT_IS_fpu))
    const char cli_prompt[] = "fpu";
#elif (defined(PRODUCT_IS_smu))
    const char cli_prompt[] = "smu";
#elif (defined(PRODUCT_IS_stub))
    const char cli_prompt[] = "stub";
#elif (defined(PRODUCT_IS_lbu))
    const char cli_prompt[] = "lbu";
#else
    const char cli_prompt[] = "upf";
#endif

    sprintf(pStr,"%s_",cli_prompt);

    len = strlen(pStr);

	va_start(ap, format);
    n = vsnprintf(&pStr[len], (sizeof(buf) - len), format, ap);
	va_end(ap);
    if (n >= 4096)
    {
        return;
    }

    prctl(PR_SET_NAME,pStr);

}

/* Number of available cores */
uint8_t ros_avail_core_num;

uint8_t ros_get_avail_core_num(void)
{
    return ros_avail_core_num;
}

/* Parse cpuset cpus */
uint8_t ros_parse_cpuset_cpus(uint8_t cpus[])
{
    uint8_t ret_cnt = 0;
    char delim[] = ",";
    char *token = NULL;
    char result[ROS_MAX_CPUS_NUM];
    char *s = result;
    char print_str[256];
    uint8_t cnt, str_cnt = 0;

    if (0 > ros_read_from_shell_cmd(result, sizeof(result), "cat /sys/fs/cgroup/cpuset/cpuset.cpus")) {
        LOG(ROS, ERR, "ros_read_from_shell_cmd fail ");
        return ret_cnt;
    }

    for (token = strsep(&s, delim); token != NULL; token = strsep(&s, delim)) {
        if (*token == 0) {
            continue;
        }

        if (strchr(token, '-')) {
            char ch[] = "-";
            char *tk = NULL;
            uint8_t start, last;

            tk = strsep(&token, ch);
            if (tk) {
                start = atoi(tk);
            } else {
                LOG(ROS, ERR, "Parse cpuset cpus fail, token: %s", token);
                return 0;
            }
            tk = strsep(&token, ch);
            if (tk) {
                last = atoi(tk);
            } else {
                LOG(ROS, ERR, "Parse cpuset cpus fail, token: %s", token);
                return 0;
            }

            for (; start <= last; ++start) {
                cpus[ret_cnt++] = start;
            }
        } else {
            cpus[ret_cnt++] = atoi(token);
        }
    }

    str_cnt = sprintf(print_str, "Use CPUs number %d as:", ret_cnt);
    for (cnt = 0; cnt < ret_cnt; ++cnt) {
        str_cnt += sprintf(&print_str[str_cnt], " %d", cpus[cnt]);
    }
    LOG(ROS, MUST, "%s", print_str);

    return ret_cnt;
}

/* 获取当前函数(调用EOS_GetCurrentFp的函数)的函数栈基址 */
void EOS_GetCurrentFp()
{
    /* 这个函数的栈除了保存rbp到 rax寄存器，不保存其他寄存器*/
    /* 所以rbp就是指向FP的指针，把它指向的值传给rax返回 */
	asm("mov	(%rsp), %rax");

}

void *ros_checktime_task(__mb_unused void *arg)
{
    uint32_t loop_count = 0;
    uint32_t current_time = 0;
    struct tm *info;
    time_t  raw_time;

    ros_app_run_time = 0;

    ros_set_task_name("ros_time");

    time(&raw_time);
    info = localtime(&raw_time);
    ros_boottime = mktime(info);

    for (;;) {
        ros_app_run_time++;
        loop_count++;
        if (loop_count >= 3600) {
            current_time = time((time_t *)NULL);
            if ((ros_boottime + ros_app_run_time) != current_time)
                ros_boottime = (current_time - ros_app_run_time);
            loop_count = 0;
        }
        sleep(1);
    }
}

int ros_read_from_shell_cmd(char *result, size_t sizeof_result, const char *command)
{
    FILE *fp;
    char *pnt;

    if ((fp = popen(command, "r")) == NULL) {
        return -1;
    }
    fread(result, 1, sizeof_result, fp);

    if ((pnt = strrchr(result, '\n')) != NULL) {
        *pnt = 0;
    }
    (void)pclose(fp);

    return *result == 0 ? -1 : 0;
}

int ros_get_if_mac_addr(char *if_name, uint8_t *mac)
{
    struct ifreq s;
    int fd;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (0 > fd) {
        LOG(ROS, ERR, "Socket fail:%s", strerror(errno));
        return -1;
    }

    strcpy(s.ifr_name, if_name);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        memcpy(mac, s.ifr_addr.sa_data, ETH_ALEN);
        return 0;
    }

    return -1;
}

uint64_t ros_init(struct pcf_file *conf)
{
    uint64_t ret = G_SUCCESS;
    uint8_t cpus[ROS_MAX_CPUS_NUM];
    char result[64];

    /* It needs to be created in advance, otherwise SMU will not get the exact time in initialization */
    if (pthread_create(&ros_checktime_thread, NULL,
                    ros_checktime_task, NULL) != 0)    {
		LOG(ROS, ERR, "Fail to create pthread, errno:%s",
                                strerror(errno));
		return G_FAILURE;
	}

    if (0 > ros_read_from_shell_cmd(result, sizeof(result), "nproc")) {
        LOG(ROS, ERR, "ros_read_from_shell_cmd fail ");
        ret = G_FAILURE;
        return ret;
    }
    ros_avail_core_num = atoi(result);

    if (ros_avail_core_num != ros_parse_cpuset_cpus(cpus)) {
        LOG(ROS, ERR, "Parse cpuset cpus fail.");
        ret = G_FAILURE;
        return ret;
    }

    ros_set_tsc_freq();

    ret = ros_timer_init(cpus[0]);
    if (ret != G_SUCCESS) {
        LOG(ROS, ERR, "ros_timer_init fail ");
        return ret;
    }
    LOG(ROS, MUST, "ros_timer_init success ");

    return ret;
}

uint64_t ros_exit(void)
{
    uint64_t ret = G_SUCCESS;

    ret = ros_timer_exit();
    if (ret != G_SUCCESS)
        LOG(ROS, ERR, "ros_timer_exit fail ");

    if (ros_checktime_thread)
        pthread_cancel(ros_checktime_thread);

    return ret;
}

uint64_t ros_pkts_stat_init(struct ros_pkts_stat *pstPktStat,uint64_t total_pkts_num)
{
    pstPktStat->pkts_num    = 1;
    pstPktStat->num_sec     = 1;
    pstPktStat->ulPktCpyLen = 0;
    pstPktStat->max_rate    = 0;
    pstPktStat->ulStartFlag = G_FALSE;
    pstPktStat->total_pkts_num = total_pkts_num;
    pstPktStat->pkts_len    = 0;
    pstPktStat->pkts_error  = 0;
    pstPktStat->ulDelay     = 0;
    pstPktStat->ullSpeed    = 0;
    pstPktStat->ullLastSpeed= 0;
    pstPktStat->ulDelay     = 0;
    pstPktStat->cur_tsc     = 0;
    pstPktStat->prev_tsc    = 0;
    pstPktStat->pkt_byte_per_sec = 0;
    pstPktStat->ulRunSatus = ROS_PKTS_TASK_IDLE;
    pstPktStat->drain_tsc  = rte_get_tsc_hz();

    return 0;
}

uint64_t ros_pkts_stat_reset(struct ros_pkts_stat *pstPktStat)
{
    pstPktStat->pkts_num    = 1;
    pstPktStat->num_sec     = 1;
    pstPktStat->max_rate    = 0;
    pstPktStat->pkts_len    = 0;
    pstPktStat->ulStartFlag = G_FALSE;
    return 0;
}

uint8_t* ros_GetSecToTimeStr(uint32_t ulSec ,uint8_t* szTimeBuf,uint32_t ulTimeBufLen)
{
    uint32_t ulDate,ulHour, ulMinute,ulSecond;

    ulHour = (uint32_t)(ulSec/3600);
    ulMinute = (uint32_t)((ulSec%3600)/60);
    ulSecond = (uint32_t)((ulSec%3600)%60);

    ulDate = ulHour/24;
    ulHour = ulHour%24;

    if(!szTimeBuf)
    {
        return NULL;
    }

    memset(szTimeBuf,0,ulTimeBufLen);

    sprintf((char*)szTimeBuf,"[%d-%02d:%02d:%02d]",ulDate,ulHour,ulMinute,ulSecond);
    return szTimeBuf;
}

void ros_GetCountRatePerSec(uint64_t ulByteNumPerSec ,uint8_t* szRateBuf,uint32_t ulRateBufLen)
{
    uint64_t ulBits;

    ulBits = 8 * ulByteNumPerSec;

    memset(szRateBuf,0,ulRateBufLen);

    if(ulBits < (1024 *1024))
    {
        sprintf((char*)szRateBuf,"%ld.%ld Kb/s",(ulBits / 1024),(ulBits % 1024));
    }
    else
    {
        ulBits = ulBits/1024;
        sprintf((char*)szRateBuf,"%ld.%ld Mb/s",(ulBits / 1024),(ulBits % 1024));
    }
}

uint32_t ros_GetSecOffset(uint32_t ulTickEnd , uint32_t ulTickStart)
{
    if ( ulTickEnd >= ulTickStart )
    {
        return ulTickEnd - ulTickStart;
    }
    else
    {
        return (0xFFFFFFFF - ulTickStart + ulTickEnd + 1);
    }
}


uint64_t ros_GetTscOffset(uint64_t ulTscEnd , uint64_t ulTscStart)
{
    if ( ulTscEnd >= ulTscStart )
    {
        return ulTscEnd - ulTscStart;
    }
    else
    {
        return (0xFFFFFFFFFFFFFFFF - ulTscStart + ulTscEnd + 1);
    }
}

_F64 ros_pkts_stat_dump(char *prefix, struct ros_pkts_stat *pkts_stat, uint64_t pkts)
{
    uint64_t    timeuse, real_time;
    _F64    rate;
    uint32_t    ulTime;
    uint8_t     aucStr[64];
    uint8_t     aucStrRate[64];
    _F64    dulAvgRate;
    uint64_t    ullAvgRate;

    ROS_DIFF_TIME(pkts_stat->starttime, pkts_stat->endtime, timeuse);
    ROS_DIFF_TIME(pkts_stat->tmptime, pkts_stat->endtime, real_time);

    rate= ((double)((pkts-pkts_stat->num_sec) * EOS_TICKS_PER_SECOND)/(double)real_time);

    if ((rate - pkts_stat->max_rate) > 0.0001)
    {
        pkts_stat->max_rate = rate;
        if(0xFFFFFFFF<pkts_stat->max_rate)
        {
            pkts_stat->max_rate = 0;
        }
    }

    memset(aucStr,0,sizeof(aucStr));

    ulTime = timeuse / EOS_TICKS_PER_SECOND;

    ros_GetSecToTimeStr(ulTime,aucStr,sizeof(aucStr));

    dulAvgRate = (((_F64)(pkts * EOS_TICKS_PER_SECOND))/(_F64)timeuse);

    ullAvgRate = (((_F64)(pkts_stat->pkts_len * EOS_TICKS_PER_SECOND))/(_F64)timeuse);

    ros_GetCountRatePerSec(ullAvgRate,(uint8_t*)aucStrRate,sizeof(aucStrRate));

    dbg_printf("%-20s%-24llu%-24u%-18s%-18.2lf%-18s%-18.2lf%-18.2lf%-8u\n",
                                            prefix,(pkts),pkts_stat->pkts_error,aucStr,
                                            dulAvgRate,aucStrRate,
                                            pkts_stat->max_rate,rate,pkts_stat->ulDelay);

    pkts_stat->num_sec = pkts_stat->pkts_num;
    ROS_GET_TIME(pkts_stat->tmptime);

    return rate;
}

void ros_pkts_show_stat_top(void)
{
    dbg_printf("---------------------------------------------------------------------------------------------------------------------------------------\n");
    dbg_printf("%-20s%-24s%-24s%-18s%-18s%-18s%-18s%-18s%-8s\n",
    "C/S", "Pkts", "Pkts other","Time used(s)",
    "Avg rate(pps)","Avg rate","Max rate(pps)",
    "Rate(pps)","Delay");
}

void ros_pkts_stat_inc(struct ros_pkts_stat *pkts_stat,uint32_t pkt_len)
{
    if(G_TRUE != pkts_stat->ulStartFlag)
    {
        ROS_GET_TIME(pkts_stat->starttime);
        ROS_GET_TIME(pkts_stat->tmptime);
        pkts_stat->cur_tsc = rte_rdtsc();
        pkts_stat->prev_tsc = pkts_stat->cur_tsc;
        pkts_stat->pkt_byte_per_sec = pkt_len;
        pkts_stat->ulStartFlag = G_TRUE;
    }

    pkts_stat->pkts_num++;
    pkts_stat->pkts_len += pkt_len;

    if(pkts_stat->ullSpeed)
    {
        pkts_stat->cur_tsc = rte_rdtsc();
        if(pkts_stat->drain_tsc < ros_GetTscOffset(pkts_stat->cur_tsc,pkts_stat->prev_tsc))
        {
            pkts_stat->ullLastSpeed = pkts_stat->pkt_byte_per_sec;

            if((pkts_stat->ullLastSpeed/(50*1024*1024)) < (pkts_stat->ullSpeed/(50*1024*1024)))
            {
                if(0 <pkts_stat->ulDelay)
                {
                    pkts_stat->ulDelay = pkts_stat->ulDelay / 2;
                }
            }
            else if((pkts_stat->ullLastSpeed/(50*1024*1024)) > (pkts_stat->ullSpeed/(50*1024*1024)))
            {
                pkts_stat->ulDelay += 1;
            }

            pkts_stat->prev_tsc = pkts_stat->cur_tsc;
            pkts_stat->pkt_byte_per_sec = 0;
        }
        pkts_stat->pkt_byte_per_sec += pkt_len;
    }

}

int ros_pkt_stat_show(struct cli_def *cli,struct ros_pkts_stat *pkts_stat)
{
    uint8_t     aucStr[64];
    uint8_t     aucStrRate[64];
    cli_print_val(cli,"%-30s:%ld",pkts_stat->ulRunSatus);
    cli_print_val(cli,"%-30s:%d",pkts_stat->ulStartFlag);
    cli_print_val(cli,"%-30s:%ld",pkts_stat->pkts_num);
    cli_print_val(cli,"%-30s:%ld",pkts_stat->total_pkts_num);

    cli_print_val(cli,"%-30s:%-10ld",pkts_stat->num_sec);
    ros_GetCountRatePerSec(pkts_stat->max_rate,(uint8_t*)aucStrRate,sizeof(aucStrRate));
    cli_print_val(cli,"%-30s:%-10lf(%s)",pkts_stat->max_rate,aucStrRate);
    ros_GetSecToTimeStr(pkts_stat->starttime,aucStr,sizeof(aucStr));
    cli_print_val(cli,"%-30s:%-10ld(%s)",pkts_stat->starttime,aucStr);
    ros_GetSecToTimeStr(pkts_stat->endtime,aucStr,sizeof(aucStr));
    cli_print_val(cli,"%-30s:%-10ld(%s)",pkts_stat->endtime,aucStr);
    ros_GetSecToTimeStr(pkts_stat->tmptime,aucStr,sizeof(aucStr));
    cli_print_val(cli,"%-30s:%-10ld(%s)",pkts_stat->tmptime,aucStr);
    cli_print_val(cli,"%-30s:%lld",pkts_stat->pkts_len); //每次发送包的长度
    cli_print_val(cli,"%-30s:%d",pkts_stat->ulResend);
    cli_print_val(cli,"%-30s:%d",pkts_stat->pkts_error);

    ros_GetCountRatePerSec(pkts_stat->ullSpeed,(uint8_t*)aucStrRate,sizeof(aucStrRate));
    cli_print_val(cli,"%-30s:%-10ld(%s)",pkts_stat->ullSpeed,aucStrRate);

    ros_GetCountRatePerSec(pkts_stat->ullLastSpeed,(uint8_t*)aucStrRate,sizeof(aucStrRate));

    cli_print_val(cli,"%-30s:%-10ld(%s)",pkts_stat->ullLastSpeed,aucStrRate);
    cli_print_val(cli,"%-30s:%d",pkts_stat->ulDelay);

	cli_print_val(cli,"%-30s:%d",pkts_stat->pkt_byte_per_sec);
    return 0;
}

int cli_get_time(struct cli_def *cli,int argc, char **argv)
{
    time_t cur_time = time(NULL);
    /* 28800 is +08:00's second */
    cur_time += 28800;
    cli_print(cli,"Run Time: %d s \r\n", ros_getruntime());
    cli_print(cli,"UTC Time: %u s (From 1900.01.01)\r\n", ros_getime());
    cli_print(cli,"Time    : %s", asctime(gmtime(&cur_time)));
    return 0;
}

int cli_show_version(struct cli_def *cli,int argc, char *argv[])
{
	cli_print(cli, "Version:0.15");
	return 0;
}

/*修改配置文件中的某一个参数，key为参数名；value为值；num为参数个数；grep_v为每一个参数筛选时要过滤的字段；
file是路径，如果为null，则读取环境变量的路径；symbol代表分隔符使用竖杠还是斜杠，0表示斜杠，1表示竖杠。
key,value和grep_v都是指向一组参数的二级指针*/
int set_config_to_file(struct cli_def *cli,char **key, char **value,int num,char **grep_v,char *file,int symbol)
{
    char command[512]={0};
    int i=0;

    if(!key || !value)
    {
        if(cli)
            cli_print(cli,"\r\nkey[%x] or value[%x] is NULL!\r\n",key,value);
        return -1;
    }

    if(!file)
    {
        file = pcf_get_env(UPU_ENV_NAME);
    }
    if(file && (num > 0))
    {
        for(i=0;i<num;i++)
        {
            if(key[i] && value[i])
            {
                //grep_v存在则使用，否则使用默认的";"
                if(grep_v && grep_v[i])
                {
                    //symbol为1，表示使用"|"作为分隔符
                    if(symbol)
                        sprintf(command,"sed -i \"s|`cat %s | grep \"%s\" | grep -v \"%s\"`|%s = %s|g\" %s",file,key[i],grep_v[i],key[i],value[i],file);
                    else
                        sprintf(command,"sed -i \"s/`cat %s | grep \"%s\" | grep -v \"%s\"`/%s = %s/g\" %s",file,key[i],grep_v[i],key[i],value[i],file);
                 }
                else
                {
                    if(symbol)
                        sprintf(command,"sed -i \"s|`cat %s | grep \"%s\" | grep -v \";\"`|%s = %s|g\" %s",file,key[i],key[i],value[i],file);
                    else
                        sprintf(command,"sed -i \"s/`cat %s | grep \"%s\" | grep -v \";\"`/%s = %s/g\" %s",file,key[i],key[i],value[i],file);
                 }

               // cli_print(cli,"\r\n%s\r\n",command);
                system(command);
            }
        }
    }
    else
    {
        if(cli)
            cli_print(cli,"\r\nfile is null. file[%x] num[%d]\r\n",file,num);
        return -1;
    }
    return 0;
}
static int ros_read_status(char *filename, struct proc_info *proc) {
    FILE *file;
    char line[MAX_LINE]={0};
    unsigned int uid, gid;
    char task_name[PROC_NAME_LEN]={0};
    char Cpus_allowed_list[THREAD_NAME_LEN]={0};

    unsigned int Cpus_allowed;

    char strName[] = "Name";
    char strUid[] = "Uid";
    char strGid[] = "Gid";
    char strCpus_allowed[] = "Cpus_allowed";
    char strCpus_allowed_list[] = "Cpus_allowed_list";

    file = fopen(filename, "r");
    if (!file) return 1;
    while (fgets(line, MAX_LINE, file))
    {
        //dbg_printf("%s:%s",__FUNCTION__,line);
        if(!strncmp(strName,line,strlen(strName)))
        {
           sscanf(line, "Name: %s",task_name);
        }
        else if(!strncmp(strUid,line,strlen(strUid)))
        {
            sscanf(line, "Uid: %u", &uid);
        }
        else if(!strncmp(strGid,line,strlen(strGid)))
        {
            sscanf(line, "Gid: %u", &gid);
        }
        else if(!strncmp(strCpus_allowed_list,line,strlen(strCpus_allowed_list)))
        {
            sscanf(line, "Cpus_allowed_list: %s",Cpus_allowed_list);
            //strcpy(Cpus_allowed_list,&line[strlen(strCpus_allowed_list)+1]);
        }
        else if(!strncmp(strCpus_allowed,line,strlen(strCpus_allowed)))
        {
           sscanf(line, "Cpus_allowed: %x", &Cpus_allowed);
        }
        memset(line,0,MAX_LINE);
    }
    fclose(file);
    strcpy(proc->tname,task_name);
    strcpy(proc->Cpus_allowed_list,Cpus_allowed_list);
    proc->uid = uid;
    proc->gid = gid;
    proc->Cpus_allowed = Cpus_allowed;
    return 0;
}

extern unsigned int cm_get_callstack_self(unsigned long *pc, unsigned long *bp,unsigned long max);
extern unsigned int cm_get_callstack_bypid(pid_t pid, unsigned long *pc, unsigned long *bp,unsigned long max);
int cli_show_task(struct cli_def *cli,int argc, char **argv)
{
    char filename[128]={0};
    pid_t pid, tid;
    DIR *task_dir;
    struct dirent  *tid_dir;
    struct proc_info stProc;
    unsigned long rip_array[32],rbp_array[32],rip_len,i;
    char **symb = NULL;

    memset(&rip_array,0,sizeof(rip_array));
    memset(&rbp_array,0,sizeof(rbp_array));
    rip_len = 0;
    if(0 == argc)
    {
    pid = getpid();

    sprintf(filename, "/proc/%d/task", pid);
    task_dir = opendir(filename);
    if (!task_dir)
    {
        return 0;
    }

    cli_print(cli,"===========================================================");
    cli_print(cli,"%-10s %-10s %-10s %-10s","PID","CPU_MASK","CPU_LIST","NAME");

    while ((tid_dir = readdir(task_dir)))
    {
        if (!isdigit(tid_dir->d_name[0]))
            continue;

        tid = atoi(tid_dir->d_name);

        memset(&stProc,0,sizeof(struct proc_info));

        stProc.pid = pid; stProc.tid = tid;

        sprintf(filename, "/proc/%d/task/%d/status", pid, tid);

        ros_read_status(filename, &stProc);

        cli_print(cli,"%-10d %-10x %-10s %-10s",
                stProc.tid,stProc.Cpus_allowed,
                stProc.Cpus_allowed_list,stProc.tname);

    }
    }
    else
    {
        //ulFlag = (uint32_t)atol(argv[0]);
        if (1 == sscanf(argv[0],"%d",&pid))
        {
            if (pid == getpid())
            {
                cli_print(cli,"can not show fpu task info");
                //*(int *)0x00005a01a5 = 0;
                return 0;
            }

            rip_len = cm_get_callstack_bypid(pid,&rip_array[0],&rbp_array[0],sizeof(rip_array)/sizeof(rip_array[0]));
            if (!rip_len)
            {
                cli_print(cli,"get pid(%d) info fail(%d) ",pid,rip_len);
                //cm_get_callstack_self(&rip_array[0],&rbp_array[0],sizeof(rip_array)/sizeof(rip_array[0]));
            }
            else
            {
                cli_print(cli,"call stack:");
                symb = backtrace_symbols((void *const *) (&rip_array), (int)rip_len);
                for(i=0;i<rip_len;i++)
                {
                    cli_print(cli,"%016lx  %08x[%s]",rbp_array[i],rip_array[i],symb? symb[i] : " ");
                }

                if (symb)
                    free(symb);
            }
        }
    }
    return 0;
}

int git_version(struct cli_def *cli, int argc, char **argv)
{
    char *ver_info;

    ver_info = pcf_get_env(UPF_VERSION_ENV);
    if (NULL == ver_info) {
        return -1;
    }

	cli_print(cli, "UPF version %s\n", ver_info);

    return 0;
}

/* Common command */
cli_register_cmd(time, cli_get_time);
cli_register_cmd(version, git_version);

int ros_show_mempool(struct cli_def *cli,int argc, char *argv[])
{
#if (defined(PRODUCT_IS_fpu))
    uint32_t ulCoreId = 0;

    if ((argc == 1) && (*argv[0] == '?' || strcmp(argv[0],"help") == 0))
    {
        return 0;
    }

    if(argc)
    {
        ulCoreId = (uint32_t)atol(argv[0]);
    }

    dpdk_show_mempool(ulCoreId, cli->client);
#endif
    return 0;
}

int ros_show_dpdk_lcore(struct cli_def *cli,int argc, char *argv[])
{
#if (defined(PRODUCT_IS_fpu))
    extern void rte_show_lcore_config(int ulCoreId,FILE *f);
    //uint32_t ulCoreId = 0xFF;

    if ((argc == 1) && (*argv[0] == '?' || strcmp(argv[0],"help") == 0))
    {
        return 0;
    }

    if(argc)
    {
        //ulCoreId = (uint32_t)atol(argv[0]);
    }
    //rte_show_lcore_config(ulCoreId, cli->client);
#endif
    return 0;
}

int ros_show_mac(struct cli_def *cli,int argc, char *argv[])
{
#if (defined(PRODUCT_IS_fpu))
    if ((argc == 1) && (*argv[0] == '?' || strcmp(argv[0],"help") == 0))
    {
        return 0;
    }
    dpdk_show_mac(cli->client);
#endif
    return 0;
}

int ros_show_info(struct cli_def *cli,int argc, char *argv[])
{
#if (defined(PRODUCT_IS_fpu))
    uint32_t ulFlag = 0;
    if ((argc == 1) && (*argv[0] == '?' || strcmp(argv[0],"help") == 0))
    {
        return 0;
    }

    if(argc)
    {
        //ulFlag = (uint32_t)atol(argv[0]);
        sscanf(argv[0],"%x",&ulFlag);
        cli_print(cli,"ulFlag=%x \n",ulFlag);
    }
    dpdk_show_info(cli->client,ulFlag);
#endif
    return 0;
}

uint64_t ros_byte_atoi( const char *inString )
{
    double theNum = 0;
    char suffix = '\0';

    const long kKilo_to_Unit = 1024;
    const long kMega_to_Unit = 1024 * 1024;
    const long kGiga_to_Unit = 1024 * 1024 * 1024;

    const long kkilo_to_Unit = 1000;
    const long kmega_to_Unit = 1000 * 1000;
    const long kgiga_to_Unit = 1000 * 1000 * 1000;

    if(inString == NULL )
    {
        return 0;
    }

    /* scan the number and any suffices */
    sscanf( inString, "%lf%c", &theNum, &suffix );

    /* convert according to [Gg Mm Kk] */
    switch ( suffix ) {
        case 'G':  theNum *= kGiga_to_Unit;  break;
        case 'M':  theNum *= kMega_to_Unit;  break;
        case 'K':  theNum *= kKilo_to_Unit;  break;
        case 'g':  theNum *= kgiga_to_Unit;  break;
        case 'm':  theNum *= kmega_to_Unit;  break;
        case 'k':  theNum *= kkilo_to_Unit;  break;
        default: break;
    }
    return (uint64_t) theNum;
} /* end byte_atof */



void ros_random_uuid(uint8_t *uuid)
{
    const uint8_t h[4] = {0x8, 0x9, 0xa, 0xb};
    uint8_t cnt, tmp, rand_value;

    for( cnt = 0; cnt < 16; ++cnt) {
        rand_value = rand() % 255;
        switch(cnt) {
            case 6:
                uuid[cnt] = (4 << 4) + (rand_value % 15);
            break;
            case 8:
                tmp = h[rand() % sizeof(h)];
                uuid[cnt] = (tmp << 4) + (rand_value % 15);
            break;
            default:
                uuid[cnt] = rand_value;
            break;
        }
    }
}

/* Common command */
cli_register_cmd(time, cli_get_time);
cli_register_cmd(version, git_version);
cli_register_cmd(timer_status, ros_timer_resource_status);
cli_register_cmd(rqueue, rqueue_test);
#if (defined(PRODUCT_IS_fpu))
int cli_show_dpdk_stat(struct cli_def *cli, int argc, char **argv)
{
    dpdk_show_stat(cli->client);
    return 0;
}

int fast_get_show(struct cli_def *cli,int argc, char **argv)
{
    if (argc != 2 || *argv[0] == '?' || strcmp(argv[0],"help") == 0) {
        cli_print(cli,"SYNOPSIS\n"
               "       show_fast type index\n"
               "OPTIONS\n"
               "       [type    hash table type, 0:ipv4, 1:ipv6, 2:mac]\n"
               "       [index   entry index]\n");
        return -1;
    }
    fp_msg_entry_show(cli,(uint32_t)atol(argv[0]), (uint32_t)atol(argv[1]));
    return 0;
}

int inst_get_show(struct cli_def *cli,int argc, char **argv)
{
    if (argc != 1 || *argv[0] == '?' || strcmp(argv[0],"help") == 0) {
        cli_print(cli,"SYNOPSIS\n"
               "       show_inst index\n"
               "OPTIONS\n"
               "       [index   entry index]\n");
        return -1;
    }
    fp_msg_inst_show(cli,(uint32_t)atol(argv[0]));
    return 0;
}

int far_get_show(struct cli_def *cli,int argc, char **argv)
{
    if (argc != 1 || *argv[0] == '?' || strcmp(argv[0],"help") == 0) {
        cli_print(cli,"SYNOPSIS\n"
               "       show_far index\n"
               "OPTIONS\n"
               "       [index   entry index]\n");
        return -1;
    }
    fp_msg_far_show(cli,(uint32_t)atol(argv[0]));
    return 0;
}

int bar_get_show(struct cli_def *cli,int argc, char **argv)
{
    if (argc != 1 || *argv[0] == '?' || strcmp(argv[0],"help") == 0) {
        cli_print(cli,"SYNOPSIS\n"
               "       show_bar index\n"
               "OPTIONS\n"
               "       [index   entry index]\n");
        return -1;
    }
    fp_msg_bar_show(cli,(uint32_t)atol(argv[0]));
    return 0;
}

int qer_get_show(struct cli_def *cli,int argc, char **argv)
{
    if (argc != 1 || *argv[0] == '?' || strcmp(argv[0],"help") == 0) {
        cli_print(cli,"SYNOPSIS\n"
               "       show_qer index\n"
               "OPTIONS\n"
               "       [index   entry index]\n");
        return -1;
    }
    fp_msg_qer_show(cli,(uint32_t)atol(argv[0]));
    return 0;
}

int dns_get_show(struct cli_def *cli,int argc, char **argv)
{
    if (argc != 1 || *argv[0] == '?' || strcmp(argv[0],"help") == 0) {
        cli_print(cli,"SYNOPSIS\n"
               "       show_dns index\n"
               "OPTIONS\n"
               "       [index   entry index]\n");
        return -1;
    }
    fp_msg_dns_show(cli,(uint32_t)atol(argv[0]));
    return 0;
}

int fp_get_start_config_show(struct cli_def *cli,int argc, char **argv)
{
    fp_start_config_show(cli);
    return 0;
}

cli_register_cmd(status, fp_show_packet_stat);
cli_register_cmd(sig_trace, fp_conf_signal_trace);
cli_register_cmd(sig_trace_ueip, fp_show_signal_trace_ueip);
cli_register_cmd(show_fast, fast_get_show);
cli_register_cmd(show_inst, inst_get_show);
cli_register_cmd(show_far, far_get_show);
cli_register_cmd(show_bar, bar_get_show);
cli_register_cmd(show_qer, qer_get_show);
cli_register_cmd(config, fp_get_start_config_show);
cli_register_cmd(show_ip, fp_ip_show);
cli_register_cmd(res_status, fp_stats_resource_info);
cli_register_cmd(show_cblk, fp_show_cblock_info);

#endif


#if (defined(PRODUCT_IS_stub))

cli_register_cmd(assoc, stub_build_assoc);
cli_register_cmd(session, stub_build_session_pkt);
cli_register_cmd(pfd, stub_build_pfd);
cli_register_cmd(sess_perf, stub_session_test);
cli_register_cmd(show_recv_stat, stub_show_recv_stat);
#endif

/* UPC command */
#if (defined(PRODUCT_IS_smu))
extern void service_channel_show(void *token);

int cli_asso_setup(struct cli_def *cli, int argc, char **argv)
{
    uint32_t ipv4;
    uint16_t peer_port;

    if (argc < 2) {
        cli_print(cli,"\r\nPlease input IPv4 address and peer port.\r\n");
        return 0;
    }

    ipv4 = ntohl(inet_addr(argv[0]));
    peer_port = htons(atoi(argv[1]));

    upc_node_create_node(0, ipv4, NULL, peer_port);

    cli_print(cli,"\r\nCreate node for smf %08x.\r\n", ipv4);

    return 0;
}

int cli_asso_update(struct cli_def *cli, int argc, char **argv)
{
	int ret = 0;
	extern int upc_node_update(void);

	ret = upc_node_update();
	if(ret > 0)
		cli_print(cli,"update total %d node success\n",ret);
	else
		cli_print(cli,"update node failure\n");
	return 0;
}

int cli_asso_update_release(struct cli_def *cli, int argc, char **argv)
{
	uint32_t ipv4 = 0;
	extern int upc_node_update_release(struct cli_def *cli,uint32_t ipv4);

	if(argc < 1)
	{
		cli_print(cli,"argumetn missing,please input ip\n");
		return 0;
	}

	ipv4 = inet_addr(argv[0]);
	if(ipv4 < 0)
	{
		cli_print(cli,"%s error,input again",argv[0]);
		return 0;
	}
	else if(ipv4 == 0)
	{
		upc_node_update_release(cli,0);
		return 0;
	}

	if(upc_node_update_release(cli,ipv4) < 0)
		cli_print(cli,"update_release error\n");
	else
		cli_print(cli,"update_release success\n");
	return 0;
}

int cli_del_all_node(struct cli_def *cli, int argc, char **argv)
{
	extern int upc_node_del_cli(struct cli_def *cli);
	upc_node_del_cli(cli);
	return 0;
}

int cli_show_node(struct cli_def *cli, int argc, char **argv)
{
	extern void upc_node_show(struct cli_def *cli);
	upc_node_show(cli);
	return 0;
}

int cli_delete_node(struct cli_def *cli, int argc, char **argv)
{
#if 0
	int index = 0;
	extern int upc_delete_node(int index);
	if(argc != 1)
	{
		cli_print(cli,"delete_node index");
		return 0;
	}

	index = strtol(argv[0],NULL,10);

	if(1) //(upc_delete_node(atoi(argv[0])))
		cli_print(cli,"delete node error");
	else
		cli_print(cli,"delete node success");
#endif
	return 0;
}


int cli_show_up_features(struct cli_def * cli, int argc, char * * argv)
{
	extern int upc_node_show_up_cp(struct cli_def * cli,int index, int flag);
	upc_node_show_up_cp(cli,0,0);
	return 0;
}

int cli_set_hb_time(struct cli_def * cli, int argc, char * * argv)
{
	extern int upc_set_hb_time(uint32_t sec);
	uint32_t time = 0;

	if(argc < 1)
	{
		cli_print(cli,"Eg:set_hb_time sec");
		return 0;
	}
	time = strtol(argv[0],NULL,10);
	upc_set_hb_time(time);
	return 0;
}

int cli_pf_rule(struct cli_def *cli, int argc, char **argv)
{
	extern int upc_node_create_pf_rule(char *act,char *pf_rule_name);

	if(argc < 2){
        cli_print(cli,"\r\nPlease input add/del and pf_rule_name.\r\n");
        return 0;
    }

	if(strcmp(argv[0],"add") && strcmp(argv[0],"del"))
	{
        cli_print(cli,"\r\nPlease input add/del and pf_rule_name.\r\n");
        return 0;
    }

	upc_node_create_pf_rule(argv[0],argv[1]);

	cli_print(cli,"\r\ncli_pf_rule[%s][%s]\r\n",argv[0],argv[1]);

	return 0;
}

int cli_user_sig_trace(struct cli_def *cli, int argc, char **argv)
{
	extern int upc_set_sig_trace(struct cli_def *cli, char *sig_type,char *user_id);
	extern int upc_off_sig_trace(struct cli_def *cli);

	if(argc < 1){
        cli_print(cli,"\r\nPlease input imsi/msisdn/off. argc %d\r\n", argc);
        return 0;
    }

	if(!strcmp(argv[0],"off")) {
        cli_print(cli,"\r\nsig_trace off.\r\n");
		upc_off_sig_trace(cli);
        return 0;
    }

	if(argc != 2 ) {
		cli_print(cli,"\r\nPlease input imsi/msidn and number. argc %d.\r\n", argc);
        return 0;
	}

	upc_set_sig_trace(cli, argv[0], argv[1]);

	return 0;


}

cli_register_cmd(sig_trace, upc_sig_trace_show);
cli_register_cmd(sig_trace, cli_user_sig_trace);
cli_register_cmd(pf_rule, cli_pf_rule);
cli_register_cmd(show_up_features, cli_show_up_features);
cli_register_cmd(show_node, cli_show_node);
cli_register_cmd(delete_node,cli_delete_node);
cli_register_cmd(asso_setup,   cli_asso_setup);
cli_register_cmd(asso_update,  cli_asso_update);
cli_register_cmd(status,  upc_show_packet_stats);
cli_register_cmd(ueip, ueip_pool_show);
cli_register_cmd(teid, upc_cmd_teid);
cli_register_cmd(ass, upc_ha_active_standby_switch);
cli_register_cmd(ha_status, upc_show_working_status);
cli_register_cmd(res_status, upc_stats_resource_info);


extern void service_channel_show(void *token);
extern void *session_chn_token_gwu;
extern int session_show_info(struct cli_def *cli,const uint64_t local_seid,const uint64_t cp_seid);
extern int session_show_ueip(struct cli_def *cli, const uint32_t ipv4, const uint8_t ip_type);


int cli_show_session(struct cli_def *cli, int argc, char **argv)
{
	uint64_t local_seid = 0;
	uint64_t cp_seid = 0;
	if (argc != 2) {
		cli_print(cli, "show_session local_seid cp_seid");
		return 0;
	}
    if (('0' == argv[0][0]) && (('x' == argv[0][1]) || ('X' == argv[0][1]))) {
    	local_seid = strtoll(argv[0], NULL, 16);
    	cp_seid    = strtoll(argv[1], NULL, 16);
    } else {
        local_seid = strtoll(argv[0], NULL, 10);
    	cp_seid    = strtoll(argv[1], NULL, 10);
    }
	session_show_info(cli, local_seid, cp_seid);

	return 0;
}

int cli_session_ip(struct cli_def *cli, int argc, char **argv)
{
	uint32_t ipv4 = 0;
	if(argc < 1)
	{
		cli_print(cli,"Eg:session_show ueip");
		return 0;
	}
	ipv4 = inet_addr(argv[0]);
	session_show_ueip(cli,ipv4,0);
	return 0;
}


/* SP command */
extern void service_channel_show(void *token);
extern int pf_rule_table_show(int argc, char **argv);

#endif

/* LB command */
#if (defined(PRODUCT_IS_lbu))

#endif


