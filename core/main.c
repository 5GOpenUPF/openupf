/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include <unistd.h>
#include <getopt.h>

#include "service.h"

extern void cm_signal(int, siginfo_t *, void *);

extern int exception_logfile;

static void sighandler(int sig)
{
    switch (sig) {
        case SIGINT:
            printf("Termination of proceedings.\n");

            service_deinit();
            cli_exit();
            ros_exit();
            log_exit();
            exit(1);

        default:
            break;
    }
}

int main(int argc, char **argv)
{
    struct pcf_file *conf;
    struct sigaction stAct;

    exception_logfile = open("exception_logfile", O_RDWR | O_CREAT, 0755);
    if (exception_logfile > 0)
    {
        lseek(exception_logfile,0,2);
    }

    stAct.sa_sigaction = cm_signal;
    /* sa_mask字段说明了一个信号集，在调用该信号处理函数之前，这一信号集要加进进程的信号屏蔽字中。
       仅当从信号处理函数返回时再将进程的信号屏蔽字复位为原先值。 这里清零，表示不屏蔽，如要屏蔽
       则需要调用sigaddset函数，例如sigaddset(&act.sa_mask, SIGQUIT);
     */
    sigemptyset(&stAct.sa_mask);
    stAct.sa_flags = 0;

    /*sa_flags包含了许多标志位，比较重要的一个是SA_SIGINFO，
     *当设定了该标志位时，表示信号附带的参数可以传递到信号处理函数中。
     *即使sa_sigaction指定信号处理函数，如果不设置SA_SIGINFO，
     *信号处理函数同样不能得到信号传递过来的数据，在信号处理函数中对这些信息的访问都将导致段错误
     */
    stAct.sa_flags |= SA_SIGINFO;
    //stAct.sa_flags |= SA_ONESHOT;
    //stAct.sa_flags |= SA_RESETHAND;
    if(sigaction(SIGSEGV, &stAct, NULL) < 0)
    {
        printf("sigaction signo:SIGSEGV fail\n");
        return 1;
    }

    if(sigaction(SIGUSR1, &stAct, NULL) < 0)
    {
        printf("sigaction signo:SIGUSR1 fail\n");
        return 1;
    }

    if(sigaction(SIGUSR2, &stAct, NULL) < 0)
    {
        printf("sigaction signo:SIGUSR2 fail\n");
        return 1;
    }

    if(sigaction(SIGABRT, &stAct, NULL) < 0)
    {
        printf("sigaction signo:SIGABRT fail\n");
        return 1;
    }

    if(sigaction(SIGBUS, &stAct, NULL) < 0)
    {
        printf("sigaction signo:SIGBUS fail\n");
        return 1;
    }

    conf = pcf_conf_read(UPU_ENV_NAME);
    if (!conf) {
        printf("Read configure file failed.\n");
        return 1;
    }

    if (G_SUCCESS != log_init(conf)) {
        printf("log init failed.\n");
        return 1;
    }

#if (defined(PRODUCT_IS_fpu))
    LOG(ROS, ERR,
        "-------------Launch (%s build on %s %s)------------",
        "UPF fast data plane", __TIME__, __DATE__);
#elif (defined(PRODUCT_IS_smu))
    LOG(ROS, ERR,
        "-------------Launch (%s build on %s %s)------------",
        "UPF control plane", __TIME__, __DATE__);
#elif (defined(PRODUCT_IS_lbu))
    LOG(ROS, ERR,
        "-------------Launch (%s build on %s %s)------------",
        "UPF load-Balancer", __TIME__, __DATE__);
#endif

    if (service_init(conf) < 0) {
        printf("service_init failed.\n");
        return 1;
    }
    pcf_conf_free(conf);

    if (cli_parse_argv(argc, argv) == G_SUCCESS) {
        ros_exit();
        log_exit();
        return 0;
    }

    cli_init();

    signal(SIGINT, sighandler);

    for (;;) {
        sleep(3600);
    }

    service_deinit();
    cli_exit();
    ros_exit();
    log_exit();

    return 0;
}

