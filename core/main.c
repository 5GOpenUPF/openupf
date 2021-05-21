/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include <unistd.h>
#include <getopt.h>

#include "service.h"

__maybe_unused static void sighandler(int sig)
{
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            LOG(ROS, MUST, "Termination of proceedings.\n");

            service_deinit();
            cli_exit();
            ros_exit();
            log_exit();
            exit(0);

        default:
            break;
    }
}

int main(int argc, char **argv)
{
    struct pcf_file *conf;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

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

    cli_init();

    for (;;) {
        sleep(3600);
    }

    service_deinit();
    cli_exit();
    ros_exit();
    log_exit();

    return 0;
}

