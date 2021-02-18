/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "fp_msg.h"
#include "fp_backend_mgmt.h"
#include "fp_start.h"

CVMX_SHARED fp_start_status_type_t fp_start_status;
CVMX_SHARED uint32_t fp_prev_reconnect_time = 0;
extern CVMX_SHARED uint16_t comm_msg_comm_id;

inline int fp_start_get_status(void)
{
    return fp_start_status;
}

void fp_start_set_status(fp_start_status_type_t new_status)
{
    if (new_status < FP_START_STATUS_BUTT) {
        fp_start_status = new_status;
    }
}

inline int fp_start_is_init(void)
{
    return (fp_start_status == FP_START_STATUS_INIT);
}

inline int fp_start_is_run(void)
{
    return (fp_start_status == FP_START_STATUS_RUN);
}

int fp_start_proc_reset(void)
{
    fp_start_status_type_t start_status;

    start_status = fp_start_get_status();
    switch (start_status)
    {
        /* 收到就需要重新初始化 */
        case FP_START_STATUS_RUN:
            //break;
        case FP_START_STATUS_INIT:
        case FP_START_STATUS_READY:
        default:
            fp_start_set_status(FP_START_STATUS_INIT);
            break;
    }

    LOG(COMM, MUST,
        "reset, current start status %d.",
        fp_start_get_status());

    return EN_COMM_ERRNO_OK;
}

int fp_start_proc_config(comm_msg_ie_t *ie)
{
    comm_msg_system_config_t    *cfg = NULL;
    fp_start_status_type_t      start_status;
    comm_msg_system_config_t    *fp_config = fp_config_var_get();

    cfg = (comm_msg_system_config_t *)(ie->data);
    start_status = fp_start_get_status();

    switch (start_status)
    {
        case FP_START_STATUS_INIT:
            {
                uint8_t cnt;
                fp_backend_config *be_cfg = fp_be_get_config_public();

                fp_start_set_status(FP_START_STATUS_READY);

                fp_init_phaseII_deinit();

                ros_memcpy(fp_config, cfg, sizeof(comm_msg_system_config_t));

                fp_config->fast_num         = ntohl(fp_config->fast_num);
                fp_config->fast_bucket_num  = ntohl(fp_config->fast_bucket_num);
                fp_config->session_num      = ntohl(fp_config->session_num);
                fp_config->block_num        = ntohl(fp_config->block_num);
                fp_config->block_size       = ntohl(fp_config->block_size);
                fp_config->cblock_num       = ntohl(fp_config->cblock_num);
                fp_config->dns_num          = ntohl(fp_config->dns_num);

                for (cnt = 0; cnt < EN_PORT_BUTT; ++cnt) {
                    fp_config->upf_ip[cnt].ipv4 = ntohl(fp_config->upf_ip[cnt].ipv4);
                }

                memcpy((void *)be_cfg->loadbalancer_mac, (void *)fp_config->upf_mac, EN_PORT_BUTT * ETH_ALEN);

                fp_init_phaseII();
            }
            break;

        case FP_START_STATUS_READY:
        case FP_START_STATUS_RUN:
        default:
            return EN_COMM_ERRNO_PARAM_INVALID;
    }

    LOG(COMM, MUST,
        "config, current start status %d.",
        fp_start_get_status());

    return EN_COMM_ERRNO_OK;
}

int fp_start_proc_start(void)
{
    fp_start_status_type_t start_status;

    start_status = fp_start_get_status();
    switch (start_status)
    {
        case FP_START_STATUS_INIT:
            return EN_COMM_ERRNO_PARAM_INVALID;

        case FP_START_STATUS_RUN:
            break;

        case FP_START_STATUS_READY:
        default:
            fp_start_set_status(FP_START_STATUS_RUN);
            break;
    }

    LOG(COMM, MUST,
        "start, current start status %d.",
        fp_start_get_status());

    return EN_COMM_ERRNO_OK;
}

void fp_start_config_show(struct cli_def *cli)
{
    comm_msg_system_config_t *fp_config = NULL;

    fp_config = fp_config_var_get();

    cli_print(cli,"fast_num           %d\n", fp_config->fast_num);
    cli_print(cli,"fast_bucket_num    %d\n", fp_config->fast_bucket_num);
    cli_print(cli,"session_num        %d\n", fp_config->session_num);
    cli_print(cli,"block_num          %d\n", fp_config->block_num);
    cli_print(cli,"block_size         %d\n", fp_config->block_size);
    cli_print(cli,"cblock_num         %d\n", fp_config->cblock_num);
    cli_print(cli,"dns_num            %d\n", fp_config->dns_num);

}

