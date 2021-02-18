/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "log.h"

uint64_t log_switch[LOG_TYPE_BUTT][LOG_LEVEL_BUTT];
int      log_fd = -1;
ROS_MUTEX_ID log_lock;
char     log_path[LOG_PATH_NAME_LEN];
char    *log_level_elem[LOG_LEVEL_BUTT] = {
        "MUST",
        "ERR",
        "RUNNING",
        "DEBUG",
        "PERIOD",
};

int      log_level_sw[LOG_LEVEL_BUTT];
int      log_type_sw[LOG_TYPE_BUTT];
int      log_current_status_value[LOG_TYPE_BUTT][LOG_LEVEL_BUTT];
char    *log_type_elem[LOG_TYPE_BUTT] = {
        "CM",
        "CLI",
        "RDB",
        "ROS",
        "ROS_TIMER",
        "ROS_EVENT",
        "ROS_TASK",
        "ROS_LOCK",
        "SERVER",
        "SESSION",
        "FASTPASS",
        "COMM",
        "COMM_NIC",
        "ARP",
        "UPC",
        "STUB",
        "LB",
};

static int log_parse_level(char *level_str)
{
    int i;
    int cnt = 0;
    uint64_t level;
    char buf[LOG_LEVEL_BUTT][PCF_STR_LEN];

    if (!level_str) {
        return -1;
    }

    if (!strcmp("ALL", level_str)) {
        for (level = LOG_LEVEL_MUST; level < LOG_LEVEL_BUTT; level++) {
            log_level_sw[level] = G_TRUE;
        }
        return 0;
    }

    cnt = pcf_str_split(level_str, '|', buf, LOG_LEVEL_BUTT);
    if (cnt < 0) {
        return -1;
    }

    for (level = LOG_LEVEL_MUST; level < LOG_LEVEL_BUTT; level++) {
        for (i = 0; i < cnt; i++) {
            if (!strcmp(log_level_elem[level], buf[i])) {
                log_level_sw[level] = G_TRUE;
            }
        }
    }

    return 0;
}

static int log_parse_type(char *type_str)
{
    int i = 0;
    int cnt = 0;
    uint64_t type;
    char buf[LOG_TYPE_BUTT][PCF_STR_LEN];

    if (!type_str) {
        return -1;
    }

    if (!strcmp("ALL", type_str)) {
        for (type = LOG_TYPE_BEGIN; type < LOG_TYPE_BUTT; type++) {
            log_type_sw[type] = G_TRUE;
        }
        return 0;
    }

    cnt = pcf_str_split(type_str, '|', buf, LOG_TYPE_BUTT);
    if (cnt < 0) {
        return -1;
    }

    for (type = LOG_TYPE_BEGIN; type < LOG_TYPE_BUTT; ++type) {
        for (i = 0; i < cnt; i++) {
            if (NULL != log_type_elem[type]) {
                if (!strcmp(log_type_elem[type], buf[i])) {
                    log_type_sw[type] = G_TRUE;
                }
            }
        }
    }

    return 0;
}

static int log_parse_cfg(struct pcf_file *conf)
{
    int index = 0;

    struct kv_pair log_key_pair[] = {
        { "debug_level", NULL },
        { "debug_type", NULL },
        { "log_path", NULL },
        { NULL, NULL, }
    };

    while (log_key_pair[index].key != NULL) {
        log_key_pair[index].val = pcf_get_key_value(conf,
                     SECTION_DBG_NAME, log_key_pair[index].key);
        if (!log_key_pair[index].val) {
            printf("Can't get key[%s] in section[%s].\n",
                log_key_pair[index].key, SECTION_DBG_NAME);
            return -1;
        }
        ++index;
    }

    index = 0;
    /* debug_level */
    if (log_parse_level(log_key_pair[index++].val) < 0) {
        printf("log parse level failed!\n");
        return -1;
    }

    /* debug_type */
    if (log_parse_type(log_key_pair[index++].val) < 0) {
        printf("log parse type failed!\n");
        return -1;
    }

    /* log_path */
    strcpy(log_path, log_key_pair[index++].val);

    return 0;
}

uint64_t log_init(struct pcf_file *conf)
{
    uint64_t ret = G_SUCCESS;
    uint64_t type;
    uint64_t level;
    memset(log_switch, 0, sizeof(log_switch));
    memset(log_level_sw, 0, sizeof(log_level_sw));
    memset(log_type_sw, 0, sizeof(log_type_sw));

    if (conf) {
        if (log_parse_cfg(conf) < 0) {
            return G_FAILURE;
        }

        for (type = LOG_TYPE_BEGIN; type < LOG_TYPE_BUTT; type++) {
            if (!log_type_sw[type])
                continue;
            for (level = LOG_LEVEL_MUST; level < LOG_LEVEL_BUTT; level++) {
                log_switch[type][level] = log_level_sw[level];
            }
        }
        ROS_MutexCreate(NULL, &log_lock);
        ret = log_open(log_path);
    } else {
        for (type = LOG_TYPE_BEGIN; type < LOG_TYPE_BUTT; type++) {
            for (level = LOG_LEVEL_MUST; level < LOG_LEVEL_BUTT; level++) {
                log_switch[type][level] = 1;
            }
        }

        ROS_MutexCreate(NULL, &log_lock);
        ret = log_open(NULL);
    }

#ifdef LOG_MODE_DEBUG
    openlog("UPF", LOG_CONS, LOG_USER);
#endif

    return ret;
}

uint64_t log_exit(void)
{
    uint64_t ret = G_SUCCESS;
    ret = log_close();
    ROS_MutexDelete(&log_lock);
#ifdef LOG_MODE_DEBUG
    closelog();
#endif
    return ret;
}

uint64_t log_open(const char *filepath)
{
    char path[128];

    memset(path, 0, sizeof(path));

    if (filepath == NULL) {
        sprintf(path, "%s%s", LOG_FILE_PATH, LOG_FILE_NAME);
    } else {
        sprintf(path, "%s", filepath);
    }

    log_fd = open(path, O_RDWR | O_CREAT | O_APPEND, 0660);
    if (log_fd < 0) {
        printf("%s(%d) open fail! \r\n", __FUNCTION__, __LINE__);
        return G_FAILURE;
    }
    return G_SUCCESS;
}

uint64_t log_close(void)
{
    if (log_fd < 0) {
        close(log_fd);
        log_fd = -1;
    }

    return G_SUCCESS;
}

uint64_t log_write(const char *fmt, ...)
{
    int n;
    int ret;
    char buf[4096];
    va_list ap;

    if (log_fd < 0) {
        printf("%s(%d) log_fd is NULL! \r\n", __FUNCTION__, __LINE__);
        return G_FAILURE;
    }

    va_start(ap, fmt);
    n = vsnprintf(buf, 4096, fmt, ap);
    va_end(ap);

    if (n >= 4096) {
        printf("%s(%d) Buf(%d) exceeds the specified range(%d)! \r\n",
            __FUNCTION__, __LINE__, n, 4096);
        return G_FAILURE;
    }

    ROS_MutexLock(&log_lock);
    ret = write(log_fd, buf, n);
    ROS_MutexUnLock(&log_lock);
    if (ret != n) {
        printf("%s(%d) write fail! \r\n", __FUNCTION__, __LINE__);
        return G_FAILURE;
    }

    return G_SUCCESS;
}

void log_current_status(void)
{
    uint64_t type;
    uint64_t level;
    for (type = LOG_TYPE_BEGIN; type < LOG_TYPE_BUTT; type++) {
        for (level = LOG_LEVEL_MUST; level < LOG_LEVEL_BUTT; level++) {
            log_current_status_value[type][level] = log_switch[type][level];
        }
    }

}

void log_close_fast_com(void)
{
    uint64_t level;
    for (level = LOG_LEVEL_MUST; level < LOG_LEVEL_BUTT; level++) {
        log_switch[LOG_TYPE_FASTPASS][level] = 0;
        log_switch[LOG_TYPE_COMM][level] = 0;
    }
}

void log_revive_status(void)
{
    uint64_t type;
    uint64_t level;
    for (type = LOG_TYPE_BEGIN; type < LOG_TYPE_BUTT; type++) {
        for (level = LOG_LEVEL_MUST; level < LOG_LEVEL_BUTT; level++) {
            log_switch[type][level] = log_current_status_value[type][level];
        }
    }

}

int log_cli_show_log_switch(struct cli_def *cli,int argc, char **argv)
{
    uint64_t type,level;

    for (type = LOG_TYPE_BEGIN; type < LOG_TYPE_BUTT; type++)
    {
        for (level = LOG_LEVEL_MUST; level < LOG_LEVEL_BUTT; level++)
        {
            cli_print(cli,"[%02d:%-20s]-[%02d:%-20s]:%d",
                        type,log_type_elem[type],
                        level,log_level_elem[level],
                        log_switch[type][level]);
        }
    }
    return 0;
}

int log_cli_set_log_switch(struct cli_def *cli, int argc, char **argv)
{
    uint32_t type, level, type_cnt, level_cnt, SET_ALL = 0xFFFFFFFF;
    uint64_t value;
    char help_str[512];
    uint32_t help_str_len = 0;

    if (3 > argc) {
        cli_print(cli, "Parameter too few...\r\n");
        goto help;
    }

    if (0 == strncasecmp(argv[0], "ALL", 3)) {
        type = SET_ALL;
    } else {
        type = atoi(argv[0]);
    }

    if (0 == strncasecmp(argv[1], "ALL", 3)) {
        level = SET_ALL;
    } else {
        level = atoi(argv[1]);
    }
    value = atoi(argv[2]);

    if (SET_ALL != type && LOG_TYPE_BUTT <= type) {
        cli_print(cli, "Abnormal parameter, LOG type: %u error\r\n", type);
        goto help;
    }

    if (SET_ALL != level && LOG_LEVEL_BUTT <= level) {
        cli_print(cli, "Abnormal parameter, LOG level: %u error\r\n", level);
        goto help;
    }

    if (value & 0xFFFFFFFFFFFFFFFE) {
        cli_print(cli, "Abnormal parameter, LOG value: %u error\r\n", value);
        goto help;
    }

    if (SET_ALL == type) {
        for (type_cnt = LOG_TYPE_BEGIN; type_cnt < LOG_TYPE_BUTT; ++type_cnt) {
            if (SET_ALL == level) {
                for (level_cnt = LOG_LEVEL_MUST; level_cnt < LOG_LEVEL_BUTT; ++level_cnt) {
                    log_switch[type_cnt][level_cnt] = value;
                }
            } else {
                log_switch[type_cnt][level] = value;
            }
        }
    } else {
        if (SET_ALL == level) {
            for (level_cnt = LOG_LEVEL_MUST; level_cnt < LOG_LEVEL_BUTT; ++level_cnt) {
                log_switch[type][level_cnt] = value;
            }
        } else {
            log_switch[type][level] = value;
        }
    }
    cli_print(cli, "LOG set success.\r\n");

    return 0;

help:

    cli_print(cli, "log set <type> <level> <value>");

    help_str_len = 0;
    for (type = LOG_TYPE_BEGIN; type < LOG_TYPE_BUTT; ++type) {
        help_str_len += sprintf(&help_str[help_str_len], "%d(%s) ", type, log_type_elem[type]);
    }
    cli_print(cli, "type : ALL %s", help_str);

    help_str_len = 0;
    for (level = LOG_LEVEL_MUST; level < LOG_LEVEL_BUTT; ++level) {
        help_str_len += sprintf(&help_str[help_str_len], "%d(%s) ", level, log_level_elem[level]);
    }
    cli_print(cli, "level: ALL %s", help_str);

    cli_print(cli, "value: 0(disable) 1(enable)");
    cli_print(cli, "e.g. log set 10 2 1");
    cli_print(cli, "e.g. log set ALL ALL 1\r\n");

    return -1;
}

