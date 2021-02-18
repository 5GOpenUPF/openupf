/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LOG_H__
#define _LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <syslog.h>

/* log type or log level elem string max length */
#define LOG_PATH_NAME_LEN (128)
#define LOG_FILE_PATH     "./"
#define LOG_FILE_NAME     "upf.log"

enum log_type
{
    LOG_TYPE_BEGIN  = 0,
    LOG_TYPE_CM = LOG_TYPE_BEGIN,
    LOG_TYPE_CLI,
    LOG_TYPE_RDB,
    LOG_TYPE_ROS,
    LOG_TYPE_ROS_TIMER,
    LOG_TYPE_ROS_EVENT,
    LOG_TYPE_ROS_TASK,
    LOG_TYPE_ROS_LOCK,
    LOG_TYPE_SERVER,
    LOG_TYPE_SESSION,
    LOG_TYPE_FASTPASS,
    LOG_TYPE_COMM,
    LOG_TYPE_COMM_NIC,
    LOG_TYPE_ARP,
    LOG_TYPE_UPC,
    LOG_TYPE_STUB,
    LOG_TYPE_LB,

    LOG_TYPE_BUTT
};

enum log_level
{
    LOG_LEVEL_MUST = 0,
    LOG_LEVEL_ERR,
    LOG_LEVEL_RUNNING,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_PERIOD,

    LOG_LEVEL_BUTT
};

extern uint64_t log_switch[LOG_TYPE_BUTT][LOG_LEVEL_BUTT];
extern uint64_t log_init(struct pcf_file *conf);
extern uint64_t log_exit(void);
extern uint64_t log_open(const char *path);
extern uint64_t log_close(void);
extern uint64_t log_write(const char *fmt, ...);
extern void log_current_status(void);
extern void log_close_fast_com(void);
extern void log_revive_status(void);

#define LOG_MODE_DEBUG
#ifdef LOG_MODE_DEBUG
#define LOG_TRACE(type, level, trace_flag, fmt, arg...) \
do { \
    if ((log_switch[LOG_TYPE_ ## type][LOG_LEVEL_ ## level] == 1) \
      ||(trace_flag)) { \
        syslog(LOG_INFO, "%s(%d) "fmt, __FUNCTION__, __LINE__, ##arg); \
    } \
   } while((0))

#define LOG(type, level, fmt, arg...) \
    do { \
        if (log_switch[LOG_TYPE_ ## type][LOG_LEVEL_ ## level] == 1)  { \
            syslog(LOG_INFO, "%s(%d) "fmt, __FUNCTION__, __LINE__, ##arg); \
        } \
       } while((0))

#else
#define LOG_TRACE(type, level, trace_flag, fmt, arg...) \
    do { \
       } while((0))
#define LOG(type, level, fmt, arg...) \
    do { \
       } while((0))
#endif

#define PLog_Raw(type, level, fmt, arg...) \
do { \
    if (log_switch[LOG_TYPE_ ## type][LOG_LEVEL_ ## level] == 1) \
        log_write(fmt, ##arg); \
   } while((0))


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _LOG_H__ */
