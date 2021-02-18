/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __LIB_CLI_H___
#define __LIB_CLI_H___

#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <regex.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <execinfo.h>

#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <memory.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <termios.h>
#include <signal.h>
#include <dirent.h>
#include <linux/stat.h>
#include <sys/stat.h>


#ifndef G_YES
#define G_YES                   1
#define G_NO                    0
#endif


#define EXIT_SUCCESS    0
#define EXIT_FAILURE    1

#define CLI_OK			0
#define CLI_ERROR		-1
#define CLI_QUIT		-2
#define CLI_ERROR_ARG		-3
#define CLITEST_PORT                8000
#define MODE_CONFIG_INT             10

#define MAX_HISTORY		256

#define PRIVILEGE_UNPRIVILEGED	0
#define PRIVILEGE_PRIVILEGED	15
#define MODE_ANY		-1
#define MODE_EXEC		0
#define MODE_CONFIG		1

#define LIBCLI_HAS_ENABLE	1

#define PRINT_PLAIN		0
#define PRINT_FILTERED		0x01
#define PRINT_BUFFERED		0x02

#define CLIENT_INIT_ATTEMPTS 20

#define CLI_LIB_PRINT_LEN   4096

// 定义语种类型枚举
typedef enum
{
    EN_CLI_LANGUAGE_ENG = 0,        // 英文
    EN_CLI_LANGUAGE_CHS = 1,        // 简体中文
    EN_CLI_LANGUAGE_CHT = 2,        // 繁体中文
    EN_CLI_LANGUAGE_JP  = 3,         // 日文

    // 其它语种以后需要再定义
    EN_CLI_LANGUAGE_LANG_BUTT
}EN_CLI_LANGUAGE;

struct cli_def {
    int completion_callback;
    struct cli_command *commands;
    int (*auth_callback)(char *, char *);
    int (*regular_callback)(struct cli_def *cli);
    int (*checkalive_callback)(struct cli_def *cli);
    int (*enable_callback)(char *);
    char *banner;
    struct unp *users;
    char *enable_password;
    char *history[MAX_HISTORY];
    char showprompt;
    char *promptchar;
    char *hostname;
    char *modestring;
    int privilege;
    int mode;
    int state;
    struct cli_filter *filters;
    void (*print_callback)(struct cli_def *cli, char *string);
    FILE *client;
    int  iOutSocket;
    /* internal buffers */
    void *conn;
    void *service;
    char *commandname;  // temporary buffer for cli_command_name() to prevent leak
    char *buffer;
    unsigned buf_size;
    struct timeval timeout_tm;
    unsigned int idle_timeout;
    time_t last_action;
    EN_CLI_LANGUAGE enCliLaguage;
    int (*error_callback)(struct cli_def *cli, char *InvalidCmd,int iMsgCode);
    int iIsPtyCmd;
};

struct cli_filter {
    int (*filter)(struct cli_def *cli, char *string, void *data);
    void *data;
    struct cli_filter *next;
};

struct cli_command {
    char *command;
    int (*callback)(struct cli_def *, int, char **);
    unsigned int unique_len;
    char *help;
    int privilege;
    int mode;
    struct cli_command *next;
    struct cli_command *children;
    struct cli_command *parent;
};

struct cli_def *cli_lib_init();
int cli_done(struct cli_def *cli);
struct cli_command *cli_register_command(struct cli_def *cli, struct cli_command *parent, char *command, int (*callback)(struct cli_def *, int , char **), int privilege, int mode, char *help);
int cli_unregister_command(struct cli_def *cli, char *command);
int cli_run_command(struct cli_def *cli, char *command);
int cli_loop(struct cli_def *cli,int fd_in, int fd_out);
int cli_file(struct cli_def *cli, FILE *fh, int privilege, int mode);
void cli_set_auth_callback(struct cli_def *cli, int (*auth_callback)(char *, char *));
void cli_set_enable_callback(struct cli_def *cli, int (*enable_callback)(char *));
void cli_allow_user(struct cli_def *cli, char *username, char *password);
void cli_allow_enable(struct cli_def *cli, char *password);
void cli_deny_user(struct cli_def *cli, char *username);
void cli_set_banner(struct cli_def *cli, char *banner);
void cli_set_hostname(struct cli_def *cli, char *hostname);
void cli_set_promptchar(struct cli_def *cli, char *promptchar);
void cli_set_modestring(struct cli_def *cli, char *modestring);
int cli_set_privilege(struct cli_def *cli, int privilege);
int cli_set_configmode(struct cli_def *cli, int mode, char *config_desc);
void cli_reprompt(struct cli_def *cli);
void cli_regular(struct cli_def *cli, int (*callback)(struct cli_def *cli));
void cli_regular_interval(struct cli_def *cli, int seconds);
void _cli_print(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, char *format, ...) ;//__attribute__((format (printf, 2, 3)));
void cli_bufprint(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, char *format, ...);// __attribute__((format (printf, 2, 3)));
void cli_vabufprint(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, char *format, va_list ap);
void _cli_error(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, char *format, ...) ;//__attribute__((format (printf, 4, 5)));
void cli_print_callback(struct cli_def *cli, void (*callback)(struct cli_def *, char *));
void cli_free_history(struct cli_def *cli);
void cli_set_idle_timeout(struct cli_def *cli, unsigned int seconds);
void init_signal(void);
void _cli_fprintf(const char * pucFuncName,_U32 ulLine,struct cli_def *cli,const _S8 *pFormat, ... );
void cli_set_error_callback(struct cli_def *cli, int (*error_callback)(struct cli_def *cli, char *InvalidCmd));
int cli_no_pty_proc(struct cli_def *cli, int argc, char *argv[]);
void _print(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, int print_mode, char *format, va_list ap);
void _dbg_printf(const char * pucFuncName,_U32 ulLine, char *format, ...);

#define cli_print(CLI,format, ...)    _cli_print(__FUNCTION__,__LINE__,CLI,format, ##__VA_ARGS__)
#define cli_error(CLI,format, ...)    _cli_error(__FUNCTION__,__LINE__,CLI,format, ##__VA_ARGS__)
#define dbg_printf(format, ...)      _dbg_printf(__FUNCTION__,__LINE__,format, ##__VA_ARGS__)

#define cli_print_val(cli,fmt,Var,...)    _cli_print(__FUNCTION__,__LINE__,cli,fmt,#Var ,Var,##__VA_ARGS__)

#define CLI_SYSLOG_INFO( FMT,ARGS...)\
{\
   syslog(LOG_INFO, "cli %s<%d> "FMT,__FUNCTION__,__LINE__,##ARGS);\
}

#define SSDB_CLI_DEBUG_FILE "/tmp/ssdbcli_debug_enable"
#define SSDB_CLI_DEBUG_FILE_2 "/tmp/ssdbcli_debug_enable_2"

#define CLI_SYSLOG_ERROR(FMT,ARGS...)\
{\
   syslog(LOG_INFO,"cli Error %s<%d> "FMT,__FUNCTION__,__LINE__,##ARGS);\
}

#define CLI_SYSLOG_INFO_2( FMT,ARGS...)\
{\
   syslog(LOG_INFO, "cli "FMT,##ARGS);\
}

#define SYSLOG_DEBUG_2(FMT,ARGS...)

#define CLI_SYSLOG_ERROR_2(FMT,ARGS...)\
{\
   syslog(LOG_INFO,  "cli Error "FMT,##ARGS);\
}


extern void set_input_mode(int fd);

#endif
