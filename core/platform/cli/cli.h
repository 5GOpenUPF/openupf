/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _CLI_H__
#define _CLI_H__

#ifdef __cplusplus
extern "C" {
#endif

#define CLI_SMU_PORT        344
#define CLI_LBU_PORT        345
#define CLI_FPU_PORT        346
#define CLI_STUB_PORT       347

typedef int (*cli_handle_t)(int argc, char **argv);
struct cli_table_entry
{
	const char *cmd;
	cli_handle_t handle;
    struct cli_table_entry *next;
};
extern struct cli_table_entry cli_table_head;

#if 0
#define cli_register_cmd(x, h)                      \
    static struct cli_table_entry __cr_##x;         \
static void __cli_registration_##x (void)           \
    __attribute__((__constructor__)) ;              \
static void __cli_registration_##x (void)           \
{                                                   \
    __cr_##x.cmd = __stringify(x);                  \
    __cr_##x.handle = h;                            \
    __cr_##x.next = cli_table_head.next;            \
    cli_table_head.next = &__cr_##x;                \
}
#else
#define cli_register_cmd(x, h)
#endif
/*
 * cmdInfo -- name/value pair for information about command
 *
 * Commands should have at least the following names:
 * "help" - short description of command
 * "style" - synopsis of command
 * "desc" - description of command, or empty string
 */
struct _cmdInfo
{
    const char *name;           /* name of information, or NULL for list end */
    const char *data;           /* non-NULL information */
};
typedef struct _cmdInfo cmdInfo;

typedef int (*cmdFunc)(int, char**);

/*
 * cmdDef - command definition
 */
struct _cmdDef
{
    const char      *name;          /* command */
    const cmdInfo   *info;          /* command help info */
    int              min_args;     /* min args */
    int              max_args;     /* max args */
    cmdFunc          func;         /* function */
};
typedef struct _cmdDef cmdDef;

uint64_t cli_init(void);
uint64_t cli_exit(void);
uint64_t cli_parse_argv(int argc, char **argv);
int cli_cmd_run(const cmdDef *cmds, int argc, char **argv);
const char * cli_cmd_getinfo(const cmdDef * cmd, const char *name);
int cli_cmd_help(const cmdDef *pCmd);
void cli_dump_args(int argc, char **argv);



#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _CLI_H__ */
