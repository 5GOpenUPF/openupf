/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __LIB_CLI_C__
#define __LIB_CLI_C__

#include "common_typedef.h"
#include "libcli.h"

unsigned int regular_count = 0;
unsigned int debug_regular = 0;

// vim:sw=4 ts=8

#ifdef __GNUC__
# define UNUSED(d) d __attribute__ ((unused))
#else
# define UNUSED(d) d
#endif

enum cli_states {
    STATE_LOGIN,
    STATE_PASSWORD,
    STATE_NORMAL,
    STATE_ENABLE_PASSWORD,
    STATE_ENABLE
};

struct unp {
    char *username;
    char *password;
    struct unp *next;
};

struct cli_filter_cmds
{
    char *cmd;
    char *help;
};

/* free and zero (to avoid double-free) */
#define free_z(p) do { if (p) { free(p); (p) = 0; } } while (0)

int cli_match_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt);
int cli_range_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt);
int cli_count_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt);
int cli_match_filter(struct cli_def *cli, char *string, void *data);
int cli_range_filter(struct cli_def *cli, char *string, void *data);
int cli_count_filter(struct cli_def *cli, char *string, void *data);

static struct cli_filter_cmds filter_cmds[] =
{
    { "begin",   "Begin with lines that match" },
    { "between", "Between lines that match" },
    { "count",   "Count of lines"   },
    { "exclude", "Exclude lines that match" },
    { "include", "Include lines that match" },
    { "grep",    "Include lines that match regex (options: -v, -i, -e)" },
    { "egrep",   "Include lines that match extended regex" },
    { NULL, NULL}
};





_S32 _cli_Write(const char * pucFuncName,_U32 ulLine, _S32 slHandle, const char *pucBuff, _U32 ulCount)
{
    int iRet;
    if (0 == ulCount)
    {
        return 0L;
    }
    else
    {
        iRet = write(slHandle, pucBuff, ulCount);
        if(iRet != ulCount)
        {
            CLI_SYSLOG_ERROR_2("%s()<%d> iRet=%d errno=%d ",pucFuncName,ulLine, (iRet), errno);
        }
        return iRet;
    }
}

#define cli_Write(slHandle,pucBuff,ulCount)    _cli_Write(__FUNCTION__,__LINE__,slHandle,pucBuff,ulCount)

/*
 * ensure all of data on socket comes through. f==read || f==write
 */
ssize_t atomicio(f, fd, _s, n)
	ssize_t (*f) ();
	int fd;
	void *_s;
	size_t n;
{
	char *s = _s;
	ssize_t res;
	size_t pos = 0;

	while (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		switch (res) {
		case -1:
#ifdef EWOULDBLOCK
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
#else
			if (errno == EINTR || errno == EAGAIN)
#endif
				continue;
		case 0:
			return (res);
		default:
			pos += res;
		}
	}
	return (pos);
}



char *cli_command_name(struct cli_def *cli, struct cli_command *command)
{
    char *name = cli->commandname;
    char *o;

    if (name) free(name);
    if (!(name = calloc(1, 1)))
        return NULL;

    while (command)
    {
        o = name;
        asprintf(&name, "%s%s%s", command->command, *o ? " " : "", o);
        command = command->parent;
        free(o);
    }
    cli->commandname = name;
    return name;
}

void cli_set_auth_callback(struct cli_def *cli, int (*auth_callback)(char *, char *))
{
    cli->auth_callback = auth_callback;
}

void cli_set_enable_callback(struct cli_def *cli, int (*enable_callback)(char *))
{
    cli->enable_callback = enable_callback;
}

void cli_set_error_callback(struct cli_def *cli, int (*error_callback)(struct cli_def *cli, char *InvalidCmd))
{
    cli->error_callback = (void*)error_callback;
}

void cli_allow_user(struct cli_def *cli, char *username, char *password)
{
    struct unp *u, *n;
    if (!(n = malloc(sizeof(struct unp))))
    {
        fprintf(stderr, "Couldn't allocate memory for user: %s", strerror(errno));
        return;
    }
    if (!(n->username = strdup(username)))
    {
        fprintf(stderr, "Couldn't allocate memory for username: %s", strerror(errno));
        free(n);
        return;
    }
    if (!(n->password = strdup(password)))
    {
        fprintf(stderr, "Couldn't allocate memory for password: %s", strerror(errno));
        free(n->username);
        free(n);
        return;
    }
    n->next = NULL;

    if (!cli->users)
        cli->users = n;
    else
    {
        for (u = cli->users; u && u->next; u = u->next);
        if (u) u->next = n;
    }
}

void cli_allow_enable(struct cli_def *cli, char *password)
{
    free_z(cli->enable_password);
    if (!(cli->enable_password = strdup(password)))
    {
        fprintf(stderr, "Couldn't allocate memory for enable password: %s", strerror(errno));
    }
}

void cli_deny_user(struct cli_def *cli, char *username)
{
    struct unp *u, *p = NULL;
    if (!cli->users) return;
    for (u = cli->users; u; u = u->next)
    {
        if (strcmp(username, u->username) == 0)
        {
            if (p)
                p->next = u->next;
            else
                cli->users = u->next;
            free(u->username);
            free(u->password);
            free(u);
            break;
        }
        p = u;
    }
}

void cli_set_banner(struct cli_def *cli, char *banner)
{
    free_z(cli->banner);
    if (banner && *banner)
        cli->banner = strdup(banner);
}

void cli_set_hostname(struct cli_def *cli, char *hostname)
{
    free_z(cli->hostname);
    if (hostname && *hostname)
        cli->hostname = strdup(hostname);
}

void cli_set_promptchar(struct cli_def *cli, char *promptchar)
{
    free_z(cli->promptchar);
    cli->promptchar = strdup(promptchar);
}

static int cli_build_shortest(struct cli_def *cli, struct cli_command *commands)
{
    struct cli_command *c, *p;
    char *cp, *pp;
    int len;

    for (c = commands; c; c = c->next)
    {
        c->unique_len = strlen(c->command);
        if ((c->mode != MODE_ANY && c->mode != cli->mode) ||
            c->privilege > cli->privilege)
            continue;

        c->unique_len = 1;
        for (p = commands; p; p = p->next)
        {
            if (c == p)
                    continue;

            if ((p->mode != MODE_ANY && p->mode != cli->mode) ||
                p->privilege > cli->privilege)
                    continue;

            cp = c->command;
            pp = p->command;
            len = 1;

            while (*cp && *pp && *cp++ == *pp++)
                len++;

            if (len > c->unique_len)
                c->unique_len = len;
        }

        if (c->children)
            cli_build_shortest(cli, c->children);
    }

    return CLI_OK;
}

int cli_set_privilege(struct cli_def *cli, int priv)
{
    int old = cli->privilege;
    cli->privilege = priv;

    if (priv != old)
    {
        cli_set_promptchar(cli, priv == PRIVILEGE_PRIVILEGED ? "#" : ">");
        cli_build_shortest(cli, cli->commands);
    }

    return old;
}

void cli_set_modestring(struct cli_def *cli, char *modestring)
{
    free_z(cli->modestring);
    if (modestring)
        cli->modestring = strdup(modestring);
}

int cli_set_configmode(struct cli_def *cli, int mode, char *config_desc)
{
    int old = cli->mode;
    cli->mode = mode;

    if (mode != old)
    {
        if (!cli->mode)
        {
            // Not config mode
            cli_set_modestring(cli, NULL);
        }
        else if (config_desc && *config_desc)
        {
            char string[64];
            snprintf(string, sizeof(string), "(config-%s)", config_desc);
            cli_set_modestring(cli, string);
        }
        else
        {
            cli_set_modestring(cli, "(config)");
        }

        cli_build_shortest(cli, cli->commands);
    }

    return old;
}

struct cli_command *cli_register_command(struct cli_def *cli,
    struct cli_command *parent, char *command,
    int (*callback)(struct cli_def *cli,int, char **),
    int privilege, int mode, char *help)
{
    struct cli_command *c, *p;

    if (!command) return NULL;
    if (!(c = calloc(sizeof(struct cli_command), 1))) return NULL;

    c->callback = callback;
    c->next = NULL;
    if (!(c->command = strdup(command)))
        return NULL;
    c->parent = parent;
    c->privilege = privilege;
    c->mode = mode;
    if (help)
        if (!(c->help = strdup(help)))
            return NULL;

    if (parent)
    {
        if (!parent->children)
        {
            parent->children = c;
        }
        else
        {
            for (p = parent->children; p && p->next; p = p->next);
            if (p) p->next = c;
        }
    }
    else
    {
        if (!cli->commands)
        {
            cli->commands = c;
        }
        else
        {
            for (p = cli->commands; p && p->next; p = p->next);
            if (p) p->next = c;
        }
    }
    return c;
}

static void cli_free_command(struct cli_command *cmd)
{
    struct cli_command *c,*p;

    for (c = cmd->children; c;)
    {
        p = c->next;
        cli_free_command(c);
        c = p;
    }

    free(cmd->command);
    if (cmd->help) free(cmd->help);
    free(cmd);
}

int cli_unregister_command(struct cli_def *cli, char *command)
{
    struct cli_command *c, *p = NULL;

    if (!command) return -1;
    if (!cli->commands) return CLI_OK;

    for (c = cli->commands; c; c = c->next)
    {
        if (strcmp(c->command, command) == 0)
        {
            if (p)
                p->next = c->next;
            else
                cli->commands = c->next;

            cli_free_command(c);
            return CLI_OK;
        }
        p = c;
    }

    return CLI_OK;
}

int cli_show_help(struct cli_def *cli, struct cli_command *c)
{
    struct cli_command *p;

    for (p = c; p; p = p->next)
    {
        if (p->command && p->callback && cli->privilege >= p->privilege &&
            (p->mode == cli->mode || p->mode == MODE_ANY))
        {
            cli_error(cli, "  %-20s %s", cli_command_name(cli, p), p->help ? : "");
        }

        if (p->children)
            cli_show_help(cli, p->children);
    }

    return CLI_OK;
}

int cli_int_enable(struct cli_def *cli,UNUSED(int argc), UNUSED(char *argv[]))
{
    if (cli->privilege == PRIVILEGE_PRIVILEGED)
        return CLI_OK;

    if (!cli->enable_password && !cli->enable_callback)
    {
        /* no password required, set privilege immediately */
        cli_set_privilege(cli, PRIVILEGE_PRIVILEGED);
        cli_set_configmode(cli, MODE_EXEC, NULL);
    }
    else
    {
        /* require password entry */
        cli->state = STATE_ENABLE_PASSWORD;
    }

    return CLI_OK;
}

int cli_int_disable(struct cli_def *cli, UNUSED(int argc), UNUSED(char *argv[]))
{
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, NULL);
    return CLI_OK;
}

int cli_show_info(struct cli_def *cli, UNUSED(int argc), UNUSED(char *argv[]))
{
    cli_print(cli,"%-40s:%d","iOutSocket",cli->iOutSocket);
    cli_print(cli,"%-40s:%d","iIsPtyCmd",cli->iIsPtyCmd);
    cli_print(cli,"%-40s:%d","state",cli->state);
    return CLI_OK;
}

int cli_int_help(struct cli_def *cli, UNUSED(int argc), UNUSED(char *argv[]))
{
    cli_error(cli, "\nCommands available:");
    cli_show_help(cli, cli->commands);
    return CLI_OK;
}

int cli_int_history(struct cli_def *cli,UNUSED(int argc), UNUSED(char *argv[]))
{
    int i;

    cli_error(cli, "\nCommand history:");
    for (i = 0; i < MAX_HISTORY; i++)
    {
        if (cli->history[i])
            cli_error(cli, "%3d. %s", i, cli->history[i]);
    }

    return CLI_OK;
}

int cli_int_quit(struct cli_def *cli, UNUSED(int argc), UNUSED(char *argv[]))
{
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, NULL);
    return CLI_QUIT;
}

int cli_int_exit(struct cli_def *cli, int argc, char *argv[])
{
    if (cli->mode == MODE_EXEC)
        return cli_int_quit(cli, argc, argv);

    if (cli->mode > MODE_CONFIG)
        cli_set_configmode(cli, MODE_CONFIG, NULL);
    else
        cli_set_configmode(cli, MODE_EXEC, NULL);

    cli->service = NULL;
    return CLI_OK;
}
int config_start,config_end;
int cli_int_configure_slot(struct cli_def *cli, UNUSED(int argc), UNUSED(char *argv[]))
{
	if(argc==1)
	{
		config_start=config_end = atoi(argv[0]);
	}
	else if(argc==2)
	{
		config_start = atoi(argv[0]);
		config_end = atoi(argv[1]);
	}
	else
		return CLI_ERROR;
    cli_set_configmode(cli, MODE_CONFIG, NULL);

    return CLI_OK;
}

struct cli_def *cli_lib_init()
{
    struct cli_def *cli;
    struct cli_command *c;

    if (!(cli = calloc(sizeof(struct cli_def), 1)))
        return 0;

    cli->buf_size = 1024;
    if (!(cli->buffer = calloc(cli->buf_size, 1)))
    {
        free_z(cli);
        return 0;
    }

    cli_register_command(cli, 0, "help", cli_int_help, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show available commands");
    cli_register_command(cli, 0, "quit", cli_int_quit, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Disconnect");
    //cli_register_command(cli, 0, "logout", cli_int_quit, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Disconnect");
    cli_register_command(cli, 0, "exit", cli_int_exit, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Exit from current mode");
    cli_register_command(cli, 0, "history", cli_int_history, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show a list of previously run commands");
    cli_register_command(cli, 0, "enable", cli_int_enable, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Turn on privileged commands");
    cli_register_command(cli, 0, "disable", cli_int_disable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Turn off privileged commands");
    cli_register_command(cli, 0, "cli_info", cli_show_info, PRIVILEGE_PRIVILEGED, MODE_EXEC, "cli_show_info");

    c = cli_register_command(cli, 0, "configure", 0, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Enter configuration mode");
    cli_register_command(cli, c, "slot", cli_int_configure_slot, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Configure from the terminal");

    cli->privilege = cli->mode = -1;
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, 0);

    // Default to 1 second timeout intervals
    cli->timeout_tm.tv_sec = 1;
    cli->timeout_tm.tv_usec = 0;
    return cli;
}

void cli_unregister_all(struct cli_def *cli, struct cli_command *command)
{
    struct cli_command *c, *p = NULL;

    if (!command) command = cli->commands;
    if (!command) return;

    for (c = command; c; )
    {
        p = c->next;

        // Unregister all child commands
        if (c->children)
            cli_unregister_all(cli, c->children);

        if (c->command) free(c->command);
        if (c->help) free(c->help);
        free(c);

        c = p;
    }
}

int cli_done(struct cli_def *cli)
{
    struct unp *u = cli->users, *n;

    if (!cli) return CLI_OK;
    cli_free_history(cli);

    // Free all users
    while (u)
    {
        if (u->username) free(u->username);
        if (u->password) free(u->password);
        n = u->next;
        free(u);
        u = n;
    }

    /* free all commands */
    cli_unregister_all(cli, 0);

    free_z(cli->commandname);
    free_z(cli->modestring);
    free_z(cli->banner);
    free_z(cli->promptchar);
    free_z(cli->hostname);
    free_z(cli->buffer);
    free_z(cli);

    return CLI_OK;
}

static int cli_add_history(struct cli_def *cli, char *cmd)
{
    int i;
    for (i = 0; i < MAX_HISTORY; i++)
    {
        if (!cli->history[i])
        {
            if (i == 0 || strcasecmp(cli->history[i-1], cmd))
            if (!(cli->history[i] = strdup(cmd)))
                return CLI_ERROR;
            return CLI_OK;
        }
    }
    // No space found, drop one off the beginning of the list
    free(cli->history[0]);
    for (i = 0; i < MAX_HISTORY-1; i++)
        cli->history[i] = cli->history[i+1];
    if (!(cli->history[MAX_HISTORY - 1] = strdup(cmd)))
        return CLI_ERROR;
    return CLI_OK;
}

void cli_free_history(struct cli_def *cli)
{
    int i;
    for (i = 0; i < MAX_HISTORY; i++)
    {
        if (cli->history[i])
            free_z(cli->history[i]);
    }
}

static int cli_parse_line(char *line, char *words[], int max_words)
{
    int nwords = 0;
    char *p = line;
    char *word_start = 0;
    int inquote = 0;

    while (*p)
    {
        if (!isspace(*p))
        {
            word_start = p;
            break;
        }
        p++;
    }

    while (nwords < max_words - 1)
    {
        if (!*p || *p == inquote || (word_start && !inquote && (isspace(*p) || *p == '|')))
        {
            if (word_start)
            {
                int len = p - word_start;

                memcpy(words[nwords] = malloc(len + 1), word_start, len);
                words[nwords++][len] = 0;
            }

            if (!*p)
                break;

            if (inquote)
                p++; /* skip over trailing quote */

            inquote = 0;
            word_start = 0;
        }
        else if (*p == '"' || *p == '\'')
        {
            inquote = *p++;
            word_start = p;
        }
        else
        {
            if (!word_start)
            {
                if (*p == '|')
                {
                    if (!(words[nwords++] = strdup("|")))
                        return 0;
                }
                else if (!isspace(*p))
                    word_start = p;
            }

            p++;
        }
    }

    return nwords;
}

static char *join_words(int argc, char **argv)
{
    char *p;
    int len = 0;
    int i;

    for (i = 0; i < argc; i++)
    {
        if (i)
            len += 1;

        len += strlen(argv[i]);
    }

    p = malloc(len + 1);
    p[0] = 0;

    for (i = 0; i < argc; i++)
    {
        if (i)
            strcat(p, " ");

        strcat(p, argv[i]);
    }

    return p;
}

int cli_check_parm(struct cli_def *cli, int argc, char **argv)
{
    if ((1 == argc) && (*argv[0] == '?' || strcmp(argv[0],"help") == 0))
    {
        if (cli->commands->parent && cli->commands->parent->callback && cli->commands->parent->help)
        {
            if (cli->commands->parent->help) {
                cli_error(cli, "%-20s %s", cli_command_name(cli, cli->commands->parent),  cli->commands->parent->help ? : "");
            }
            else {
                return 0; /* Using help in callback functions */
            }
        }
        else {
            return 0; /* Using help in callback functions */
        }

        return -1;
    }

    if ((1 < argc) && (*argv[argc-1] == '?' || strcmp(argv[argc-1],"help") == 0))
    {
        if (cli->commands->parent && cli->commands->parent->callback)
        {
            if (cli->commands->parent->help) {
            cli_error(cli, "%-20s %s", cli_command_name(cli, cli->commands->parent),  cli->commands->parent->help ? : "");
            }
            else {
                return 0; /* Using help in callback functions */
            }
        }
        else {
            return 0; /* Using help in callback functions */
        }

        return -1;
    }
    return 0;
}

static int cli_find_command(struct cli_def *cli, struct cli_command *commands, int num_words, char *words[], int start_word, int filters[])
{
    struct cli_command *c, *again = NULL;
    int c_words = num_words;

    if (filters[0])
        c_words = filters[0];

    // Deal with ? for help
    if (!words[start_word])
        return CLI_ERROR;

    if (words[start_word][strlen(words[start_word]) - 1] == '?')
    {
        int l = strlen(words[start_word])-1;

        if (commands->parent && commands->parent->callback)
            cli_error(cli, "%-20s %s", cli_command_name(cli, commands->parent),  commands->parent->help ? : "");

        for (c = commands; c; c = c->next)
        {
            if (strncasecmp(c->command, words[start_word], l) == 0
                && (c->callback || c->children)
                && cli->privilege >= c->privilege
                && (c->mode == cli->mode || c->mode == MODE_ANY))
                    cli_error(cli, "  %-20s %s", c->command, c->help ? : "");
        }

        return CLI_OK;
    }

    for (c = commands; c; c = c->next)
    {
        if (cli->privilege < c->privilege)
            continue;

        if (strncasecmp(c->command, words[start_word], c->unique_len))
            continue;

        if (strncasecmp(c->command, words[start_word], strlen(words[start_word])))
            continue;

        AGAIN:
        if (c->mode == cli->mode || c->mode == MODE_ANY)
        {
            int rc = CLI_OK;
            int f;
            struct cli_filter **filt = &cli->filters;

            // Found a word!
            if (!c->children)
            {
                // Last word
                if (!c->callback)
                {
                    cli_error(cli, "No callback for \"%s\"", cli_command_name(cli, c));
                    return CLI_ERROR;
                }
            }
            else
            {
                if (start_word == c_words - 1)
                {
                    if (c->callback)
                        goto CORRECT_CHECKS;

                    cli_error(cli, "Incomplete command");
                    return CLI_ERROR;
                }
                rc = cli_find_command(cli, c->children, num_words, words, start_word + 1, filters);
                if (rc == CLI_ERROR_ARG)
                {
                    if (c->callback)
                    {
                        rc = CLI_OK;
                        goto CORRECT_CHECKS;
                    }
                    else
                    {
                        cli_error(cli, "Invalid %s \"%s\"", commands->parent ? "argument" : "command", words[start_word]);
                    }
                }
                return rc;
            }

            if (!c->callback)
            {
                cli_error(cli, "Internal server error processing \"%s\"", cli_command_name(cli, c));
                return CLI_ERROR;
            }

            CORRECT_CHECKS:
            for (f = 0; rc == CLI_OK && filters[f]; f++)
            {
                int n = num_words;
                char **argv;
                int argc;
                int len;

                if (filters[f+1])
                n = filters[f+1];

                if (filters[f] == n - 1)
                {
                    cli_error(cli, "Missing filter");
                    return CLI_ERROR;
                }

                argv = words + filters[f] + 1;
                argc = n - (filters[f] + 1);
                len = strlen(argv[0]);
                if (argv[argc - 1][strlen(argv[argc - 1]) - 1] == '?')
                {
                    if (argc == 1)
                    {
                        int i;

                        for(i = 0; filter_cmds[i].cmd; i++)
                        {
                            cli_error(cli, "  %-20s %s", filter_cmds[i].cmd, filter_cmds[i].help );
                        }
                    }
                    else
                    {
                        if (argv[0][0] != 'c') // count
                            cli_error(cli, "  WORD");

                        if (argc > 2 || argv[0][0] == 'c') // count
                            cli_error(cli, "  <cr>");
                    }

                    return CLI_OK;
                }

                if (argv[0][0] == 'b' && len < 3) // [beg]in, [bet]ween
                {
                    cli_error(cli, "Ambiguous filter \"%s\" (begin, between)", argv[0]);
                    return CLI_ERROR;
                }
                *filt = calloc(sizeof(struct cli_filter), 1);

                if (!strncmp("include", argv[0], len) ||
                    !strncmp("exclude", argv[0], len) ||
                    !strncmp("grep", argv[0], len) ||
                    !strncmp("egrep", argv[0], len))
                        rc = cli_match_filter_init(cli, argc, argv, *filt);
                else if (!strncmp("begin", argv[0], len) ||
                    !strncmp("between", argv[0], len))
                        rc = cli_range_filter_init(cli, argc, argv, *filt);
                else if (!strncmp("count", argv[0], len))
                    rc = cli_count_filter_init(cli, argc, argv, *filt);
                else
                {
                    cli_error(cli, "Invalid filter \"%s\"", argv[0]);
                    rc = CLI_ERROR;
                }

                if (rc == CLI_OK)
                {
                    filt = &(*filt)->next;
                }
                else
                {
                    free(*filt);
                    *filt = 0;
                }
            }

            if (rc == CLI_OK)
            {
                if (0 == cli_check_parm(cli, c_words - start_word - 1,words + start_word + 1))
                {
                    //rc = c->callback(cli, cli_command_name(cli, c), c_words - start_word - 1,words + start_word + 1);
                    rc = c->callback(cli, c_words - start_word - 1,words + start_word + 1);
                }
            }

            while (cli->filters)
            {
                struct cli_filter *filt = cli->filters;

                // call one last time to clean up
                filt->filter(cli, NULL, filt->data);
                cli->filters = filt->next;
                free(filt);
            }

            return rc;
        }
        else if (cli->mode > MODE_CONFIG && c->mode == MODE_CONFIG)
        {
            // command matched but from another mode,
            // remember it if we fail to find correct command
            again = c;
        }
    }

    // drop out of config submode if we have matched command on MODE_CONFIG
    if (again)
    {
        c = again;
        cli_set_configmode(cli, MODE_CONFIG, NULL);
        goto AGAIN;
    }

    if (start_word == 0)
    {
        if(cli->error_callback)
        {
            cli->error_callback(cli,words[start_word],2); //EN_SSDB_ERROR_CODE_PARAM=2
        }
        else
        {
            cli_error(cli, "Invalid %s \"%s\"", commands->parent ? "argument" : "command", words[start_word]);
        }
    }

    return CLI_ERROR_ARG;
}

int cli_run_command(struct cli_def *cli, char *command)
{
    int r;
    unsigned int num_words, i, f;
    char *words[128] = {0};
    int filters[128] = {0};

    if (!command) return CLI_ERROR;
    while (isspace(*command))
        command++;

    if (!*command) return CLI_OK;

    num_words = cli_parse_line(command, words, sizeof(words) / sizeof(words[0]));
    for (i = f = 0; i < num_words && f < sizeof(filters) / sizeof(filters[0]) - 1; i++)
    {
        if (words[i][0] == '|')
        filters[f++] = i;
    }

    filters[f] = 0;

    if (num_words)
    {
        r = cli_find_command(cli, cli->commands, num_words, words, 0, filters);
    }
    else
    {
        r = CLI_ERROR;
    }

    for (i = 0; i < num_words; i++)
        free(words[i]);

    if (r == CLI_QUIT)
        return r;

    return CLI_OK;
}

static int cli_get_completions(struct cli_def *cli, char *command, char **completions, int max_completions)
{
    struct cli_command *c;
    struct cli_command *n;
    int num_words, i, k=0;
    char *words[128] = {0};
    int filter = 0;

    if (!command) return 0;
    while (isspace(*command))
        command++;

    num_words = cli_parse_line(command, words, sizeof(words)/sizeof(words[0]));
    if (!command[0] || command[strlen(command)-1] == ' ')
        num_words++;

    if (!num_words)
            return 0;

    for (i = 0; i < num_words; i++)
    {
        if (words[i] && words[i][0] == '|')
            filter = i;
    }

    if (filter) // complete filters
    {
        unsigned len = 0;

        if (filter < num_words - 1) // filter already completed
            return 0;

        if (filter == num_words - 1)
            len = strlen(words[num_words-1]);

        for (i = 0; filter_cmds[i].cmd && k < max_completions; i++)
            if (!len || (len < strlen(filter_cmds[i].cmd)
                && !strncmp(filter_cmds[i].cmd, words[num_words - 1], len)))
                    completions[k++] = filter_cmds[i].cmd;

        completions[k] = NULL;
        return k;
    }

    for (c = cli->commands, i = 0; c && i < num_words && k < max_completions; c = n)
    {
        n = c->next;

        if (cli->privilege < c->privilege)
            continue;

        if (c->mode != cli->mode && c->mode != MODE_ANY)
            continue;

        if (words[i] && strncasecmp(c->command, words[i], strlen(words[i])))
            continue;

        if (i < num_words - 1)
        {
            if (strlen(words[i]) < c->unique_len)
                    continue;

            n = c->children;
            i++;
            continue;
        }

        completions[k++] = c->command;
    }

    return k;
}

static void cli_clear_line(int sockfd, char *cmd, int l, int cursor)
{
    int i;
    if (cursor < l) for (i = 0; i < (l - cursor); i++) cli_Write(sockfd, " ", 1);
    for (i = 0; i < l; i++) cmd[i] = '\b';
    for (; i < l * 2; i++) cmd[i] = ' ';
    for (; i < l * 3; i++) cmd[i] = '\b';
    cli_Write(sockfd, cmd, i);
    memset(cmd, 0, i);
    l = cursor = 0;
}

void cli_reprompt(struct cli_def *cli)
{
    if (!cli) return;
    cli->showprompt = 1;
}

void cli_regular(struct cli_def *cli, int (*callback)(struct cli_def *cli))
{
    if (!cli) return;
    cli->regular_callback = callback;
}

void cli_regular_interval(struct cli_def *cli, int seconds)
{
    if (seconds < 1) seconds = 1;
    cli->timeout_tm.tv_sec = seconds;
    cli->timeout_tm.tv_usec = 0;
}

void cli_checkalive(struct cli_def *cli, int (*callback)(struct cli_def *cli))
{
    cli->checkalive_callback = callback;
}

#define DES_PREFIX "{crypt}"        /* to distinguish clear text from DES crypted */
#define MD5_PREFIX "$1$"

static int pass_matches(char *pass, char *try)
{
    int des;
    if ((des = !strncasecmp(pass, DES_PREFIX, sizeof(DES_PREFIX)-1)))
        pass += sizeof(DES_PREFIX)-1;


    return !strcmp(pass, try);
}

//#define CTRL(c) (c - '@')

static int _show_prompt(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, int sockfd)
{
    int len = 0;

    if (cli->hostname)
        len += _cli_Write(pucFuncName,ulLine,sockfd, cli->hostname, strlen(cli->hostname));

    if (cli->modestring)
        len += _cli_Write(pucFuncName,ulLine,sockfd, cli->modestring, strlen(cli->modestring));

    return len + _cli_Write(pucFuncName,ulLine,sockfd, cli->promptchar, strlen(cli->promptchar));
}

#define show_prompt(cli,sockfd)    if(_show_prompt(__FUNCTION__,__LINE__,cli,sockfd)<0)return -1;

char g_acCmd[4096]={0};

extern void cli_drop_connect();

int cli_loop(struct cli_def *cli,int fd_in, int fd_out)
{
    unsigned char c;
    int n, l, oldl = 0, is_telnet_option = 0, skip = 0, esc = 0;
    int cursor = 0, insertmode = 1;
    char *cmd = NULL, *oldcmd = 0;
    char *username = NULL, *password = NULL;
    #if 0
    char *negotiate =
        "\xFF\xFB\x03"
        "\xFF\xFB\x01"
        "\xFF\xFD\x03"
        "\xFF\xFD\x01";
    #endif

    cli_build_shortest(cli, cli->commands);
    cli->state = STATE_LOGIN;

    cli_free_history(cli);
    //cli_Write(sockfd, negotiate, strlen(negotiate));

    #if 0
    if ((cmd = malloc(4096)) == NULL)
        return CLI_ERROR;
    #else

    cmd = &g_acCmd[0];

    #endif

    if (!(cli->client = fdopen(fd_out, "w+")))
        return CLI_ERROR;

    cli->iOutSocket = fd_out;

    setbuf(cli->client, NULL);
    if (cli->banner)
        cli_error(cli, "%s", cli->banner);

    // Set the last action now so we don't time immediately
    if (cli->idle_timeout)
        time(&cli->last_action);

    /* start off in unprivileged mode */
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, NULL);

    /* no auth required? */
    if (!cli->users && !cli->auth_callback)
        cli->state = STATE_NORMAL;

    if (cli->checkalive_callback)
    {
        if(0 !=  cli->checkalive_callback(cli))
        {
            CLI_SYSLOG_ERROR("checkalive_callback failed");
            goto EXIT;
        }
    }

    while (1)
    {
        signed int in_history = 0;
        int lastchar = 0;
        struct timeval tm;

        cli->showprompt = 1;

        if (oldcmd)
        {
            l = cursor = oldl;
            oldcmd[l] = 0;
            cli->showprompt = 1;
            oldcmd = NULL;
            oldl = 0;
        }
        else
        {
            memset(cmd, 0, 4096);
            l = 0;
            cursor = 0;
        }

        memcpy(&tm, &cli->timeout_tm, sizeof(tm));

        while (1)
        {
            int sr;
            fd_set r;

            cli_drop_connect();
            if (cli->showprompt)
            {
                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                {
                    //cli_Write(fd_out, "\r\n", 2);
                    //cli_Write(fd_out, "\n", 1);
                }

                switch (cli->state)
                {
                    case STATE_LOGIN:
                        cli_Write(fd_out, "Username: ", strlen("Username: "));
                        break;

                    case STATE_PASSWORD:
                        cli_Write(fd_out, "Password: ", strlen("Password: "));
                        break;

                    case STATE_NORMAL:
                    case STATE_ENABLE:
                        show_prompt(cli, fd_out);
                        cli_Write(fd_out, cmd, l);
                        if (cursor < l)
                        {
                            int n = l - cursor;
                            while (n--)
                                cli_Write(fd_out, "\b", 1);
                        }
                        break;

                    case STATE_ENABLE_PASSWORD:
                        cli_Write(fd_out, "Password: ", strlen("Password: "));
                        break;

                }

                cli->showprompt = 0;
            }

            FD_ZERO(&r);
            FD_SET(fd_in, &r);

            if ((sr = select(fd_in + 1, &r, NULL, NULL, &tm)) < 0)
            {
				syslog(LOG_ERR,"select err:%d",errno);
                /* select error */
                if (errno == EINTR)
                    continue;

                perror("select");
                l = -1;
                break;
            }

            if (sr == 0)
            {
                /* timeout every second */
                if (cli->regular_callback && cli->regular_callback(cli) != CLI_OK)
                    break;

                if (cli->idle_timeout)
                {
                    if (time(NULL) - cli->last_action >= cli->idle_timeout)
                    {
                        cli_print(cli, "Idle timeout");
                        strncpy(cmd, "quit", 4095);
                        break;
                    }
                }

                memcpy(&tm, &cli->timeout_tm, sizeof(tm));
                continue;
            }

            if ((n = read(fd_in, &c, 1)) < 0)
            {
                if (errno == EINTR)
                    continue;

                perror("read");
                l = -1;
                break;
            }

            if (cli->idle_timeout)
                time(&cli->last_action);

            if (n == 0)
            {
                l = -1;
                break;
            }

            //printf("c=%d(%c) \n",c,c);
            //CLI_SYSLOG_INFO("c=%d(%c) \n",c,c)
            if (skip)
            {
                skip--;
                continue;
            }

            if (c == 255 && !is_telnet_option)
            {
                is_telnet_option++;
                continue;
            }

            if (is_telnet_option)
            {
                if (c >= 251 && c <= 254)
                {
                    is_telnet_option = c;
                    continue;
                }

                if (c != 255)
                {
                    is_telnet_option = 0;
                    continue;
                }

                is_telnet_option = 0;
            }

            /* handle ANSI arrows */
            if (esc)
            {
                if (esc == '[')
                {
                    /* remap to readline control codes */
                    switch (c)
                    {
                        case 'A': /* Up */
                            c = CTRL('P');
                            break;

                        case 'B': /* Down */
                            c = CTRL('N');
                            break;

                        case 'C': /* Right */
                            c = CTRL('F');
                            break;

                        case 'D': /* Left */
                            c = CTRL('B');
                            break;

                        default:
                            c = 0;
                    }

                    esc = 0;
                }
                else
                {
                    esc = (c == '[') ? c : 0;
                    continue;
                }
            }

            if (c == 0)
            {
                continue;
            }

            #if 0

            //�س���
            if (c == '\n') continue;

            if (c == '\r')
            {
                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                    cli_Write(fd_out, "\r\n", 2);
                break;
            }
            #else
            if (c == '\r') continue;

            if (c == '\n')
            {
                //���»س�������ַ�
                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                {
                    //cli_Write(fd_out, "\r\n", 2);
                    cli_Write(fd_out, "\n", 1);
                }
                break;
            }
            #endif
            if (c == 27)
            {
                esc = 1;
                continue;
            }

            if (c == CTRL('C'))
            {
                cli_Write(fd_out, "\a", 1);
                continue;
            }

            /* back word, backspace/delete */
            if (c == CTRL('W') || c == CTRL('H') || c == 0x7f)
            {
                int back = 0;

                if (c == CTRL('W')) /* word */
                {
                    int nc = cursor;

                    if (l == 0 || cursor == 0)
                        continue;

                    while (nc && cmd[nc - 1] == ' ')
                    {
                        nc--;
                        back++;
                    }

                    while (nc && cmd[nc - 1] != ' ')
                    {
                        nc--;
                        back++;
                    }
                }
                else /* char */
                {
                    if (l == 0 || cursor == 0)
                    {
                        cli_Write(fd_out, "\a", 1);
                        continue;
                    }

                    back = 1;
                }

                if (back)
                {
                    while (back--)
                    {
                        if (l == cursor)
                        {
                            cmd[--cursor] = 0;
                            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                                cli_Write(fd_out, "\b \b", 3);
                        }
                        else
                        {
                            int i;
                            cursor--;
                            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            {
                                for (i = cursor; i <= l; i++) cmd[i] = cmd[i+1];
                                cli_Write(fd_out, "\b", 1);
                                cli_Write(fd_out, cmd + cursor, strlen(cmd + cursor));
                                cli_Write(fd_out, " ", 1);
                                for (i = 0; i <= (int)strlen(cmd + cursor); i++)
                                    cli_Write(fd_out, "\b", 1);
                            }
                        }
                        l--;
                    }

                    continue;
                }
            }

            /* redraw */
            if (c == CTRL('L'))
            {
                int i;
                int cursorback = l - cursor;

                if (cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    continue;

                //cli_Write(fd_out, "\r\n", 2);
                cli_Write(fd_out, "\n", 1);
                show_prompt(cli, fd_out);
                cli_Write(fd_out, cmd, l);

                for (i = 0; i < cursorback; i++)
                    cli_Write(fd_out, "\b", 1);

                continue;
            }

            /* clear line */
            if (c == CTRL('U'))
            {
                if (cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    memset(cmd, 0, l);
                else
                    cli_clear_line(fd_out, cmd, l, cursor);

                l = cursor = 0;
                continue;
            }

            /* kill to EOL */
            if (c == CTRL('K'))
            {
                if (cursor == l)
                    continue;

                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                {
                    int c;
                    for (c = cursor; c < l; c++)
                        cli_Write(fd_out, " ", 1);

                    for (c = cursor; c < l; c++)
                        cli_Write(fd_out, "\b", 1);
                }

                memset(cmd + cursor, 0, l - cursor);
                l = cursor;
                continue;
            }

            /* EOT */
            if (c == CTRL('D'))
            {
                if (cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    break;

                if (l)
                    continue;

                strcpy(cmd, "quit");
                l = cursor = strlen(cmd);
                cli_Write(fd_out, "quit\r\n", l + 2);
                break;
            }

            /* disable */
            if (c == CTRL('Z'))
            {
                if (cli->mode != MODE_EXEC)
                {
                    cli_clear_line(fd_out, cmd, l, cursor);
                    cli_set_configmode(cli, MODE_EXEC, NULL);
                    cli->showprompt = 1;
                }

                continue;
            }

            /* TAB completion */
            if (c == CTRL('I'))
            {
                char *completions[128];
                int num_completions = 0;

                if (cli->state == STATE_LOGIN || cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    continue;

                if (cursor != l) continue;

                num_completions = cli_get_completions(cli, cmd, completions, 128);
                if (num_completions == 0)
                {
                    cli_Write(fd_out, "\a", 1);
                }
                else if (num_completions == 1)
                {
                    // Single completion
                    for (; l > 0; l--, cursor--)
                    {
                        if (cmd[l-1] == ' ' || cmd[l-1] == '|')
                            break;
                        cli_Write(fd_out, "\b", 1);
                    }
                    strcpy((cmd + l), completions[0]);
                    l += strlen(completions[0]);
                    cmd[l++] = ' ';
                    cursor = l;
                    cli_Write(fd_out, completions[0], strlen(completions[0]));
                    cli_Write(fd_out, " ", 1);
                }
                else if (lastchar == CTRL('I'))
                {
                    // double tab
                    int i;
                    //cli_Write(fd_out, "\r\n", 2);
                    cli_Write(fd_out, "\n", 1);
                    for (i = 0; i < num_completions; i++)
                    {
                        cli_Write(fd_out, completions[i], strlen(completions[i]));
                        if (i % 4 == 3)
                            cli_Write(fd_out, "\n", 1);
                        else
                            cli_Write(fd_out, "     ", 1);
                    }
                    //if (i % 4 != 3) cli_Write(fd_out, "\r\n", 2);
                    if (i % 4 != 3) cli_Write(fd_out, "\n", 1);
                        cli->showprompt = 1;
                }
                else
                {
                    // More than one completion
                    lastchar = c;
                    cli_Write(fd_out, "\a", 1);
                }
                continue;
            }

            /* history */
            if (c == CTRL('P') || c == CTRL('N'))
            {
                int history_found = 0;

                if (cli->state == STATE_LOGIN || cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    continue;

                if (c == CTRL('P')) // Up
                {
                    in_history--;
                    if (in_history < 0)
                    {
                        for (in_history = MAX_HISTORY-1; in_history >= 0; in_history--)
                        {
                            if (cli->history[in_history])
                            {
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cli->history[in_history]) history_found = 1;
                    }
                }
                else // Down
                {
                    in_history++;
                    if (in_history >= MAX_HISTORY || !cli->history[in_history])
                    {
                        int i = 0;
                        for (i = 0; i < MAX_HISTORY; i++)
                        {
                            if (cli->history[i])
                            {
                                in_history = i;
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cli->history[in_history]) history_found = 1;
                    }
                }
                if (history_found && cli->history[in_history])
                {
                    // Show history item
                    cli_clear_line(fd_out, cmd, l, cursor);
                    memset(cmd, 0, 4096);
                    strncpy(cmd, cli->history[in_history], 4095);
                    l = cursor = strlen(cmd);
                    cli_Write(fd_out, cmd, l);
                }

                continue;
            }

            /* left/right cursor motion */
            if (c == CTRL('B') || c == CTRL('F'))
            {
                if (c == CTRL('B')) /* Left */
                {
                    if (cursor)
                    {
                        if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            cli_Write(fd_out, "\b", 1);

                        cursor--;
                    }
                }
                else /* Right */
                {
                    if (cursor < l)
                    {
                        if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            cli_Write(fd_out, &cmd[cursor], 1);

                        cursor++;
                    }
                }

                continue;
            }

            /* start of line */
            if (c == CTRL('A'))
            {
                if (cursor)
                {
                    if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                    {
                        //ȥ��������
                        //cli_Write(fd_out, "\r", 1);
                        show_prompt(cli, fd_out);
                    }

                    cursor = 0;
                }

                continue;
            }

            /* end of line */
            if (c == CTRL('E'))
            {
                if (cursor < l)
                {
                    if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                        cli_Write(fd_out, &cmd[cursor], l - cursor);

                    cursor = l;
                }

                continue;
            }

            /* normal character typed */
            if (cursor == l)
            {
                 /* append to end of line */
                cmd[cursor] = c;
                if (l < 4095)
                {
                    l++;
                    cursor++;
                }
                else
                {
                    cli_Write(fd_out, "\a", 1);
                    continue;
                }
            }
            else
            {
                // Middle of text
                if (insertmode)
                {
                    int i;
                    // Move everything one character to the right
                    if (l >= 4094) l--;
                    for (i = l; i >= cursor; i--)
                        cmd[i + 1] = cmd[i];
                    // Write what we've just added
                    cmd[cursor] = c;

                    cli_Write(fd_out, &cmd[cursor], l - cursor + 1);
                    for (i = 0; i < (l - cursor + 1); i++)
                        cli_Write(fd_out, "\b", 1);
                    l++;
                }
                else
                {
                    cmd[cursor] = c;
                }
                cursor++;
            }

            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
            {
                if (c == '?' && cursor == l)
                {
                    //cli_Write(fd_out, "\r\n", 2);
                    cli_Write(fd_out, "\n", 1);
                    oldcmd = cmd;
                    oldl = cursor = l - 1;
                    break;
                }
                cli_Write(fd_out, (char *)&c, 1);
            }

            oldcmd = 0;
            oldl = 0;
            lastchar = c;
        }

        if (l < 0) break;
        if (!strcasecmp(cmd, "quit")) break;

        if (cli->state == STATE_LOGIN)
        {
            if (l == 0) continue;

            /* require login */
            free_z(username);
            if (!(username = strdup(cmd)))
                return 0;
            cli->state = STATE_PASSWORD;
            cli->showprompt = 1;
        }
        else if (cli->state == STATE_PASSWORD)
        {
            /* require password */
            int allowed = 0;

            free_z(password);
            if (!(password = strdup(cmd)))
            {
                return 0;
            }

            if (cli->auth_callback)
            {

                if (cli->auth_callback(username, password) == CLI_OK)
                    allowed++;
            }

            if (!allowed)
            {
                struct unp *u;
                for (u = cli->users; u; u = u->next)
                {
                    if (!strcmp(u->username, username) && pass_matches(u->password, password))
                    {
                        allowed++;
                        break;
                    }
                }
            }

            if (allowed)
            {
                cli_error(cli, "");
                cli->state = STATE_NORMAL;
            }
            else
            {
                cli_error(cli, "\n\nAccess denied");
                free_z(username);
                free_z(password);
                cli->state = STATE_LOGIN;
            }

            cli->showprompt = 1;
        }
        else if (cli->state == STATE_ENABLE_PASSWORD)
        {
            int allowed = 0;
            if (cli->enable_password)
            {
                /* check stored static enable password */
                if (pass_matches(cli->enable_password, cmd))
                    allowed++;
            }

            if (!allowed && cli->enable_callback)
            {
                /* check callback */
                if (cli->enable_callback(cmd))
                    allowed++;
            }

            if (allowed)
            {
                cli->state = STATE_ENABLE;
                cli_set_privilege(cli, PRIVILEGE_PRIVILEGED);
            }
            else
            {
                cli_error(cli, "\n\nAccess denied");
                cli->state = STATE_NORMAL;
            }
        }
        else
        {
            if (l == 0) continue;
            if (cmd[l - 1] != '?' && strcasecmp(cmd, "history") != 0)
                cli_add_history(cli, cmd);

            if (cli_run_command(cli, cmd) == CLI_QUIT)
                break;
        }

        // Update the last_action time now as the last command run could take a
        // long time to return
        if (cli->idle_timeout)
            time(&cli->last_action);
    }

EXIT:
    //��������һ�£������˳������ʱ����쳣�������ӽ��̱�ɽ�ʬ���̣�
    //�������޷��յ��ź�
    memset(cmd, 0, 4096);

    cli_free_history(cli);
    free_z(username);
    free_z(password);
    //free_z(cmd);
    cli->iOutSocket = 0;
    fclose(cli->client);
    cli->client = 0;
    return CLI_OK;
}

#if 1
int cli_no_pty_proc(struct cli_def *cli, int argc, char *argv[])
{
    int i;
    int iArgvLen,iStrLen = 0;
    char aucCmd[1024]={0};

    //cli_build_shortest(cli, cli->commands);

    if(!cli)
    {
        return CLI_ERROR;
    }

    if(0 >= argc)
    {
        CLI_SYSLOG_ERROR("argc=%d \n",argc);
        return CLI_ERROR;
    }

    for (i = 0; i < argc; i++)
    {
        iArgvLen = strlen(argv[i]);
        iArgvLen += 1;
        //CLI_SYSLOG_ERROR("argc[%d]=%s \n",i,argv[i]);
    }

    if(sizeof(aucCmd) <= iArgvLen)
    {
        CLI_SYSLOG_ERROR("iArgvLen=%d aucCmd=%d\n",iArgvLen,(int)sizeof(aucCmd));
        return CLI_ERROR;
    }

    for (i = 0; i < argc; i++)
    {
        iStrLen += sprintf(&aucCmd[iStrLen],"%s ",argv[i]);
    }

    cli->state = STATE_LOGIN;

    cli_free_history(cli);

    if (!(cli->client = fdopen(STDOUT_FILENO, "w+")))
    {
        CLI_SYSLOG_ERROR("fdopen STDOUT_FILENO faild errno=%d\n",errno);
        return CLI_ERROR;
    }

    cli->iOutSocket = 0;

    //setbuf(cli->client, NULL);

    if (cli->banner)
        cli_error(cli, "%s", cli->banner);

    // Set the last action now so we don't time immediately
    if (cli->idle_timeout)
        time(&cli->last_action);

    /* start off in unprivileged mode */
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, NULL);

    /* no auth required? */
    if (!cli->users && !cli->auth_callback)
        cli->state = STATE_NORMAL;

    cli->showprompt = 0;

    if(CLI_OK != cli_run_command(cli, aucCmd))
    {
        fclose(cli->client);
        cli->client = 0;
        CLI_SYSLOG_ERROR("fd_out=%d command=%s \n",STDOUT_FILENO,aucCmd);
        return CLI_ERROR;
    }

    fclose(cli->client);
    cli->client = 0;
    return CLI_OK;
}


#else

int cli_no_pty_proc(struct cli_def *cli,int fd_out,char *command)
{
    unsigned char c;
    int n, l, oldl = 0, is_telnet_option = 0, skip = 0, esc = 0;
    int cursor = 0, insertmode = 1;
    char *cmd = NULL, *oldcmd = 0;
    char *username = NULL, *password = NULL;
    char *negotiate =
        "\xFF\xFB\x03"
        "\xFF\xFB\x01"
        "\xFF\xFD\x03"
        "\xFF\xFD\x01";

    cli_build_shortest(cli, cli->commands);
    cli->state = STATE_LOGIN;

    int fd_in = STDIN_FILENO;

    cli_free_history(cli);
    //cli_Write(sockfd, negotiate, strlen(negotiate));

    #if 0
    if ((cmd = malloc(4096)) == NULL)
        return CLI_ERROR;
    #else

    cmd = &g_acCmd[0];

    #endif


    cli->iOutSocket = fd_out;
    cli->client = fd_out;

    if (cli->banner)
        cli_error(cli, "%s", cli->banner);

    // Set the last action now so we don't time immediately
    if (cli->idle_timeout)
        time(&cli->last_action);

    /* start off in unprivileged mode */
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, NULL);

    /* no auth required? */
    if (!cli->users && !cli->auth_callback)
        cli->state = STATE_NORMAL;

    if (cli->checkalive_callback)
    {
        if(0 !=  cli->checkalive_callback(cli))
        {
            CLI_SYSLOG_ERROR("checkalive_callback failed");
            goto EXIT;
        }
    }

    cli->showprompt = 1;

    if(CLI_OK != cli_run_command(cli, command))
    {
        CLI_SYSLOG_ERROR("fd_out=%d command=%d \n",fd_out,command);
        return CLI_ERROR;
    }

    cli->showprompt = 0;

    while (1)
    {
        signed int in_history = 0;
        int lastchar = 0;
        struct timeval tm;

        cli->showprompt = 1;

        if (oldcmd)
        {
            l = cursor = oldl;
            oldcmd[l] = 0;
            cli->showprompt = 1;
            oldcmd = NULL;
            oldl = 0;
        }
        else
        {
            memset(cmd, 0, 4096);
            l = 0;
            cursor = 0;
        }

        memcpy(&tm, &cli->timeout_tm, sizeof(tm));

        while (1)
        {
            int sr;
            fd_set r;
            if (cli->showprompt)
            {
                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                {
                    //cli_Write(fd_out, "\r\n", 2);
                    //cli_Write(fd_out, "\n", 1);
                }

                switch (cli->state)
                {
                    case STATE_LOGIN:
                        cli_Write(fd_out, "Username: ", strlen("Username: "));
                        break;

                    case STATE_PASSWORD:
                        cli_Write(fd_out, "Password: ", strlen("Password: "));
                        break;

                    case STATE_NORMAL:
                    case STATE_ENABLE:
                        show_prompt(cli, fd_out);
                        cli_Write(fd_out, cmd, l);
                        if (cursor < l)
                        {
                            int n = l - cursor;
                            while (n--)
                                cli_Write(fd_out, "\b", 1);
                        }
                        break;

                    case STATE_ENABLE_PASSWORD:
                        cli_Write(fd_out, "Password: ", strlen("Password: "));
                        break;

                }

                cli->showprompt = 0;
            }

            FD_ZERO(&r);
            FD_SET(fd_in, &r);

            if ((sr = select(fd_in + 1, &r, NULL, NULL, &tm)) < 0)
            {
                /* select error */
                if (errno == EINTR)
                    continue;

                perror("select");
                l = -1;
                break;
            }

            if (sr == 0)
            {
                /* timeout every second */
                if (cli->regular_callback && cli->regular_callback(cli) != CLI_OK)
                    break;

                if (cli->idle_timeout)
                {
                    if (time(NULL) - cli->last_action >= cli->idle_timeout)
                    {
                        cli_print(cli, "Idle timeout");
                        strncpy(cmd, "quit", 4095);
                        break;
                    }
                }

                memcpy(&tm, &cli->timeout_tm, sizeof(tm));
                continue;
            }

            if ((n = read(fd_in, &c, 1)) < 0)
            {
                if (errno == EINTR)
                    continue;

                perror("read");
                l = -1;
                break;
            }

            if (cli->idle_timeout)
                time(&cli->last_action);

            if (n == 0)
            {
                l = -1;
                break;
            }

            //printf("c=%d(%c) \n",c,c);
            CLI_SYSLOG_INFO("c=%d(%c) \n",c,c)
            if (skip)
            {
                skip--;
                continue;
            }

            if (c == 255 && !is_telnet_option)
            {
                is_telnet_option++;
                continue;
            }

            if (is_telnet_option)
            {
                if (c >= 251 && c <= 254)
                {
                    is_telnet_option = c;
                    continue;
                }

                if (c != 255)
                {
                    is_telnet_option = 0;
                    continue;
                }

                is_telnet_option = 0;
            }

            /* handle ANSI arrows */
            if (esc)
            {
                if (esc == '[')
                {
                    /* remap to readline control codes */
                    switch (c)
                    {
                        case 'A': /* Up */
                            c = CTRL('P');
                            break;

                        case 'B': /* Down */
                            c = CTRL('N');
                            break;

                        case 'C': /* Right */
                            c = CTRL('F');
                            break;

                        case 'D': /* Left */
                            c = CTRL('B');
                            break;

                        default:
                            c = 0;
                    }

                    esc = 0;
                }
                else
                {
                    esc = (c == '[') ? c : 0;
                    continue;
                }
            }

            if (c == 0)
            {
                continue;
            }

            #if 0

            //�س���
            if (c == '\n') continue;

            if (c == '\r')
            {
                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                    cli_Write(fd_out, "\r\n", 2);
                break;
            }
            #else
            if (c == '\r') continue;

            if (c == '\n')
            {
                //���»س�������ַ�
                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                {
                    //cli_Write(fd_out, "\r\n", 2);
                    //cli_Write(fd_out, "\n", 1);
                }
                break;
            }
            #endif
            if (c == 27)
            {
                esc = 1;
                continue;
            }

            if (c == CTRL('C'))
            {
                cli_Write(fd_out, "\a", 1);
                continue;
            }

            /* back word, backspace/delete */
            if (c == CTRL('W') || c == CTRL('H') || c == 0x7f)
            {
                int back = 0;

                if (c == CTRL('W')) /* word */
                {
                    int nc = cursor;

                    if (l == 0 || cursor == 0)
                        continue;

                    while (nc && cmd[nc - 1] == ' ')
                    {
                        nc--;
                        back++;
                    }

                    while (nc && cmd[nc - 1] != ' ')
                    {
                        nc--;
                        back++;
                    }
                }
                else /* char */
                {
                    if (l == 0 || cursor == 0)
                    {
                        cli_Write(fd_out, "\a", 1);
                        continue;
                    }

                    back = 1;
                }

                if (back)
                {
                    while (back--)
                    {
                        if (l == cursor)
                        {
                            cmd[--cursor] = 0;
                            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                                cli_Write(fd_out, "\b \b", 3);
                        }
                        else
                        {
                            int i;
                            cursor--;
                            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            {
                                for (i = cursor; i <= l; i++) cmd[i] = cmd[i+1];
                                cli_Write(fd_out, "\b", 1);
                                cli_Write(fd_out, cmd + cursor, strlen(cmd + cursor));
                                cli_Write(fd_out, " ", 1);
                                for (i = 0; i <= (int)strlen(cmd + cursor); i++)
                                    cli_Write(fd_out, "\b", 1);
                            }
                        }
                        l--;
                    }

                    continue;
                }
            }

            /* redraw */
            if (c == CTRL('L'))
            {
                int i;
                int cursorback = l - cursor;

                if (cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    continue;

                //cli_Write(fd_out, "\r\n", 2);
                cli_Write(fd_out, "\n", 1);
                show_prompt(cli, fd_out);
                cli_Write(fd_out, cmd, l);

                for (i = 0; i < cursorback; i++)
                    cli_Write(fd_out, "\b", 1);

                continue;
            }

            /* clear line */
            if (c == CTRL('U'))
            {
                if (cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    memset(cmd, 0, l);
                else
                    cli_clear_line(fd_out, cmd, l, cursor);

                l = cursor = 0;
                continue;
            }

            /* kill to EOL */
            if (c == CTRL('K'))
            {
                if (cursor == l)
                    continue;

                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                {
                    int c;
                    for (c = cursor; c < l; c++)
                        cli_Write(fd_out, " ", 1);

                    for (c = cursor; c < l; c++)
                        cli_Write(fd_out, "\b", 1);
                }

                memset(cmd + cursor, 0, l - cursor);
                l = cursor;
                continue;
            }

            /* EOT */
            if (c == CTRL('D'))
            {
                if (cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    break;

                if (l)
                    continue;

                strcpy(cmd, "quit");
                l = cursor = strlen(cmd);
                cli_Write(fd_out, "quit\r\n", l + 2);
                break;
            }

            /* disable */
            if (c == CTRL('Z'))
            {
                if (cli->mode != MODE_EXEC)
                {
                    cli_clear_line(fd_out, cmd, l, cursor);
                    cli_set_configmode(cli, MODE_EXEC, NULL);
                    cli->showprompt = 1;
                }

                continue;
            }

            /* TAB completion */
            if (c == CTRL('I'))
            {
                char *completions[128];
                int num_completions = 0;

                if (cli->state == STATE_LOGIN || cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    continue;

                if (cursor != l) continue;

                num_completions = cli_get_completions(cli, cmd, completions, 128);
                if (num_completions == 0)
                {
                    cli_Write(fd_out, "\a", 1);
                }
                else if (num_completions == 1)
                {
                    // Single completion
                    for (; l > 0; l--, cursor--)
                    {
                        if (cmd[l-1] == ' ' || cmd[l-1] == '|')
                            break;
                        cli_Write(fd_out, "\b", 1);
                    }
                    strcpy((cmd + l), completions[0]);
                    l += strlen(completions[0]);
                    cmd[l++] = ' ';
                    cursor = l;
                    cli_Write(fd_out, completions[0], strlen(completions[0]));
                    cli_Write(fd_out, " ", 1);
                }
                else if (lastchar == CTRL('I'))
                {
                    // double tab
                    int i;
                    //cli_Write(fd_out, "\r\n", 2);
                    cli_Write(fd_out, "\n", 1);
                    for (i = 0; i < num_completions; i++)
                    {
                        cli_Write(fd_out, completions[i], strlen(completions[i]));
                        if (i % 4 == 3)
                            cli_Write(fd_out, "\n", 1);
                        else
                            cli_Write(fd_out, "     ", 1);
                    }
                    //if (i % 4 != 3) cli_Write(fd_out, "\r\n", 2);
                    if (i % 4 != 3) cli_Write(fd_out, "\n", 1);
                        cli->showprompt = 1;
                }
                else
                {
                    // More than one completion
                    lastchar = c;
                    cli_Write(fd_out, "\a", 1);
                }
                continue;
            }

            /* history */
            if (c == CTRL('P') || c == CTRL('N'))
            {
                int history_found = 0;

                if (cli->state == STATE_LOGIN || cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    continue;

                if (c == CTRL('P')) // Up
                {
                    in_history--;
                    if (in_history < 0)
                    {
                        for (in_history = MAX_HISTORY-1; in_history >= 0; in_history--)
                        {
                            if (cli->history[in_history])
                            {
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cli->history[in_history]) history_found = 1;
                    }
                }
                else // Down
                {
                    in_history++;
                    if (in_history >= MAX_HISTORY || !cli->history[in_history])
                    {
                        int i = 0;
                        for (i = 0; i < MAX_HISTORY; i++)
                        {
                            if (cli->history[i])
                            {
                                in_history = i;
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cli->history[in_history]) history_found = 1;
                    }
                }
                if (history_found && cli->history[in_history])
                {
                    // Show history item
                    cli_clear_line(fd_out, cmd, l, cursor);
                    memset(cmd, 0, 4096);
                    strncpy(cmd, cli->history[in_history], 4095);
                    l = cursor = strlen(cmd);
                    cli_Write(fd_out, cmd, l);
                }

                continue;
            }

            /* left/right cursor motion */
            if (c == CTRL('B') || c == CTRL('F'))
            {
                if (c == CTRL('B')) /* Left */
                {
                    if (cursor)
                    {
                        if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            cli_Write(fd_out, "\b", 1);

                        cursor--;
                    }
                }
                else /* Right */
                {
                    if (cursor < l)
                    {
                        if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            cli_Write(fd_out, &cmd[cursor], 1);

                        cursor++;
                    }
                }

                continue;
            }

            /* start of line */
            if (c == CTRL('A'))
            {
                if (cursor)
                {
                    if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                    {
                        //ȥ��������
                        //cli_Write(fd_out, "\r", 1);
                        show_prompt(cli, fd_out);
                    }

                    cursor = 0;
                }

                continue;
            }

            /* end of line */
            if (c == CTRL('E'))
            {
                if (cursor < l)
                {
                    if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                        cli_Write(fd_out, &cmd[cursor], l - cursor);

                    cursor = l;
                }

                continue;
            }

            /* normal character typed */
            if (cursor == l)
            {
                 /* append to end of line */
                cmd[cursor] = c;
                if (l < 4095)
                {
                    l++;
                    cursor++;
                }
                else
                {
                    cli_Write(fd_out, "\a", 1);
                    continue;
                }
            }
            else
            {
                // Middle of text
                if (insertmode)
                {
                    int i;
                    // Move everything one character to the right
                    if (l >= 4094) l--;
                    for (i = l; i >= cursor; i--)
                        cmd[i + 1] = cmd[i];
                    // Write what we've just added
                    cmd[cursor] = c;

                    cli_Write(fd_out, &cmd[cursor], l - cursor + 1);
                    for (i = 0; i < (l - cursor + 1); i++)
                        cli_Write(fd_out, "\b", 1);
                    l++;
                }
                else
                {
                    cmd[cursor] = c;
                }
                cursor++;
            }

            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
            {
                if (c == '?' && cursor == l)
                {
                    //cli_Write(fd_out, "\r\n", 2);
                    cli_Write(fd_out, "\n", 1);
                    oldcmd = cmd;
                    oldl = cursor = l - 1;
                    break;
                }
                cli_Write(fd_out, &c, 1);
            }

            oldcmd = 0;
            oldl = 0;
            lastchar = c;
        }

        if (l < 0) break;
        if (!strcasecmp(cmd, "quit")) break;

        if (cli->state == STATE_LOGIN)
        {
            if (l == 0) continue;

            /* require login */
            free_z(username);
            if (!(username = strdup(cmd)))
                return 0;
            cli->state = STATE_PASSWORD;
            cli->showprompt = 1;
        }
        else if (cli->state == STATE_PASSWORD)
        {
            /* require password */
            int allowed = 0;

            free_z(password);
            if (!(password = strdup(cmd)))
            {
                return 0;
            }

            if (cli->auth_callback)
            {

                if (cli->auth_callback(username, password) == CLI_OK)
                    allowed++;
            }

            if (!allowed)
            {
                struct unp *u;
                for (u = cli->users; u; u = u->next)
                {
                    if (!strcmp(u->username, username) && pass_matches(u->password, password))
                    {
                        allowed++;
                        break;
                    }
                }
            }

            if (allowed)
            {
                cli_error(cli, "");
                cli->state = STATE_NORMAL;
            }
            else
            {
                cli_error(cli, "\n\nAccess denied");
                free_z(username);
                free_z(password);
                cli->state = STATE_LOGIN;
            }

            cli->showprompt = 1;
        }
        else if (cli->state == STATE_ENABLE_PASSWORD)
        {
            int allowed = 0;
            if (cli->enable_password)
            {
                /* check stored static enable password */
                if (pass_matches(cli->enable_password, cmd))
                    allowed++;
            }

            if (!allowed && cli->enable_callback)
            {
                /* check callback */
                if (cli->enable_callback(cmd))
                    allowed++;
            }

            if (allowed)
            {
                cli->state = STATE_ENABLE;
                cli_set_privilege(cli, PRIVILEGE_PRIVILEGED);
            }
            else
            {
                cli_error(cli, "\n\nAccess denied");
                cli->state = STATE_NORMAL;
            }
        }
        else
        {
            if (l == 0) continue;
            if (cmd[l - 1] != '?' && strcasecmp(cmd, "history") != 0)
                cli_add_history(cli, cmd);

            if (cli_run_command(cli, cmd) == CLI_QUIT)
                break;
        }

        // Update the last_action time now as the last command run could take a
        // long time to return
        if (cli->idle_timeout)
            time(&cli->last_action);
    }

EXIT:
    //��������һ�£������˳������ʱ����쳣�������ӽ��̱�ɽ�ʬ���̣�
    //�������޷��յ��ź�
    memset(cmd, 0, 4096);

    cli_free_history(cli);
    free_z(username);
    free_z(password);
    //free_z(cmd);

    //fclose(cli->client);
    cli->client = 0;
    return CLI_OK;
}

#endif

int cli_file(struct cli_def *cli, FILE *fh, int privilege, int mode)
{
    int oldpriv = cli_set_privilege(cli, privilege);
    int oldmode = cli_set_configmode(cli, mode, NULL);
    char buf[4096];

    while (1)
    {
        char *p;
        char *cmd;
        char *end;

        if (fgets(buf, sizeof(buf), fh) == NULL)
            break; /* end of file */

        if ((p = strpbrk(buf, "#\r\n")))
            *p = 0;

        cmd = buf;
        while (isspace(*cmd))
            cmd++;

        if (!*cmd)
            continue;

        for (p = end = cmd; *p; p++)
            if (!isspace(*p))
                end = p;

        *++end = 0;
        if (strcasecmp(cmd, "quit") == 0)
            break;

        if (cli_run_command(cli, cmd) == CLI_QUIT)
            break;
    }

    cli_set_privilege(cli, oldpriv);
    cli_set_configmode(cli, oldmode, NULL /* didn't save desc */);

    return CLI_OK;
}

void _print(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, int print_mode, char *format, va_list ap)
{
    static char *buffer;
    static int size, len;
    char *p;
    int n;

    if (!cli) return; // sanity check

    buffer = cli->buffer;
    size = cli->buf_size;
    len = strlen(buffer);

    while ((n = vsnprintf(buffer+len, size-len, format, ap)) >= size-len)
    {
        if (!(buffer = realloc(buffer, size += 1024)))
            return;

        cli->buffer = buffer;
        cli->buf_size = size;
    }

    if (n < 0) // vaprintf failed
        return;

    p = buffer;
    do
    {
        char *next = strchr(p, '\n');
        struct cli_filter *f = (print_mode & PRINT_FILTERED) ? cli->filters : 0;
        int print = 1;

        if (next)
            *next++ = 0;
        else if (print_mode & PRINT_BUFFERED)
            break;

        while (print && f)
        {
            print = (f->filter(cli, p, f->data) == CLI_OK);
            f = f->next;
        }
        if (print)
        {
            if (cli->print_callback)
                cli->print_callback(cli, p);
            else if (cli->client)
                if((EN_CLI_LANGUAGE_CHS == cli->enCliLaguage)||
                   (EN_CLI_LANGUAGE_ENG == cli->enCliLaguage)||
                   (EN_CLI_LANGUAGE_CHT == cli->enCliLaguage))
                {
                    _cli_fprintf(pucFuncName,ulLine,cli, "%s\r\n", p);
                }
        }

        p = next;
    } while (p);

    if (p && *p)
    {
        if (p != buffer)
	    memmove(buffer, p, strlen(p));
    }
    else *buffer = 0;
}

void cli_bufprint(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, char *format, ...)
{
    va_list ap;

    if (!cli)
    {
        return ;
    }

    va_start(ap, format);
    _print(pucFuncName,ulLine,cli, PRINT_BUFFERED|PRINT_FILTERED, format, ap);
    va_end(ap);
}

void cli_vabufprint(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, char *format, va_list ap)
{
    _print(pucFuncName,ulLine,cli, PRINT_BUFFERED, format, ap);
}

void _cli_print(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, char *format, ...)
{
    va_list ap;

    if (!cli)
    {
        return ;
    }

    va_start(ap, format);
    _print(pucFuncName,ulLine,cli, PRINT_FILTERED, format, ap);
    va_end(ap);
}


void _cli_fprintf(const char * pucFuncName,_U32 ulLine,struct cli_def *cli,const _S8 *pFormat, ... )
{
    va_list args;
	int res,iStrLen;
	char sbuffer[CLI_LIB_PRINT_LEN];
	memset(sbuffer,0,sizeof(sbuffer));
	if (!cli)
    {
        return ;
    }
	va_start(args, pFormat);
	iStrLen = vsnprintf(sbuffer,((sizeof(char)*CLI_LIB_PRINT_LEN)), pFormat, args);
	va_end(args);

	if((0 > iStrLen)||(CLI_LIB_PRINT_LEN < iStrLen))
	{
        CLI_SYSLOG_ERROR_2("%s()<%d> string too long %d\n",pucFuncName,ulLine,iStrLen);
        return;
	}

	if(CLI_LIB_PRINT_LEN == iStrLen)
	{
        sbuffer[CLI_LIB_PRINT_LEN - 1]='\0';
	}

	if(G_YES == cli->iIsPtyCmd)
	{
        fprintf(cli->client, "%s", sbuffer);
	}
	else
	{
        res = _cli_Write(pucFuncName,ulLine,cli->iOutSocket, sbuffer, iStrLen);
        if(iStrLen != res)
        {
            CLI_SYSLOG_ERROR_2("%s()<%d> iRet=%d errno=%d iStrLen=%d ",pucFuncName,ulLine,res,errno,iStrLen);
        }
	}
}

#define cli_fprintf(CLI,FMT,ARGS...)    _cli_fprintf(__FUNCTION__,__LINE__,CLI,FMT,##ARGS)

void _cli_error(const char * pucFuncName,_U32 ulLine,struct cli_def *cli, char *format, ...)
{
    va_list ap;

    if (!cli)
    {
        return ;
    }
    va_start(ap, format);
    _print(pucFuncName,ulLine,cli, PRINT_PLAIN, format, ap);
    va_end(ap);
}


struct cli_match_filter_state
{
    int flags;
#define MATCH_REGEX                1
#define MATCH_INVERT                2
    union {
        char *string;
        regex_t re;
    } match;
};

int cli_match_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt)
{
    struct cli_match_filter_state *state;
    int rflags;
    int i;
    char *p;

    if (argc < 2)
    {
        if (cli->client)
            cli_fprintf(cli, "Match filter requires an argument\r\n");

        return CLI_ERROR;
    }

    filt->filter = cli_match_filter;
    filt->data = state = calloc(sizeof(struct cli_match_filter_state), 1);

    if (argv[0][0] == 'i' || // include/exclude
        (argv[0][0] == 'e' && argv[0][1] == 'x'))
    {
        if (argv[0][0] == 'e')
            state->flags = MATCH_INVERT;

        state->match.string = join_words(argc-1, argv+1);
        return CLI_OK;
    }


    state->flags = MATCH_REGEX;

    // grep/egrep
    rflags = REG_NOSUB;
    if (argv[0][0] == 'e') // egrep
        rflags |= REG_EXTENDED;

    i = 1;
    while (i < argc - 1 && argv[i][0] == '-' && argv[i][1])
    {
        int last = 0;
        p = &argv[i][1];

        if (strspn(p, "vie") != strlen(p))
            break;

        while (*p)
        {
            switch (*p++)
            {
                case 'v':
                    state->flags |= MATCH_INVERT;
                    break;

                case 'i':
                    rflags |= REG_ICASE;
                    break;

                case 'e':
                    last++;
                    break;
            }
        }

        i++;
        if (last)
            break;
    }

    p = join_words(argc-i, argv+i);
    if ((i = regcomp(&state->match.re, p, rflags)))
    {
        if (cli->client)
            cli_fprintf(cli, "Invalid pattern \"%s\"\r\n", p);

        free_z(p);
        return CLI_ERROR;
    }

    free_z(p);
    return CLI_OK;
}

int cli_match_filter(UNUSED(struct cli_def *cli), char *string, void *data)
{
    struct cli_match_filter_state *state = data;
    int r = CLI_ERROR;

    if (!string) // clean up
    {
        if (state->flags & MATCH_REGEX)
            regfree(&state->match.re);
        else
            free(state->match.string);

        free(state);
        return CLI_OK;
    }

    if (state->flags & MATCH_REGEX)
    {
        if (!regexec(&state->match.re, string, 0, NULL, 0))
            r = CLI_OK;
    }
    else
    {
        if (strstr(string, state->match.string))
            r = CLI_OK;
    }

    if (state->flags & MATCH_INVERT)
    {
        if (r == CLI_OK)
            r = CLI_ERROR;
        else
            r = CLI_OK;
    }

    return r;
}

struct cli_range_filter_state {
    int matched;
    char *from;
    char *to;
};

int cli_range_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt)
{
    struct cli_range_filter_state *state;
    char *from = 0;
    char *to = 0;

    if (!strncmp(argv[0], "bet", 3)) // between
    {
        if (argc < 3)
        {
            if (cli->client)
                cli_fprintf(cli, "Between filter requires 2 arguments\r\n");

            return CLI_ERROR;
        }

        if (!(from = strdup(argv[1])))
            return CLI_ERROR;
        to = join_words(argc-2, argv+2);
    }
    else // begin
    {
        if (argc < 2)
        {
            if (cli->client)
                cli_fprintf(cli, "Begin filter requires an argument\r\n");

            return CLI_ERROR;
        }

        from = join_words(argc-1, argv+1);
    }

    filt->filter = cli_range_filter;
    filt->data = state = calloc(sizeof(struct cli_range_filter_state), 1);

    state->from = from;
    state->to = to;

    return CLI_OK;
}

int cli_range_filter(UNUSED(struct cli_def *cli), char *string, void *data)
{
    struct cli_range_filter_state *state = data;
    int r = CLI_ERROR;

    if (!string) // clean up
    {
        free_z(state->from);
        free_z(state->to);
        free_z(state);
        return CLI_OK;
    }

    if (!state->matched)
    state->matched = !!strstr(string, state->from);

    if (state->matched)
    {
        r = CLI_OK;
        if (state->to && strstr(string, state->to))
            state->matched = 0;
    }

    return r;
}

int cli_count_filter_init(struct cli_def *cli, int argc, UNUSED(char **argv), struct cli_filter *filt)
{
    if (argc > 1)
    {
        if (cli->client)
            cli_fprintf(cli, "Count filter does not take arguments\r\n");

        return CLI_ERROR;
    }

    filt->filter = cli_count_filter;
    if (!(filt->data = calloc(sizeof(int), 1)))
        return CLI_ERROR;

    return CLI_OK;
}

int cli_count_filter(struct cli_def *cli, char *string, void *data)
{
    int *count = data;

    if (!string) // clean up
    {
        // print count
        if (cli->client)
            cli_fprintf(cli, "%d\r\n", *count);

        free(count);
        return CLI_OK;
    }

    while (isspace(*string))
        string++;

    if (*string)
        (*count)++;  // only count non-blank lines

    return CLI_ERROR; // no output
}

void cli_print_callback(struct cli_def *cli, void (*callback)(struct cli_def *, char *))
{
    cli->print_callback = callback;
}

void cli_set_idle_timeout(struct cli_def *cli, unsigned int seconds)
{
    if (seconds < 1) seconds = 0;
    cli->idle_timeout = seconds;
    time(&cli->last_action);
}


void pc(UNUSED(struct cli_def *cli), char *string)
{
    printf("%s\n", string);
}
int regular_callback(struct cli_def *cli)
{
    regular_count++;
    if (debug_regular)
    {
        cli_print(cli, "Regular callback - %u times so far", regular_count);
        cli_reprompt(cli);
    }
    return CLI_OK;
}
int check_auth(char *username, char *password)
{
    if (strcasecmp(username, "admin") != 0)
        return CLI_ERROR;
    if (strcasecmp(password, "admin") != 0)
        return CLI_ERROR;
    return CLI_OK;
}
int check_enable(char *password)
{
    return !strcasecmp(password, "admin");
}

struct termios stTermOld;

void set_input_mode(int fd)
{

    struct termios stTerm;
    tcgetattr(fd,&stTermOld);
    tcgetattr(fd,&stTerm);

    //SYSLOG_DEBUG("c_iflag=0x%x",stTerm.c_iflag);
    //SYSLOG_DEBUG("c_oflag=0x%x",stTerm.c_oflag);
    //SYSLOG_DEBUG("c_cflag=0x%x",stTerm.c_cflag);
    //SYSLOG_DEBUG("c_lflag=0x%x",stTerm.c_lflag);

    //����Ϊ�Ǽӹ�ģʽ
    stTerm.c_lflag &= ~(ICANON|ECHO|ISIG);
    //���ٶ�һ���ַ�
    stTerm.c_cc[VMIN]=1;
    stTerm.c_cc[VTIME]=0;
    if(!isatty(fd))
    {
        CLI_SYSLOG_ERROR("fd=%d is not a tty\n",fd);
        return;
    }
    tcsetattr(fd,TCSANOW,&stTerm);

}

void resume_input_mode(int fd)
{
    tcsetattr(fd,TCSANOW,&stTermOld);
}

void pro_exit(int signo)
{
    CLI_SYSLOG_ERROR(" signo=%d \n",signo);
	if (signo)
	{
		_exit(1);
	}
	else
	{
		exit(1);
	}
}

static void cli_ExceptionBacktarce(int signo)
{
	#define CALL_BACK_NUM_MAX 48
    void *array[CALL_BACK_NUM_MAX];
    int CallBackNum,i;
    char **strings;
    _S8   ascStr[4096];
    //_S8   *pscStr = &ascStr[0];

    memset(ascStr,0,sizeof(ascStr));
    CallBackNum = backtrace(array, CALL_BACK_NUM_MAX);
    strings = backtrace_symbols(array,CallBackNum);

    CLI_SYSLOG_ERROR("signo:%d \n",signo);
    if(NULL != strings)
    {

        for(i= 1; i < CallBackNum; i++)
        {
            CLI_SYSLOG_ERROR("Backtarce:%p %s \n",array[i],(char *)strings[i]);
        }

        free ((void*)strings);
    }
    strings=NULL;
    _exit(EXIT_FAILURE);
}

void init_signal(void)
{

    (void)signal(SIGSEGV, cli_ExceptionBacktarce);
    (void)signal(SIGILL, cli_ExceptionBacktarce);

    (void)signal(SIGPIPE, pro_exit);
    (void)signal(SIGINT, pro_exit);
    (void)signal(SIGQUIT, pro_exit);
    (void)signal(SIGILL, pro_exit);
    (void)signal(SIGTRAP, pro_exit);

    (void)signal(SIGABRT, pro_exit);
    (void)signal(SIGALRM, pro_exit);
    (void)signal(SIGSTOP, pro_exit);
    /* Revert to normal sigchld handling */
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
	{
		syslog(LOG_ERR, "set SIGCHLD  SIG_DFL\n");
	}
}

int cmd_config_int_exit(struct cli_def *cli, UNUSED(char *command),
    UNUSED(char *argv[]), UNUSED(int argc))
{
    cli_set_configmode(cli, MODE_CONFIG, NULL);
    return CLI_OK;
}


#endif

