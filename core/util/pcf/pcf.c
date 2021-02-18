/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

/*
  pcf:Parsing the configuration file
  Configuration file store format:
  [section1]
  #comment1
  #comment2
  #comment3
  #comment4
  key1=value1
  key2=value2
  ...
  [section2]
  #comment1
  #comment2
  #comment3
  #comment4
  key1=value1
  key2=value2
  ...
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "pcf.h"

/* strip ctrl and space char in string
* string "key1 =    value1" will convert to "key1=value1";
*/
static inline int pcf_string_strip(char *str)
{
    char buf[PCF_LINE_LEN] = {'\0'};
    unsigned int str_len;
    unsigned int i = 0;
    unsigned int j = 0;

    if ((!str) || (!strlen(str))) {
        return 0;
    }

    str_len = strlen(str);
    while (i < str_len) {
        if ((!iscntrl(str[i])) && (!isspace(str[i]))) {
            buf[j] = str[i];
            j++;
        }
        i++;
    }

    if (!j) {
        return 0;
    }

    memset(str, '\0', str_len);
    strncpy(str, buf, j);

    return j;
}

/* check key-value pair is valid or not,
 * key=value, if there is no any '=' or more than one '=' exist,
 * it's not a valid key-value pair.
 * if valid return key length, otherwise return 0.
 */
static inline int pcf_check_kv(char *str)
{
    int str_len;
    int i = 0;
    int num = 0;
    int pos = 0;

    if ((!str) || (!strlen(str))) {
        return 0;
    }

    str_len = strlen(str);
    while (i < str_len) {
        if (str[i] == '=') {
            ++num;
            pos = i;
        }
        ++i;
    }

    if ((!pos) || (pos == str_len - 1) || (num != 1)) {
        return 0;
    }
    return pos;
}

/* get specify env from system env */
char* pcf_get_env(const char *env)
{
    char *path;

    if (!env) {
        printf("%s(%d):input param is NULL.\n", __func__, __LINE__);
        return NULL;
    }

    path = getenv(env);
    if (!path) {
        printf("%s(%d):Can't find env with %s.\n", __func__, __LINE__, env);
        return NULL;
    }

    return path;
}

/* internal function, new section node, and store section name */
static inline struct pcf_section *pcf_new_section(char *section)
{
    int i = 0;
    int sect_len = strlen(section);
    struct pcf_section *sect = (struct pcf_section *)calloc(1, sizeof(*sect));

    if (!sect) {
        return NULL;
    }

    sect->section = (char *)calloc(1, sect_len - 1);
    if (!sect) {
        free(sect);
        return NULL;
    }

    sect_len -= 2;
    while (i < sect_len) {
        sect->section[i] = section[i+1];
        ++i;
    }
    sect->section[i] = '\0';
    sect->key_head = NULL;
    sect->key_num  = 0;

    return sect;
}

/* internal function, new key node, and store key-value pair */
static inline struct pcf_key *pcf_new_key(char *str, int key_len)
{
    int i = 0;
    int j = 0;
    int val_len = strlen(str) - key_len;
    struct pcf_key *key = (struct pcf_key *)calloc(1, sizeof(*key));
    if (!key) {
        return NULL;
    }

    key->pair.key = (char *)calloc(1, key_len + 1);
    if (!key->pair.key) {
        free(key);
        return NULL;
    }

    key->pair.val = (char *)calloc(1, val_len + 1);
    if (!key) {
        free(key);
        free(key->pair.key);
        return NULL;
    }

    i = 0;
    while (i < key_len) {
        key->pair.key[i] = str[i];
        ++i;
    }

    ++i;
    while (j < val_len) {
        key->pair.val[j] = str[i];
        ++i;
        ++j;
    }

    return key;
}

/* conf free, free the alloced memory */
int pcf_conf_free(struct pcf_file *file)
{
    struct pcf_section *section;
    struct pcf_key     *key;

    if (!file) {
        printf("%s(%d):input param is NULL.\n", __func__, __LINE__);
        return -1;
    }

    section = file->section_head;
    while (section != NULL) {
        key = section->key_head;
        while (key != NULL) {
            free(key->pair.key);
            free(key->pair.val);
            free(key);
            key->pair.key = NULL;
            key->pair.val = NULL;
            key = key->next;
        }
        key = NULL;

        free(section->section);
        free(section);
        section->section = NULL;
        section = section->next;
    }
    file->section_head = NULL;

    free(file);
    file = NULL;

    return 0;
}

/* pcf read conf file, and store in pcf file struct */
struct pcf_file *pcf_conf_read(const char *env)
{
    char *path;
    FILE *fp;
    struct pcf_file *file = NULL;
    char line[PCF_LINE_LEN] = {'\0'};

    if ((!env) || (!strlen(env))) {
        printf("%s(%d):input param is invalid.\n", __func__, __LINE__);
        return NULL;
    }

    /* get config path from env */
    path = pcf_get_env(env);
    if (!path) {
        return NULL;
    }

    /* open config file */
    fp = fopen(path, "r");
    if (!fp) {
        printf("%s(%d):open file %s failed.\n", __func__, __LINE__, path);
        return NULL;
    }

    /* alloc head node */
    file = (struct pcf_file *)calloc(1, sizeof(*file));
    if (!file) {
        printf("%s(%d):calloc failed.\n", __func__, __LINE__);
        return NULL;
    }
    file->section_num = 0;
    file->section_head = NULL;

    while (fgets(line, PCF_LINE_LEN, fp) != NULL)
    {
        int len;
        /* skip comment line, empty line */
        if (('#' == line[0]) || (';' == line[0])
            || ('\r' == line[0]) || ('\n' == line[0])) {
            continue;
        }

        /* if line only contains space, skip it */
        len = pcf_string_strip(line);
        if (!len) {
            continue;
        }

        /* section */
        if (('[' == line[0]) && (']' == line[len - 1])) {
            struct pcf_section *sect = pcf_new_section(line);
            if (!sect) {
                goto err;
            }

            if (NULL == file->section_head) {
                file->section_head = sect;
            }
            else {
                sect->next = file->section_head;
                file->section_head = sect;
            }
            file->section_num++;
        }
        else {
            /* check key-value pair line */
            struct pcf_section *sect = file->section_head;
            struct pcf_key     *key;
            int key_len = pcf_check_kv(line);
            if ((!key_len) || (!sect)) {
                continue;
            }

            key  = pcf_new_key(line, key_len);
            if (!key) {
                goto err;
            }

            if (NULL == sect->key_head) {
                sect->key_head = key;
            }
            else {
                key->next = sect->key_head;
                sect->key_head = key;
            }
            sect->key_num++;
        }
    }

    fclose(fp);

    if (!file->section_num) {
        printf("Can't read any section in %s.\n", path);
        printf("It's not a valid configure file.\n");
        free(file);
        file = NULL;
    }

    return file;

err:
    pcf_conf_free(file);
    return NULL;
}

/* pcf read conf file, and store in pcf file struct */
struct pcf_file *pcf_conf_read_from_path(const char *path_env,
    const char *filename)
{
    char file_path[512] = {0};
    char *path = NULL;
    FILE *fp = NULL;
    struct pcf_file *file = NULL;
    char line[PCF_LINE_LEN] = {'\0'};

    if ((!path_env) || (!strlen(path_env)) ||
        (!filename) || (!strlen(filename))) {
        printf("%s(%d):input param is invalid.\n", __func__, __LINE__);
        return NULL;
    }

    /* get config path from env */
    path = pcf_get_env(path_env);
    if (!path) {
        return NULL;
    }

    if ((strlen(path) + strlen(filename)) < sizeof(file_path)) {
        sprintf(file_path, "%s/%s", path, filename);
    } else {
        printf("variable \"file_name\" memory is not enough.\n");
        return NULL;
    }

    /* open config file */
    fp = fopen(file_path, "r");
    if (!fp) {
        printf("%s(%d):open file %s failed.\n", __func__, __LINE__, file_path);
        return NULL;
    }

    /* alloc head node */
    file = (struct pcf_file *)calloc(1, sizeof(*file));
    if (!file) {
        printf("%s(%d):calloc failed.\n", __func__, __LINE__);
        return NULL;
    }
    file->section_num = 0;
    file->section_head = NULL;

    while (fgets(line, PCF_LINE_LEN, fp) != NULL)
    {
        int len;
        /* skip comment line, empty line */
        if (('#' == line[0]) || (';' == line[0])
            || ('\r' == line[0]) || ('\n' == line[0])) {
            continue;
        }

        /* if line only contains space, skip it */
        len = pcf_string_strip(line);
        if (!len) {
            continue;
        }

        /* section */
        if (('[' == line[0]) && (']' == line[len - 1])) {
            struct pcf_section *sect = pcf_new_section(line);
            if (!sect) {
                goto err;
            }

            if (NULL == file->section_head) {
                file->section_head = sect;
            }
            else {
                sect->next = file->section_head;
                file->section_head = sect;
            }
            file->section_num++;
        }
        else {
            /* check key-value pair line */
            struct pcf_section *sect = file->section_head;
            struct pcf_key     *key;
            int key_len = pcf_check_kv(line);
            if ((!key_len) || (!sect)) {
                continue;
            }

            key  = pcf_new_key(line, key_len);
            if (!key) {
                goto err;
            }

            if (NULL == sect->key_head) {
                sect->key_head = key;
            }
            else {
                key->next = sect->key_head;
                sect->key_head = key;
            }
            sect->key_num++;
        }
    }

    fclose(fp);

    if (!file->section_num) {
        printf("Can't read any section in %s.\n", path);
        printf("It's not a valid configure file.\n");
        free(file);
        file = NULL;
    }

    return file;

err:
    pcf_conf_free(file);
    return NULL;
}

struct pcf_file *pcf_conf_read_from_given_path(const char *path,const char *filename)
{
    char file_path[512] = {0};
    FILE *fp = NULL;
    struct pcf_file *file = NULL;
    char line[PCF_LINE_LEN] = {'\0'};

    if ((!path) || (!strlen(path)) ||
        (!filename) || (!strlen(filename))) {
        printf("%s(%d):input param is invalid.\n", __func__, __LINE__);
        return NULL;
    }


    if ((strlen(path) + strlen(filename)) < sizeof(file_path)) {
        sprintf(file_path, "%s/%s", path, filename);
    } else {
        printf("variable \"file_name\" memory is not enough.\n");
        return NULL;
    }

    /* open config file */
    fp = fopen(file_path, "r");
    if (!fp) {
        printf("%s(%d):open file %s failed.\n", __func__, __LINE__, file_path);
        return NULL;
    }

    /* alloc head node */
    file = (struct pcf_file *)calloc(1, sizeof(*file));
    if (!file) {
        printf("%s(%d):calloc failed.\n", __func__, __LINE__);
        return NULL;
    }
    file->section_num = 0;
    file->section_head = NULL;

    while (fgets(line, PCF_LINE_LEN, fp) != NULL)
    {
        int len;
        /* skip comment line, empty line */
        if (('#' == line[0]) || (';' == line[0])
            || ('\r' == line[0]) || ('\n' == line[0])) {
            continue;
        }

        /* if line only contains space, skip it */
        len = pcf_string_strip(line);
        if (!len) {
            continue;
        }

        /* section */
        if (('[' == line[0]) && (']' == line[len - 1])) {
            struct pcf_section *sect = pcf_new_section(line);
            if (!sect) {
                goto err;
            }

            if (NULL == file->section_head) {
                file->section_head = sect;
            }
            else {
                sect->next = file->section_head;
                file->section_head = sect;
            }
            file->section_num++;
        }
        else {
            /* check key-value pair line */
            struct pcf_section *sect = file->section_head;
            struct pcf_key     *key;
            int key_len = pcf_check_kv(line);
            if ((!key_len) || (!sect)) {
                continue;
            }

            key  = pcf_new_key(line, key_len);
            if (!key) {
                goto err;
            }

            if (NULL == sect->key_head) {
                sect->key_head = key;
            }
            else {
                key->next = sect->key_head;
                sect->key_head = key;
            }
            sect->key_num++;
        }
    }

    fclose(fp);

    if (!file->section_num) {
        printf("Can't read any section in %s.\n", path);
        printf("It's not a valid configure file.\n");
        free(file);
        file = NULL;
    }

    return file;

err:
    pcf_conf_free(file);
    return NULL;
}

/* get section struct by section name */
struct pcf_section *pcf_get_section(struct pcf_file *file,
                                  const char *sname)
{
    struct pcf_section *section = NULL;

    if ((!file) || (!sname)) {
        printf("%s(%d):input param is NULL.\n", __func__, __LINE__);
        return NULL;
    }

    section = file->section_head;
    while (section != NULL) {
        if ((strlen(section->section) == strlen(sname)) &&
            (!strncmp(sname, section->section, strlen(sname)))) {
            return section;
        }
        section = section->next;
    }
    return NULL;
}

/* get value string by section name and key name */
char *pcf_get_key_value(struct pcf_file *file,
                              const char *sname, const char *kname)
{
    struct pcf_section *section;
    struct pcf_key     *key;

    if ((!file) || (!sname) || (!kname)) {
        printf("%s(%d):input param is NULL.\n", __func__, __LINE__);
        return NULL;
    }

    section = file->section_head;
    while (section != NULL) {
        if (strlen(section->section) == strlen(sname) &&
            (!strncmp(sname, section->section, strlen(sname)))) {
            key = section->key_head;
            while (key != NULL) {
                if (strlen(key->pair.key) == strlen(kname) &&
                    (!strncmp(kname, key->pair.key, strlen(kname)))) {
                    return key->pair.val;
                }
                key = key->next;
            }
        }
        section = section->next;
    }

    return NULL;
}

/* dump specify section content */
void pcf_dump_section(struct pcf_file *file, const char *sname)
{
    struct pcf_section *sect;
    struct pcf_key     *key;

    if ((!file) || (!sname)) {
        printf("%s(%d):input param is NULL.\n", __func__, __LINE__);
        return;
    }

    sect = file->section_head;
    while (sect != NULL) {
        if (!strcmp(sname, sect->section)) {
            printf("seciton:%s, key_num:%d\n", sect->section, sect->key_num);
            key = sect->key_head;
            while (key != NULL) {
                printf("key:%s value:%s\n", key->pair.key, key->pair.val);
                key = key->next;
            }
        }
        sect = sect->next;
        printf("\n");
    }
}

/* dump all section content */
void pcf_dump_all(struct pcf_file *file)
{
    struct pcf_section *sect;
    struct pcf_key     *key;
    if (!file) {
        printf("%s(%d):input param is NULL.\n", __func__, __LINE__);
        return;
    }

    printf("section num:%d.\n", file->section_num);
    sect = file->section_head;
    while (sect != NULL) {
        printf("seciton:%s, key_num:%d\n", sect->section, sect->key_num);
        key = sect->key_head;
        while (key != NULL) {
            printf("key:%s value:%s\n", key->pair.key, key->pair.val);
            key = key->next;
        }
        sect = sect->next;
        printf("\n");
    }
}

