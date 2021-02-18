/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __PCF_H
#define __PCF_H

#define PCF_LINE_LEN (256)
#define PCF_STR_LEN (128)

struct kv_pair {
    char              *key;
    char              *val;
};

/* pcf key struct, store key and value */
struct pcf_key {
    struct kv_pair    pair;
    struct pcf_key   *next;
};

/* pcf section struct, store section */
struct pcf_section {
    int                   key_num;
    char                 *section;
    struct pcf_key      *key_head;
    struct pcf_section  *next;
};

/* pcf file struct */
struct pcf_file {
    int                   section_num;
    struct pcf_section  *section_head;
};

/* split string to multi single string by separator
 * str: origin string
 * sep: separator char, such as ':', '=', '|' and so on
 * out: splited string store buff, max single string must be PCF_STR_LEN -1.
 * num: the expect number of single string
 * if success, return the split num.
 * else
 * -1 for no valid string between "|"
 * -2 for too many elements
 * -3 for too long element
 */
static inline int
pcf_str_split(char *str, char sep, char out[][PCF_STR_LEN], int num)
{
    int i = 0;
    int j = 0;
    int cnt = 0;
    int len = strlen(str);
    int size = sizeof(out[0]);

    if ((!str)||(len <= 0)||(!out)) {
        return -1;
    }

    while (i < len) {
        if (sep == str[i]) {
            if (!j) {
                return -1;
            }
            out[cnt][j] = '\0';
            j = 0;
            ++cnt;
            if (cnt > num) {
                return -2;
            }
        }
        else {
            if (j < size - 1) {
                out[cnt][j] = str[i];
                j++;
            }
            else {
                return -3;
            }
        }
        i++;
    }
    out[cnt][j] = '\0';
    cnt++;
    if (cnt > num) {
        return -2;
    }
    return cnt;
}

char* pcf_get_env(const char *env);
int pcf_conf_free(struct pcf_file *file);
struct pcf_file *pcf_conf_read(const char *env);
struct pcf_file *pcf_conf_read_from_path(const char *path_env,
    const char *filename);
struct pcf_file *pcf_conf_read_from_given_path(const char *path,
	const char *filename);
struct pcf_section *pcf_get_section(struct pcf_file *file,
                                  const char *sname);
char *pcf_get_key_value(struct pcf_file *file,
                              const char *sname, const char *kname);
void pcf_dump_section(struct pcf_file *file, const char *sname);
void pcf_dump_all(struct pcf_file *file);


#endif
