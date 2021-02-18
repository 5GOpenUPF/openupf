/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _PFD_MGMT_H__
#define _PFD_MGMT_H__

#ifdef __cplusplus
extern "C" {
#endif

#define PFD_RULE_PATH       "./config/pfrule"

typedef enum tag_EN_PFD_MATCH_ATTRIBUTE {
    EN_PFD_MATCH_FAIL   = 0,
    EN_PFD_MATCH_FD     = 1,
    EN_PFD_MATCH_URL    = 2,
    EN_PFD_MATCH_DNP    = 4,
    EN_PFD_MATCH_CP     = 8,
    EN_PFD_MATCH_ALL    = 16,
} EN_PFD_MATCH_ATTRIBUTE;

typedef struct tag_pfd_entry {
    struct rb_node                  node;
    ros_rwlock_t                    lock;
    uint32_t                        index;
    session_application_ids_pfds    pfd;
} pfd_entry;

typedef struct tag_pfd_table_header {
    pfd_entry                   *entry;
    struct rb_root              pfd_root;  /* All valid seid */
    uint32_t                    max_num;
    ros_rwlock_t                lock;
    uint16_t                    pool_id;
} pfd_table_header;

pfd_table_header *pfd_get_table_header_public(void);
pfd_entry *pfd_get_entry_public(uint32_t index);

int64_t pfd_table_init(uint32_t pfd_num);
int pfd_entry_insert(session_application_ids_pfds *pfd);
int pfd_entry_remove(char *application_id);
void pfd_table_clean_all(void);

int pfd_match_process(struct filter_key *key, uint8_t *field_offset,
    char *app_id, int *url_depth);


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _PFD_MGMT_H__ */



