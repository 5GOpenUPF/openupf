/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __SESSION_CHECK_H
#define __SESSION_CHECK_H

int session_check_equ(session_seid_pair *seid_pair);
int session_table_cmp(session_content_create *exp, struct session_t *act);

#endif /* __SESSION_CHECK_H */

