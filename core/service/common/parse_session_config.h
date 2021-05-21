/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _PARSE_SESSION_CONFIG_H__
#define _PARSE_SESSION_CONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

#define PREDEF_SESSION_UP_SEID      0x0UL
#define PREDEF_SESSION_CP_SEID      0x0UL

int psc_parse_predefined_rules(session_content_create *sess, char *filename);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _PARSE_SESSION_CONFIG_H__ */


