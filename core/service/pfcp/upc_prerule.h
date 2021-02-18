/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _UPC_BUILD_BLOCK_H__
#define _UPC_BUILD_BLOCK_H__

#ifdef __cplusplus
extern "C" {
#endif


#define MAX_TEST_FILENAME_LEN       256
#define PREDEFINE_RULE_PATH       "./config/predefined"


int upc_parse_session_content(session_content_create *sess, struct pcf_file *conf);


#ifdef __cplusplus
}
#endif

#endif

