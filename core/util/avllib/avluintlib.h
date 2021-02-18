/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __AVL_UINT_LIB_H__
#define __AVL_UINT_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct avlu_node {
    struct avlu_node *left;
    struct avlu_node *right;
    int height;
    uint32_t key;
} AVLU_NODE;

typedef AVLU_NODE *AVLU_TREE;

typedef int (*AVLU_CALLBACK)(AVLU_NODE *pNode, void *pArg);

int avluint_insert(AVLU_TREE *pRoot, AVLU_NODE *pNode);
AVLU_NODE *avluint_delete(AVLU_TREE *pRoot, uint32_t key);
AVLU_NODE *avluint_search(AVLU_TREE root, uint32_t key);
AVLU_NODE *avluint_successorget(AVLU_TREE root, uint32_t key);
AVLU_NODE *avluint_predecessorget(AVLU_TREE root, uint32_t key);
AVLU_NODE *avluint_minimumget(AVLU_TREE root);
AVLU_NODE *avluint_maximumget(AVLU_TREE root);
int avluint_treewalk (AVLU_TREE pRoot, AVLU_CALLBACK preRtn,
                           void *preArg, AVLU_CALLBACK inRtn, void *inArg,
                           AVLU_CALLBACK postRtn, void *postArg);

#ifdef __cplusplus
}
#endif

#endif
