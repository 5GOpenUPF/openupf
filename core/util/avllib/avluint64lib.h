/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __AVL_UINT64_LIB_H__
#define __AVL_UINT64_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct avluint64_node {
    struct avluint64_node *left;
    struct avluint64_node *right;
    uint64_t key;
    int    height;
} AVLU64_NODE;

typedef AVLU64_NODE *AVLU64_TREE;

typedef int (*AVLU64_CALLBACK)(AVLU64_NODE *pNode, void *pArg);

typedef int (*AVLU64_FREE)(AVLU64_NODE *pNode);

int avluint64_insert(AVLU64_TREE *pRoot, AVLU64_NODE * pNode);
AVLU64_NODE *avluint64_delete(AVLU64_TREE *pRoot, uint64_t key);
AVLU64_NODE *avluint64_search(AVLU64_TREE root, uint64_t key);
AVLU64_NODE *avluint64_successorget(AVLU64_TREE root, uint64_t key);
AVLU64_NODE *avluint64_predecessorget(AVLU64_TREE root, uint64_t key);
AVLU64_NODE *avluint64_minimumget(AVLU64_TREE root);
AVLU64_NODE *avluint64_maximumget(AVLU64_TREE root);
int avluint64_destroy(AVLU64_TREE root, AVLU64_FREE free_rtn);
int avluint64_treewalk(AVLU64_TREE pRoot,
                        AVLU64_CALLBACK preRtn, void *preArg,
                        AVLU64_CALLBACK inRtn, void *inArg,
                        AVLU64_CALLBACK postRtn, void *postArg);

#ifdef __cplusplus
}
#endif

#endif
