/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __AVL_LIB_H__
#define __AVL_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

/* typedefs */

typedef struct avl_node {
    struct avl_node *  left;    /* pointer to the left subtree */
    struct avl_node *  right;    /* pointer to the right subtree */
    int    height;         /* height of the subtree rooted at this node */
} AVL_NODE;

typedef AVL_NODE * AVL_TREE;    /* points to the root node of the tree */

typedef int (*AVL_COMPARE)(AVL_NODE *pNode, void * pKey);

/* callback routines for avluint_treewalk */

typedef int (*AVL_CALLBACK)(AVL_NODE *pNode, void * pArg);

typedef int (*AVL_FREE)(AVL_NODE *pNode);

/* function declarations */

int     avl_insert (AVL_TREE * pRoot, AVL_NODE * pNode, void * pKey, AVL_COMPARE cmpRtn);
int     avl_destroy(AVL_TREE root, AVL_FREE free_rtn);
AVL_NODE * avl_delete (AVL_TREE * pRoot, void * pKey, AVL_COMPARE cmpRtn);
AVL_NODE * avl_search (AVL_TREE root, void * pKey, AVL_COMPARE cmpRtn);
AVL_NODE * avl_successor_get (AVL_TREE root, void * pKey, AVL_COMPARE cmpRtn);
AVL_NODE * avl_predecessor_get (AVL_TREE root, void * pKey, AVL_COMPARE cmpRtn);
AVL_NODE * avl_minimum_get (AVL_TREE root);
AVL_NODE * avl_maximum_get (AVL_TREE root);
int     avl_tree_walk (AVL_TREE pRoot, AVL_CALLBACK preRtn, void * preArg,
                       AVL_CALLBACK inRtn, void * inArg, AVL_CALLBACK postRtn, void * postArg);
int     avl_insert_inform (AVL_TREE * pRoot, void * pNewNode, void * key,
                           void ** ppKeyHolder, AVL_COMPARE cmpRtn);
void *  avl_remove_insert (AVL_TREE * pRoot, void * pNewNode, void * key, AVL_COMPARE cmpRtn);

#ifdef __cplusplus
}
#endif

#endif /* __AVL_LIB_H__ */

