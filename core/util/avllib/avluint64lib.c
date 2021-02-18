/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "avluint64lib.h"

#define AVLU64_MAX_HEIGHT 28

LOCAL void avluint64_rebalance(AVLU64_NODE ***ancestors, int count);

int avluint64_insert(AVLU64_TREE *pRoot, AVLU64_NODE *pNewNode)
{
    AVLU64_NODE **ppNode;
    AVLU64_NODE **ancestor[AVLU64_MAX_HEIGHT];
    int           ancestorCount;
    uint64_t      key;

    if ((pNewNode == NULL) || (pRoot == NULL))
        return (ERROR);

    key = pNewNode->key;
    ppNode = pRoot;
    ancestorCount = 0;

    while (ancestorCount < AVLU64_MAX_HEIGHT) {
        AVLU64_NODE * pNode;
        pNode = *ppNode;
        if (pNode == NULL)
           break;
        ancestor[ancestorCount++] = ppNode;

        if (key == pNode->key)
            return (ERROR);
        else if (key < pNode->key)
            ppNode = &(pNode->left);
        else
            ppNode = &(pNode->right);
    }

    if (ancestorCount == AVLU64_MAX_HEIGHT)
        return (ERROR);
    ((AVLU64_NODE *)pNewNode)->left = NULL;
    ((AVLU64_NODE *)pNewNode)->right = NULL;
    ((AVLU64_NODE *)pNewNode)->height = 1;

    *ppNode = pNewNode;

    avluint64_rebalance (ancestor, ancestorCount);

    return (OK);
}

AVLU64_NODE *avluint64_delete(AVLU64_TREE *pRoot, uint64_t key)
{
    AVLU64_NODE **ppNode;
    AVLU64_NODE *pNode = NULL;
    AVLU64_NODE **ancestor[AVLU64_MAX_HEIGHT];
    int           ancestorCount;
    AVLU64_NODE *pDelete;

    ppNode = pRoot;
    ancestorCount = 0;

    while (ancestorCount < AVLU64_MAX_HEIGHT) {
        pNode = *ppNode;
        if (pNode == NULL)
            return (NULL);

        ancestor[ancestorCount++] = ppNode;
        if (key == pNode->key)
            break;
        else if (key < pNode->key)
            ppNode = &(pNode->left);
        else
            ppNode = &(pNode->right);
    }
    if (ancestorCount == AVLU64_MAX_HEIGHT)
        return (NULL);
    pDelete = pNode;
    if (pNode->left == NULL) {
        *ppNode = pNode->right;
        ancestorCount--;
    } else {
        AVLU64_NODE ** ppDelete;
        int  deleteAncestorCount;
        deleteAncestorCount = ancestorCount;
        ppDelete = ppNode;
        pDelete  = pNode;
        ppNode = &(pNode->left);
        while (ancestorCount < AVLU64_MAX_HEIGHT) {
            pNode = *ppNode;
            if (pNode->right == NULL)
                break;
            ancestor[ancestorCount++] = ppNode;
            ppNode = &(pNode->right);
        }
        if (ancestorCount == AVLU64_MAX_HEIGHT)
            return (NULL);
        *ppNode = pNode->left;
        pNode->left = pDelete->left;
        pNode->right = pDelete->right;
        pNode->height = pDelete->height;
        *ppDelete = pNode;
        ancestor[deleteAncestorCount] = &(pNode->left);
    }
    avluint64_rebalance ((AVLU64_NODE ***)ancestor, ancestorCount);
    return (pDelete);
}

int avluint64_destroy(AVLU64_TREE root, AVLU64_FREE free_rtn)
{
    if (NULL == root) {
        return (OK);
    }

    /* walk left side */
    if (!(NULL == root->left)) {
        if (avluint64_destroy (root->left, free_rtn) == ERROR)
        return (ERROR);
    }

    /* walk right side */
    if (!(NULL == root->right)) {
        if (avluint64_destroy (root->right, free_rtn) == ERROR)
            return (ERROR);
    }

    /* call free routine */
    if (free_rtn != NULL)
        if (free_rtn (root) == ERROR)
            return (ERROR);

    return (OK);
}

AVLU64_NODE *avluint64_search(AVLU64_TREE root, uint64_t key)
{
    AVLU64_NODE *pNode;

    pNode = root;

    while (pNode != NULL) {
        if (key == pNode->key)
            return (pNode);
        else if (key < pNode->key)
            pNode = pNode->left;
        else
            pNode = pNode->right;
    }
    return (NULL);
}

AVLU64_NODE *avluint64_successorget(AVLU64_TREE root, uint64_t key)
{
    AVLU64_NODE *pNode;
    AVLU64_NODE *pSuccessor;

    pNode = root;
    pSuccessor = NULL;

    while (pNode != NULL) {
        if (key >= pNode->key)
            pNode = pNode->right;
        else {
            pSuccessor = pNode;
            pNode = pNode->left;
        }
    }

    return (pSuccessor);
}

AVLU64_NODE *avluint64_predecessorget(AVLU64_TREE root, uint64_t key)
{
    AVLU64_NODE *pNode;
    AVLU64_NODE *pPred;

    pNode = root;
    pPred = NULL;

    while (pNode != NULL) {
        if (key <= pNode->key)
            pNode = pNode->left;
        else {
            pPred = pNode;
            pNode = pNode->right;
        }
    }
    return (pPred);
}

AVLU64_NODE *avluint64_minimumget(AVLU64_TREE root)
{
    if (NULL == root)
        return (NULL);

    while (root->left != NULL) {
        root = root->left;
    }

    return (root);
}

AVLU64_NODE *avluint64_maximumget(AVLU64_TREE root)
{
    if (NULL == root)
        return (NULL);

    while (root->right != NULL) {
        root = root->right;
    }

    return (root);
}

int avluint64_treewalk(AVLU64_TREE  root, AVLU64_CALLBACK preRtn,
                       void *preArg, AVLU64_CALLBACK inRtn,
                       void *inArg, AVLU64_CALLBACK postRtn,
                       void *postArg)
{
#ifndef AVLU64_RECURSIVE_WALK

    AVLU64_NODE *pNode;
    uint64_t nodeStack [2 * AVLU64_MAX_HEIGHT];
    uint32_t ix = 0;

    if (NULL == root) {
        return (OK);
    }

    if ((preRtn != NULL) || (inRtn != NULL)) {
        pNode = root;

        while (ix < 2 * AVLU64_MAX_HEIGHT) {
            while (pNode != NULL) {
                if (preRtn != NULL)
                    if (preRtn (pNode, preArg) == ERROR)
                        return (ERROR);

            nodeStack[ix++] = (uint64_t) pNode;

            if (ix == AVLU64_MAX_HEIGHT)
                return (ERROR);
            pNode = pNode->left;
            }
            if (ix == 0)
                break;
            else {
                AVLU64_NODE * right;
                pNode = (AVLU64_NODE *) nodeStack[--ix];
                right = pNode->right;
                if (inRtn != NULL)
                    if (inRtn (pNode, inArg) == ERROR)
                        return (ERROR);
                pNode = right;
            }
        }
    }

    if (postRtn != NULL) {
        ix = 0;
        pNode = root;
        nodeStack[ix++] = (uint64_t) pNode;

        while (ix > 0) {
            ix--;
            pNode  = (AVLU64_NODE *) (nodeStack[ix] & -1UL);
            if ((nodeStack[ix] & 0x01) == 0) {
                nodeStack[ix++] = (uint64_t) pNode | 1;
                if ((ix + 2) >= 2 * AVLU64_MAX_HEIGHT)
				    return (ERROR);
                if (pNode->right != NULL)
                    nodeStack[ix++] = (uint64_t) pNode->right;
                if (pNode->left != NULL)
                    nodeStack[ix++] = (uint64_t) pNode->left;
            } else {
                if (postRtn (pNode, postArg) == ERROR)
                return (ERROR);
            }
        }
    }

    return (OK);

#else

    if (NULL == root) {
        return (OK);
    }

    if (preRtn != NULL)
        if (preRtn (root, preArg) == ERROR)
            return (ERROR);
    if (!(NULL == root->left)) {
        if (avluint64_treewalk (root->left, preRtn, preArg, inRtn, inArg,
            postRtn, postArg) == ERROR)
            return (ERROR);
    }

    if (inRtn != NULL)
        if (inRtn (root, inArg) == ERROR)
            return (ERROR);

    if (!(NULL == root->right)) {
        if (avluint64_treewalk (root->right, preRtn, preArg, inRtn, inArg,
            postRtn, postArg) == ERROR)
            return (ERROR);
    }
    if (postRtn != NULL)
        if (postRtn (root, postArg) == ERROR)
            return (ERROR);

    return (OK);

#endif
}

LOCAL void avluint64_rebalance(AVLU64_NODE ***ancestors, int count)
{
    while (count > 0) {
        AVLU64_NODE **ppNode;
        AVLU64_NODE *pNode;
        AVLU64_NODE *leftp;
        int          lefth;
        AVLU64_NODE *rightp;
        int          righth;

        ppNode = ancestors[--count];
        pNode = *ppNode;
        leftp = pNode->left;
        lefth = (leftp != NULL) ? leftp->height : 0;
        rightp = pNode->right;
        righth = (rightp != NULL) ? rightp->height : 0;

        if (righth - lefth < -1) {
            AVLU64_NODE * leftleftp;
            AVLU64_NODE * leftrightp;
            int           leftrighth;
            leftleftp = leftp->left;
            leftrightp = leftp->right;
            leftrighth = (leftrightp != NULL) ? leftrightp->height : 0;

            if ((leftleftp != NULL) && (leftleftp->height >= leftrighth)) {
                pNode->left = leftrightp;
                pNode->height = leftrighth + 1;
                leftp->right = pNode;
                leftp->height = leftrighth + 2;
                *ppNode = leftp;
            } else {
                leftp->right = leftrightp->left;
                leftp->height = leftrighth;
                pNode->left = leftrightp->right;
                pNode->height = leftrighth;
                leftrightp->left = leftp;
                leftrightp->right = pNode;
                leftrightp->height = leftrighth + 1;
                *ppNode = leftrightp;
            }
        } else if (righth - lefth > 1) {
            AVLU64_NODE * rightleftp;
            int    rightlefth;
            AVLU64_NODE * rightrightp;
            rightleftp = rightp->left;
            rightlefth = (rightleftp != NULL) ? rightleftp->height : 0;
            rightrightp = rightp->right;

            if ((rightrightp != NULL) && (rightrightp->height >= rightlefth)) {
                pNode->right = rightleftp;
                pNode->height = rightlefth + 1;
                rightp->left = pNode;
                rightp->height = rightlefth + 2;
                *ppNode = rightp;
            } else {
                pNode->right = rightleftp->left;
                pNode->height = rightlefth;
                rightp->left = rightleftp->right;
                rightp->height = rightlefth;
                rightleftp->left = pNode;
                rightleftp->right = rightp;
                rightleftp->height = rightlefth + 1;
                *ppNode = rightleftp;
            }
        } else {
            int height;
            height = ((righth > lefth) ? righth : lefth) + 1;
            if (pNode->height == height)
                break;
            pNode->height = height;
        }
    }
}
