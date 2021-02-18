/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "avluintlib.h"

#define AVLU_MAX_HEIGHT 32

LOCAL void avluint_rebalance(AVLU_NODE ***ancestors, int count);

int avluint_insert(AVLU_TREE *pRoot, AVLU_NODE *pNewNode)
{

    AVLU_NODE **ppNode;
    AVLU_NODE **ancestor[AVLU_MAX_HEIGHT];
    int ancestorCount;
    uint32_t key;

    if ((pNewNode == NULL) || (pRoot == NULL))
        return (ERROR);

    key = pNewNode->key;
    ppNode = pRoot;
    ancestorCount = 0;

    while (ancestorCount < AVLU_MAX_HEIGHT) {
        AVLU_NODE *pNode;
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
    if (ancestorCount == AVLU_MAX_HEIGHT)
        return (ERROR);

    ((AVLU_NODE *)pNewNode)->left = NULL;
    ((AVLU_NODE *)pNewNode)->right = NULL;
    ((AVLU_NODE *)pNewNode)->height = 1;
    *ppNode = pNewNode;

    avluint_rebalance (ancestor, ancestorCount);
    return (OK);
}

AVLU_NODE *avluint_delete(AVLU_TREE *pRoot, uint32_t key)
{
    AVLU_NODE **ppNode;
    AVLU_NODE *pNode = NULL;
    AVLU_NODE **ancestor[AVLU_MAX_HEIGHT];
    int ancestorCount;
    AVLU_NODE *pDelete;

    ppNode = pRoot;
    ancestorCount = 0;

    while (ancestorCount < AVLU_MAX_HEIGHT) {
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

    if (ancestorCount == AVLU_MAX_HEIGHT)
        return (NULL);

    pDelete = pNode;

    if (pNode->left == NULL) {
        *ppNode = pNode->right;
        ancestorCount--;
    } else {
        AVLU_NODE **ppDelete;
        int     deleteAncestorCount;
        deleteAncestorCount = ancestorCount;
        ppDelete = ppNode;
        pDelete  = pNode;

        ppNode = &(pNode->left);

        while (ancestorCount < AVLU_MAX_HEIGHT) {
            pNode = *ppNode;
            if (pNode->right == NULL)
                break;
            ancestor[ancestorCount++] = ppNode;
            ppNode = &(pNode->right);
        }
        if (ancestorCount == AVLU_MAX_HEIGHT)
            return (NULL);

        *ppNode = pNode->left;
        pNode->left = pDelete->left;
        pNode->right = pDelete->right;
        pNode->height = pDelete->height;
        *ppDelete = pNode;

        ancestor[deleteAncestorCount] = &(pNode->left);
    }
    avluint_rebalance ((AVLU_NODE ***)ancestor, ancestorCount);
    return (pDelete);
}

AVLU_NODE *avluint_search(AVLU_TREE root, uint32_t key)
{
    AVLU_NODE *pNode;
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

AVLU_NODE *avluint_successorget(AVLU_TREE root, uint32_t key)
{
    AVLU_NODE *pNode;
    AVLU_NODE *pSuccessor;

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

AVLU_NODE *avluint_predecessorget(AVLU_TREE root, uint32_t key)
{
    AVLU_NODE *pNode;
    AVLU_NODE *pPred;
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

AVLU_NODE *avluint_minimumget(AVLU_TREE root)
{
    if (NULL == root)
        return (NULL);
    while (root->left != NULL) {
        root = root->left;
    }
    return (root);
}

AVLU_NODE *avluint_maximumget(AVLU_TREE root)
{
    if (NULL == root)
        return (NULL);
    while (root->right != NULL) {
        root = root->right;
    }
    return (root);
}

int avluint_treewalk(AVLU_TREE root, AVLU_CALLBACK preRtn,
                     void *preArg, AVLU_CALLBACK inRtn,
                     void *inArg, AVLU_CALLBACK postRtn,
                     void *postArg)
{
#ifndef AVLU_RECURSIVE_WALK

    AVLU_NODE *pNode;
    uint64_t nodeStack [2 * AVLU_MAX_HEIGHT];
    uint32_t ix = 0;

    if (NULL == root) {
            return (OK);
    }
    if ((preRtn != NULL) || (inRtn != NULL)) {
        pNode = root;
        while (ix < 2 * AVLU_MAX_HEIGHT) {

            while (pNode != NULL) {
                if (preRtn != NULL)
                    if (preRtn (pNode, preArg) == ERROR)
                        return (ERROR);
                nodeStack[ix++] = (uint64_t) pNode;
                if (ix == AVLU_MAX_HEIGHT)
                    return (ERROR);
                pNode = pNode->left;
            }

            if (ix == 0)
                break;
            else {
                AVLU_NODE * right;
                pNode = (AVLU_NODE *) nodeStack[--ix];
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
            pNode  = (AVLU_NODE *) (nodeStack[ix] & ~1UL);
            if ((nodeStack[ix] & 0x01) == 0) {
                nodeStack[ix++] = (uint64_t) pNode | 1;
                if ((ix + 2) >= 2 * AVLU_MAX_HEIGHT)
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
        if (avluint_treewalk (root->left, preRtn, preArg, inRtn, inArg,
        postRtn, postArg) == ERROR)
            return (ERROR);
    }
    if (inRtn != NULL)
        if (inRtn (root, inArg) == ERROR)
            return (ERROR);
    if (!(NULL == root->right)) {
        if (avluint_treewalk (root->right, preRtn, preArg, inRtn, inArg,
            postRtn, postArg) == ERROR)
            return (ERROR);
    }

    if (postRtn != NULL)
        if (postRtn (root, postArg) == ERROR)
            return (ERROR);
    return (OK);

#endif
}

LOCAL void avluint_rebalance(AVLU_NODE ***ancestors, int count)
{
    while (count > 0) {
        AVLU_NODE **ppNode;
        AVLU_NODE *pNode;
        AVLU_NODE *leftp;
        int        lefth;
        AVLU_NODE *rightp;
        int        righth;


        ppNode = ancestors[--count];
        pNode = *ppNode;
        leftp = pNode->left;
        lefth = (leftp != NULL) ? leftp->height : 0;
        rightp = pNode->right;
        righth = (rightp != NULL) ? rightp->height : 0;

        if (righth - lefth < -1) {
            AVLU_NODE *  leftleftp;
            AVLU_NODE *  leftrightp;
            int          leftrighth;

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
            AVLU_NODE *rightleftp;
            int         rightlefth;
            AVLU_NODE *rightrightp;

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
