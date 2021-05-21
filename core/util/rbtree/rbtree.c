/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "rbtree.h"


/* 数据结构8字节对齐后尾部的空闲比特可以用来存放color */
#define RB_GET_PARENT(r)    ((struct rb_node *)((r)->parent_and_color & ~3))
#define RB_GET_COLOR(r)     ((r)->parent_and_color & RB_COLOR_MASK)
#define RB_IS_RED(r)        (!RB_GET_COLOR(r))
#define RB_IS_BLACK(r)      (RB_GET_COLOR(r))
#define RB_SET2RED(r)       do { (r)->parent_and_color &= ~RB_COLOR_MASK; } while (0)
#define RB_SET2BLACK(r)     do { (r)->parent_and_color |= RB_COLOR_MASK; } while (0)


static inline void rbtree_set_parent(struct rb_node *rb, struct rb_node *p)
{
	rb->parent_and_color = (rb->parent_and_color & 3) | (unsigned long)p;
}

static inline void rbtree_set_color(struct rb_node *rb, int color)
{
	rb->parent_and_color = (rb->parent_and_color & ~RB_COLOR_MASK) | color;
}

static void rbtree_rotate_left(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *right = node->right_node;
    struct rb_node *parent = RB_GET_PARENT(node);

    if ((node->right_node = right->left_node))
        rbtree_set_parent(right->left_node, node);
    right->left_node = node;

    rbtree_set_parent(right, parent);

    if (parent)
    {
        if (node == parent->left_node)
            parent->left_node = right;
        else
            parent->right_node = right;
    }
    else
        root->rb_node = right;
    rbtree_set_parent(node, right);
}

static void rbtree_rotate_right(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *left = node->left_node;
    struct rb_node *parent = RB_GET_PARENT(node);

    if ((node->left_node = left->right_node))
        rbtree_set_parent(left->right_node, node);
    left->right_node = node;

    rbtree_set_parent(left, parent);

    if (parent) {
        if (node == parent->right_node)
            parent->right_node = left;
        else
            parent->left_node = left;
    } else {
        root->rb_node = left;
    }

    rbtree_set_parent(node, left);
}

static void __rbtree_insert(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *parent, *gparent;

    while ((parent = RB_GET_PARENT(node)) && RB_IS_RED(parent))
    {
        gparent = RB_GET_PARENT(parent);

        if (parent == gparent->left_node)
        {
            {
                register struct rb_node *uncle = gparent->right_node;
                if (uncle && RB_IS_RED(uncle))
                {
                    RB_SET2BLACK(uncle);
                    RB_SET2BLACK(parent);
                    RB_SET2RED(gparent);
                    node = gparent;
                    continue;
                }
            }

            if (parent->right_node == node)
            {
                register struct rb_node *tmp;
                rbtree_rotate_left(parent, root);
                tmp = parent;
                parent = node;
                node = tmp;
            }

            RB_SET2BLACK(parent);
            RB_SET2RED(gparent);
            rbtree_rotate_right(gparent, root);
        } else {
            {
                register struct rb_node *uncle = gparent->left_node;
                if (uncle && RB_IS_RED(uncle))
                {
                    RB_SET2BLACK(uncle);
                    RB_SET2BLACK(parent);
                    RB_SET2RED(gparent);
                    node = gparent;
                    continue;
                }
            }

            if (parent->left_node == node)
            {
                register struct rb_node *tmp;
                rbtree_rotate_right(parent, root);
                tmp = parent;
                parent = node;
                node = tmp;
            }

            RB_SET2BLACK(parent);
            RB_SET2RED(gparent);
            rbtree_rotate_left(gparent, root);
        }
    }

    RB_SET2BLACK(root->rb_node);
}

static void __rbtree_erase(struct rb_node *node, struct rb_node *parent,
                 struct rb_root *root)
{
    struct rb_node *other;

    while ((!node || RB_IS_BLACK(node)) && node != root->rb_node)
    {
        if (parent->left_node == node)
        {
            other = parent->right_node;
            if (RB_IS_RED(other))
            {
                RB_SET2BLACK(other);
                RB_SET2RED(parent);
                rbtree_rotate_left(parent, root);
                other = parent->right_node;
            }
            if ((!other->left_node || RB_IS_BLACK(other->left_node)) &&
                (!other->right_node || RB_IS_BLACK(other->right_node)))
            {
                RB_SET2RED(other);
                node = parent;
                parent = RB_GET_PARENT(node);
            }
            else
            {
                if (!other->right_node || RB_IS_BLACK(other->right_node))
                {
                    RB_SET2BLACK(other->left_node);
                    RB_SET2RED(other);
                    rbtree_rotate_right(other, root);
                    other = parent->right_node;
                }
                rbtree_set_color(other, RB_GET_COLOR(parent));
                RB_SET2BLACK(parent);
                RB_SET2BLACK(other->right_node);
                rbtree_rotate_left(parent, root);
                node = root->rb_node;
                break;
            }
        }
        else
        {
            other = parent->left_node;
            if (RB_IS_RED(other))
            {
                RB_SET2BLACK(other);
                RB_SET2RED(parent);
                rbtree_rotate_right(parent, root);
                other = parent->left_node;
            }
            if ((!other->left_node || RB_IS_BLACK(other->left_node)) &&
                (!other->right_node || RB_IS_BLACK(other->right_node)))
            {
                RB_SET2RED(other);
                node = parent;
                parent = RB_GET_PARENT(node);
            }
            else
            {
                if (!other->left_node || RB_IS_BLACK(other->left_node))
                {
                    RB_SET2BLACK(other->right_node);
                    RB_SET2RED(other);
                    rbtree_rotate_left(other, root);
                    other = parent->left_node;
                }
                rbtree_set_color(other, RB_GET_COLOR(parent));
                RB_SET2BLACK(parent);
                RB_SET2BLACK(other->left_node);
                rbtree_rotate_right(parent, root);
                node = root->rb_node;
                break;
            }
        }
    }
    if (node)
        RB_SET2BLACK(node);
}

void rbtree_erase(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *child, *parent;
    int color;

    if (!node->left_node)
        child = node->right_node;
    else if (!node->right_node)
        child = node->left_node;
    else
    {
        struct rb_node *old = node, *left;

        node = node->right_node;
        while ((left = node->left_node) != NULL)
            node = left;

        if (RB_GET_PARENT(old)) {
            if (RB_GET_PARENT(old)->left_node == old)
                RB_GET_PARENT(old)->left_node = node;
            else
                RB_GET_PARENT(old)->right_node = node;
        } else
            root->rb_node = node;

        child = node->right_node;
        parent = RB_GET_PARENT(node);
        color = RB_GET_COLOR(node);

        if (parent == old) {
            parent = node;
        } else {
            if (child)
                rbtree_set_parent(child, parent);
            parent->left_node = child;

            node->right_node = old->right_node;
            rbtree_set_parent(old->right_node, node);
        }

        node->parent_and_color = old->parent_and_color;
        node->left_node = old->left_node;
        rbtree_set_parent(old->left_node, node);

        if (color == RB_BLACK)
            __rbtree_erase(child, parent, root);
        return;
    }

    parent = RB_GET_PARENT(node);
    color = RB_GET_COLOR(node);

    if (child)
        rbtree_set_parent(child, parent);
    if (parent) {
        if (parent->left_node == node)
            parent->left_node = child;
        else
            parent->right_node = child;
    } else {
        root->rb_node = child;
    }

    if (color == RB_BLACK)
        __rbtree_erase(child, parent, root);
}

struct rb_node *rbtree_first(const struct rb_root *root)
{
    struct rb_node  *next;

    next = root->rb_node;
    if (!next)
        return NULL;
    while (next->left_node)
        next = next->left_node;
    return next;
}

struct rb_node *rbtree_next(const struct rb_node *node)
{
    struct rb_node *parent;

    if (RB_GET_PARENT(node) == node)
        return NULL;

    if (node->right_node) {
        node = node->right_node;
        while (node->left_node)
            node=node->left_node;
        return (struct rb_node *)node;
    }

    while ((parent = RB_GET_PARENT(node)) && node == parent->right_node) {
        node = parent;
    }

    return parent;
}

int rbtree_insert(struct rb_root *root, struct rb_node *node,
                             void *key, RBTREE_COMPARE compare)
{
    struct rb_node **new;
    struct rb_node *parent = NULL;
    if ((NULL == root) || (NULL == node)) {
        return -1;
    }

    new = &(root->rb_node);

    /* Figure out where to put new node */
    while (*new)
    {
        struct rb_node *cur_node;    /* pointer to the current node */
        int              delta;       /* result of the comparison operation */

        cur_node = *new;
        parent   = *new;
        delta = compare(cur_node, key);
        if (delta < 0)
            new = &((*new)->left_node);
        else if (delta > 0)
            new = &((*new)->right_node);
        else
            return -1;
    }

    node->parent_and_color = (unsigned long )parent;
	node->left_node = node->right_node = NULL;
	*new = node;

    __rbtree_insert(node, root);

    return 0;
}

struct rb_node *rbtree_search(struct rb_root *root, void *key, RBTREE_COMPARE compare)
{
    struct rb_node *node;
    if (NULL == root) {
        return NULL;
    }

    node = root->rb_node;
    while (node != NULL) {
        int delta;       /* result of the comparison operation */

        delta = compare(node, key);
        if (delta < 0)
            node = node->left_node;
        else if (delta > 0)
            node = node->right_node;
        else
            return node;
    }

    return NULL;
}

struct rb_node *rbtree_delete(struct rb_root *root, void *key, RBTREE_COMPARE compare)
{
    struct rb_node *node;

    if (NULL == root) {
        return NULL;
    }

    node = root->rb_node;
    while (node != NULL) {
        int delta;       /* result of the comparison operation */

        delta = compare(node, key);
        if (delta < 0) {
            node = node->left_node;
        }
        else if (delta > 0) {
            node = node->right_node;
        }
        else {
            break;
        }
    }

    if (node != NULL) {
        rbtree_erase(node, root);
        return node;
    }

    return node;
}

void rbtree_replace_node(struct rb_node *victim, struct rb_node *new, struct rb_root *root)
{
    struct rb_node *parent = RB_GET_PARENT(victim);

    /* Set the surrounding nodes to point to the replacement */
    if (parent) {
        if (victim == parent->left_node)
            parent->left_node = new;
        else
            parent->right_node = new;
    } else {
        root->rb_node = new;
    }
    if (victim->left_node)
        rbtree_set_parent(victim->left_node, new);
    if (victim->right_node)
        rbtree_set_parent(victim->right_node, new);

    /* Copy the pointers/colour from the victim to the replacement */
    *new = *victim;
}

int rbtree_count(struct rb_root *root)
{
    int count = 0;
    struct rb_node *node;

    if (NULL == root) {
        return 0;
    }

    node = (struct rb_node *)rbtree_first(root);
    while (node) {
        /* get next */
        node = (struct rb_node *)rbtree_next(node);
        count++;
    }
    return count;
}

