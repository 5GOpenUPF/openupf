/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef	___RBTREE_H
#define	___RBTREE_H

#include <stdio.h>

#define	RB_RED              0
#define	RB_BLACK            1
#define RB_COLOR_MASK       1

struct rb_node {
	unsigned long       parent_and_color;
	struct rb_node      *right_node;
	struct rb_node      *left_node;
} __attribute__((aligned(sizeof(long))));

struct rb_root {
	struct rb_node      *rb_node;
};

typedef int (*RBTREE_COMPARE)(struct rb_node *node, void * key);


#define RB_ROOT_INIT_VALUE	(struct rb_root) { NULL }

void rbtree_erase(struct rb_node *, struct rb_root *);

struct rb_node *rbtree_next(const struct rb_node *);
struct rb_node *rbtree_first(const struct rb_root *);

void rbtree_replace_node(struct rb_node *victim,
			    struct rb_node *new, struct rb_root *root);
struct rb_node *rbtree_delete(struct rb_root *root,
                     void *key, RBTREE_COMPARE compare);
struct rb_node *rbtree_search(struct rb_root *root,
                     void *key, RBTREE_COMPARE compare);
int rbtree_insert(struct rb_root *root, struct rb_node *node,
            void *key, RBTREE_COMPARE compare);
int rbtree_count(struct rb_root *root);


#endif	/* __RBTREE_H */
