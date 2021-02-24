/*
 * Doubly-linked list
 * Copyright (c) 2009-2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef LIST_H
#define LIST_H

/**
 * struct dl_list - Doubly-linked list
 */
struct dl_list {
	struct dl_list *next;
	struct dl_list *prev;
};

#define DL_LIST_HEAD_INIT(l) { &(l), &(l) }

static inline void dl_list_init(struct dl_list *list)
{
	list->next = list;
	list->prev = list;
}

static inline void dl_list_add(struct dl_list *list, struct dl_list *item)
{
	item->next = list->next;
	item->prev = list;
	list->next->prev = item;
	list->next = item;
}

static inline void dl_list_add_tail(struct dl_list *list, struct dl_list *item)
{
	dl_list_add(list->prev, item);
}

static inline void dl_list_del(struct dl_list *item)
{
	if (item->next) {
		item->next->prev = item->prev;
		item->prev->next = item->next;
	}
	item->next = NULL;
	item->prev = NULL;
}

static inline int dl_list_empty(struct dl_list *list)
{
	return list->next == list;
}

static inline unsigned int dl_list_len(struct dl_list *list)
{
	struct dl_list *item;
	int count = 0;
	for (item = list->next; item != list; item = item->next)
		count++;
	return count;
}

#define dl_list_entry(item, type, member) \
	container_of(item, type, member)

#define dl_list_entry_first(list, type, member) \
	 dl_list_entry((list)->next, type, member)

#define dl_list_entry_next(item, member) \
	dl_list_entry((item)->member.next, typeof(*(item)), member)

#define dl_list_entry_prev(item, member) \
	dl_list_entry((item)->member.prev, typeof(*(item)), member)

#define dl_list_entry_last(list, type, member) \
	 dl_list_entry((list)->prev, type, member)

#define dl_list_for_each_entry(item, list, member) \
	for (item = dl_list_entry_first((list), typeof(*item), member); \
	     &item->member != (list); \
	     item = dl_list_entry_next(item, member))

#define dl_list_for_each_entry_safe(item, n, list, member) \
    for (item = dl_list_entry_first(list, typeof(*item), member),	\
		n = dl_list_entry_next(item, member);			\
	     &item->member != (list); 					\
	     item = n, n = dl_list_entry_next(n, member))

#define dl_list_for_each_entry_reverse(item, list, member) \
	for (item = dl_list_entry_last(list, typeof(*item), member); \
	     &item->member != (list); \
	     item = dl_list_entry_prev(item, member))

#define dl_list_for_each(item, list) \
	for (item = (list)->next; item != (list); item = item->next)

#define dl_list_for_each_safe(item, n, list) \
	for (item = (list)->next, n = item->next; item != (list); \
		item = n, n = item->next)

#define dl_list_for_each_prev(item, list) \
	for (item = (list)->prev; item != (list); item = item->prev)

#define dl_list_for_each_entry_reverse_safe(item, n, list, member) \
	for (item = dl_list_entry_last(list, typeof(*item), member),		\
		n = dl_list_entry_prev(item, member);			\
	     &item->member != (list); 					\
	     item = n, n = dl_list_entry_prev(n, member))

#define DEFINE_DL_LIST(name) \
	struct dl_list name = { &(name), &(name) }

#endif /* LIST_H */

