/*
 *	Simple single-linked list implementation macros
 *
 *	Copyright (C) 2023 SUSE LLC
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski
 */
#ifndef NI_WICKED_SLIST_IMPL_H
#define NI_WICKED_SLIST_IMPL_H

#include <wicked/slist.h>


#define			ni_define_slist_insert(prefix)				\
	ni_bool_t								\
	prefix##_list_insert(prefix##_t **list, prefix##_t *item)		\
	{									\
		prefix##_t *tail = item;					\
										\
		if (list && tail) {						\
			while (tail->next)					\
				tail = tail->next;				\
			tail->next = *list;					\
			*list = item;						\
			return TRUE;						\
		}								\
		return FALSE;							\
	}

#define			ni_define_slist_append(prefix)				\
	ni_bool_t								\
	prefix##_list_append(prefix##_t **list, prefix##_t *item)		\
	{									\
		if (list && item) {						\
			while (*list)						\
				list = &(*list)->next;				\
			*list = item;						\
			return TRUE;						\
		}								\
		return FALSE;							\
	}

#define			ni_define_slist_remove(prefix)				\
	ni_bool_t								\
	prefix##_list_remove(prefix##_t **list, prefix##_t *item)		\
	{									\
		prefix##_t **pos;						\
										\
		if (list && item) {						\
			ni_slist_foreach_pos(list, pos) {			\
				if (item == *pos) {				\
					*pos = item->next;			\
					item->next = NULL;			\
					return TRUE;				\
				}						\
			}							\
		}								\
		return FALSE;							\
	}

#define			ni_define_slist_delete(prefix)				\
	ni_bool_t								\
	prefix##_list_delete(prefix##_t **list, prefix##_t *item)		\
	{									\
		if (prefix##_list_remove(list, item)) {				\
			prefix##_free(item);					\
			return TRUE;						\
		}								\
		return FALSE;							\
	}

#define			ni_define_slist_replace(prefix)				\
	ni_bool_t								\
	prefix##_list_replace(prefix##_t **list, prefix##_t *item,		\
			prefix##_t *head)					\
	{									\
		prefix##_t **pos, *tail = head;					\
										\
		if (!list || !item || !tail)					\
			return FALSE;						\
										\
		while (tail->next)						\
			tail = tail->next;					\
										\
		ni_slist_foreach_pos(list, pos) { 				\
			if (item == *pos) {					\
				tail->next = item->next;			\
				item->next = NULL;				\
				*pos = head;					\
				return TRUE;					\
			}							\
		}								\
		return FALSE;							\
	}

#define			ni_define_slist_destroy(prefix)				\
	void									\
	prefix##_list_destroy(prefix##_t **list)				\
	{									\
		prefix##_t *item;						\
										\
		if (list) {							\
			while ((item = *list)) {				\
				*list = item->next;				\
				item->next = NULL;				\
				prefix##_free(item);				\
			}							\
		}								\
	}

#define			ni_define_slist_copy(prefix)				\
	ni_bool_t								\
	prefix##_list_copy(prefix##_t **dlist, const prefix##_t *slist)		\
	{									\
		const prefix##_t *sitem;					\
		prefix##_t *ditem;						\
										\
		if (!dlist)							\
			return FALSE;						\
										\
		prefix##_list_destroy(dlist);					\
		ni_slist_foreach(slist, sitem) {				\
			ditem = prefix##_clone(sitem);				\
										\
			if (prefix##_list_append(dlist, ditem))			\
				continue;					\
										\
			prefix##_free(ditem);					\
			prefix##_list_destroy(dlist);				\
			return FALSE;						\
		}								\
		return TRUE;							\
	}

#define			ni_define_slist_tail(prefix)				\
	prefix##_t *								\
	prefix##_list_tail(prefix##_t *head)					\
	{									\
		if (head) {							\
			while (head->next)					\
				head = head->next;				\
		}								\
		return head;							\
	}

#define			ni_define_slist_count(prefix)				\
	size_t									\
	prefix##_list_count(const prefix##_t *head)				\
	{									\
		const prefix##_t *item;						\
		size_t count = 0;						\
										\
		ni_slist_foreach(head, item)					\
			count++;						\
										\
		return count;							\
	}

#endif /* NI_WICKED_SLIST_IMPL_H */
