/*
 *	Simple single-linked list declaration macros
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
#ifndef NI_WICKED_SLIST_DECL_H
#define NI_WICKED_SLIST_DECL_H

/*
 * Common slist utility macros
 */
#define			ni_slist_foreach(head, item)				\
	for (item = head; item; item = item->next)

#define			ni_slist_foreach_next(head, item, nitem)		\
	for (item = head; item && ((nitem = item->next) || 1); item = nitem)

#define			ni_slist_foreach_pos(list, pos)				\
	for (pos = list; *pos; pos = &(*pos)->next)

/*
 * Prototype declaration macros
 */
#define			ni_declare_slist_insert(prefix)				\
	ni_bool_t	prefix##_list_insert(prefix##_t **, prefix##_t *)

#define			ni_declare_slist_append(prefix)				\
	ni_bool_t	prefix##_list_append(prefix##_t **, prefix##_t *)

#define			ni_declare_slist_remove(prefix)				\
	ni_bool_t	prefix##_list_remove(prefix##_t **, prefix##_t *)

#define			ni_declare_slist_delete(prefix)				\
	ni_bool_t	prefix##_list_delete(prefix##_t **, prefix##_t *)

#define			ni_declare_slist_replace(prefix)			\
	ni_bool_t	prefix##_list_replace(prefix##_t **, prefix##_t *,	\
					prefix##_t *)

#define			ni_declare_slist_destroy(prefix)			\
	void		prefix##_list_destroy(prefix##_t **)

#define			ni_declare_slist_copy(prefix)				\
	ni_bool_t	prefix##_list_copy(prefix##_t **, const prefix##_t *)

#define			ni_declare_slist_tail(prefix)				\
	prefix##_t *	prefix##_list_tail(prefix##_t *)

#define			ni_declare_slist_count(prefix)				\
	size_t		prefix##_list_count(const prefix##_t *)

#endif /* NI_WICKED_SLIST_DECL_H */
