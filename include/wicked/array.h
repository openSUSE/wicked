/*
 *	Common array utility macros
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
 *		Clemens Famulla-Conrad
 *		Marius Tomaschewski
 */
#ifndef NI_WICKED_ARRAY_H
#define NI_WICKED_ARRAY_H


#define NI_ARRAY_INIT	{ .count = 0, .data = NULL }

#define			ni_declare_ptr_array_struct(prefix)				\
	struct prefix##_array {								\
		unsigned int	count;							\
		prefix##_t **	data;							\
	}

#define			ni_declare_ptr_array_type(prefix)				\
	typedef ni_declare_ptr_array_struct(prefix) prefix##_array_t

#define			ni_declare_ptr_array_cmp_fn(prefix)				\
	typedef int (*prefix##_array_cmp_fn)(const prefix##_t *, const prefix##_t *)

#define			ni_declare_ptr_array_init(prefix)				\
	ni_bool_t	prefix##_array_init(prefix##_array_t *)

#define			ni_declare_ptr_array_move(prefix)				\
	ni_bool_t	prefix##_array_move(prefix##_array_t *, prefix##_array_t *)

#define			ni_declare_ptr_array_destroy(prefix)				\
	void		prefix##_array_destroy(prefix##_array_t *)

#define			ni_declare_ptr_array_realloc(prefix)				\
	ni_bool_t	prefix##_array_realloc(prefix##_array_t *)

#define			ni_declare_ptr_array_append(prefix)				\
	ni_bool_t	prefix##_array_append(prefix##_array_t *, prefix##_t *)

#define			ni_declare_ptr_array_insert(prefix)				\
	ni_bool_t	prefix##_array_insert(prefix##_array_t *, unsigned int,		\
					prefix##_t *)

#define			ni_declare_ptr_array_delete_at(prefix)				\
	ni_bool_t	prefix##_array_delete_at(prefix##_array_t *, unsigned int)

#define			ni_declare_ptr_array_remove_at(prefix)				\
	prefix##_t *	prefix##_array_remove_at(prefix##_array_t *, unsigned int)

#define			ni_declare_ptr_array_at(prefix)					\
	prefix##_t *	prefix##_array_at(const prefix##_array_t *, unsigned int)

#define			ni_declare_ptr_array_index(prefix)				\
	unsigned int	prefix##_array_index(const prefix##_array_t *, const prefix##_t *)

#define			ni_declare_ptr_array_delete(prefix)				\
	ni_bool_t	prefix##_array_delete(prefix##_array_t *, const prefix##_t *)

#define			ni_declare_ptr_array_remove(prefix)				\
	prefix##_t *	prefix##_array_remove(prefix##_array_t *, const prefix##_t *)

#define			ni_declare_ptr_array_qsort(prefix)				\
	void		prefix##_array_qsort(prefix##_array_t *, prefix##_array_cmp_fn)


/*
 * Utilities for reference counted entries
 */
#define			ni_declare_ptr_array_append_ref(prefix)				\
	ni_bool_t	prefix##_array_append_ref(prefix##_array_t *, prefix##_t *)

#define			ni_declare_ptr_array_insert_ref(prefix)				\
	ni_bool_t	prefix##_array_insert_ref(prefix##_array_t *, unsigned int,	\
					prefix##_t *)

#endif /* NI_WICKED_ARRAY_H */
