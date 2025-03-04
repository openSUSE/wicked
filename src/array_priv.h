/*
 *	Pointer array implementation macros
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

#ifndef NI_WICKED_ARRAY_PRIV_H
#define NI_WICKED_ARRAY_PRIV_H

#include <limits.h>
#include <stdlib.h>

#define			ni_define_ptr_array_init(prefix)				\
	ni_bool_t									\
	prefix##_array_init(prefix##_array_t *arr)					\
	{										\
		if (arr) {								\
			memset(arr, 0, sizeof(*arr));					\
			return TRUE;							\
		}									\
		return FALSE;								\
	}

#define			ni_define_ptr_array_move(prefix)				\
	ni_bool_t									\
	prefix##_array_move(prefix##_array_t *dst, prefix##_array_t *src)		\
	{										\
		if (dst && src) {							\
			prefix##_array_destroy(dst);					\
			*dst = *src;							\
			return prefix##_array_init(src);				\
		}									\
		return FALSE;								\
	}

#define			ni_define_ptr_array_destroy(prefix)				\
	void prefix##_array_destroy(prefix##_array_t *arr)				\
	{										\
		if (arr) {								\
			while (arr->count) {						\
				arr->count--;						\
				prefix##_free(arr->data[arr->count]);			\
			}								\
			free(arr->data);						\
			prefix##_array_init(arr);					\
		}									\
	}

#define			ni_define_ptr_array_realloc(prefix, chunk_size)			\
	ni_bool_t									\
	prefix##_array_realloc(prefix##_array_t *arr)					\
	{										\
		static const size_t entsize = sizeof(prefix##_t *);			\
		prefix##_t ** newdata;							\
		unsigned int newcount;							\
											\
		if (!arr)								\
			return FALSE;							\
											\
		if ((arr->count % chunk_size) != 0)					\
			return TRUE;							\
											\
		if ((UINT_MAX - arr->count) <= chunk_size)				\
			return FALSE;							\
											\
		newcount = arr->count + chunk_size + 1;					\
		if (SIZE_MAX / entsize < newcount)					\
			return FALSE;							\
											\
		newdata = realloc(arr->data, newcount * entsize);			\
		if (!newdata)								\
			return FALSE;							\
											\
		arr->data = newdata;							\
		memset(&arr->data[arr->count], 0, (newcount - arr->count) * entsize);	\
											\
		return TRUE;								\
	}

#define			ni_define_ptr_array_append(prefix)				\
	ni_bool_t									\
	prefix##_array_append(prefix##_array_t *arr, prefix##_t *ent)			\
	{										\
		if (!ent || !prefix##_array_realloc(arr))				\
			return FALSE;							\
											\
		arr->data[arr->count++] = ent;						\
		return TRUE;								\
	}

#define			ni_define_ptr_array_insert(prefix)				\
	ni_bool_t									\
	prefix##_array_insert(prefix##_array_t *arr, unsigned int pos,			\
			prefix##_t *ent)						\
	{										\
		if (!ent || !prefix##_array_realloc(arr))				\
			return FALSE;							\
											\
		if (pos >= arr->count) {						\
			arr->data[arr->count++] = ent;					\
		} else {								\
			memmove(&arr->data[pos + 1], &arr->data[pos],			\
					(arr->count - pos) * sizeof(ent));		\
			arr->data[pos] = ent;						\
			arr->count++;							\
		}									\
		return TRUE;								\
	}

#define			ni_define_ptr_array_delete_at(prefix)				\
	ni_bool_t									\
	prefix##_array_delete_at(prefix##_array_t *arr, unsigned int idx)		\
	{										\
		prefix##_t *ent;							\
											\
		if (!arr || idx >= arr->count)						\
			return FALSE;							\
											\
		ent = arr->data[idx];							\
		arr->count--;								\
		if (idx < arr->count) {							\
			memmove(&arr->data[idx], &arr->data[idx + 1],			\
				(arr->count - idx) * sizeof(*arr->data));		\
		}									\
		arr->data[arr->count] = NULL;						\
		prefix##_free(ent);							\
											\
		return TRUE;								\
	}

#define			ni_define_ptr_array_remove_at(prefix)				\
	prefix##_t *									\
	prefix##_array_remove_at(prefix##_array_t *arr, unsigned int idx)		\
	{										\
		prefix##_t *ent;							\
											\
		if (!arr || idx >= arr->count)						\
			return NULL;							\
											\
		ent = arr->data[idx];							\
		arr->count--;								\
		if (idx < arr->count) {							\
			memmove(&arr->data[idx], &arr->data[idx + 1],			\
				(arr->count - idx) * sizeof(ent));			\
		}									\
		arr->data[arr->count] = NULL;						\
											\
		return ent;								\
	}

#define			ni_define_ptr_array_at(prefix)					\
	prefix##_t *									\
	prefix##_array_at(const prefix##_array_t *arr, unsigned int idx)		\
	{										\
		if (!arr || idx >= arr->count)						\
			return NULL;							\
											\
		return arr->data[idx];							\
	}

#define			ni_define_ptr_array_index(prefix)				\
	unsigned int									\
	prefix##_array_index(const prefix##_array_t *arr, const prefix##_t *needle)	\
	{										\
		unsigned int i;								\
											\
		if (!arr || !needle)							\
			return -1U;							\
											\
		for (i = 0; i < arr->count; i++) {					\
			if (arr->data[i] == needle)					\
				return i;						\
		}									\
		return -1U;								\
	}

#define			ni_define_ptr_array_delete(prefix)				\
	ni_bool_t									\
	prefix##_array_delete(prefix##_array_t *arr, const prefix##_t *ent)		\
	{										\
		return prefix##_array_delete_at(arr, prefix##_array_index(arr, ent));	\
	}

#define			ni_define_ptr_array_remove(prefix)				\
	prefix##_t *									\
	prefix##_array_remove(prefix##_array_t *arr, const prefix##_t *ent)		\
	{										\
		return prefix##_array_remove_at(arr, prefix##_array_index(arr, ent));	\
	}

#define			ni_define_ptr_array_qsort_cmp_fn(prefix)			\
	int										\
	prefix##_array_qsort_cmp_fn(const void *pa, const void *pb, void *arg)		\
	{										\
		const prefix##_t **a = (const prefix##_t **)pa;				\
		const prefix##_t **b = (const prefix##_t **)pb;				\
											\
		prefix##_array_cmp_fn cmpfn = (prefix##_array_cmp_fn)arg;		\
		return cmpfn(*a, *b);							\
	}

#define			ni_define_ptr_array_qsort(prefix)				\
	void										\
	prefix##_array_qsort(prefix##_array_t *arr, prefix##_array_cmp_fn cmpfn)	\
	{										\
		qsort_r(arr->data, arr->count, sizeof(arr->data[0]),			\
				prefix##_array_qsort_cmp_fn, cmpfn);			\
	}

/*
 * Utilities for reference counted entries
 */
#define			ni_define_ptr_array_append_ref(prefix)				\
	ni_bool_t									\
	prefix##_array_append_ref(prefix##_array_t *arr, prefix##_t *ent)		\
	{										\
		prefix##_t *ref = prefix##_ref(ent);					\
											\
		if (!ref || !prefix##_array_realloc(arr)) {				\
			prefix##_free(ref);						\
			return FALSE;							\
		}									\
											\
		arr->data[arr->count++] = ref;						\
		return TRUE;								\
	}

#define			ni_define_ptr_array_insert_ref(prefix)				\
	ni_bool_t									\
	prefix##_array_insert_ref(prefix##_array_t *arr, unsigned int pos,		\
			prefix##_t *ent)						\
	{										\
		prefix##_t *ref = prefix##_ref(ent);					\
											\
		if (!ref || !prefix##_array_realloc(arr)) {				\
			prefix##_free(ref);						\
			return FALSE;							\
		}									\
											\
		if (pos >= arr->count) {						\
			arr->data[arr->count++] = ref;					\
		} else {								\
			memmove(&arr->data[pos + 1], &arr->data[pos],			\
					(arr->count - pos) * sizeof(ent));		\
			arr->data[pos] = ref;						\
			arr->count++;							\
		}									\
		return TRUE;								\
	}

#endif /* NI_WICKED_ARRAY_PRIV_H */
