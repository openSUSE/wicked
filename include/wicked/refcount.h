/*
 *	refcount -- reference counting utils and declaration macros
 *
 *	Copyright (C) 2022-2023 SUSE LLC
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
 *		Clemens Famulla-Conrad
 */
#ifndef NI_WICKED_REFCOUNT_DECL_H
#define NI_WICKED_REFCOUNT_DECL_H

#include <wicked/types.h>


typedef unsigned int	ni_refcount_t;

extern ni_bool_t	ni_refcount_init(ni_refcount_t *refcount);
extern ni_bool_t	ni_refcount_increment(ni_refcount_t *refcount);
extern ni_bool_t	ni_refcount_decrement(ni_refcount_t *refcount);


#define			ni_declare_refcounted_new(prefix, args...)	\
	prefix##_t *		prefix##_new(args)

#define			ni_declare_refcounted_ref(prefix)		\
	prefix##_t *		prefix##_ref(prefix##_t *)

#define			ni_declare_refcounted_free(prefix)		\
	void			prefix##_free(prefix##_t *)

#define			ni_declare_refcounted_hold(prefix)		\
	ni_bool_t		prefix##_hold(prefix##_t **, prefix##_t *)

#define			ni_declare_refcounted_drop(prefix)		\
	ni_bool_t		prefix##_drop(prefix##_t **)

#define			ni_declare_refcounted_move(prefix)		\
	ni_bool_t		prefix##_move(prefix##_t **, prefix##_t **)

#endif /* NI_WICKED_REFCOUNT_DECL_H */
