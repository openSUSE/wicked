/*
 *	refcount -- reference counting utils
 *
 *	Copyright (C) 2022 SUSE LLC
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/types.h>
#include <wicked/refcount.h>
#include <wicked/logging.h>

ni_bool_t
ni_refcount_init(ni_refcount_t *refcount)
{
	ni_assert(refcount);
	*refcount = 1;
	return TRUE;
}

ni_bool_t
ni_refcount_increment(ni_refcount_t *refcount)
{
	ni_assert(refcount && *refcount);
	*refcount += 1;
	return *refcount != 0;
}

ni_bool_t
ni_refcount_decrement(ni_refcount_t *refcount)
{
	ni_assert(refcount && *refcount);
	*refcount -= 1;
	return *refcount == 0;
}

