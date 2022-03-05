/*
 * Buffer functions.
 * Most of these are inlines defined in buffer.h
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "buffer.h"

ni_bool_t
ni_buffer_ensure_tailroom(ni_buffer_t *bp, size_t min_room)
{
	unsigned char *	new_base;
	size_t		new_size;

	if (!bp || (SIZE_MAX - bp->size) < min_room)
		return FALSE;

	if (ni_buffer_tailroom(bp) >= min_room)
		return TRUE;

	new_size = bp->size + min_room;
	if (bp->allocated) {
		new_base = xrealloc(bp->base, new_size);
		if (!new_base)
			return FALSE;

		bp->base = new_base;
	} else {
		new_base = xmalloc(new_size);
		if (!new_base)
			return FALSE;

		if (bp->size)
			memcpy(new_base, bp->base, bp->size);
		bp->base = new_base;
		bp->allocated = 1;
	}
	bp->size = new_size;
	return TRUE;
}
