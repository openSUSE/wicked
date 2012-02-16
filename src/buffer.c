/*
 * Buffer functions.
 * Most of these are inlines defined in buffer.h
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#include "buffer.h"

void
ni_buffer_ensure_tailroom(ni_buffer_t *bp, unsigned int min_room)
{
	size_t	new_size;

	if (ni_buffer_tailroom(bp) >= min_room)
		return;

	new_size = bp->size + min_room;
	if (bp->allocated) {
		bp->base = realloc(bp->base, new_size);
	} else {
		unsigned char *new_base;

		new_base = malloc(new_size);
		memcpy(new_base, bp->base, bp->size);
		bp->base = new_base;
		bp->allocated = 1;
	}
	bp->size = new_size;
}
