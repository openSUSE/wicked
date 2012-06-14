/*
 * Internal helper functions.
 * Do not confuse with <wicked/util.h> which is public.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_UTIL_PRIV_H__
#define __WICKED_UTIL_PRIV_H__

extern void *	xmalloc(size_t);
extern void *	xcalloc(unsigned int, size_t);
extern void *	xrealloc(void *ptr, size_t size);

extern char *	xstrdup(const char *);

#endif /* __WICKED_UTIL_PRIV_H__ */


