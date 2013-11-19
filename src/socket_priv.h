/*
 * Network socket related functionality for wicked.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_SOCKET_PRIV_H__
#define __WICKED_SOCKET_PRIV_H__

#include <stdio.h>

#include <wicked/types.h>
#include <wicked/socket.h>
#include "buffer.h"

struct ni_socket {
	unsigned int		refcount;
	ni_socket_array_t *	active;

	int		__fd;
	unsigned int	error  : 1;
	int		poll_flags;

	ni_buffer_t	rbuf;
	ni_buffer_t	wbuf;

	void		(*close)(ni_socket_t *);

	void		(*receive)(ni_socket_t *);
	void		(*transmit)(ni_socket_t *);
	void		(*handle_error)(ni_socket_t *);
	void		(*handle_hangup)(ni_socket_t *);

	int		(*accept)(ni_socket_t *, uid_t, gid_t);

	int		(*get_timeout)(const ni_socket_t *, struct timeval *);
	void		(*check_timeout)(ni_socket_t *, const struct timeval *);

	void *		user_data;
};

struct ni_socket_array {
	unsigned int	count;
	ni_socket_t **	data;
};

#define NI_SOCKET_ARRAY_INIT	{ .count = 0, .data = NULL }

extern void		ni_socket_array_init(ni_socket_array_t *);
extern void		ni_socket_array_destroy(ni_socket_array_t *);
extern void		ni_socket_array_cleanup(ni_socket_array_t *);

extern ni_bool_t	ni_socket_array_append(ni_socket_array_t *, ni_socket_t *);
extern ni_socket_t *	ni_socket_array_remove_at(ni_socket_array_t *, unsigned int);
extern ni_socket_t *	ni_socket_array_remove(ni_socket_array_t *, ni_socket_t *);
extern unsigned int	ni_socket_array_find(ni_socket_array_t *, ni_socket_t *);

extern ni_bool_t	ni_socket_array_activate(ni_socket_array_t *, ni_socket_t *);
extern ni_bool_t	ni_socket_array_deactivate(ni_socket_array_t *, ni_socket_t *);

#endif /* __WICKED_SOCKET_PRIV_H__ */

