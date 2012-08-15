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
	unsigned int	refcount;

	int		__fd;
	unsigned int	active : 1,
			error  : 1;
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


#endif /* __WICKED_SOCKET_PRIV_H__ */

