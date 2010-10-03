/*
 * Network socket related functionality for wicked.
 * No user serviceable parts inside.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_SOCKET_H__
#define __WICKED_SOCKET_H__

#include <stdio.h>

#include <wicked/types.h>

struct ni_socket_ops {
	int		(*pull)(ni_socket_t *);
	int		(*begin_buffering)(ni_socket_t *);
	int		(*push)(ni_socket_t *);
	int		(*send)(ni_socket_t *, const void *, size_t);
	int		(*recv)(ni_socket_t *, void *, size_t);
};

struct ni_socket {
	int		__fd;
	FILE *		wfile;
	FILE *		rfile;
	unsigned int	stream : 1,
			active : 1,
			error : 1;

	struct {
		char *	rbuf;
		size_t	rsize;
		char *	wbuf;
		size_t	wsize;
	} dgram;

	const struct ni_socket_ops *iops;

	int		(*get_timeout)(const ni_socket_t *, struct timeval *);
	void		(*data_ready)(ni_socket_t *);
	int		(*accept)(ni_socket_t *, uid_t, gid_t);
	void		(*check_timeout)(ni_socket_t *, const struct timeval *);

	void *		user_data;
};

extern ni_socket_t *	ni_local_socket_listen(const char *, unsigned int);
extern ni_socket_t *	ni_local_socket_connect(const char *);
extern ni_socket_t *	ni_local_socket_accept(ni_socket_t *, uid_t *, gid_t *);
extern int		ni_local_socket_pair(ni_socket_t **, ni_socket_t **);

extern ni_socket_t *	ni_socket_wrap(int fd, int sotype);
extern void		ni_socket_activate(ni_socket_t *);
extern void		ni_socket_deactivate(ni_socket_t *);
extern void		ni_socket_deactivate_all(void);
extern int		ni_socket_wait(long timeout);

extern int		ni_socket_printf(ni_socket_t *, const char *, ...);
extern int		ni_socket_send_xml(ni_socket_t *, const xml_node_t *);
extern int		ni_socket_push(ni_socket_t *);
extern char *		ni_socket_gets(ni_socket_t *, char *, size_t);
extern xml_node_t *	ni_socket_recv_xml(ni_socket_t *);
extern void		ni_socket_close(ni_socket_t *);
extern int		ni_socket_pull(ni_socket_t *);


#endif /* __WICKED_SOCKET_H__ */

