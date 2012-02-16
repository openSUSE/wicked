/*
 * General functions for AF_LOCAL sockets
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/xml.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "socket_priv.h"
#include "config.h"

static void			__ni_socket_close(ni_socket_t *);
static void			__ni_socket_accept(ni_socket_t *);
static void			__ni_stream_receive(ni_socket_t *);
static void			__ni_stream_transmit(ni_socket_t *);
static void			__ni_dgram_receive(ni_socket_t *);
static void			__ni_dgram_transmit(ni_socket_t *);
static void			__ni_default_error_handler(ni_socket_t *);
static void			__ni_default_hangup_handler(ni_socket_t *);

static struct ni_socket_ops	__ni_listener_ops;
static struct ni_socket_ops	__ni_stream_ops;
static struct ni_socket_ops	__ni_dgram_ops;

static unsigned int		__ni_socket_count;
static ni_socket_t **		__ni_sockets;

/*
 * Install a socket so we check it for incoming data.
 */
void
ni_socket_activate(ni_socket_t *sock)
{
	if (sock->active)
		return;

	if ((__ni_socket_count % 16) == 0) {
		__ni_sockets = realloc(__ni_sockets, (__ni_socket_count + 16) * sizeof(ni_socket_t *));
		if (__ni_sockets == NULL)
			ni_fatal("%s: realloc failed", __FUNCTION__);
	}

	__ni_sockets[__ni_socket_count++] = sock;
	sock->refcount++;
	sock->active = 1;
	sock->poll_flags = POLLIN;
}

static inline void
__ni_socket_deactivate(ni_socket_t **slot)
{
	ni_socket_t *sock = *slot;

	*slot = NULL;
	sock->active = 0;
	ni_socket_release(sock);
}

void
ni_socket_deactivate(ni_socket_t *sock)
{
	unsigned int i;

	if (!sock->active)
		return;

	for (i = 0; i < __ni_socket_count; ++i) {
		if (__ni_sockets[i] == sock) {
			__ni_socket_deactivate(&__ni_sockets[i]);
			return;
		}
	}

	ni_error("%s: socket not found", __FUNCTION__);
}

void
ni_socket_deactivate_all(void)
{
	unsigned int i;

	for (i = 0; i < __ni_socket_count; ++i) {
		if (__ni_sockets[i] != NULL)
			__ni_socket_deactivate(&__ni_sockets[i]);
	}
}

void
ni_socket_release(ni_socket_t *sock)
{
	if (sock->refcount == 0)
		ni_fatal("refcounting error in ni_socket_release");
	sock->refcount--;
	if (sock->refcount == 0) {
		__ni_socket_close(sock);
		assert(!sock->active);
		free(sock);
	}
}

void
ni_socket_set_accept_callback(ni_socket_t *sock, ni_socket_accept_callback_t fn)
{
	sock->accept = fn;
}

void
ni_socket_set_request_callback(ni_socket_t *sock, ni_socket_request_callback_t fn)
{
	sock->process_request = fn;
	if (sock->stream) {
		sock->receive = __ni_stream_receive;
		sock->transmit = __ni_stream_transmit;
	} else {
		sock->receive = __ni_dgram_receive;
		sock->transmit = __ni_dgram_transmit;
	}
}

static inline void
__ni_socket_set_rfile(ni_socket_t *sock, FILE *fp)
{
	if (sock->rfile && sock->rfile != fp)
		fclose(sock->rfile);
	sock->rfile = fp;
}

static inline void
__ni_socket_set_wfile(ni_socket_t *sock, FILE *fp)
{
	if (sock->wfile && sock->wfile != fp) {
		fflush(sock->wfile);
		fclose(sock->wfile);
	}
	sock->wfile = fp;
}

static inline int
__ni_socket_open_rfile(ni_socket_t *sock, ni_buffer_t *bp)
{
	FILE *fp;

	fp = fmemopen(ni_buffer_head(bp), ni_buffer_count(bp), "r");
	__ni_socket_set_rfile(sock, fp);
	if (fp == NULL) {
		ni_error("Unable to open memstream for reading: %m");
		return -1;
	}

	return 0;
}

static inline int
__ni_socket_open_wfile(ni_socket_t *sock, ni_buffer_t *bp)
{
	FILE *fp;

	ni_buffer_destroy(bp);

	fp = open_memstream((char **) &bp->base, &bp->tail);
	__ni_socket_set_wfile(sock, fp);

	if (fp == NULL) {
		ni_error("Unable to open memstream for writing: %m");
		return -1;
	}

	bp->allocated = 1;
	return 0;
}

void
__ni_default_error_handler(ni_socket_t *sock)
{
	/* Deactivate socket */
	ni_warn("POLLERR on socket - deactivating. Note: this is not the right approach, fix it");
	sock->error = 1;
}

void
__ni_default_hangup_handler(ni_socket_t *sock)
{
}


/*
 * Wait for incoming data on any of the sockets.
 */
int
ni_socket_wait(long timeout)
{
	struct pollfd pfd[__ni_socket_count];
	struct timeval now, expires;
	unsigned int i, j, socket_count;

	/* We don't care about the exit status of children */
	signal(SIGCHLD, SIG_IGN);

	/* First step - remove all inactive sockets from the array. */
	for (i = j = 0; i < __ni_socket_count; ++i) {
		if (__ni_sockets[i])
			__ni_sockets[j++] = __ni_sockets[i];
	}
	__ni_socket_count = j;

	/* Second step - build pollfd array and get timeouts */
	timerclear(&expires);
	for (i = 0; i < __ni_socket_count; ++i) {
		ni_socket_t *sock = __ni_sockets[i];
		struct timeval socket_expires;

		timerclear(&socket_expires);
		if (sock->get_timeout && sock->get_timeout(sock, &socket_expires) == 0) {
			if (!timerisset(&expires) || timercmp(&socket_expires, &expires, <))
				expires = socket_expires;
		}

		pfd[i].fd = sock->__fd;
		pfd[i].events = sock->poll_flags;
	}
	socket_count = __ni_socket_count;

	gettimeofday(&now, NULL);
	if (timerisset(&expires)) {
		struct timeval delta;
		long delta_ms;

		if (timercmp(&expires, &now, <)) {
			timeout = 0;
		} else {
			timersub(&expires, &now, &delta);
			delta_ms = 1000 * delta.tv_sec + delta.tv_usec / 1000;
			if (timeout < 0 || delta_ms < timeout)
				timeout = delta_ms;
		}
	}

	if (socket_count == 0 && timeout < 0) {
		ni_error("no sockets left to watch");
		return -1;
	}

	if (poll(pfd, socket_count, timeout) < 0) {
		if (errno == EINTR)
			return 0;
		ni_error("poll returns error: %m");
		return -1;
	}

	for (i = 0; i < socket_count; ++i) {
		ni_socket_t *sock = __ni_sockets[i];

		if (sock == NULL)
			continue;
		sock->refcount++;

		if (pfd[i].revents & POLLERR) {
			/* Deactivate socket */
			__ni_socket_deactivate(&__ni_sockets[i]);
			sock->handle_error(sock);
			goto done_with_this_socket;
		}

		if (pfd[i].revents & POLLHUP) {
			if (sock->handle_hangup)
				sock->handle_hangup(sock);
		}

		if (pfd[i].revents & POLLIN) {
			if (sock->receive == NULL) {
				ni_error("socket %d has no receive callback", sock->__fd);
				__ni_socket_deactivate(&__ni_sockets[i]);
			} else {
				sock->receive(sock);
			}
		}

		if (pfd[i].revents & POLLOUT) {
			if (sock->transmit == NULL) {
				ni_error("socket %d has no transmit callback", sock->__fd);
				__ni_socket_deactivate(&__ni_sockets[i]);
			} else {
				sock->transmit(sock);
			}
		}

done_with_this_socket:
		ni_socket_release(sock);
	}

	gettimeofday(&now, NULL);
	for (i = 0; i < socket_count; ++i) {
		ni_socket_t *sock = __ni_sockets[i];

		if (sock && sock->check_timeout)
			sock->check_timeout(sock, &now);
	}

	return 0;
}

/*
 * Wrap a file descriptor in a ni_socket object
 */
static ni_socket_t *
__ni_socket_wrap(int fd, int sotype, const struct ni_socket_ops *iops)
{
	ni_socket_t *socket;

	socket = calloc(1, sizeof(*socket));
	socket->refcount = 1;
	socket->__fd = fd;
	socket->stream = (sotype == SOCK_STREAM)? 1 : 0;
	socket->iops = iops;

	socket->handle_error = __ni_default_error_handler;
	socket->handle_hangup = __ni_default_hangup_handler;

	if (sotype == SOCK_STREAM) {
		socket->wfile = fdopen(dup(fd), "w");
		socket->rfile = fdopen(dup(fd), "r");
	}

	return socket;
}

ni_socket_t *
ni_socket_wrap(int fd, int sotype)
{
	ni_socket_t *sock;

	if (sotype < 0) {
		socklen_t len = sizeof(sotype);

		if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sotype, &len) < 0) {
			ni_error("%s: cannot determine socket type", __FUNCTION__);
			return NULL;
		}
	}

	switch (sotype) {
	case SOCK_DGRAM:
		sock = __ni_socket_wrap(fd, sotype, &__ni_dgram_ops);
		break;
	case SOCK_STREAM:
		sock = __ni_socket_wrap(fd, sotype, &__ni_stream_ops);
		break;
	default:
		ni_error("ni_socket_wrap: unsupported socket type %d", sotype);
		return NULL;
	}

	return sock;
}

/*
 * Close socket
 */
static void
__ni_socket_close(ni_socket_t *sock)
{
	if (sock->close) {
		sock->close(sock);
	} else if (sock->__fd >= 0) {
		close(sock->__fd);
	}
	sock->__fd = -1;

	if (sock->rfile)
		fclose(sock->rfile);
	sock->rfile = NULL;
	if (sock->wfile)
		fclose(sock->wfile);
	sock->wfile = NULL;

	ni_buffer_destroy(&sock->wbuf);
	ni_buffer_destroy(&sock->rbuf);

	if (sock->active)
		ni_socket_deactivate(sock);
}

void
ni_socket_close(ni_socket_t *sock)
{
	__ni_socket_close(sock);
	ni_socket_release(sock);
}


/*
 * Begin send buffering
 */
static inline int
ni_socket_begin_send(ni_socket_t *sock)
{
	if (sock->wfile)
		return 0;
	if (!sock->iops || !sock->iops->begin_buffering)
		return -1;
	return sock->iops->begin_buffering(sock);
}

/*
 * Write data to socket, printf style
 */
int
ni_socket_printf(ni_socket_t *sock, const char *fmt, ...)
{
	va_list ap;

	if (ni_socket_begin_send(sock) < 0)
		return -1;

	va_start(ap, fmt);
	vfprintf(sock->wfile, fmt, ap);
	va_end(ap);

	if (ferror(sock->wfile)) {
		ni_error("send error: %m");
		return -1;
	}
	return 0;
}

/*
 * Send XML to socket
 */
int
ni_socket_send_xml(ni_socket_t *sock, const xml_node_t *node)
{
	if (ni_socket_begin_send(sock) < 0)
		return -1;

	xml_node_print(node, sock->wfile);

	if (ferror(sock->wfile)) {
		ni_error("send error: %m");
		return -1;
	}
	return 0;
}

/*
 * Receive line of text from socket
 */
char *
ni_socket_gets(ni_socket_t *sock, char *buffer, size_t size)
{
	if (!sock->rfile)
		return NULL;
	return fgets(buffer, size, sock->rfile);
}

xml_node_t *
ni_socket_recv_xml(ni_socket_t *sock)
{
	if (!sock->rfile)
		return NULL;
	return xml_node_scan(sock->rfile);
}

/*
 * Push data to socket
 */
int
ni_socket_push(ni_socket_t *sock)
{
	if (sock->wfile)
		fflush(sock->wfile);
	if (sock->iops && sock->iops->push)
		return sock->iops->push(sock);
	return 0;
}

/*
 * Create a listener socket
 */
ni_socket_t *
ni_local_socket_listen(const char *path, unsigned int permissions)
{
	ni_socket_t *sock;
	int fd, bound = 0;

	permissions &= 0777;
	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		ni_error("cannot open AF_LOCAL socket: %m");
		return NULL;
	}

	if (path) {
		struct sockaddr_un sun;
		unsigned int len = strlen(path);

		if (len + 1 > sizeof(sun.sun_path)) {
			ni_error("can't set AF_LOCAL address: path too long!");
			return NULL;
		}

		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_LOCAL;
		strcpy(sun.sun_path, path);

		unlink(path);
		if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
			ni_error("bind(%s) failed: %m", path);
			goto failed;
		}
		bound = 1;

		if (chmod(path, permissions) < 0) {
			ni_error("chmod(%s, 0%3o) failed: %m", path, permissions);
			goto failed;
		}

	}

	if (listen(fd, 128) < 0) {
		ni_error("cannot listen on local socket: %m");
		goto failed;
	}

	sock = __ni_socket_wrap(fd, SOCK_STREAM, &__ni_listener_ops);
	sock->receive = __ni_socket_accept;

	ni_socket_activate(sock);
	return sock;

failed:
	if (bound && path)
		unlink(path);
	close(fd);
	return NULL;
}

ni_socket_t *
ni_local_socket_connect(const char *path)
{
	int fd;

	if (!path) {
		ni_error("cannot connect to server - no server socket path specified");
		return NULL;
	}

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		ni_error("cannot open AF_LOCAL socket: %m");
		return NULL;
	}

	{
		struct sockaddr_un sun;
		unsigned int len = strlen(path);

		if (len + 1 > sizeof(sun.sun_path)) {
			ni_error("can't set AF_LOCAL address: path too long!");
			goto failed;
		}

		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_LOCAL;
		strcpy(sun.sun_path, path);

		if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
			ni_error("connect(%s) failed: %m", path);
			goto failed;
		}
	}

	return ni_socket_wrap(fd, SOCK_STREAM);

failed:
	close(fd);
	return NULL;
}

void
__ni_socket_accept(ni_socket_t *master)
{
	ni_socket_t *sock;
	struct ucred cred;
	socklen_t clen;
	int fd;

	fd = accept(master->__fd, NULL, NULL);
	if (fd < 0)
		return;

	clen = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) < 0) {
		ni_error("failed to get client credentials: %m");
		close(fd);
		return;
	}

	sock = __ni_socket_wrap(fd, SOCK_STREAM, &__ni_stream_ops);
	if (master->accept == NULL || master->accept(sock, cred.uid, cred.gid) >= 0) {
		ni_buffer_init_dynamic(&sock->rbuf, ni_global.config->recv_max);
		ni_socket_activate(sock);
	}
	ni_socket_release(sock);
}

/*
 * Create a local socket pair
 */
int
ni_local_socket_pair(ni_socket_t **p1, ni_socket_t **p2)
{
	int fd[2];

	if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, fd) < 0) {
		ni_error("unable to create AF_LOCAL socketpair: %m");
		return -1;
	}

	*p1 = ni_socket_wrap(fd[0], SOCK_DGRAM);
	*p2 = ni_socket_wrap(fd[1], SOCK_DGRAM);
	return 0;
}

/*
 * Generic socket functions (dgram and stream)
 */
static int
__ni_socket_recv_generic(ni_socket_t *sock)
{
	ni_buffer_t *bp = &sock->rbuf;
	int cnt;

	cnt = recv(sock->__fd, ni_buffer_tail(bp), ni_buffer_tailroom(bp), MSG_DONTWAIT);
	if (cnt >= 0) {
		bp->tail += cnt;
	} else if (errno != EWOULDBLOCK) {
		ni_error("recv error on socket: %m");
		ni_socket_deactivate(sock);
	}
	return cnt;
}

static int
__ni_socket_send_generic(ni_socket_t *sock)
{
	ni_buffer_t *bp = &sock->wbuf;
	int cnt;

	cnt = send(sock->__fd, ni_buffer_head(bp), ni_buffer_count(bp), MSG_DONTWAIT);
	if (cnt >= 0) {
		bp->head += cnt;
	} else if (errno != EWOULDBLOCK) {
		ni_error("send error on socket: %m");
		ni_socket_deactivate(sock);
	}

	return cnt;
}

static void
__ni_socket_process_request(ni_socket_t *sock)
{
	if (ni_buffer_count(&sock->rbuf) != 0) {
		int rv;

		/* rbuf contains the data we read from the socket.
		 * Create a memstream that reads from this buffer. */
		__ni_socket_open_rfile(sock, &sock->rbuf);

		/* We want to buffer our response in wbuf. Open a memstream
		 * that writes to the buffer. */
		__ni_socket_open_wfile(sock, &sock->wbuf);

		rv = sock->process_request(sock);

		/* Closing the wfile memstream flushes its content
		 * to wbuf. */
		__ni_socket_set_wfile(sock, NULL);

		/* Get rid of the request; we're done */
		ni_buffer_destroy(&sock->rbuf);

		/* If we have a response, send it back. */
		if (rv >= 0 && ni_buffer_count(&sock->wbuf))
			sock->poll_flags |= POLLOUT;
	}

	if (sock->poll_flags == 0)
		ni_socket_deactivate(sock);
}

static void
__ni_socket_response_sent(ni_socket_t *sock)
{
	ni_buffer_destroy(&sock->wbuf);

	if (sock->shutdown_after_send && sock->stream)
		shutdown(sock->__fd, SHUT_WR);

	sock->poll_flags &= ~POLLOUT;
	if (sock->poll_flags == 0)
		ni_socket_deactivate(sock);
}

/*
 * Datagram sockets
 */
static void
__ni_dgram_receive(ni_socket_t *sock)
{
	ni_buffer_init_dynamic(&sock->rbuf, 65536);
	if (__ni_socket_recv_generic(sock) >= 0)
		__ni_socket_process_request(sock);
}

static void
__ni_dgram_transmit(ni_socket_t *sock)
{
	if (__ni_socket_send_generic(sock) >= 0)
		__ni_socket_response_sent(sock);
}

static int
__ni_socket_dgram_begin_buffering(ni_socket_t *sock)
{
	if (sock->wfile == NULL)
		__ni_socket_open_wfile(sock, &sock->wbuf);
	return 0;
}

static int
__ni_socket_dgram_push(ni_socket_t *sock)
{
	if (sock->wfile == NULL)
		return 0;

	/* Closing the wfile memstream flushes everything to wbuf */
	__ni_socket_set_wfile(sock, NULL);

	if (__ni_socket_send_generic(sock) < 0)
		return -1;

	ni_buffer_destroy(&sock->wbuf);
	return 0;
}

static struct ni_socket_ops __ni_dgram_ops = {
	.begin_buffering = __ni_socket_dgram_begin_buffering,
	.push = __ni_socket_dgram_push,
};

/*
 * Stream sockets
 */
static void
__ni_stream_receive(ni_socket_t *sock)
{
	ni_buffer_t *bp = &sock->rbuf;
	int cnt;

	cnt = __ni_socket_recv_generic(sock);
	if (cnt < 0)
		return;

	if (cnt == 0 || ni_buffer_tailroom(bp) == 0) {
		/* We're done receiving this request. */
		sock->poll_flags &= ~POLLIN;

		__ni_socket_process_request(sock);
	}
}

static void
__ni_stream_transmit(ni_socket_t *sock)
{
	if (__ni_socket_send_generic(sock) < 0)
		return;

	if (ni_buffer_count(&sock->wbuf) == 0)
		__ni_socket_response_sent(sock);
}

static int
__ni_socket_stream_push(ni_socket_t *sock)
{
	if (sock->active) {
		sock->shutdown_after_send = 1;
	} else {
		/* client side socket */
		__ni_socket_set_wfile(sock, NULL);
		shutdown(sock->__fd, SHUT_WR);
	}
	return 0;
}

static struct ni_socket_ops __ni_stream_ops = {
	.push = __ni_socket_stream_push,
};
