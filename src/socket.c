/*
 * General functions for AF_LOCAL sockets
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/xml.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "socket_priv.h"
#include "appconfig.h"

#define	NI_SOCKET_ARRAY_CHUNK	16

static void			__ni_socket_close(ni_socket_t *);
static void			__ni_default_error_handler(ni_socket_t *);
static void			__ni_default_hangup_handler(ni_socket_t *);

static ni_socket_array_t	__ni_sockets;


/*
 * Install a socket so we check it for incoming data.
 */
ni_bool_t
ni_socket_activate(ni_socket_t *sock)
{
	return ni_socket_array_activate(&__ni_sockets, sock);
}

static inline void
__ni_socket_deactivate(ni_socket_t **slot)
{
	ni_socket_t *sock = *slot;

	*slot = NULL;
	sock->active = NULL;
	ni_socket_release(sock);
}

ni_bool_t
ni_socket_deactivate(ni_socket_t *sock)
{
	if (!sock || !sock->active)
		return FALSE;

	return ni_socket_array_deactivate(sock->active, sock);
}

void
ni_socket_deactivate_all(void)
{
	ni_socket_array_destroy(&__ni_sockets);
}

ni_socket_t *
ni_socket_hold(ni_socket_t *sock)
{
	ni_assert(sock);
	ni_assert(sock->refcount);
	sock->refcount++;
	return sock;
}

void
ni_socket_release(ni_socket_t *sock)
{
	ni_assert(sock);
	ni_assert(sock->refcount);

	sock->refcount--;
	if (sock->refcount == 0) {
		__ni_socket_close(sock);
		ni_assert(!sock->active);
		if (sock->release_user_data)
			sock->release_user_data(sock->user_data);
		free(sock);
	}
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
ni_socket_array_wait(ni_socket_array_t *array, long timeout)
{
	struct pollfd pfd[array->count];
	struct timeval now, expires;
	unsigned int i, socket_count;

	/* First step - cleanup empty socket slots from the array. */
	ni_socket_array_cleanup(array);

	/* Second step - build pollfd array and get timeouts */
	timerclear(&expires);
	socket_count = 0;
	for (i = 0; i < array->count; ++i) {
		ni_socket_t *sock = array->data[i];
		struct timeval socket_expires;

		if (sock->active != array)
			continue;

		timerclear(&socket_expires);
		if (sock->get_timeout && sock->get_timeout(sock, &socket_expires) == 0) {
			if (!timerisset(&expires) || timercmp(&socket_expires, &expires, <))
				expires = socket_expires;
		}

		pfd[socket_count].fd = sock->__fd;
		pfd[socket_count].events = sock->poll_flags;
		socket_count++;
	}

	ni_timer_get_time(&now);
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
		ni_debug_socket("no sockets left to watch");
		return 1;
	}

	if (poll(pfd, socket_count, timeout) < 0) {
		if (errno == EINTR)
			return 0;
		ni_error("poll returns error: %m");
		return -1;
	}

	for (i = 0; i < socket_count; ++i) {
		ni_socket_t *sock = array->data[i];

		if (!sock || sock->active != array)
			continue;

		if (pfd[i].fd != sock->__fd)
			continue;

		ni_socket_hold(sock);

		if (pfd[i].revents & POLLERR) {
			/* Deactivate socket */
			__ni_socket_deactivate(&array->data[i]);
			sock->handle_error(sock);
			goto done_with_this_socket;
		}

		if (pfd[i].revents & POLLIN) {
			if (sock->receive == NULL) {
				ni_error("socket %d has no receive callback", sock->__fd);
				__ni_socket_deactivate(&array->data[i]);
			} else {
				sock->receive(sock);
			}
			if (sock->__fd < 0)
				goto done_with_this_socket;
		}

		if (pfd[i].revents & POLLHUP) {
			if (sock->handle_hangup)
				sock->handle_hangup(sock);
			if (sock->__fd < 0)
				goto done_with_this_socket;
		} else

		if (pfd[i].revents & POLLOUT) {
			if (sock->transmit == NULL) {
				ni_error("socket %d has no transmit callback", sock->__fd);
				__ni_socket_deactivate(&array->data[i]);
			} else {
				sock->transmit(sock);
			}
		}

done_with_this_socket:
		ni_socket_release(sock);
	}

	ni_timer_get_time(&now);
	for (i = 0; i < array->count && i < socket_count; ++i) {
		ni_socket_t *sock = array->data[i];

		if (!sock || sock->active != array)
			continue;

		if (sock->check_timeout)
			sock->check_timeout(sock, &now);
	}

	/* Finally cleanup deactivated/released sockets */
	ni_socket_array_cleanup(array);

	return 0;
}

int
ni_socket_wait(long timeout)
{
	return ni_socket_array_wait(&__ni_sockets, timeout);
}

/*
 * Wrap a file descriptor in a ni_socket object
 */
static ni_socket_t *
__ni_socket_wrap(int fd, int sotype)
{
	ni_socket_t *socket;

	socket = xcalloc(1, sizeof(*socket));
	socket->refcount = 1;
	socket->__fd = fd;

	socket->handle_error = __ni_default_error_handler;
	socket->handle_hangup = __ni_default_hangup_handler;

	return socket;
}

ni_socket_t *
ni_socket_wrap(int fd, int sotype)
{
	if (sotype < 0) {
		socklen_t len = sizeof(sotype);

		if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sotype, &len) < 0) {
			ni_error("%s: cannot determine socket type", __FUNCTION__);
			return NULL;
		}
	}

	return __ni_socket_wrap(fd, sotype);
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
 * Socket array manipulation functions
 */
void
ni_socket_array_init(ni_socket_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_socket_array_destroy(ni_socket_array_t *array)
{
	ni_socket_t *sock;

	if (array) {
		while (array->count--) {
			sock = array->data[array->count];
			array->data[array->count] = NULL;
			if (sock) {
				if (sock->active == array)
					sock->active = NULL;
				ni_socket_release(sock);
			}
		}
		free(array->data);
		memset(array, 0, sizeof(*array));
	}
}

void
ni_socket_array_cleanup(ni_socket_array_t *array)
{
	unsigned int i, j;

	for (i = j = 0; i < array->count; ++i) {
		if (array->data[i])
			array->data[j++] = array->data[i];
	}
	array->count = j;
}

static inline void
__ni_socket_array_realloc(ni_socket_array_t *array, unsigned int newsize)
{
	ni_socket_t **newdata;
	unsigned int i;

	newsize = (newsize + NI_SOCKET_ARRAY_CHUNK);
	newdata = xrealloc(array->data, newsize * sizeof(ni_socket_t *));

	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		array->data[i] = NULL;
}

ni_bool_t
ni_socket_array_append(ni_socket_array_t *array, ni_socket_t *sock)
{
	if (array && sock) {
		if (ni_socket_array_find(array, sock) != -1U)
			return TRUE;

		if ((array->count % NI_SOCKET_ARRAY_CHUNK) == 0)
			__ni_socket_array_realloc(array, array->count);

		array->data[array->count++] = sock;
		return TRUE;
	}
	return FALSE;
}

ni_socket_t *
ni_socket_array_remove_at(ni_socket_array_t *array, unsigned int index)
{
	ni_socket_t *sock;

	if (!array || index >= array->count)
		return NULL;

	sock = array->data[index];
	array->count--;
	if (index < array->count) {
		memmove(&array->data[index], &array->data[index + 1],
			(array->count - index) * sizeof(ni_socket_t *));
	}
	array->data[array->count] = NULL;

	if (sock && sock->active == array)
		sock->active = NULL;
	return sock;
}

ni_socket_t *
ni_socket_array_remove(ni_socket_array_t *array, ni_socket_t *sock)
{
	unsigned int i;

	if (array && sock) {
		for (i = 0; i < array->count; ++i) {
			if (sock != array->data[i])
				continue;
			return ni_socket_array_remove_at(array, i);
		}
	}
	return NULL;
}

unsigned int
ni_socket_array_find(ni_socket_array_t *array, ni_socket_t *sock)
{
	unsigned int i;

	if (array && sock) {
		for (i = 0; i < array->count; ++i) {
			if (sock == array->data[i])
				return i;
		}
	}
	return -1U;
}

ni_bool_t
ni_socket_array_activate(ni_socket_array_t *array, ni_socket_t *sock)
{
	if (!array || !sock)
		return FALSE;

	if (sock->active)
		return sock->active == array;

	if (!ni_socket_array_append(array, sock))
		return FALSE;

	ni_socket_hold(sock);
	sock->active = array;
	sock->poll_flags = POLLIN;
	return TRUE;
}

ni_bool_t
ni_socket_array_deactivate(ni_socket_array_t *array, ni_socket_t *sock)
{
	unsigned int i;

	if (!array || !sock || !sock->active || sock->active != array)
		return FALSE;

	for (i = 0; i < array->count; ++i) {
		if (sock == array->data[i]) {
			ni_socket_array_remove_at(array, i);
			ni_socket_release(sock);
			return TRUE;
		}
	}
	return FALSE;
}
