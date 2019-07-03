/*
 * Support rfkill.
 * This is a rather simplified implementation, in that all
 * rfkill switches are made to apply to all radio devices.
 * We ignore any of the device/kill switch mapping that is
 * available through sysfs.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/socket.h>
#include <wicked/wireless.h>
#include "socket_priv.h"

#include <linux/rfkill.h>

typedef struct ni_rfkill_switch ni_rfkill_switch_t;
struct ni_rfkill_switch {
	ni_rfkill_switch_t *	next;

	unsigned int		idx;
	unsigned int		type;
	ni_bool_t		soft_blocked;
	ni_bool_t		hard_blocked;
};

static ni_rfkill_event_handler_t *ni_rfkill_callback;
static void *			ni_rfkill_callback_data;
static ni_socket_t *		ni_rfkill_socket;
static ni_rfkill_switch_t *	ni_rfkill_switches;

static ni_bool_t		ni_rfkill_state[__NI_RFKILL_TYPE_MAX];

static void			__ni_rfkill_recv(ni_socket_t *);

int
ni_rfkill_open(ni_rfkill_event_handler_t *callback, void *user_data)
{
	int fd;

	if (ni_rfkill_socket)
		return 0;

	if ((fd = open("/dev/rfkill", O_RDONLY | O_NONBLOCK)) < 0) {
		if (errno != ENOENT)
			ni_error("cannot open /dev/rfkill: %m");
		return -1;
	}

	ni_rfkill_socket = ni_socket_wrap(fd, SOCK_STREAM);
	if (ni_rfkill_socket == NULL) {
		close(fd);
		return -1;
	}

	ni_rfkill_socket->receive = __ni_rfkill_recv;

	ni_socket_activate(ni_rfkill_socket);
	ni_rfkill_callback = callback;
	ni_rfkill_callback_data = user_data;
	return 0;
}

void
ni_rfkill_close(void)
{
	if (ni_rfkill_socket) {
		ni_socket_close(ni_rfkill_socket);
		ni_rfkill_socket = NULL;
	}
}

void
__ni_rfkill_recv(ni_socket_t *sock)
{
	struct rfkill_event ev;
	ni_rfkill_switch_t *sw;
	ni_bool_t state[__NI_RFKILL_TYPE_MAX];
	unsigned int type;
	ssize_t n;

	while ((n = read(sock->__fd, &ev, sizeof(ev))) >= 0) {
		ni_rfkill_switch_t **pos;

		if ((size_t)n < sizeof(ev)) {
			ni_error("cannot read rfkill event: short read");
			ni_socket_deactivate(sock);
			break;
		}

		for (pos = &ni_rfkill_switches; (sw = *pos) != NULL; pos = &sw->next) {
			if (sw->idx == ev.idx)
				break;
		}

#if 0
		ni_debug_wireless("rfkill event, idx=%u, op=%u, type=%u, soft=%u, hard=%u",
				ev.idx, ev.op, ev.type, ev.soft, ev.hard);
#endif

		if (ev.op == RFKILL_OP_DEL) {
			if (sw != NULL) {
				*pos = sw->next;
				free(sw);
			}
		} else {
			if (sw == NULL) {
				*pos = sw = xcalloc(1, sizeof(*sw));
				sw->idx = ev.idx;
				sw->type = ev.type;
			}

			sw->soft_blocked = ev.soft;
			sw->hard_blocked = ev.hard;
		}
	}

	memset(state, 0, sizeof(state));
	for (sw = ni_rfkill_switches; sw != NULL; sw = sw->next) {
		if (!sw->soft_blocked && !sw->hard_blocked)
			continue;

		switch (sw->type) {
		case RFKILL_TYPE_ALL:
			for (type = 0; type < __NI_RFKILL_TYPE_MAX; ++type)
				state[type] = TRUE;
			break;

		case RFKILL_TYPE_BLUETOOTH:
			state[NI_RFKILL_TYPE_BLUETOOTH] = TRUE;
			break;

		default:
			state[NI_RFKILL_TYPE_WIRELESS] = TRUE;
			break;
		}
	}

	for (type = 0; type < __NI_RFKILL_TYPE_MAX; ++type) {
		if (ni_rfkill_state[type] != state[type]) {
			ni_rfkill_state[type] = state[type];
			if (ni_rfkill_callback)
				ni_rfkill_callback(type, ni_rfkill_state[type], ni_rfkill_callback_data);
		}
	}
}

const char *
ni_rfkill_type_string(ni_rfkill_type_t type)
{
	switch (type) {
	case NI_RFKILL_TYPE_WIRELESS:
		return "wireless";

	case NI_RFKILL_TYPE_BLUETOOTH:
		return "bluetooth";

	case NI_RFKILL_TYPE_MOBILE:
		return "mobile";

	default: ;
	}

	return "unknown";
}

ni_bool_t
ni_rfkill_disabled(ni_rfkill_type_t type)
{
	if (type >= __NI_RFKILL_TYPE_MAX)
		return FALSE;

	return ni_rfkill_state[type];
}

