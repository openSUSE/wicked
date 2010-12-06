/*
 * Handling of timers in wickedd
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/time.h>
#include <stdlib.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"

struct ni_timer {
	ni_timer_t *		next;
	unsigned int		ident;
	struct timeval		expires;
	ni_timeout_callback_t	*callback;
	void *			user_data;
};

static ni_timer_t *		ni_timer_list;

const ni_timer_t *
ni_timer_register(unsigned long timeout, ni_timeout_callback_t *callback, void *data)
{
	static unsigned int id_counter;
	ni_timer_t *timer, *tail, **pos;

	timer = xcalloc(1, sizeof(*timer));
	timer->callback = callback;
	timer->user_data = data;
	gettimeofday(&timer->expires, NULL);
	timer->expires.tv_sec += timeout / 1000;
	timer->expires.tv_usec += (timeout % 1000) * 1000;
	if (timer->expires.tv_usec >= 1000000) {
		timer->expires.tv_sec++;
		timer->expires.tv_usec -= 1000000;
	}

	timer->ident = id_counter++;

	for (pos = &ni_timer_list; (tail = *pos) != NULL; pos = &tail->next) {
		if (timercmp(&timer->expires, &tail->expires, <))
			break;
	}

	timer->next = tail;
	*pos = timer;

	return timer;
}

void *
ni_timer_cancel(const ni_timer_t *handle)
{
	ni_timer_t **pos, *timer;
	void *user_data = NULL;

	for (pos = &ni_timer_list; (timer = *pos) != NULL; pos = &timer->next) {
		if (timer == handle) {
			*pos = timer->next;
			user_data = timer->user_data;
			free(timer);
			break;
		}
	}
	return user_data;
}

long
ni_timer_next_timeout(void)
{
	struct timeval now, delta;
	ni_timer_t *timer;

	gettimeofday(&now, NULL);
	while ((timer = ni_timer_list) != NULL) {
		if (timercmp(&timer->expires, &now, >)) {
			timersub(&timer->expires, &now, &delta);
			return delta.tv_sec * 1000 + delta.tv_usec / 1000;
		}

#if 0
		ni_trace("timer %p expires (now=%ld.%06lu, expires=%ld.%06lu)", timer,
				(long) now.tv_sec, (long) now.tv_usec,
				(long) timer->expires.tv_sec, (long) timer->expires.tv_usec);
#endif
		ni_timer_list = timer->next;
		timer->callback(timer->user_data);
		free(timer);
	}

	return -1;
}
