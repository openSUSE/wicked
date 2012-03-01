/*
 * Handling of timers in wickedd
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
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

static void			__ni_timer_arm(ni_timer_t *, unsigned long);
static ni_timer_t *		__ni_timer_disarm(const ni_timer_t *);

const ni_timer_t *
ni_timer_register(unsigned long timeout, ni_timeout_callback_t *callback, void *data)
{
	static unsigned int id_counter;
	ni_timer_t *timer;

	timer = xcalloc(1, sizeof(*timer));
	timer->callback = callback;
	timer->user_data = data;
	timer->ident = id_counter++;
	__ni_timer_arm(timer, timeout);

	return timer;
}

void *
ni_timer_cancel(const ni_timer_t *handle)
{
	void *user_data = NULL;
	ni_timer_t *timer;

	if ((timer = __ni_timer_disarm(handle)) != NULL) {
		user_data = timer->user_data;
		free(timer);
	}
	return user_data;
}

const ni_timer_t *
ni_timer_rearm(const ni_timer_t *handle, unsigned long timeout)
{
	 ni_timer_t *timer;

	 if ((timer = __ni_timer_disarm(handle)) != NULL)
		 __ni_timer_arm(timer, timeout);
	 return timer;
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
		timer->callback(timer->user_data, timer);
		free(timer);
	}

	return -1;
}

static void
__ni_timer_arm(ni_timer_t *timer, unsigned long timeout)
{
	ni_timer_t *tail, **pos;

	gettimeofday(&timer->expires, NULL);
	timer->expires.tv_sec += timeout / 1000;
	timer->expires.tv_usec += (timeout % 1000) * 1000;
	if (timer->expires.tv_usec >= 1000000) {
		timer->expires.tv_sec++;
		timer->expires.tv_usec -= 1000000;
	}

	for (pos = &ni_timer_list; (tail = *pos) != NULL; pos = &tail->next) {
		if (timercmp(&timer->expires, &tail->expires, <))
			break;
	}

	timer->next = tail;
	*pos = timer;
}

static ni_timer_t *
__ni_timer_disarm(const ni_timer_t *handle)
{
	ni_timer_t **pos, *timer;

	for (pos = &ni_timer_list; (timer = *pos) != NULL; pos = &timer->next) {
		if (timer == handle) {
			*pos = timer->next;
			timer->next = NULL;
			break;
		}
	}
	return timer;
}
