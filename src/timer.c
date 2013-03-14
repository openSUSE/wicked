/*
 * Handling of timers in wickedd
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "util_priv.h"

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
	long timeout;

	ni_timer_get_time(&now);
	while ((timer = ni_timer_list) != NULL) {
		if (!timercmp(&timer->expires, &now, <)) {
			timersub(&timer->expires, &now, &delta);
			timeout = delta.tv_sec * 1000 + delta.tv_usec / 1000;
			if (timeout > 0)
				return timeout;
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

	ni_timer_get_time(&timer->expires);
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

int
ni_timer_get_time(struct timeval *tv)
{
#if 0
/*  defined(WITH_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC) */
	/*
	 * Note: Requires to link using -lrt
	 */
	static int use_monotonic = 1;

	if (use_monotonic == 1) {
		use_monotonic = clock_getres(CLOCK_MONOTONIC, NULL);
	}
	if (use_monotonic == 0) {
		struct timespec now;
		int ret;

		ret = clock_gettime(CLOCK_MONOTONIC, &now);
		TIMESPEC_TO_TIMEVAL(tv, &now);

		return ret;
	}
#endif
	return gettimeofday(tv, NULL);
}

/*
 * Timeout handling
 */
ni_bool_t
ni_timeout_recompute(ni_timeout_param_t *tmo)
{
	if (tmo->nretries == 0)
		return FALSE;

	if (tmo->increment >= 0)
		tmo->timeout += tmo->increment;
	else
		tmo->timeout <<= 1;
	if (tmo->timeout > tmo->max_timeout)
		tmo->timeout = tmo->max_timeout;

	if (tmo->backoff_callback)
		return tmo->backoff_callback(tmo);
	return TRUE;
}

static unsigned long
__ni_timeout_arm_msec(struct timeval *deadline, unsigned long timeout, const ni_int_range_t *jitter)
{
	timeout = ni_timeout_randomize(timeout, jitter);

	ni_debug_socket("arming retransmit timer (%lu msec)", timeout);
	ni_timer_get_time(deadline);
	deadline->tv_sec += timeout / 1000;
	deadline->tv_usec += (timeout % 1000) * 1000;
	if (deadline->tv_usec < 0) {
		deadline->tv_sec -= 1;
		deadline->tv_usec += 1000000;
	} else
	if (deadline->tv_usec > 1000000) {
		deadline->tv_sec += 1;
		deadline->tv_usec -= 1000000;
	}
	return timeout;
}

unsigned long
ni_timeout_randomize(unsigned long timeout, const ni_int_range_t *jitter)
{
	if (jitter && jitter->min < jitter->max) {
		unsigned int jitter_range = (jitter->max - jitter->min);
		timeout += ((long) random() % jitter_range) + jitter->min;
	}
	return timeout;
}

unsigned long
ni_timeout_arm_msec(struct timeval *deadline, const ni_timeout_param_t *tp)
{
	return __ni_timeout_arm_msec(deadline, tp->timeout, &tp->jitter);
}

unsigned long
ni_timeout_arm(struct timeval *deadline, const ni_timeout_param_t *tp)
{
	ni_int_range_t jitter = tp->jitter;
	jitter.min *= 1000;
	jitter.max *= 1000;
	return __ni_timeout_arm_msec(deadline, tp->timeout * 1000, &jitter);
}

