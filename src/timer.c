/*
 * Handling of timers in wickedd
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>
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
	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
			"%s: new timer %p id %x, callback %p/%p",
			__func__, timer, timer->ident, callback, data);
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
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: released timer %p", __func__, timer);
	} else {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p NOT found", __func__, handle);
	}
	return user_data;
}

const ni_timer_t *
ni_timer_rearm(const ni_timer_t *handle, unsigned long timeout)
{
	 ni_timer_t *timer;

	 if ((timer = __ni_timer_disarm(handle)) != NULL)
		 __ni_timer_arm(timer, timeout);
	 else
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p NOT found", __func__, handle);
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
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
					"%s: timer %p timeout %ld", __func__, timer, timeout);
			if (timeout > 0)
				return timeout;
		}

		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p expired (now=%ld.%06lu, expires=%ld.%06lu)",
				__func__, timer,
				(long) now.tv_sec, (long) now.tv_usec,
				(long) timer->expires.tv_sec, (long) timer->expires.tv_usec);
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

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
			"%s: timer %p timeout %lu", __func__, timer, timeout);
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
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
					"%s: timer %p found", __func__, handle);
			return timer;
		}
	}
	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
			"%s: timer %p NOT found", __func__, handle);
	return NULL;
}

static inline int
ni_time_get_realtime(struct timeval *tv)
{
	struct timespec ts;
	int ret;

	if ((ret = clock_gettime(CLOCK_REALTIME, &ts)) == 0)
		TIMESPEC_TO_TIMEVAL(tv, &ts);

	return ret;
}

static inline int
ni_time_get_monotonic(struct timeval *tv)
{
	struct timespec ts;
	int ret;

	if ((ret = clock_gettime(CLOCK_MONOTONIC, &ts)) == 0)
		TIMESPEC_TO_TIMEVAL(tv, &ts);

	return ret;
}

static inline int
ni_time_get_boottime(struct timeval *tv)
{
	struct timespec ts;
	int ret;

	if ((ret = clock_gettime(CLOCK_BOOTTIME, &ts)) == 0)
		TIMESPEC_TO_TIMEVAL(tv, &ts);

	return ret;
}

int
ni_timer_get_time(struct timeval *tv)
{
	return ni_time_get_boottime(tv);
}

/*
 * The wallclock time has to be used in leases when stored on disk
 */
int
ni_time_timer_to_real(const struct timeval *ttime, struct timeval *real)
{
	struct timeval tnow, rnow, diff;
	int ret;

	if (!ttime || !real)
		return -1;

	if (!timerisset(ttime)) {
		ni_warn("%s: timer time reference unset", __func__);
		return ni_time_get_realtime(real);
	}

	if ((ret = ni_timer_get_time(&tnow)) != 0)
		return ret;

	if ((ret = ni_time_get_realtime(&rnow)) != 0)
		return ret;

	timersub(&tnow, ttime, &diff);
	timersub(&rnow, &diff, real);
	return 0;
}

int
ni_time_real_to_timer(const struct timeval *real, struct timeval *ttime)
{
	struct timeval tnow, rnow, diff;
	int ret;

	if (!ttime || !real)
		return -1;

	if (!timerisset(real)) {
		ni_warn("%s: real time reference unset", __func__);
		return ni_timer_get_time(ttime);
	}

	if ((ret = ni_timer_get_time(&tnow)) != 0)
		return ret;

	if ((ret = ni_time_get_realtime(&rnow)) != 0)
		return ret;

	timersub(&rnow, real, &diff);
	timersub(&tnow, &diff, ttime);
	return 0;
}

/*
 * Timeout handling
 */
ni_bool_t
ni_timeout_recompute(ni_timeout_param_t *tmo)
{
	if (tmo->nretries == 0)
		return FALSE;
	else if (tmo->nretries > 0)
		tmo->nretries--;

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

	ni_debug_timer("arming retransmit timer (%lu msec)", timeout);
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
		long adj = ((long) random() % jitter_range) + jitter->min;
		ni_debug_timer("timeout %lu adjusted by %ld to %lu (jr %u)",
				timeout, adj, timeout + adj, jitter_range);
		timeout += adj;
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

