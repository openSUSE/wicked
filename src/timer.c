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
#include <limits.h>

#include <wicked/time.h>

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

static ni_bool_t		ni_timer_arm(ni_timer_t *, ni_timeout_t);
static ni_timer_t *		ni_timer_disarm(const ni_timer_t *);

static inline void
ni_timer_list_insert(ni_timer_t **list, ni_timer_t *timer)
{
	ni_timer_t *tail, **pos;

	for (pos = list; (tail = *pos) != NULL; pos = &tail->next) {
		if (timercmp(&timer->expires, &tail->expires, <))
			break;
	}
	timer->next = tail;
	*pos = timer;
}

static inline ni_timer_t *
ni_timer_list_remove(ni_timer_t **list, const ni_timer_t *timer)
{
	ni_timer_t **pos, *cur;

	for (pos = list; (cur = *pos) != NULL; pos = &cur->next) {
		if (cur == timer) {
			*pos = cur->next;
			cur->next = NULL;
			return cur;
		}
	}
	return NULL;
}

const ni_timer_t *
ni_timer_register(ni_timeout_t timeout, ni_timeout_callback_t *callback, void *data)
{
	static unsigned int id_counter;
	ni_timer_t *timer;

	if (!(timer = calloc(1, sizeof(*timer))))
		return NULL;

	timer->callback = callback;
	timer->user_data = data;
	if (!(timer->ident = ++id_counter))
		timer->ident = ++id_counter;

	if (ni_timer_arm(timer, timeout)) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p id %x registered with callback %p/%p",
				__func__, timer, timer->ident, callback, data);
		return timer;
	}

	free(timer);
	return NULL;
}

void *
ni_timer_cancel(const ni_timer_t *handle)
{
	void *user_data = NULL;
	ni_timer_t *timer;

	if ((timer = ni_timer_disarm(handle)) != NULL) {
		user_data = timer->user_data;
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p id %x canceled",
				__func__, timer, timer->ident);
		free(timer);
	} else {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p NOT found",
				__func__, handle);
	}
	return user_data;
}

const ni_timer_t *
ni_timer_rearm(const ni_timer_t *handle, ni_timeout_t timeout)
{
	ni_timer_t *timer;

	if ((timer = ni_timer_disarm(handle)) != NULL)
		ni_timer_arm(timer, timeout);
	else
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p NOT found",
				__func__, handle);
	return timer;
}

/**
 * @return next poll timeout - msec as int with -1 for infinite
 */
ni_timeout_t
ni_timer_next_timeout(void)
{
	ni_timeout_t timeout;
	struct timeval now;
	ni_timer_t *timer;

	if (ni_timer_get_time(&now))
		return NI_TIMEOUT_INFINITE;

	while ((timer = ni_timer_list) != NULL) {
		if (timer->expires.tv_sec == LONG_MAX) {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
					"%s: timer %p id %x next timeout is infinite",
					__func__, timer, timer->ident);
			return NI_TIMEOUT_INFINITE;
		}

		timeout = ni_timeout_left(&timer->expires, &now, NULL);
		if (timeout > 0) {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
					"%s: timer %p id %x next timeout in %u.%03u sec",
					__func__, timer, timer->ident,
					NI_TIMEOUT_SEC(timeout), NI_TIMEOUT_MSEC(timeout));
			return timeout;
		}

		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p id %x expired (now=%ld.%06ld, expires=%ld.%06ld)",
				__func__, timer, timer->ident,
				now.tv_sec, now.tv_usec,
				timer->expires.tv_sec, timer->expires.tv_usec);

		ni_timer_list = timer->next;
		timer->callback(timer->user_data, timer);
		free(timer);
	}

	return NI_TIMEOUT_INFINITE;
}

static ni_bool_t
ni_timer_arm(ni_timer_t *timer, ni_timeout_t timeout)
{
	if (!timer || ni_timer_get_time(&timer->expires))
		return FALSE;

	ni_timeval_add_timeout(&timer->expires, timeout);
	ni_timer_list_insert(&ni_timer_list, timer);

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
			"%s: timer %p id %x armed with timeout %u.%03u (expires=%ld.%06ld)",
			__func__, timer, timer->ident,
			NI_TIMEOUT_SEC(timeout), NI_TIMEOUT_MSEC(timeout),
			timer->expires.tv_sec, timer->expires.tv_usec);
	return TRUE;
}

static ni_timer_t *
ni_timer_disarm(const ni_timer_t *handle)
{
	ni_timer_t *timer;

	if (handle && (timer = ni_timer_list_remove(&ni_timer_list, handle))) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p id %x disarmed",
				__func__, timer, timer->ident);
		return timer;
	} else {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timer %p NOT found",
				__func__, handle);
		return NULL;
	}
}

/*
 * boot + real time retrieving
 */
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
	ni_timeout_t timeout;

	if (tmo->nretries == 0)
		return FALSE;

	if (tmo->nretries > 0) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: timeout retry count %d--",
			       __func__, tmo->nretries);
		tmo->nretries--;
	}

	timeout = tmo->timeout;
	if (tmo->increment > 0) {
		tmo->timeout += tmo->increment;

		if (tmo->timeout > tmo->max_timeout) {
			tmo->timeout = tmo->max_timeout;
			tmo->increment = 0;

			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
					"%s: timeout %u.%03u incremented to max timeout %u.%03u",
					__func__, NI_TIMEOUT_SEC(timeout), NI_TIMEOUT_MSEC(timeout),
					NI_TIMEOUT_SEC(tmo->timeout), NI_TIMEOUT_MSEC(tmo->timeout));
		} else {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
					"%s: timeout %u.%03u incremented by %d to %u.03u",
					__func__, NI_TIMEOUT_SEC(timeout), NI_TIMEOUT_MSEC(timeout),
					NI_TIMEOUT_SEC(tmo->timeout), NI_TIMEOUT_MSEC(tmo->timeout));
		}
	} else
	if (tmo->increment < 0) {
		tmo->timeout <<= 1;

		if (tmo->timeout > tmo->max_timeout) {
			tmo->timeout = tmo->max_timeout;
			tmo->increment = 0;

			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
					"%s: timeout %u.%03u doubled to max timeout %u.%03u",
					__func__, NI_TIMEOUT_SEC(timeout), NI_TIMEOUT_MSEC(timeout),
					NI_TIMEOUT_SEC(tmo->timeout), NI_TIMEOUT_MSEC(tmo->timeout));
		} else {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
					"%s: timeout %u.%03u doubled to %u.%03u",
					__func__, NI_TIMEOUT_SEC(timeout), NI_TIMEOUT_MSEC(timeout),
					NI_TIMEOUT_SEC(tmo->timeout), NI_TIMEOUT_MSEC(tmo->timeout));
		}
	}

	if (tmo->backoff_callback) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"%s: calling backoff callback %p/%p",
				__func__, tmo->backoff_callback, tmo);
		return tmo->backoff_callback(tmo);
	}
	return TRUE;
}

ni_timeout_t
ni_timeout_randomize(ni_timeout_t timeout, const ni_int_range_t *jitter)
{
	ni_timeout_t rtimeout = timeout;
	unsigned int range;
	long adj;

	if (timeout >= NI_TIMEOUT_INFINITE)
		return rtimeout;

	if (!jitter || jitter->min >= jitter->max)
		return rtimeout;

	range = (jitter->max - jitter->min);
	adj = ((long)random() % range) + jitter->min;

	if (adj > 0 && (timeout + adj >= NI_TIMEOUT_INFINITE - 1))
		rtimeout = NI_TIMEOUT_INFINITE - 1;
	else
	if (adj < 0 && (timeout < (ni_timeout_t)-adj))
		rtimeout = 0;
	else
		rtimeout += adj;

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
			"timeout %llu randomized by %ld [%d .. %d] to %llu",
			timeout, adj, jitter->min, jitter->max, rtimeout);

	return rtimeout;
}

static ni_timeout_t
ni_timeout_arm_randomized(struct timeval *deadline, ni_timeout_t timeout, const ni_int_range_t *jitter)
{
	if (deadline) {
		timeout = ni_timeout_randomize(timeout, jitter);

		ni_timer_get_time(deadline);
		ni_timeval_add_timeout(deadline, timeout);
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_TIMER,
				"armed randomized timeout %u.%us to execute at %ld.%03ld",
				NI_TIMEOUT_SEC(timeout), NI_TIMEOUT_MSEC(timeout),
				deadline->tv_sec, deadline->tv_usec);
	}
	return timeout;
}

ni_timeout_t
ni_timeout_arm_msec(struct timeval *deadline, const ni_timeout_param_t *tp)
{
	return ni_timeout_arm_randomized(deadline, tp->timeout, &tp->jitter);
}

ni_timeout_t
ni_timeout_arm_sec(struct timeval *deadline, const ni_timeout_param_t *tp)
{
	ni_timeout_t timeout = NI_TIMEOUT_FROM_SEC(tp->timeout);
	ni_int_range_t jitter = tp->jitter;
	jitter.min *= NI_TIMEOUT_UNIT;
	jitter.max *= NI_TIMEOUT_UNIT;
	return ni_timeout_arm_randomized(deadline, timeout, &jitter);
}

ni_bool_t
ni_timeval_add_timeout(struct timeval *tv, ni_timeout_t timeout)
{
	/* We set tv_sec to LONG_MAX on infinite timeout
	 * or up to LONG_MAX - 1 plus tv_msec otherwise.
	 */
	static const ni_timeout_t max = (ni_timeout_t)LONG_MAX - 1;
	ni_timeout_t secs, leap = 0;

	if (!tv)
		return FALSE;

	secs = NI_TIMEOUT_SEC(timeout);
	if (secs >= NI_LIFETIME_INFINITE) {
		tv->tv_sec = LONG_MAX;
		tv->tv_usec = 0;
		return TRUE;
	}

	tv->tv_usec += NI_TIMEOUT_USEC(timeout);
	if (tv->tv_usec >= 1000000) {
		tv->tv_usec -= 1000000;
		leap++;
	}
	if ((ni_timeout_t)tv->tv_sec + secs + leap < max)
		tv->tv_sec += secs + leap;
	else
		tv->tv_sec = max;

	return TRUE;
}

static ni_timeout_t
ni_timeval_delta(const struct timeval *beg, const struct timeval *end, struct timeval *dif)
{
	struct timeval delta;
	ni_timeout_t timeout;

	if (!dif)
		dif = &delta;

	if (!beg || !end || !timercmp(end, beg, >)) {
		timerclear(dif);
		timeout = 0;
	} else {
		timersub(end, beg, dif);
		if ((ni_timeout_t)dif->tv_sec >= (ni_timeout_t)NI_LIFETIME_INFINITE)
			timeout = NI_TIMEOUT_INFINITE;
		else
			timeout = NI_TIMEOUT_FROM_SEC(dif->tv_sec)
				+ dif->tv_usec / 1000;
	}
	return timeout;
}

ni_timeout_t
ni_timeout_since(const struct timeval *acquired, const struct timeval *now, struct timeval *since)
{
	struct timeval current;	/* since|uptime = now > acquired ? now - acquired : 0 */

	if (!now && ni_timer_get_time(&current) == 0)
		now = &current;

	return ni_timeval_delta(acquired, now, since);
}

ni_timeout_t
ni_timeout_left(const struct timeval *expires, const struct timeval *now, struct timeval *left)
{
	struct timeval current;	/* left = expires > now ? expires - now : 0 */

	if (!now && ni_timer_get_time(&current) == 0)
		now = &current;

	return ni_timeval_delta(now, expires, left);
}

