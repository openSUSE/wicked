/*
 *	Time related functionality for wicked.
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2021 SUSE LLC
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Olaf Kirch
 *		Marius Tomaschewski
 */

#ifndef WICKED_TIME_H
#define WICKED_TIME_H

#include <wicked/types.h>

/*
 * Lifetime is an uint32 in seconds as in dhcp, ipv6 RFCs, ...
 *
 * Timeout is a sufficient type to store lifetimes and timeouts
 * from config files/user options in miliseconds.
 *
 * Jitter is an int range (in miliseconds limitted to +/-24days)
 * to randomize a timeout (usually +/-0.1sec or 1-10sec ranges).
 *
 * We're using timeval for the actual time in microseconds, what
 * allows to use the timeradd, ... <sys/time.h> macros/functions.
 */
#define NI_SECONDS_INFINITE	0xffffffffU

#define NI_LIFETIME_EXPIRED	0U
#define NI_LIFETIME_INFINITE	NI_SECONDS_INFINITE

#define NI_TIMEOUT_UNIT		((ni_timeout_t)1000)
#define NI_TIMEOUT_FROM_SEC(s)	((ni_timeout_t)s * NI_TIMEOUT_UNIT)
#define NI_TIMEOUT_SEC(t)	((unsigned int)(t / NI_TIMEOUT_UNIT))
#define NI_TIMEOUT_MSEC(t)	((unsigned int)(t % NI_TIMEOUT_UNIT))
#define NI_TIMEOUT_USEC(t)	((suseconds_t)(t % NI_TIMEOUT_UNIT) * 1000)

#define NI_TIMEOUT_INFINITE	NI_TIMEOUT_FROM_SEC(NI_SECONDS_INFINITE)

typedef struct ni_timeout_param	ni_timeout_param_t;

struct ni_timeout_param {
	int			nretries;	/* limit the number of retries; < 0 means unlimited */

	ni_timeout_t		timeout;	/* current timeout value, without jitter */
	int			increment;	/* how to change the timeout every time ni_timeout_increase()
						 * is called.
						 * If == 0, timeout stays constant.
						 * If > 0, timeout is incremented by this value every time (linear backoff).
						 * If < 0, timeout is doubled every time (exponential backoff)
						 */
	ni_int_range_t		jitter;		/* randomize timeout in [jitter.min, jitter.max] interval */
	ni_timeout_t		max_timeout;	/* timeout is capped by max_timeout */

	ni_bool_t		(*backoff_callback)(struct ni_timeout_param *);
	int			(*timeout_callback)(void *);
	void			*timeout_data;
};

typedef struct ni_timer		ni_timer_t;
typedef void			ni_timeout_callback_t(void *, const ni_timer_t *);

extern const ni_timer_t *	ni_timer_register(ni_timeout_t, ni_timeout_callback_t *, void *);
extern void *			ni_timer_cancel(const ni_timer_t *);
extern const ni_timer_t *	ni_timer_rearm(const ni_timer_t *, ni_timeout_t);
extern ni_timeout_t		ni_timer_next_timeout(void);
extern int			ni_timer_get_time(struct timeval *);

extern int			ni_time_timer_to_real(const struct timeval *, struct timeval *);
extern int			ni_time_real_to_timer(const struct timeval *, struct timeval *);

extern ni_timeout_t		ni_timeout_arm_sec(struct timeval *, const ni_timeout_param_t *);
extern ni_timeout_t		ni_timeout_arm_msec(struct timeval *, const ni_timeout_param_t *);
extern ni_timeout_t		ni_timeout_randomize(ni_timeout_t, const ni_int_range_t *);
extern ni_bool_t		ni_timeout_recompute(ni_timeout_param_t *);

extern ni_timeout_t		ni_timeout_since(const struct timeval *, const struct timeval *, struct timeval *);
extern ni_timeout_t		ni_timeout_left(const struct timeval *, const struct timeval *, struct timeval *);

extern ni_bool_t		ni_timeval_add_timeout(struct timeval *, ni_timeout_t);

#endif /* WICKED_TIME_H */
