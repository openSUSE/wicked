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

typedef	struct ni_timeout_param	ni_timeout_param_t;

struct ni_timeout_param {
	int			nretries;	/* limit the number of retries; < 0 means unlimited */

	unsigned int		timeout;	/* current timeout value, without jitter */
	int			increment;	/* how to change the timeout every time ni_timeout_increase()
						 * is called.
						 * If == 0, timeout stays constant.
						 * If > 0, timeout is incremented by this value every time (linear backoff).
						 * If < 0, timeout is doubled every time (exponential backoff)
						 */
	ni_int_range_t		jitter;		/* randomize timeout in [jitter.min, jitter.max] interval */
	unsigned int		max_timeout;	/* timeout is capped by max_timeout */

	ni_bool_t		(*backoff_callback)(struct ni_timeout_param *);
	int			(*timeout_callback)(void *);
	void			*timeout_data;
};

typedef struct ni_timer		ni_timer_t;
typedef void			ni_timeout_callback_t(void *, const ni_timer_t *);

extern const ni_timer_t *	ni_timer_register(unsigned long, ni_timeout_callback_t *, void *);
extern void *			ni_timer_cancel(const ni_timer_t *);
extern const ni_timer_t *	ni_timer_rearm(const ni_timer_t *, unsigned long);
extern long			ni_timer_next_timeout(void);
extern int			ni_timer_get_time(struct timeval *tv);

extern int			ni_time_timer_to_real(const struct timeval *, struct timeval *);
extern int			ni_time_real_to_timer(const struct timeval *, struct timeval *);

extern unsigned long		ni_timeout_arm(struct timeval *, const ni_timeout_param_t *);
extern unsigned long		ni_timeout_arm_msec(struct timeval *, const ni_timeout_param_t *);
extern unsigned long		ni_timeout_randomize(unsigned long timeout, const ni_int_range_t *jitter);
extern ni_bool_t		ni_timeout_recompute(ni_timeout_param_t *);

#endif /* WICKED_TIME_H */
