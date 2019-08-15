/*
 * Network socket related functionality for wicked.
 * No user serviceable parts inside.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_SOCKET_H__
#define __WICKED_SOCKET_H__

#include <stdio.h>

#include <wicked/types.h>
#include <sys/types.h>

typedef struct ni_timeout_param {
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
} ni_timeout_param_t;

typedef struct ni_timer	ni_timer_t;
typedef void		ni_timeout_callback_t(void *, const ni_timer_t *);

extern const ni_timer_t *ni_timer_register(unsigned long, ni_timeout_callback_t *, void *);
extern void *		ni_timer_cancel(const ni_timer_t *);
extern const ni_timer_t *ni_timer_rearm(const ni_timer_t *, unsigned long);
extern long		ni_timer_next_timeout(void);
extern int		ni_timer_get_time(struct timeval *tv);
extern int		ni_time_timer_to_real(const struct timeval *, struct timeval *);
extern int		ni_time_real_to_timer(const struct timeval *, struct timeval *);

extern ni_socket_t *	ni_socket_hold(ni_socket_t *);
extern void		ni_socket_release(ni_socket_t *);
extern ni_socket_t *	ni_socket_wrap(int fd, int sotype);
extern ni_bool_t	ni_socket_activate(ni_socket_t *);
extern ni_bool_t	ni_socket_deactivate(ni_socket_t *);
extern void		ni_socket_deactivate_all(void);
extern int		ni_socket_wait(long timeout);

extern void		ni_socket_close(ni_socket_t *);

extern unsigned long	ni_timeout_arm(struct timeval *, const ni_timeout_param_t *);
extern unsigned long	ni_timeout_arm_msec(struct timeval *, const ni_timeout_param_t *);
extern unsigned long	ni_timeout_randomize(unsigned long timeout, const ni_int_range_t *jitter);
extern ni_bool_t	ni_timeout_recompute(ni_timeout_param_t *);

#endif /* __WICKED_SOCKET_H__ */

