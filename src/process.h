/*
 * Execute the requested process (almost) as if it were a
 * setuid process
 *
 * Copyright (C) 2002-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_PROCESS_H__
#define __WICKED_PROCESS_H__

#include <wicked/logging.h>
#include <wicked/util.h>

struct ni_process {
	unsigned int		refcount;

	char *			command;
	ni_string_array_t	environ;

	unsigned int		timeout;
};

struct ni_process_instance {
	ni_process_t *		process;

	pid_t			pid;
	int			status;
	ni_socket_t *		socket;

	ni_string_array_t	argv;
	ni_string_array_t	environ;

	void			(*notify_callback)(ni_process_instance_t *);
	void *			user_data;
};

extern int			ni_process_instance_run(ni_process_instance_t *);
extern void			ni_process_instance_free(ni_process_instance_t *);
extern void			ni_process_free(ni_process_t *);

static inline ni_process_t *
ni_process_hold(ni_process_t *proc)
{
	ni_assert(proc->refcount);
	proc->refcount++;
	return proc;
}

static inline void
ni_process_release(ni_process_t *proc)
{
	ni_assert(proc->refcount);
	if (--(proc->refcount) == 0)
		ni_process_free(proc);
}

#endif /* __WICKED_PROCESS_H__ */
