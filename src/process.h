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

struct ni_shellcmd {
	unsigned int		refcount;

	char *			command;

	ni_string_array_t	argv;
	ni_string_array_t	environ;

	unsigned int		timeout;
};

struct ni_process {
	ni_shellcmd_t *		process;

	pid_t			pid;
	int			status;
	ni_socket_t *		socket;

	ni_string_array_t	argv;
	ni_string_array_t	environ;

	ni_tempstate_t *	temp_state;

	void			(*notify_callback)(ni_process_t *);
	void *			user_data;
};

extern ni_shellcmd_t *		ni_shellcmd_new(const ni_string_array_t *args);
extern ni_shellcmd_t *		ni_shellcmd_parse(const char *command);
extern ni_bool_t		ni_shellcmd_add_arg(ni_shellcmd_t *, const char *);
extern ni_bool_t		ni_shellcmd_fmt_arg(ni_shellcmd_t *, const char *, ...);
extern void			ni_shellcmd_setenv(ni_shellcmd_t *, const char *, const char *);

extern ni_shellcmd_t *		ni_shellcmd_hold(ni_shellcmd_t *);
extern void			ni_shellcmd_free(ni_shellcmd_t *);
static inline void		ni_shellcmd_release(ni_shellcmd_t *cmd)
{
	ni_shellcmd_free(cmd);
}

/*
 * ni_process_run functions return 0 on success, positive
 * child exit status code or the following negative errors.
 */
enum {
	NI_PROCESS_SUCCESS	=  0,	/* success                         */
	NI_PROCESS_FAILURE	= -1,	/* generic (before fork) failure   */
	NI_PROCESS_COMMAND	= -2,	/* command is not executable       */
	NI_PROCESS_IOERROR	= -3,	/* child pipe/socket i/o error     */
	NI_PROCESS_WAITPID	= -4,	/* failed to retrieve child status */
	NI_PROCESS_TERMSIG	= -5,	/* child process died with signal  */
	NI_PROCESS_UNKNOWN	= -6,	/* unknown (post fork) failure     */
};

extern ni_process_t *		ni_process_new(ni_shellcmd_t *);
extern int			ni_process_run(ni_process_t *);
extern int			ni_process_run_and_wait(ni_process_t *);
extern int			ni_process_run_and_capture_output(ni_process_t *, ni_buffer_t *);
extern void			ni_process_setenv(ni_process_t *, const char *, const char *);
extern const char *		ni_process_getenv(const ni_process_t *, const char *);
extern ni_tempstate_t *		ni_process_tempstate(ni_process_t *);
extern void			ni_process_free(ni_process_t *);

extern ni_bool_t		ni_process_running(const ni_process_t *);

extern ni_bool_t		ni_process_exited(const ni_process_t *);
extern int			ni_process_exit_status(const ni_process_t *);
extern int			ni_process_exit_status_okay(const ni_process_t *);

extern ni_bool_t		ni_process_signaled(const ni_process_t *);
extern ni_bool_t		ni_process_core_dumped(const ni_process_t *);
extern int			ni_process_term_signal(const ni_process_t *);

extern ni_bool_t		ni_process_stopped(const ni_process_t *);
extern ni_bool_t		ni_process_continued(const ni_process_t *);
extern int			ni_process_stop_signal(const ni_process_t *);

#endif /* __WICKED_PROCESS_H__ */
