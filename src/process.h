/*
 *	Execute the requested process (almost) as if it were a setuid process
 *
 *	Copyright (C) 2002-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2023 SUSE LLC
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
#ifndef NI_WICKED_PROCESS_H
#define NI_WICKED_PROCESS_H

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
	struct timeval		started;

	int			(*exec)(int argc, char *const argv[], char *const envp[]);
	ni_string_array_t	argv;
	ni_string_array_t	environ;

	ni_socket_t *		socket;
	ni_tempstate_t *	temp_state;

	void			(*notify_callback)(ni_process_t *);
	void *			user_data;
};

extern ni_shellcmd_t *		ni_shellcmd_new(const ni_string_array_t *args);
extern ni_shellcmd_t *		ni_shellcmd_parse(const char *command);
extern ni_bool_t		ni_shellcmd_add_arg(ni_shellcmd_t *, const char *);
extern ni_bool_t		ni_shellcmd_fmt_arg(ni_shellcmd_t *, const char *, ...);

extern const char *		ni_shellcmd_getenv(const ni_shellcmd_t *, const char *);
extern ni_bool_t		ni_shellcmd_setenv(ni_shellcmd_t *, const char *, const char *);
extern ni_bool_t		ni_shellcmd_getenv_vars(const ni_shellcmd_t *, ni_var_array_t *);
extern ni_bool_t		ni_shellcmd_setenv_vars(ni_shellcmd_t *, const ni_var_array_t *,
						ni_bool_t);

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
extern const char *		ni_process_getenv(const ni_process_t *, const char *);
extern ni_bool_t		ni_process_setenv(ni_process_t *, const char *,
						const char *);
extern ni_bool_t		ni_process_getenv_vars(const ni_process_t *,
						ni_var_array_t *);
extern ni_bool_t		ni_process_setenv_vars(ni_process_t *,
						const ni_var_array_t *, ni_bool_t);

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

/*
 * ni_shellcmd and ni_process (execve) environ utilities.
 */
extern const char *		ni_environ_getenv(const ni_string_array_t *, const char *);
extern ni_bool_t		ni_environ_setenv(ni_string_array_t *, const char *, const char *);
extern ni_bool_t		ni_environ_setenv_entry(ni_string_array_t *, const char *);
extern ni_bool_t		ni_environ_setenv_entries(ni_string_array_t *,
						const ni_string_array_t *);
extern ni_bool_t		ni_environ_getenv_vars(const ni_string_array_t *, ni_var_array_t *);
extern ni_bool_t		ni_environ_setenv_vars(ni_string_array_t *, const ni_var_array_t *,
						ni_bool_t);

#endif /* NI_WICKED_PROCESS_H */
