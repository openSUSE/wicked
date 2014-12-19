/*
 * Execute the requested process (almost) as if it were a setuid process.
 *
 * Copyright (C) 2002-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <wicked/logging.h>
#include <wicked/socket.h>
#include "socket_priv.h"
#include "process.h"

static int				__ni_process_run(ni_process_t *, int *);
static ni_socket_t *			__ni_process_get_output(ni_process_t *, int);
static const ni_string_array_t *	__ni_default_environment(void);

static inline ni_bool_t
__ni_shellcmd_parse(ni_string_array_t *argv, const char *command)
{
	if (ni_string_split(argv, command, " \t", 0) == 0)
		return FALSE;
	return TRUE;
}

static inline const char *
__ni_shellcmd_format(char **cmd, const ni_string_array_t *argv)
{
	return ni_string_join(cmd, argv, " ");
}

static void
__ni_shellcmd_free(ni_shellcmd_t *cmd)
{
	ni_string_free(&cmd->command);
	ni_string_array_destroy(&cmd->argv);
	ni_string_array_destroy(&cmd->environ);
	free(cmd);
}

/*
 * Create a process description
 */
ni_shellcmd_t *
ni_shellcmd_new(const ni_string_array_t *argv)
{
	ni_shellcmd_t *cmd;
	unsigned int i;

	cmd = xcalloc(1, sizeof(*cmd));
	cmd->refcount = 1;
	if (!argv)
		return cmd;

	for (i = 0; i < argv->count; ++i) {
		const char *arg = argv->data[i];

		if (ni_string_empty(arg)) {
			__ni_shellcmd_free(cmd);
			return NULL;
		}

		if (ni_string_array_append(&cmd->argv, arg) < 0) {
			__ni_shellcmd_free(cmd);
			return NULL;
		}
	}

	if (__ni_shellcmd_format(&cmd->command, &cmd->argv) == NULL) {
		__ni_shellcmd_free(cmd);
		return NULL;
	}
	if (ni_string_array_copy(&cmd->environ, __ni_default_environment()) < 0) {
		__ni_shellcmd_free(cmd);
		return NULL;
	}
	return cmd;
}

ni_shellcmd_t *
ni_shellcmd_parse(const char *command)
{
	ni_shellcmd_t *cmd;

	if (ni_string_empty(command))
		return NULL;

	cmd = xcalloc(1, sizeof(*cmd));
	cmd->refcount = 1;

	ni_string_dup(&cmd->command, command);
	if (!__ni_shellcmd_parse(&cmd->argv, cmd->command)) {
		__ni_shellcmd_free(cmd);
		return NULL;
	}
	if (ni_string_array_copy(&cmd->environ, __ni_default_environment()) < 0) {
		__ni_shellcmd_free(cmd);
		return NULL;
	}

	return cmd;
}

ni_bool_t
ni_shellcmd_fmt_arg(ni_shellcmd_t *cmd, const char *fmt, ...)
{
	char *arg = NULL;
	va_list ap;
	int ret;

	if (!cmd || ni_string_empty(fmt))
		return FALSE;

	va_start(ap, fmt);
	ret = vasprintf(&arg, fmt, ap);
	va_end(ap);
	if (ret < 0)
		return FALSE;

	if (!ni_shellcmd_add_arg(cmd, arg)) {
		ni_string_free(&arg);
		return FALSE;
	}
	ni_string_free(&arg);
	return TRUE;
}

ni_bool_t
ni_shellcmd_add_arg(ni_shellcmd_t *cmd, const char *arg)
{
	if (!cmd || ni_string_empty(arg))
		return FALSE;

	if (ni_string_array_append(&cmd->argv, arg) < 0)
		return FALSE;

	if (__ni_shellcmd_format(&cmd->command, &cmd->argv) == NULL)
		return FALSE;

	return TRUE;
}

ni_shellcmd_t *
ni_shellcmd_hold(ni_shellcmd_t *cmd)
{
	if (cmd) {
		ni_assert(cmd->refcount);
		cmd->refcount++;
		return cmd;
	}
	return NULL;
}

void
ni_shellcmd_free(ni_shellcmd_t *cmd)
{
	if (cmd) {
		ni_assert(cmd->refcount);
		cmd->refcount--;
		if (cmd->refcount == 0)
			__ni_shellcmd_free(cmd);
	}
}


ni_process_t *
ni_process_new(ni_shellcmd_t *proc)
{
	ni_process_t *pi;

	pi = xcalloc(1, sizeof(*pi));

	pi->process = ni_shellcmd_hold(proc);

	/* Copy the command array */
	ni_string_array_copy(&pi->argv, &proc->argv);

	/* Copy the environment */
	ni_string_array_copy(&pi->environ, &proc->environ);

	return pi;
}

void
ni_process_free(ni_process_t *pi)
{
	if (pi->pid) {
		if (kill(pi->pid, SIGKILL) < 0)
			ni_error("Unable to kill process %d (%s): %m", pi->pid, pi->process->command);
	}

	if (pi->socket != NULL) {
		ni_socket_close(pi->socket);
		pi->socket = NULL;
	}

	if (pi->temp_state != NULL) {
		ni_tempstate_finish(pi->temp_state);
		pi->temp_state = NULL;
	}

	ni_string_array_destroy(&pi->argv);
	ni_string_array_destroy(&pi->environ);
	ni_shellcmd_release(pi->process);
	free(pi);
}

/*
 * Setting environment variables
 */
static void
__ni_process_setenv(ni_string_array_t *env, const char *name, const char *value)
{
	unsigned int namelen = strlen(name), totlen;
	unsigned int i;
	char *newvar;

	totlen = namelen + strlen(value) + 2;
	newvar = malloc(totlen);
	snprintf(newvar, totlen, "%s=%s", name, value);

	for (i = 0; i < env->count; ++i) {
		char *oldvar = env->data[i];

		if (!strncmp(oldvar, name, namelen) && oldvar[namelen] == '=') {
			env->data[i] = newvar;
			free(oldvar);
			return;
		}
	}

	ni_string_array_append(env, newvar);
	free(newvar);
}

void
ni_shellcmd_setenv(ni_shellcmd_t *proc, const char *name, const char *value)
{
	__ni_process_setenv(&proc->environ, name, value);
}

void
ni_process_setenv(ni_process_t *pi, const char *name, const char *value)
{
	__ni_process_setenv(&pi->environ, name, value);
}

/*
 * Getting environment variables
 */
static const char *
__ni_process_getenv(const ni_string_array_t *env, const char *name)
{
	unsigned int namelen = strlen(name);
	unsigned int i;

	for (i = 0; i < env->count; ++i) {
		char *oldvar = env->data[i];

		if (!strncmp(oldvar, name, namelen) && oldvar[namelen] == '=') {
			oldvar += namelen + 1;
			return oldvar[0]? oldvar : NULL;
		}
	}

	return NULL;
}

const char *
ni_process_getenv(const ni_process_t *pi, const char *name)
{
	return __ni_process_getenv(&pi->environ, name);
}

/*
 * Populate default environment
 */
static const ni_string_array_t *
__ni_default_environment(void)
{
	static ni_string_array_t defenv;
	static int initialized = 0;
	static const char *copy_env[] = {
		"LD_LIBRARY_PATH",
		"LD_PRELOAD",
		"PATH",

		NULL,
	};

	if (!initialized) {
		const char **envpp, *name;

		for (envpp = copy_env; (name = *envpp) != NULL; ++envpp) {
			const char *value;

			if ((value = getenv(name)) != NULL)
				__ni_process_setenv(&defenv, name, value);
		}
		initialized = 1;
	}

	return &defenv;
}

/*
 * Create a temp state for this process; this state will track
 * temporary resources like tempfiles
 */
ni_tempstate_t *
ni_process_tempstate(ni_process_t *process)
{
	if (process->temp_state == NULL)
		process->temp_state = ni_tempstate_new(NULL);

	return process->temp_state;
}

/*
 * Catch sigchild
 */
static void
ni_process_sigchild(int sig)
{
	/* nop for now */
}

/*
 * Run a subprocess.
 */
int
ni_process_run(ni_process_t *pi)
{
	int pfd[2],  rv;

	/* Our code in socket.c is only able to deal with sockets for now; */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pfd) < 0) {
		ni_error("%s: unable to create pipe: %m", __func__);
		return -1;
	}

	rv = __ni_process_run(pi, pfd);
	if (rv >= 0) {
		/* Set up a socket to receive the redirected output of the
		 * subprocess. */
		pi->socket = __ni_process_get_output(pi, pfd[0]);
		ni_socket_activate(pi->socket);
		close(pfd[1]);
	} else  {
		if (pfd[0] >= 0)
			close(pfd[0]);
		if (pfd[1] >= 0)
			close(pfd[1]);
	}

	return rv;
}

int
ni_process_run_and_wait(ni_process_t *pi)
{
	int  rv;

	rv = __ni_process_run(pi, NULL);
	if (rv < 0)
		return rv;

	while (waitpid(pi->pid, &pi->status, 0) < 0) {
		if (errno == EINTR)
			continue;
		ni_error("%s: waitpid returns error (%m)", __func__);
		return -1;
	}

	pi->pid = 0;
	if (pi->notify_callback)
		pi->notify_callback(pi);

	if (!ni_process_exit_status_okay(pi)) {
		ni_error("subprocess %d (%s) exited with error",
			pi->pid, pi->process->command);
		return -1;
	}

	return rv;
}

int
ni_process_run_and_capture_output(ni_process_t *pi, ni_buffer_t *out_buffer)
{
	int pfd[2],  rv;

	if (pipe(pfd) < 0) {
		ni_error("%s: unable to create pipe: %m", __func__);
		return -1;
	}

	rv = __ni_process_run(pi, pfd);
	if (rv < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return rv;
	}

	close(pfd[1]);
	while (1) {
		int cnt;

		if (ni_buffer_tailroom(out_buffer) < 256)
			ni_buffer_ensure_tailroom(out_buffer, 4096);

		cnt = read(pfd[0], ni_buffer_tail(out_buffer), ni_buffer_tailroom(out_buffer));
		if (cnt == 0) {
			break;
		} else if (cnt > 0) {
			out_buffer->tail += cnt;
		} else if (errno != EINTR) {
			ni_error("read error on subprocess pipe: %m");
			rv = -1;
			break;
		}
	}
	close(pfd[0]);

	while (waitpid(pi->pid, &pi->status, 0) < 0) {
		if (errno == EINTR)
			continue;
		ni_error("%s: waitpid returns error (%m)", __func__);
		return -1;
	}

	pi->pid = 0;
	if (pi->notify_callback)
		pi->notify_callback(pi);

	if (!ni_process_exit_status_okay(pi)) {
		ni_error("subprocess %d (%s) exited with error",
			pi->pid, pi->process->command);
		return -1;
	}

	return rv;
}

int
__ni_process_run(ni_process_t *pi, int *pfd)
{
	const char *arg0 = pi->argv.data[0];
	pid_t pid;

	if (pi->pid != 0) {
		ni_error("Cannot execute process instance twice (%s)", pi->process->command);
		return -1;
	}

	if (!ni_file_executable(arg0)) {
		ni_error("Unable to run %s; does not exist or is not executable", arg0);
		return -1;
	}

	signal(SIGCHLD, ni_process_sigchild);

	if ((pid = fork()) < 0) {
		ni_error("%s: unable to fork child process: %m", __func__);
		return -1;
	}
	pi->pid = pid;

	if (pid == 0) {
		int maxfd;
		int fd;

		if (chdir("/") < 0)
			ni_warn("%s: unable to chdir to /: %m", __func__);

		close(0);
		if ((fd = open("/dev/null", O_RDONLY)) < 0)
			ni_warn("%s: unable to open /dev/null: %m", __func__);
		else if (dup2(fd, 0) < 0)
			ni_warn("%s: cannot dup null descriptor: %m", __func__);

		if (pfd) {
			if (dup2(pfd[1], 1) < 0 || dup2(pfd[1], 2) < 0)
				ni_warn("%s: cannot dup pipe out descriptor: %m", __func__);
		}

		maxfd = getdtablesize();
		for (fd = 3; fd < maxfd; ++fd)
			close(fd);

		/* NULL terminate argv and env lists */
		ni_string_array_append(&pi->argv, NULL);
		ni_string_array_append(&pi->environ, NULL);

		arg0 = pi->argv.data[0];
		execve(arg0, pi->argv.data, pi->environ.data);

		ni_fatal("%s: cannot execute %s: %m", __func__, arg0);
	}

	return 0;
}

/*
 * Collect the exit status of the child process
 */
static int
ni_process_reap(ni_process_t *pi)
{
	int rv;

	if (pi->pid == 0) {
		ni_error("%s: child already reaped", __func__);
		return 0;
	}

	rv = waitpid(pi->pid, &pi->status, WNOHANG);
	if (rv == 0) {
		/* This is an ugly workaround. Sometimes, we seem to get a hangup on the socket even
		 * though the script (provably) still has its end of the socket pair open for writing. */
		ni_error("%s: process %u has not exited yet; now doing a blocking waitpid()", __func__, pi->pid);
		rv = waitpid(pi->pid, &pi->status, 0);
	}

	if (rv < 0) {
		ni_error("%s: waitpid returns error (%m)", __func__);
		return -1;
	}

	if (WIFEXITED(pi->status))
		ni_debug_extension("subprocess %d (%s) exited with status %d",
				pi->pid, pi->process->command,
				WEXITSTATUS(pi->status));
	else if (WIFSIGNALED(pi->status))
		ni_debug_extension("subprocess %d (%s) died with signal %d%s",
				pi->pid, pi->process->command,
				WTERMSIG(pi->status),
				WCOREDUMP(pi->status)? " (core dumped)" : "");
	else
		ni_debug_extension("subprocess %d (%s) transcended into nirvana",
				pi->pid, pi->process->command);
	pi->pid = 0;

	if (pi->notify_callback)
		pi->notify_callback(pi);

	return 0;
}

int
ni_process_exit_status_okay(const ni_process_t *pi)
{
	if (WIFEXITED(pi->status))
		return WEXITSTATUS(pi->status) == 0;

	return 0;
}

/*
 * Connect the subprocess output to our I/O handling loop
 */
static void
__ni_process_output_recv(ni_socket_t *sock)
{
	ni_process_t *pi = sock->user_data;
	ni_buffer_t *rbuf = &sock->rbuf;
	int cnt;

	ni_assert(pi);

	/* Grow socket input buffer as needed.
	 * NB: we may put an upper limit on how much process output we capture.
	 * Anything beyond a few MB is insane...
	 */
	if (ni_buffer_tailroom(rbuf) < 256)
		ni_buffer_ensure_tailroom(rbuf, 4096);

	cnt = recv(sock->__fd, ni_buffer_tail(rbuf), ni_buffer_tailroom(rbuf), MSG_DONTWAIT);
	if (cnt >= 0) {
		rbuf->tail += cnt;
	} else if (errno != EWOULDBLOCK) {
		ni_error("read error on subprocess pipe: %m");
		ni_socket_deactivate(sock);
	}
}

static void
__ni_process_output_hangup(ni_socket_t *sock)
{
	ni_process_t *pi = sock->user_data;

	if (pi && pi->socket == sock) {
		if (ni_process_reap(pi) < 0)
			ni_error("pipe closed by child process, but child did not exit");
		ni_socket_close(pi->socket);
		pi->socket = NULL;
	}
}

static void
__ni_process_release_user_data(void *user_data)
{
	ni_process_t *pi = user_data;
	if (pi)
		ni_process_free(pi);
}

static ni_socket_t *
__ni_process_get_output(ni_process_t *pi, int fd)
{
	ni_socket_t *sock;

	sock = ni_socket_wrap(fd, SOCK_STREAM);
	sock->receive = __ni_process_output_recv;
	sock->handle_hangup = __ni_process_output_hangup;

	sock->release_user_data = __ni_process_release_user_data;
	sock->user_data = pi;
	return sock;
}

