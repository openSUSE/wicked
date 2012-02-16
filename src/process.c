/*
 * Execute the requested process (almost) as if it were a setuid process.
 *
 * Copyright (C) 2002-2012 Olaf Kirch <okir@suse.de>
 */

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

static int				__ni_process_instance_run(ni_process_instance_t *, int *);
static ni_socket_t *			__ni_process_instance_get_output(ni_process_instance_t *, int);
static const ni_string_array_t *	__ni_default_environment(void);

/*
 * Create a process description
 */
ni_process_t *
ni_process_new(const char *command)
{
	ni_process_t *proc;

	proc = calloc(1, sizeof(*proc));
	ni_string_dup(&proc->command, command);
	ni_string_array_copy(&proc->environ, __ni_default_environment());

	proc->refcount = 1;
	return proc;
}

void
ni_process_free(ni_process_t *proc)
{
	ni_assert(proc->refcount == 0);
	ni_string_array_destroy(&proc->environ);
	ni_string_free(&proc->command);
	free(proc);
}

ni_process_instance_t *
ni_process_instance_new(ni_process_t *proc)
{
	ni_process_instance_t *pi;
	char *cmd, *s;

	pi = calloc(1, sizeof(*pi));
	pi->process = ni_process_hold(proc);

	cmd = strdup(proc->command);
	for (s = strtok(cmd, " \t"); s; s = strtok(NULL, " \t"))
		ni_string_array_append(&pi->argv, s);
	free(cmd);

	/* Copy the environment */
	ni_string_array_copy(&pi->environ, &proc->environ);

	return pi;
}

void
ni_process_instance_free(ni_process_instance_t *pi)
{
	if (pi->pid) {
		if (kill(pi->pid, SIGKILL) < 0)
			ni_error("Unable to kill process %d (%s): %m", pi->pid, pi->process->command);
	}

	if (pi->socket != NULL) {
		ni_socket_close(pi->socket);
		pi->socket = NULL;
	}

	ni_string_array_destroy(&pi->argv);
	ni_string_array_destroy(&pi->environ);
	ni_process_release(pi->process);
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
ni_process_setenv(ni_process_t *proc, const char *name, const char *value)
{
	__ni_process_setenv(&proc->environ, name, value);
}

void
ni_process_instance_setenv(ni_process_instance_t *pi, const char *name, const char *value)
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
ni_process_instance_getenv(const ni_process_instance_t *pi, const char *name)
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
ni_process_instance_run(ni_process_instance_t *pi)
{
	int pfd[2],  rv;

	/* Our code in socket.c is only able to deal with sockets for now; */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pfd) < 0) {
		ni_error("%s: unable to create pipe: %m", __func__);
		return -1;
	}

	rv = __ni_process_instance_run(pi, pfd);
	if (rv < 0) {
		if (pfd[0] >= 0)
			close(pfd[0]);
		if (pfd[1] >= 0)
			close(pfd[1]);
	}

	return rv;
}

int
ni_process_instance_run_and_wait(ni_process_instance_t *pi)
{
	int  rv;

	rv = __ni_process_instance_run(pi, NULL);
	if (rv < 0)
		return rv;

	while (waitpid(pi->pid, &pi->status, WNOHANG) < 0) {
		if (errno == EINTR)
			continue;
		ni_error("%s: waitpid returns error (%m)", __func__);
		return -1;
	}

	pi->pid = 0;
	if (pi->notify_callback)
		pi->notify_callback(pi);

	if (!ni_process_exit_status_okay(pi)) {
		ni_error("subprocesses exited with error");
		return -1;
	}

	return rv;
}

int
__ni_process_instance_run(ni_process_instance_t *pi, int *pfd)
{
	pid_t pid;

	if (pi->pid != 0) {
		ni_error("Cannot execute process instance twice (%s)", pi->process->command);
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
		const char *arg0;
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

	if (pfd) {
		/* Set up a socket to receive the redirected output of the
		 * subprocess. */
		pi->socket = __ni_process_instance_get_output(pi, pfd[0]);
		ni_socket_activate(pi->socket);
		close(pfd[1]);
	}

	return 0;
}

/*
 * Collect the exit status of the child process
 */
static int
ni_process_instance_reap(ni_process_instance_t *pi)
{
	if (pi->pid == 0) {
		ni_error("%s: child already reaped", __func__);
		return 0;
	}

	if (waitpid(pi->pid, &pi->status, WNOHANG) < 0) {
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
ni_process_exit_status_okay(const ni_process_instance_t *pi)
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
	ni_process_instance_t *pi = sock->user_data;
	ni_buffer_t *rbuf = &sock->rbuf;
	int cnt;

	ni_assert(pi);
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

void
__ni_process_output_hangup(ni_socket_t *sock)
{
	ni_process_instance_t *pi = sock->user_data;

	if (pi && pi->socket == sock) {
		if (ni_process_instance_reap(pi) < 0)
			ni_error("pipe closed by child process, but child did not exit");
		ni_socket_close(pi->socket);
		pi->socket = NULL;
	}
}

static ni_socket_t *
__ni_process_instance_get_output(ni_process_instance_t *pi, int fd)
{
	ni_socket_t *sock;

	sock = ni_socket_wrap(fd, SOCK_STREAM);
	sock->receive = __ni_process_output_recv;
	sock->handle_hangup = __ni_process_output_hangup;

	sock->user_data = pi;
	return sock;
}
