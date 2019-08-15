/*
 * Functions for resolving hostnames without blocking
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/address.h>
#include <wicked/resolver.h>
#include <wicked/logging.h>
#include <wicked/socket.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <poll.h>


/*
 * Build a getaddrinfo_a request
 */
struct gaicb *
gaicb_new(const char *hostname, int af)
{
	struct addrinfo *hints;
	struct gaicb *cb;

	/* Set up the resolver hints. Note that we explicitly should not
	 * set AI_ADDRCONFIG, as that tests whether one of the interfaces
	 * has an IPv6 address set. Since we may be in the middle of setting
	 * up our networking, we cannot rely on that to always be accurate. */
	hints = calloc(1, sizeof(*hints));
	hints->ai_family = af;

	cb = calloc(1, sizeof(*cb));
	cb->ar_name = hostname;
	cb->ar_request = hints;

	return cb;
}

static void
gaicb_free(struct gaicb *cb)
{
	if (gai_cancel(cb) == EAI_NOTCANCELED) {
		ni_warn("could not cancel getaddrinfo request for %s, leaking memory",
				cb->ar_name);
		return;
	}

	if (cb->ar_request)
		free((struct addrinfo *) cb->ar_request);
	if (cb->ar_result)
		freeaddrinfo(cb->ar_result);
	free(cb);
}

static void
gaicb_list_free(struct gaicb **list, unsigned int nitems)
{
	unsigned int i;

	for (i = 0; i < nitems; ++i)
		gaicb_free(list[i]);
	free(list);
}

/*
 * Use getaddrinfo_a to resolve one or more hostnames
 */
int
gaicb_list_resolve(struct gaicb **greqs, unsigned int nreqs, unsigned int timeout)
{
	unsigned int i;
	int rv;

	if (timeout == 0) {
		rv = getaddrinfo_a(GAI_WAIT, greqs, nreqs, NULL);
		if (rv != 0) {
			ni_error("getaddrinfo_a: %s", gai_strerror(rv));
			return -1;
		}
	} else {
		struct timeval deadline, now;

		rv = getaddrinfo_a(GAI_NOWAIT, greqs, nreqs, NULL);
		if (rv != 0) {
			ni_error("getaddrinfo_a: %s", gai_strerror(rv));
			return -1;
		}

		ni_timer_get_time(&deadline);
		deadline.tv_sec += timeout;

		while (1) {
			struct timeval delta;
			struct timespec ts;
			int status;

			ni_timer_get_time(&now);
			if (timercmp(&now, &deadline, >=))
				break;

			timersub(&deadline, &now, &delta);
			TIMEVAL_TO_TIMESPEC(&delta, &ts);

			status = gai_suspend((const struct gaicb * const *) greqs, nreqs, &ts);
			if (status == EAI_ALLDONE || status == EAI_AGAIN)
				break;
		}
	}

	for (i = 0, rv = 0; i < nreqs; ++i) {
		struct gaicb *cb = greqs[i];

		switch (gai_cancel(cb)) {
		case EAI_ALLDONE:
			rv++;
			break;

		default: ;
		}
	}

	return rv;
}

static int
gaicb_get_address(struct gaicb *cb, ni_sockaddr_t *addr)
{
	int gerr;
	struct addrinfo *res;
	unsigned int alen;

	if ((gerr = gai_error(cb)) != 0)
		return gerr;

	res = cb->ar_result;
	if ((alen = res->ai_addrlen) > sizeof(*addr))
		alen = sizeof(*addr);
	memcpy(addr, res->ai_addr, alen);
	return 0;
}

int
ni_resolve_hostname_timed(const char *hostname, int af, ni_sockaddr_t *addr, unsigned int timeout)
{
	struct gaicb *cb;
	int gerr;

	cb = gaicb_new(hostname, af);
	if (gaicb_list_resolve(&cb, 1, timeout) < 0)
		return -1;

	gerr = gaicb_get_address(cb, addr);
	gaicb_free(cb);

	if (gerr != 0) {
		ni_debug_objectmodel("cannot resolve %s: %s", hostname, gai_strerror(gerr));
		return 0;
	}

	return 1;
}

int
ni_resolve_hostnames_timed(int af, unsigned int count, const char *hostnames[], ni_sockaddr_t addrs[], unsigned int timeout)
{
	struct gaicb **cblist = NULL;
	unsigned int i;

	cblist = calloc(count, sizeof(cblist[0]));
	for (i = 0; i < count; ++i)
		cblist[i] = gaicb_new(hostnames[i], af);

	if (gaicb_list_resolve(cblist, count, timeout) < 0)
		return -1;

	for (i = 0; i < count; ++i) {
		struct gaicb *cb = cblist[i];
		int gerr;

		if ((gerr = gaicb_get_address(cb, &addrs[i])) != 0) {
			ni_error("unable to resolve %s: %s", cb->ar_name, gai_strerror(gerr));
			memset(&addrs[i], 0, sizeof(addrs[i]));
		}
	}
	gaicb_list_free(cblist, count);

	return 0;
}

static int
__ni_resolve_reverse(const ni_sockaddr_t *addr, char **hostname)
{
	char hbuf[NI_MAXHOST+1] = {'\0'};
	socklen_t len;
	int ret;

	if (!addr || !hostname) {
		errno = EINVAL;
		return EAI_SYSTEM;
	}

	if (!ni_sockaddr_is_specified(addr)) {
		errno = EINVAL;
		return EAI_SYSTEM;
	}

	switch (addr->ss_family) {
	case AF_INET:
		len = sizeof(addr->sin);
		break;
	case AF_INET6:
		len = sizeof(addr->six);
		break;
	default:
		errno = EINVAL;
		return EAI_SYSTEM;
	}

	ret = getnameinfo(&addr->sa, len, hbuf, sizeof(hbuf),
				NULL, 0, NI_NAMEREQD);
	if (ret == 0) {
		ni_string_dup(hostname, hbuf);
	}
	return ret;
}

static void
__ni_resolve_reverse_sigchild(int sig)
{
	(void)sig;
}

static int
__ni_resolve_reverse_exec(const ni_sockaddr_t *addr)
{
	char *hostname = NULL;

	if (__ni_resolve_reverse(addr, &hostname) == 0) {
		fputs(hostname, stdout);
		fflush(stdout);
		ni_string_free(&hostname);
		return 0;
	}
	return 2;
}

static int
__ni_resolve_reverse_read(int fd, char **hostname, unsigned int timeout)
{
	char hbuf[NI_MAXHOST+1] = {'\0'};
	struct pollfd pfd[1] = { { fd, POLLIN, 0 } };
	struct timeval now, tv;
	ssize_t len;
	int rc;

	ni_timer_get_time(&tv);
	tv.tv_sec += timeout;
	timeout *= 1000;

	while ((rc = poll(pfd, 1, timeout)) == -1 && errno == EINTR) {
		ni_timer_get_time(&now);
		if (timercmp(&tv, &now, <)) {
			timeout = 0;
		} else {
			struct timeval delta;
			long delta_ms;

			timersub(&tv, &now, &delta);
			delta_ms = 1000 * delta.tv_sec + delta.tv_usec / 1000;
			if (delta_ms < timeout)
				timeout = delta_ms;
		}
	}
	if (rc == 1 && pfd[0].revents & POLLIN) {
		len = read(pfd[0].fd, hbuf, sizeof(hbuf) - 1);
		if (len > 0 && ni_check_domain_name(hbuf, len, 0)) {
			ni_string_dup(hostname, hbuf);
			return 0;
		}
	}
	return -1;
}

int
__ni_resolve_reverse_reap(pid_t pid)
{
	int status = -1;
	int count = 4;

	while (count--) {
		if (waitpid(pid, &status, WNOHANG) == pid) {
			if (WIFEXITED(status))
				return WEXITSTATUS(status);
			else
				return -1;
		} else if (count == 2) {
			kill(pid, SIGHUP);
		} else if (count == 1) {
			if (kill(pid, SIGKILL) < 0) {
				ni_error("Unable to kill reverse resolver");
			}
		}
		usleep(10000);
	}
	ni_error("Unable to reap reverse resolver");
	return -1;
}

/*
 * Timed IP address reverse resolve hack (see bnc#861476)
 * Unfortunately getnameinfo does not accept any timeout...
 * Any better ideas how to implement this?
 */
int
ni_resolve_reverse_timed(const ni_sockaddr_t *addr, char **hostname, unsigned int timeout)
{
	struct sigaction old, new;
	int fd[2], fds, rc;
	pid_t pid;

	if (!timeout)
		return __ni_resolve_reverse(addr, hostname);

	rc = socketpair(AF_UNIX, SOCK_STREAM, PF_LOCAL, fd);
	if (rc < 0)
		return -1;

	new.sa_flags   = 0;
	new.sa_handler = __ni_resolve_reverse_sigchild;
	sigemptyset (&new.sa_mask);
	sigaction (SIGCHLD, &new, &old);

	rc = 2;
	do {
		pid = fork();
	} while (pid == -1 && errno == EAGAIN && --rc);

	rc = -1;
	switch (pid) {
	case -1:
		close(fd[0]);
		close(fd[1]);
		break;

	case 0:
		close(fd[0]);
		if (!freopen("/dev/null", "r", stdin) ||
		    !freopen("/dev/null", "w", stderr)) {
			close(fd[1]);
			exit(1);
		}
		if (dup2(fd[1], fileno(stdout)) < 0) {
			close(fd[1]);
			exit(1);
		}

		fds = getdtablesize();
		for (fd[0] = 3; fd[0] < fds; ++fd[0])
			close(fd[0]);

		rc = __ni_resolve_reverse_exec(addr);
		exit(rc);

	default:
		close(fd[1]);
		rc = __ni_resolve_reverse_read(fd[0], hostname, timeout);
		close(fd[0]);
		if (rc < 0)
			kill(pid, SIGTERM);

		__ni_resolve_reverse_reap(pid);
	}

	sigaction (SIGCHLD, &old, &new);
	return rc;
}

