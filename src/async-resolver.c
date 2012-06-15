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
#include <stdlib.h>

#include <sys/time.h>
#include <netdb.h>


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

		gettimeofday(&deadline, NULL);
		deadline.tv_sec += timeout;

		while (1) {
			struct timeval delta;
			struct timespec ts;
			int status;

			gettimeofday(&now, NULL);
			if (timercmp(&now, &deadline, >=))
				break;

			timersub(&deadline, &now, &delta);
			ts.tv_sec = delta.tv_sec;
			ts.tv_nsec = 1000 * delta.tv_usec;

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
