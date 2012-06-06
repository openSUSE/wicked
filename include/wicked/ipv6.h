/*
 * IPv6 device settings
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_IPv6_H__
#define __WICKED_IPv6_H__

#include <sys/socket.h>
#include <stdio.h>
#include <net/if.h>
#include <netinet/in.h>

#include <wicked/types.h>

struct ni_ipv6_devinfo {
	ni_bool_t		enabled;
	unsigned int		forwarding;
	ni_bool_t		autoconf;

	ni_bool_t		accept_redirects;
	ni_bool_t		privacy;
};

#endif /* __WICKED_IPv6_H__ */
