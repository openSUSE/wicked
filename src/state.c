/*
 * Routines for discovering the current state of network interfaces
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "netinfo_priv.h"
#include "config.h"

static int	__ni_system_hostname_put(ni_handle_t *, const char *);
static int	__ni_system_hostname_get(ni_handle_t *, char *, size_t);
static void	__ni_system_close(ni_handle_t *nih);

static struct ni_ops ni_state_ops = {
	.refresh		= __ni_system_refresh_all,
	.configure_interface	= __ni_system_interface_configure,
	.delete_interface	= __ni_system_interface_delete,
	.update_lease		= __ni_system_interface_update_lease,
	.hostname_get		= __ni_system_hostname_get,
	.hostname_put		= __ni_system_hostname_put,
	.close			= __ni_system_close,
};

ni_handle_t *
ni_state_open(void)
{
	ni_handle_t *nih;

	nih = __ni_handle_new(sizeof(*nih), &ni_state_ops);

	if (rtnl_open(&nih->rth, 0) < 0) {
		error("Cannot open rtnetlink: %m");
		ni_close(nih);
		return NULL;
	}

	return nih;
}

static int
__ni_system_hostname_get(ni_handle_t *nih, char *buffer, size_t size)
{
	return gethostname(buffer, size);
}


static int
__ni_system_hostname_put(ni_handle_t *nih, const char *hostname)
{
	if (!hostname || !*hostname) {
		errno = EINVAL;
		return -1;
	}
	return sethostname(hostname, strlen(hostname));
}


static void
__ni_system_close(ni_handle_t *nih)
{
	if (nih->rth.fd >= 0) {
		rtnl_close(&nih->rth);
		nih->rth.fd = -1;
	}

	if (nih->iocfd >= 0) {
		close(nih->iocfd);
		nih->iocfd = -1;
	}
}
