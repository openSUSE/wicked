/*
 * Routines for discovering the current state of network interfaces
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <wicked/nis.h>
#include "netinfo_priv.h"
#include "config.h"

static int		__ni_system_hostname_put(ni_handle_t *, const char *);
static int		__ni_system_hostname_get(ni_handle_t *, char *, size_t);
static int		__ni_system_nis_domain_put(ni_handle_t *, const char *);
static int		__ni_system_nis_domain_get(ni_handle_t *, char *, size_t);
static int		__ni_system_nis_put(ni_handle_t *, const ni_nis_info_t *);
static ni_nis_info_t *	__ni_system_nis_get(ni_handle_t *);
static void		__ni_system_close(ni_handle_t *nih);

static struct ni_ops ni_state_ops = {
	.refresh		= __ni_system_refresh_all,
	.configure_interface	= __ni_system_interface_configure,
	.delete_interface	= __ni_system_interface_delete,
	.update_lease		= __ni_system_interface_update_lease,
	.hostname_get		= __ni_system_hostname_get,
	.hostname_put		= __ni_system_hostname_put,
	.nis_domain_get		= __ni_system_nis_domain_get,
	.nis_domain_put		= __ni_system_nis_domain_put,
	.nis_get		= __ni_system_nis_get,
	.nis_put		= __ni_system_nis_put,
	.close			= __ni_system_close,
};

ni_handle_t *
ni_global_state_handle(void)
{
	static ni_handle_t *nih = NULL;

	if (nih == NULL)
		nih = ni_state_open();
	return nih;
}

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

	/* FIXME: run update helper */
}

static int
__ni_system_nis_domain_get(ni_handle_t *nih, char *buffer, size_t size)
{
	return getdomainname(buffer, size);
}


static int
__ni_system_nis_domain_put(ni_handle_t *nih, const char *domainname)
{
	if (!domainname || !*domainname)
		return setdomainname("", 0);
	return setdomainname(domainname, strlen(domainname));

	/* FIXME: run update helper */
}

static ni_nis_info_t *
__ni_system_nis_get(ni_handle_t *nih)
{
	char domainname[256];
	ni_nis_info_t *nis;

	if ((nis = ni_nis_parse_yp_conf(_PATH_YP_CONF)) == NULL)
		return NULL;

	if (nis->domainname == NULL
	 && getdomainname(domainname, sizeof(domainname)) >= 0)
		ni_string_dup(&nis->domainname, domainname);

	return nis;
}

static int
__ni_system_nis_put(ni_handle_t *nih, const ni_nis_info_t *nis)
{
	const char *tempfile = _PATH_YP_CONF ".new";

	if (ni_nis_write_yp_conf(tempfile, nis, NULL) < 0) {
		unlink(tempfile);
		return -1;
	}
	if (rename(tempfile, _PATH_YP_CONF) < 0) {
		ni_error("cannot move temp file to %s: %m", _PATH_YP_CONF);
		unlink(tempfile);
		return -1;
	}

	if (__ni_system_nis_domain_put(nih, nis->domainname) < 0) {
		ni_error("cannot set domainname: %m");
		return -1;
	}

	/* FIXME: run update helper */
	return 0;
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
