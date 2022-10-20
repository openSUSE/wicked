/*
 *	Routines for discovering the current state of network interfaces
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2022 SUSE LLC
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
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <errno.h>

#include <wicked/nis.h>
#include <wicked/resolver.h>
#include "netinfo_priv.h"
#include "appconfig.h"

int
__ni_system_hostname_get(char *buffer, size_t size)
{
	return gethostname(buffer, size);
}


int
__ni_system_hostname_put(const char *hostname)
{
	if (!hostname || !*hostname) {
		errno = EINVAL;
		return -1;
	}
	return sethostname(hostname, strlen(hostname));
}

int
__ni_system_nis_domain_get(char *buffer, size_t size)
{
	return getdomainname(buffer, size);
}


int
__ni_system_nis_domain_put(const char *domainname)
{
	if (!domainname || !*domainname)
		return setdomainname("", 0);
	return setdomainname(domainname, strlen(domainname));
}

ni_nis_info_t *
__ni_system_nis_get(void)
{
	char domainname[256];
	ni_nis_info_t *nis;

	if ((nis = ni_nis_parse_yp_conf(NI_PATH_YP_CONF)) == NULL)
		return NULL;

	if (nis->domainname == NULL
	 && getdomainname(domainname, sizeof(domainname)) >= 0)
		ni_string_dup(&nis->domainname, domainname);

	return nis;
}

int
__ni_system_nis_put(const ni_nis_info_t *nis)
{
	const char *tempfile = NI_PATH_YP_CONF ".new";

	if (ni_nis_write_yp_conf(tempfile, nis, NULL) < 0) {
		unlink(tempfile);
		return -1;
	}
	if (rename(tempfile, NI_PATH_YP_CONF) < 0) {
		ni_error("cannot move temp file to %s: %m", NI_PATH_YP_CONF);
		unlink(tempfile);
		return -1;
	}

	if (__ni_system_nis_domain_put(nis->domainname) < 0) {
		ni_error("cannot set domainname: %m");
		return -1;
	}

	return 0;
}

int
__ni_system_nis_backup(void)
{
	return ni_backup_file_to(NI_PATH_YP_CONF, ni_config_backupdir());
}

int
__ni_system_nis_restore(void)
{
	__ni_system_nis_domain_put(NULL);
	return ni_restore_file_from(NI_PATH_YP_CONF, ni_config_backupdir());
}

ni_resolver_info_t *
__ni_system_resolver_get(void)
{
	return ni_resolver_parse_resolv_conf(NI_PATH_RESOLV_CONF);
}

int
__ni_system_resolver_put(const ni_resolver_info_t *resolver)
{
	const char *tempfile = NI_PATH_RESOLV_CONF ".new";

	if (ni_resolver_write_resolv_conf(tempfile, resolver, NULL) < 0) {
		unlink(tempfile);
		return -1;
	}
	if (rename(tempfile, NI_PATH_RESOLV_CONF) < 0) {
		ni_error("cannot move temp file to %s: %m", NI_PATH_RESOLV_CONF);
		unlink(tempfile);
		return -1;
	}

	return 0;
}

int
__ni_system_resolver_backup(void)
{
	return ni_backup_file_to(NI_PATH_RESOLV_CONF, ni_config_backupdir());
}

int
__ni_system_resolver_restore(void)
{
	return ni_restore_file_from(NI_PATH_RESOLV_CONF, ni_config_backupdir());
}
