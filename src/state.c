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
#include <wicked/resolver.h>
#include "netinfo_priv.h"
#include "config.h"

#define CONFIG_WICKED_BACKUP_DIR	CONFIG_WICKED_STATEDIR "/backup"

static void		__ni_system_close(ni_handle_t *nih);

static struct ni_ops ni_state_ops = {
	.refresh		= __ni_system_refresh_all,
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

	nih->netlink = __ni_netlink_open(0);
	if (nih->netlink == NULL) {
		ni_close(nih);
		return NULL;
	}

	return nih;
}

int
__ni_system_interface_request_scan(ni_interface_t *ifp)
{
	switch (ifp->link.type) {
	case NI_IFTYPE_WIRELESS:
		return __ni_wireless_request_scan(NULL, ifp);

	default:
		ni_error("%s: scanning not supported for this interface", ifp->name);
		return -1;
	}
}

int
__ni_system_interface_get_scan_results(ni_interface_t *ifp)
{
	switch (ifp->link.type) {
	case NI_IFTYPE_WIRELESS:
		return __ni_wireless_get_scan_results(NULL, ifp);

	default:
		ni_error("%s: scanning not supported for this interface", ifp->name);
		return -1;
	}
}

#if 0
static int
__ni_system_policy_update(ni_handle_t *nih, const ni_policy_t *new_policy)
{
	ni_interface_array_t iflist = NI_INTERFACE_ARRAY_INIT;
	ni_policy_t *policy;
	ni_interface_t *ifp;
	unsigned int i;

	ni_debug_ifconfig("%s()", __FUNCTION__);
	if (__ni_generic_policy_update(nih, new_policy, &policy) < 0)
		return -1;

	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		switch (policy->event) {
		case NI_EVENT_LINK_UP:
			if (!ni_interface_link_is_up(ifp))
				continue;
			break;

		case NI_EVENT_LINK_DOWN:
			if (ni_interface_link_is_up(ifp))
				continue;
			break;

		default:
			continue;
		}

		if (ni_policy_match_event(nih, policy->event, ifp) == policy) {
			ni_debug_ifconfig("%s: matches new policy", ifp->name);
			ni_interface_array_append(&iflist, ifp);
		}
	}

	for (i = 0; i < iflist.count; ++i) {
		ifp = iflist.data[i];

		ni_debug_ifconfig("%s: requested flags 0x%x", ifp->name, policy->interface->link.ifflags);
		if (ni_interface_configure2(nih, ifp, policy->interface) < 0) {
			ni_error("%s: error applying new policy", ifp->name);
		}
	}

	ni_interface_array_destroy(&iflist);
	return 0;
}
#endif

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

	if ((nis = ni_nis_parse_yp_conf(_PATH_YP_CONF)) == NULL)
		return NULL;

	if (nis->domainname == NULL
	 && getdomainname(domainname, sizeof(domainname)) >= 0)
		ni_string_dup(&nis->domainname, domainname);

	return nis;
}

int
__ni_system_nis_put(const ni_nis_info_t *nis)
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

	if (__ni_system_nis_domain_put(nis->domainname) < 0) {
		ni_error("cannot set domainname: %m");
		return -1;
	}

	return 0;
}

int
__ni_system_nis_backup(void)
{
	return ni_backup_file_to(_PATH_YP_CONF, CONFIG_WICKED_BACKUP_DIR);
}

int
__ni_system_nis_restore(void)
{
	__ni_system_nis_domain_put(NULL);
	return ni_restore_file_from(_PATH_YP_CONF, CONFIG_WICKED_BACKUP_DIR);
}

ni_resolver_info_t *
__ni_system_resolver_get(void)
{
	return ni_resolver_parse_resolv_conf(_PATH_RESOLV_CONF);
}

int
__ni_system_resolver_put(const ni_resolver_info_t *resolver)
{
	const char *tempfile = _PATH_RESOLV_CONF ".new";

	if (ni_resolver_write_resolv_conf(tempfile, resolver, NULL) < 0) {
		unlink(tempfile);
		return -1;
	}
	if (rename(tempfile, _PATH_RESOLV_CONF) < 0) {
		ni_error("cannot move temp file to %s: %m", _PATH_RESOLV_CONF);
		unlink(tempfile);
		return -1;
	}

	return 0;
}

int
__ni_system_resolver_backup(void)
{
	return ni_backup_file_to(_PATH_RESOLV_CONF, CONFIG_WICKED_BACKUP_DIR);
}

int
__ni_system_resolver_restore(void)
{
	return ni_restore_file_from(_PATH_RESOLV_CONF, CONFIG_WICKED_BACKUP_DIR);
}

static void
__ni_system_close(ni_handle_t *nih)
{
	if (nih->netlink) {
		__ni_netlink_close(nih->netlink);
		nih->netlink = NULL;
	}

	if (nih->iocfd >= 0) {
		close(nih->iocfd);
		nih->iocfd = -1;
	}
}
