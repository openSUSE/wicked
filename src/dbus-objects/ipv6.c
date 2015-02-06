/*
 * DBus encapsulation for interface-specific IPv6 settings
 * (ie IPv4 and IPv6).
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include <wicked/system.h>
#include <wicked/ipv6.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static ni_netdev_t *	__ni_objectmodel_protocol_arg(const ni_dbus_variant_t *, const ni_dbus_service_t *);

/*
 * IPv6.changeProtocol method
 */
static dbus_bool_t
ni_objectmodel_ipv6_change_protocol(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev, *cfg;
	dbus_bool_t rv = FALSE;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (!(cfg = __ni_objectmodel_protocol_arg(&argv[0], &ni_objectmodel_ipv6_service))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (ni_system_ipv6_setup(nc, dev, &cfg->ipv6->conf) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"failed to configure ipv6 protocol");
		goto out;
	}

	rv = TRUE;

out:
	if (cfg)
		ni_netdev_put(cfg);
	return rv;
}

/*
 * Common helper function to extract bonding device info from a dbus dict
 */
static ni_netdev_t *
__ni_objectmodel_protocol_arg(const ni_dbus_variant_t *dict, const ni_dbus_service_t *service)
{
	ni_dbus_object_t *dev_object;
	ni_netdev_t *dev;
	dbus_bool_t rv;

	dev = ni_netdev_new(NULL, 0);

	dev_object = ni_objectmodel_wrap_netif(dev);
	rv = ni_dbus_object_set_properties_from_dict(dev_object, service, dict, NULL);
	ni_dbus_object_free(dev_object);

	if (!rv) {
		ni_netdev_put(dev);
		dev = NULL;
	}
	return dev;
}

/*
 * Functions for dealing with IPv6 properties
 */
static ni_ipv6_devinfo_t *
__ni_objectmodel_ipv6_devinfo_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_ipv6_devinfo_t *ipv6_info;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->ipv6;

	 if (!(ipv6_info = ni_netdev_get_ipv6(dev))) {
		 dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to get ipv6_devinfo handle for interface");
		 return NULL;
	 }
	 return ipv6_info;
}

void *
ni_objectmodel_get_ipv6_devinfo(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_ipv6_devinfo_handle(object, write_access, error);
}

#define IPV6_INT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT_PROPERTY(ipv6_devinfo, dbus_name, member_name, rw)

const ni_dbus_property_t	ni_objectmodel_ipv6_property_table[] = {
	IPV6_INT_PROPERTY(enabled, conf.enabled, RO),
	IPV6_INT_PROPERTY(forwarding, conf.forwarding, RO),
	IPV6_INT_PROPERTY(accept-ra, conf.accept_ra, RO),
	IPV6_INT_PROPERTY(accept-dad, conf.accept_dad, RO),
	IPV6_INT_PROPERTY(autoconf, conf.autoconf, RO),
	IPV6_INT_PROPERTY(privacy, conf.privacy, RO),
	IPV6_INT_PROPERTY(accept-redirects, conf.accept_redirects, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ipv6_methods[] = {
	{ "changeProtocol",	"a{sv}",		ni_objectmodel_ipv6_change_protocol },
	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_ipv6_service = {
	.name		= NI_OBJECTMODEL_IPV6_INTERFACE,
	.methods	= ni_objectmodel_ipv6_methods,
	.properties	= ni_objectmodel_ipv6_property_table,
};

