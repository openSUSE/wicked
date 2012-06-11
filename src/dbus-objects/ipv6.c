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

	if (ni_system_ipv6_setup(nc, dev, cfg->ipv6) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to set up ethernet device");
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

	dev = ni_netdev_new(NULL, NULL, 0);
	dev->link.type = NI_IFTYPE_ETHERNET;

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
__ni_objectmodel_get_ipv6_devinfo(const ni_dbus_object_t *object, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	return ni_netdev_get_ipv6(dev);
}

void *
ni_objectmodel_get_ipv6_devinfo(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_get_ipv6_devinfo(object, error);
}

#define IPV6_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(ipv6_devinfo, dbus_name, member_name, rw)
#define IPV6_BOOL_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(ipv6_devinfo, dbus_name, member_name, rw)

const ni_dbus_property_t	ni_objectmodel_ipv6_property_table[] = {
	IPV6_BOOL_PROPERTY(enabled, enabled, RO),
	IPV6_UINT_PROPERTY(forwarding, forwarding, RO),
	IPV6_BOOL_PROPERTY(autoconf, autoconf, RO),
	IPV6_UINT_PROPERTY(accept-redirects, accept_redirects, RO),
	IPV6_BOOL_PROPERTY(privacy, privacy, RO),

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

