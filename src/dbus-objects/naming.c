/*
 * DBus encapsulation for network interfaces
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/dbus-errors.h>
#include <wicked/ethernet.h>
#include <wicked/ibft.h>
#include <wicked/modem.h>
#include "dbus-common.h"
#include "model.h"
#include "appconfig.h"
#include "debug.h"

static unsigned int		ni_objectmodel_ns_count;
static ni_objectmodel_ns_t **	ni_objectmodel_ns_list;

void
ni_objectmodel_register_ns(ni_objectmodel_ns_t *ns)
{
	if ((ni_objectmodel_ns_count % 8) == 0)
		ni_objectmodel_ns_list = realloc(ni_objectmodel_ns_list,
				(ni_objectmodel_ns_count + 8) * sizeof(ni_objectmodel_ns_list[0]));
	ni_objectmodel_ns_list[ni_objectmodel_ns_count++] = ns;
}

ni_objectmodel_ns_t *
ni_objectmodel_get_ns(const char *name)
{
	unsigned int i;

	for (i = 0; i < ni_objectmodel_ns_count; ++i) {
		ni_objectmodel_ns_t *ns;

		ns = ni_objectmodel_ns_list[i];
		if (ni_string_eq(ns->name, name))
			return ns;
	}
	return NULL;
}

/*
 * Register all naming services specified in the config file.
 * These naming services are supposed to be provided by shared libraries.
 * The symbol specified by the C binding element must refer to a
 * ni_objectmodel_ns struct.
 */
void
ni_objectmodel_register_ns_dynamic(void)
{
	ni_config_t *config = ni_global.config;
	ni_extension_t *ex;

	ni_assert(config);
	for (ex = config->ns_extensions; ex; ex = ex->next) {
		ni_c_binding_t *binding;
		void *addr;

		for (binding = ex->c_bindings; binding; binding = binding->next) {
			if ((addr = ni_c_binding_get_address(binding)) == NULL) {
				ni_error("cannot bind %s name service - invalid C binding",
						binding->name);
				continue;
			}

			ni_debug_objectmodel("trying to bind netif naming service \"%s\"", binding->name);
			ni_objectmodel_register_ns((ni_objectmodel_ns_t *) addr);
		}
	}
}

ni_dbus_object_t *
ni_objectmodel_lookup_by_attrs(ni_dbus_object_t *list_object, ni_objectmodel_ns_t *ns, const ni_var_array_t *attrs)
{
	ni_dbus_object_t *obj;

	if (ns->lookup_by_attrs)
		return ns->lookup_by_attrs(ns, attrs);

	if (ns->match_attr == NULL)
		return NULL;

	for (obj = list_object->children; obj; obj = obj->next) {
		dbus_bool_t match = TRUE;
		ni_var_t *ap;
		unsigned int i;

		for (i = 0, ap = attrs->data; match && i < attrs->count; ++i, ++ap)
			match = ns->match_attr(obj, ap->name, ap->value);
		if (match) {
			ni_debug_dbus("%s: found %s", __func__, obj->path);
			return obj;
		}
	}
	return NULL;
}

static ni_bool_t
__match_hwaddr(const ni_hwaddr_t *hwaddr, const char *string)
{
	ni_hwaddr_t match;

	if (!string)
		return FALSE;
	if (ni_link_address_parse(&match, NI_IFTYPE_ETHERNET, string) < 0)
		return FALSE;

	return ni_link_address_equal(hwaddr, &match);
}

static dbus_bool_t
ni_objectmodel_ether_match_attr(const ni_dbus_object_t *object, const char *name, const char *value)
{
	ni_netdev_t *dev;
	ni_ethernet_t *eth;

	if (!(dev = ni_objectmodel_unwrap_interface(object, NULL)))
		return FALSE;

	if (!(eth = dev->ethernet))
		return FALSE;

	if (!strcmp(name, "address"))
		return __match_hwaddr(&dev->link.hwaddr, value);

	if (!strcmp(name, "permanent-address"))
		return __match_hwaddr(&eth->permanent_address, value);

	ni_warn("%s: unsupported query attribute %s", __func__, name);
	return FALSE;
}

static ni_objectmodel_ns_t ni_objectmodel_ether_ns = {
	.name		= "ethernet",
	.match_attr	= ni_objectmodel_ether_match_attr,
};

/*
 * Match modem devices
 */
static dbus_bool_t
ni_objectmodel_modem_match_attr(const ni_dbus_object_t *object, const char *name, const char *value)
{
	ni_modem_t *modem;

	if (!(modem = ni_objectmodel_modem_unwrap(object, NULL)))
		return FALSE;

	if (!strcmp(name, "equipment-id"))
		return ni_string_eq(modem->identify.equipment, value);

	if (!strcmp(name, "device"))
		return ni_string_eq(modem->identify.device, value);

	ni_warn("%s: unsupported query attribute %s", __func__, name);
	return FALSE;
}

static ni_objectmodel_ns_t ni_objectmodel_modem_ns = {
	.name		= "modem",
	.match_attr	= ni_objectmodel_modem_match_attr,
};

/*
 * The ibft naming service just uses the node name (ethernetX)
 */
static ni_dbus_object_t *
ni_objectmodel_ibft_lookup_by_name(ni_objectmodel_ns_t *ns, const char *name)
{
#ifdef notyet
	ni_netconfig_t *nc = ni_global_state_handle(0);

	return ni_netdev_by_ibft_nodename(nc, name);
#else
	ni_warn("%s(%s): not implemented", __func__, name);
	return NULL;
#endif
}

static ni_objectmodel_ns_t ni_objectmodel_ibft_ns = {
	.name		= "ibft",
	.lookup_by_name	= ni_objectmodel_ibft_lookup_by_name,
};

void
ni_objectmodel_register_ns_builtin(void)
{
	ni_objectmodel_register_ns(&ni_objectmodel_ether_ns);
	ni_objectmodel_register_ns(&ni_objectmodel_ibft_ns);
	ni_objectmodel_register_ns(&ni_objectmodel_modem_ns);
}
