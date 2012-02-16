/*
 * DBus encapsulation for VLAN interfaces
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/vlan.h>
#include "model.h"
#include "debug.h"


static ni_interface_t *	__ni_objectmodel_vlan_newlink(ni_interface_t *, const char *, DBusError *);

/*
 * Create a new VLAN interface
 */
dbus_bool_t
ni_objectmodel_vlan_newlink(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	const ni_dbus_service_t *service;
	ni_dbus_object_t *object = NULL;
	ni_interface_t *ifp;
	const char *ifname = NULL;
	dbus_bool_t rv = FALSE;

	NI_TRACE_ENTER();

	service = ni_objectmodel_service_by_name(WICKED_DBUS_VLAN_INTERFACE);
	ni_assert(service);

	ifp = ni_interface_new(NULL, NULL, 0);
	ifp->link.type = NI_IFTYPE_VLAN;
	object = ni_objectmodel_wrap_interface(ifp);

	if (argc != 2
	 || !ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !ni_dbus_object_set_properties_from_dict(object, service, &argv[1]))
		goto bad_args;

	if (!(ifp = __ni_objectmodel_vlan_newlink(ifp, ifname, error))) {
		rv = FALSE;
	} else {
		ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;

		ni_trace("new if name=%s users=%u", ifp->name, ifp->users);

		/* free the config object */
		ni_dbus_object_free(object);

		object = ni_objectmodel_register_interface(ni_dbus_object_get_server(factory_object), ifp);
		if (!object)
			goto out;

		/* For now, we return a string here. This should really be an object-path,
		 * though. */
		ni_dbus_variant_set_string(&result, object->path);

		rv = ni_dbus_message_serialize_variants(reply, 1, &result, error);
		ni_dbus_variant_destroy(&result);
	}

out:
	if (object)
		ni_dbus_object_free(object);
	return rv;

bad_args:
	dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "unable to extract arguments");
	if (object)
		ni_dbus_object_free(object);
	return FALSE;
}

static ni_interface_t *
__ni_objectmodel_vlan_newlink(ni_interface_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_interface_t *new_ifp = NULL;
	const ni_vlan_t *vlan;
	int rv;

	vlan = ni_interface_get_vlan(cfg_ifp);
	if (!vlan || !vlan->tag || !vlan->physdev_name) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Incomplete arguments (need VLAN tag and interface name)");
		goto out;
	}

	ni_debug_dbus("VLAN.newLink(name=%s, dev=%s, tag=%u)", ifname, vlan->physdev_name, vlan->tag);

	if (ifname == NULL) {
		static char namebuf[64];
		unsigned int num;

		for (num = 0; num < 65536; ++num) {
			snprintf(namebuf, sizeof(namebuf), "vlan%u", num);
			if (!ni_interface_by_name(nc, namebuf)) {
				ifname = namebuf;
				break;
			}
		}

		if (ifname == NULL) {
			dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create vlan - too many interfaces");
			goto out;
		}
	}

	if ((rv = ni_system_vlan_create(nc, ifname, vlan, &new_ifp)) < 0) {
		if (rv != -NI_ERROR_INTERFACE_EXISTS
		 && (ifname != NULL && strcmp(ifname, new_ifp->name))) {
			dbus_set_error(error,
					DBUS_ERROR_FAILED,
					"Unable to create VLAN interface: %s",
					ni_strerror(rv));
			goto out;
		}
		ni_debug_dbus("VLAN interface exists (and name matches)");
	}

	if (new_ifp->link.type != NI_IFTYPE_VLAN) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create VLAN interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		ni_interface_put(new_ifp);
		new_ifp = NULL;
	}

out:
	if (cfg_ifp)
		ni_interface_put(cfg_ifp);
	return new_ifp;
}

/*
 * Helper function to obtain VLAN config from dbus object
 */
static void *
ni_objectmodel_get_vlan(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp;

	if (!(ifp = ni_objectmodel_unwrap_interface(object))) {
		/* FIXME: return dbus error, too */
		ni_error("trying to access %s properties for incompatible object (class %s)",
				WICKED_DBUS_VLAN_INTERFACE, object->class->name);
		return NULL;
	}

	return ni_interface_get_vlan(ifp);
}

#define VLAN_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(vlan, dbus_type, type, rw)
#define VLAN_UINT_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(vlan, dbus_type, type, rw)
#define VLAN_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(vlan, dbus_type, type, rw)

const ni_dbus_property_t	ni_objectmodel_vlan_property_table[] = {
	VLAN_STRING_PROPERTY(device, physdev_name, RO),
	VLAN_UINT16_PROPERTY(tag, tag, RO),
	{ NULL }
};
