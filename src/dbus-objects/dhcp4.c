/*
 * dbus encapsulation for dhcp4 client side
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include "dhcp/dhcp.h"
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

ni_dbus_object_t *
ni_objectmodel_wrap_addrconf_request(ni_addrconf_request_t *req)
{
	return ni_dbus_object_new(NULL, NULL, req);
}

/*
 * Get a client handle for the DHCP service
 */
ni_dbus_client_t *
wicked_dbus_dhcp_client(void)
{
	static ni_dbus_client_t *client = NULL;

	if (client == NULL) {
		client = ni_dbus_client_open(WICKED_DBUS_BUS_NAME_DHCP4);

		/* Init root object? */

		/* FIXME: add signal handler */
	}
	return client;
}

/*
 * Interface.acquire(dict options)
 * Acquire a lease for the given interface.
 *
 * The options dictionary contains addrconf request properties.
 */
dbus_bool_t
ni_objectmodel_dhcp4_acquire(ni_interface_t *dev, const ni_addrconf_request_t *req, DBusError *error)
{
	ni_dbus_client_t *client = wicked_dbus_dhcp_client();
	char object_path[256];
	ni_dbus_object_t *object;
	ni_dbus_variant_t argument;
	dbus_bool_t rv = FALSE;

	if (req == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: NULL request", __func__);
		return FALSE;
	}

	snprintf(object_path, sizeof(object_path), WICKED_DBUS_OBJECT_PATH "/DHCP4/Interface/%d", dev->link.ifindex);
	object = ni_dbus_client_object_new(client, object_path,
			WICKED_DBUS_DHCP4_INTERFACE, NULL, dev);

	ni_dbus_variant_init_dict(&argument);
	if (!__wicked_dbus_get_addrconf_request(req, &argument, error)) {
		/* dbus_set_error(error, DBUS_ERROR_FAILED, "Error marshalling addrconf request"); */
		goto failed;
	}

	if (!ni_dbus_object_call_variant(object, NULL, "acquire", 1, &argument, 0, NULL, error))
		goto failed;

	rv = TRUE;

failed:
	ni_dbus_variant_destroy(&argument);
	ni_dbus_object_free(object);
	return rv;
}

/*
 * Interface.release()
 * Release a lease for the given interface.
 *
 * The options dictionary contains addrconf request properties.
 */
dbus_bool_t
ni_objectmodel_dhcp4_release(ni_interface_t *dev, const ni_addrconf_lease_t *lease, DBusError *error)
{
	ni_dbus_client_t *client = wicked_dbus_dhcp_client();
	char object_path[256];
	ni_dbus_object_t *object;
	ni_dbus_variant_t argument;
	dbus_bool_t rv = FALSE;

	if (lease == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: NULL request", __func__);
		return FALSE;
	}

	snprintf(object_path, sizeof(object_path), WICKED_DBUS_OBJECT_PATH "/Interface/%d", dev->link.ifindex);
	object = ni_dbus_client_object_new(client, object_path,
			WICKED_DBUS_DHCP4_INTERFACE, NULL, dev);

	ni_dbus_variant_set_uuid(&argument, &lease->uuid);
	if (!ni_dbus_object_call_variant(object, NULL, "drop", 1, &argument, 0, NULL, error))
		goto failed;

	rv = TRUE;

failed:
	ni_dbus_variant_destroy(&argument);
	ni_dbus_object_free(object);
	return rv;
}
