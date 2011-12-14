/*
 * Generic dbus client functions for address configuration
 * services implemented as separate DBus services (like dhcp,
 * ipv4ll)
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
#include "dbus-common.h"
#include "model.h"
#include "debug.h"


/*
 * Interface.acquire(dict options)
 * Acquire a lease for the given interface.
 *
 * The options dictionary contains addrconf request properties.
 */
dbus_bool_t
ni_objectmodel_addrconf_acquire(ni_dbus_object_t *object, const ni_addrconf_request_t *req, DBusError *error)
{
	ni_dbus_variant_t argument;
	dbus_bool_t rv = FALSE;

	if (req == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: NULL request", __func__);
		return FALSE;
	}

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
	return rv;
}

/*
 * Interface.release()
 * Release a lease for the given interface.
 *
 * The options dictionary contains addrconf request properties.
 */
dbus_bool_t
ni_objectmodel_addrconf_release(ni_dbus_object_t *object, const ni_addrconf_lease_t *lease, DBusError *error)
{
	dbus_bool_t rv = FALSE;
	ni_dbus_variant_t argv[1];
	int argc = 0;

	if (lease != NULL) {
		ni_dbus_variant_set_uuid(&argv[argc], &lease->uuid);
		argc++;
	}

	rv = ni_dbus_object_call_variant(object, NULL, "drop", argc, argv, 0, NULL, error);

	while (argc--)
		ni_dbus_variant_destroy(&argv[0]);
	return rv;
}

/*
 * Extract interface index from object path.
 * Path names must be WICKED_DBUS_OBJECT_PATH "/" <something> "/Interface/" <index>
 */
static ni_interface_t *
ni_objectmodel_addrconf_path_to_device(const char *path)
{
	unsigned int ifindex;
	ni_handle_t *nih;
	char cc;

	if (strncmp(path, WICKED_DBUS_OBJECT_PATH, strlen(WICKED_DBUS_OBJECT_PATH)))
		return NULL;
	path += strlen(WICKED_DBUS_OBJECT_PATH);

	if (*path++ != '/')
		return NULL;
	while ((cc = *path++) != '/') {
		if (cc == '\0')
			return NULL;
	}

	if (ni_parse_int(path, &ifindex) < 0)
		return NULL;

	nih = ni_global_state_handle();
	if (ni_refresh(nih, NULL) < 0) {
		ni_error("%s: unable to refresh interfaces", __func__);
		return NULL;
	}

	return ni_interface_by_index(nih, ifindex);
}

static ni_addrconf_lease_t *
ni_objectmodel_interface_to_lease(const char *interface)
{
	if (!strcmp(interface, WICKED_DBUS_DHCP4_INTERFACE))
		return ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET);

	return NULL;
}

/*
 * Callback from addrconf supplicant whenever it acquired, released or lost a lease.
 *
 * FIXME SECURITY:
 * Is it good enough to check for the sender interface to avoid that someone is sending
 * us spoofed lease messages?!
 */
void
ni_objectmodel_addrconf_signal_handler(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	const char *signal_name = dbus_message_get_member(msg);
	ni_interface_t *ifp;
	ni_addrconf_lease_t *lease = NULL;
	ni_dbus_variant_t argv[16];
	int argc;

	memset(argv, 0, sizeof(argv));
	argc = ni_dbus_message_get_args_variants(msg, argv, 16);
	if (argc < 0) {
		ni_error("%s: cannot parse arguments for signal %s", __func__, signal_name);
		goto done;
	}

	ifp = ni_objectmodel_addrconf_path_to_device(dbus_message_get_path(msg));
	if (ifp == NULL) {
		ni_debug_dbus("%s: received signal %s for unknown interface %s", __func__,
				signal_name, dbus_message_get_path(msg));
		goto done;
	}

	lease = ni_objectmodel_interface_to_lease(dbus_message_get_interface(msg));
	if (lease == NULL) {
		ni_debug_dbus("received signal %s from %s (unknown service)",
				signal_name, dbus_message_get_interface(msg));
		goto done;
	}

	if (argc >= 1 && !ni_objectmodel_set_addrconf_lease(lease, &argv[0])) {
		ni_debug_dbus("%s: unable to parse lease argument", __func__);
		goto done;
	}

	ni_debug_dbus("received signal %s for interface %s (ifindex %d), lease %s/%s",
			signal_name, ifp->name, ifp->link.ifindex,
			ni_addrconf_type_to_name(lease->type),
			ni_addrfamily_type_to_name(lease->family));
	if (!strcmp(signal_name, "LeaseAcquired")) {
		if (lease->state != NI_ADDRCONF_STATE_GRANTED) {
			ni_error("%s: unexpected lease state in signal %s", __func__, signal_name);
			goto done;
		}
	} else
	if (strcmp(signal_name, "LeaseReleased") && strcmp(signal_name, "LeaseLost")) {
		/* Ignore unknown signal */
		goto done;
	}

	ni_interface_update_lease(ni_global_state_handle(), ifp, lease);
	lease = NULL;

done:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
	if (lease)
		ni_addrconf_lease_free(lease);
}
