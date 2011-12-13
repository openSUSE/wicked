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
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static void			ni_objectmodel_dhcp4_signal_handler(ni_dbus_connection_t *,
					 ni_dbus_message_t *, void *);
static ni_dbus_client_t *	wicked_dbus_dhcp_client(void);

/*
 * Initialize the dhcp4 client
 */
void
ni_objectmodel_dhcp4_init(ni_dbus_server_t *server)
{
	ni_dbus_client_t *client;

	client = wicked_dbus_dhcp_client();
	ni_dbus_client_add_signal_handler(client, NULL, NULL, WICKED_DBUS_DHCP4_INTERFACE,
			ni_objectmodel_dhcp4_signal_handler,
			server);
}

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
 * Get the dhcp4 object path for the device
 */
static const char *
ni_objectmodel_dhcp4_object_path(const ni_interface_t *dev)
{
	static char object_path[256];

	snprintf(object_path, sizeof(object_path), WICKED_DBUS_OBJECT_PATH "/DHCP4/Interface/%d", dev->link.ifindex);
	return object_path;
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
	ni_dbus_object_t *object;
	ni_dbus_variant_t argument;
	dbus_bool_t rv = FALSE;

	if (req == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: NULL request", __func__);
		return FALSE;
	}

	object = ni_dbus_client_object_new(client, ni_objectmodel_dhcp4_object_path(dev),
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
	ni_dbus_object_t *object;
	ni_dbus_variant_t argument;
	dbus_bool_t rv = FALSE;

	if (lease == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: NULL request", __func__);
		return FALSE;
	}

	object = ni_dbus_client_object_new(client, ni_objectmodel_dhcp4_object_path(dev),
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

/*
 * Callback from DHCP4 supplicant whenever it acquired a lease.
 */
void
ni_objectmodel_dhcp4_signal_handler(ni_dbus_connection_t *conn,
					 ni_dbus_message_t *msg, void *user_data)
{
	static const char *path_base = WICKED_DBUS_OBJECT_PATH "/DHCP4/Interface/";
	const unsigned int path_base_len = strlen(path_base);
	const char *signal_name = dbus_message_get_member(msg);
	const char *path = dbus_message_get_path(msg);
	ni_dbus_variant_t argv[16];
	ni_interface_t *ifp;
	ni_handle_t *nih;
	unsigned int ifindex;
	int argc;

	if (strncmp(path, path_base, strlen(path_base)))
		return;

	if (ni_parse_int(path + path_base_len, &ifindex) < 0)
		return;

	nih = ni_global_state_handle();
	if (ni_refresh(nih, NULL) < 0) {
		ni_error("%s: unable to refresh interfaces", __func__);
		return;
	}

	ifp = ni_interface_by_index(nih, ifindex);
	if (ifp == NULL) {
		ni_error("%s: received signal %s for unknown ifindex %d", __func__, signal_name, ifindex);
		return;
	}

	memset(argv, 0, sizeof(argv));
	argc = ni_dbus_message_get_args_variants(msg, argv, 16);
	if (argc < 0) {
		ni_error("%s: cannot parse arguments for signal %s", __func__, signal_name);
		return;
	}

	ni_debug_dhcp("received signal %s for interface %s (ifindex %d)", signal_name, ifp->name, ifindex);
	if (!strcmp(signal_name, "LeaseAcquired")) {
		ni_addrconf_lease_t *lease;

		if (argc < 1) {
			ni_error("%s: not enough arguments in signal %s", __func__, signal_name);
			goto done;
		}

		/* obtain lease from first argument */
		lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET);
		if (!ni_objectmodel_set_addrconf_lease(lease, &argv[0])) {
			ni_addrconf_lease_free(lease);
			goto done;
		}

		__ni_system_interface_update_lease(nih, ifp, lease);
	} else
	if (!strcmp(signal_name, "LeaseReleased") || !strcmp(signal_name, "LeaseLost")) {
		ni_addrconf_lease_t *lease;

		ni_debug_dhcp("%s: dropping dhcp/ipv4 lease", ifp->name);

		/* obtain lease from first argument */
		lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET);
		__ni_system_interface_update_lease(nih, ifp, lease);
	}

done:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
}
