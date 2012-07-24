/*
 * Finite state machine and associated functionality for interface
 * bring-up and take-down.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <wicked/netinfo.h>
#include <wicked/objectmodel.h>
#include <wicked/logging.h>
#include <wicked/dbus.h>
#include <wicked/dbus-errors.h>
#include <wicked/fsm.h>

#include "wicked-client.h"

static ni_bool_t		create_zookeeper_service(ni_fsm_t *fsm);
static void			discover_state(ni_dbus_server_t *);

int
do_zookeeper(int argc, char **argv)
{
	enum { OPT_FOREGROUND };
	static struct option options[] = {
		{ "foreground",	no_argument,		 NULL,	OPT_FOREGROUND },
		{ NULL }
	};
	ni_fsm_t *fsm;
	int opt_foreground = 0;
	int c;

	fsm = ni_fsm_new();

	optind = 1;
	while ((c = getopt_long(argc, argv, "", options, NULL)) != EOF) {
		switch (c) {
		case OPT_FOREGROUND:
			opt_foreground = 1;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] zookeeper [zookeeper-options]\n"
				"\nSupported zookeeper-options:\n"
				"  --foreground\n"
				"      Run zookeeper in the foreground rather than as a daemon\n"
				);
			return 1;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Too many arguments\n");
		goto usage;
	}

	create_zookeeper_service(fsm);

	if (!ni_ifworkers_create_client(fsm))
		return 1;

	ni_ifworkers_refresh_state(fsm);

	if (!opt_foreground) {
		if (ni_server_background(program_name) < 0)
			ni_fatal("unable to background server");
		ni_log_destination_syslog(program_name);
	}

	ni_ifworkers_kickstart(fsm);
	if (ni_ifworker_fsm(fsm) != 0)
		ni_ifworker_mainloop(fsm);

	return 1;
}

#if 0
static dbus_bool_t
ni_objectmodel_zookeeper_manage_interface(ni_dbus_object_t *object, const ni_dbus_method_t *method,
				unsigned int argc, const ni_dbus_variant_t *argv,
				ni_dbus_message_t *reply, DBusError *error)
{
	ni_fsm_t *fsm = object->handle;
	xml_document_t *doc;
	const char *ifxml;

	if (argc != 1 || !ni_dbus_variant_get_string(&argv[0], &ifxml))
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	doc = xml_document_from_string(ifxml);
	if (doc == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to parse document");
		return FALSE;
	}

	/* FIXME: do this properly, with error checking */
	if (ni_ifworkers_from_xml(fsm, doc, "zookeeper") != 1) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Document did not contain any interface definition");
		xml_document_free(doc);
		return FALSE;
	}

	/* FIXME: restrict this to "simple" non-composite interfaces */

	xml_document_free(doc);
	return FALSE;
}

static ni_dbus_method_t		ni_objectmodel_zookeeper_methods[] = {
	{ "manageInterface",	"s",		ni_objectmodel_zookeeper_manage_interface	},

	{ NULL }
};

static ni_dbus_service_t        ni_objectmodel_zookeeper_interface = {
	.name		= NI_OBJECTMODEL_ZOOKEEPER_INTERFACE,
	.methods	= ni_objectmodel_zookeeper_methods,
};
#endif

static ni_bool_t
create_zookeeper_service(ni_fsm_t *fsm)
{
	ni_dbus_server_t *server;
	ni_dbus_object_t *object;

	server = ni_server_listen_dbus(NI_OBJECTMODEL_DBUS_BUS_NAME_MANAGER);
	if (server == NULL)
		ni_fatal("unable to initialize dbus service");

	/* Register root interface with the root of the object hierarchy */
	object = ni_dbus_server_get_root_object(server);
#if 0
	ni_dbus_object_register_service(object, &ni_objectmodel_zookeeper_interface);
	ni_assert(object->handle == NULL);
#endif
	object->handle = fsm;

	ni_objectmodel_register_netif_classes();
	ni_objectmodel_register_modem_classes();

	discover_state(server);
	return TRUE;
}

void
discover_state(ni_dbus_server_t *server)
{
	ni_netconfig_t *nc;
	ni_netdev_t *dev;

	nc = ni_global_state_handle(1);
	if (nc == NULL)
		ni_fatal("failed to discover interface state");

	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next)
		ni_objectmodel_register_netif(server, dev, NULL);
}
