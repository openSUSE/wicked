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
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/xml.h>
#include <wicked/socket.h>
#include <wicked/dbus.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/modem.h>
#include <wicked/xpath.h>
#include <wicked/fsm.h>

#include "wicked-client.h"

extern ni_bool_t	ni_manager_call_add_policy(const char *, xml_node_t *);
extern ni_bool_t	ni_manager_call_device_enable(const char *ifname);
extern ni_dbus_object_t *ni_manager_call_get_device(const char *);
extern ni_bool_t	ni_manager_call_add_secret(const char *, const char *, const char *);

/*
 * Read a policy file
 */
static xml_node_t *
ni_ifpolicy_file_load(const char *filename, xml_document_t **doc_p)
{
	xml_document_t *config_doc;
	xml_node_t *node;

	ni_debug_readwrite("%s(%s)", __func__, filename);
	if (!(config_doc = xml_document_read(filename))) {
		ni_error("unable to load interface definition from %s", filename);
		return NULL;
	}

	node = config_doc->root;
	if (config_doc->root == NULL || config_doc->root->children == NULL) {
		ni_error("empty policy document \"%s\"", filename);
		xml_document_free(config_doc);
		return NULL;
	}

	node = config_doc->root->children;
	if (!ni_string_eq(node->name, "policy") || node->next != NULL) {
		ni_error("policy document \"%s\" should contain exactly one <policy> element", filename);
		xml_document_free(config_doc);
		return NULL;
	}

	*doc_p = config_doc;
	return node;
}

/*
 * Enable the given user interface
 */
static int
do_manager_enable(int argc, char **argv)
{
	if (optind >= argc) {
		ni_error("wicked manager enable: expected interface argument");
		return 1;
	}

	while (optind < argc)
		ni_manager_call_device_enable(argv[optind++]);
	return 0;
}

/*
 * Install a policy
 */
static int
do_manager_addpolicy(int argc, char **argv)
{
	const char *filename;
	xml_document_t *doc = NULL;
	xml_node_t *policy_node;
	const char *name;

	if (optind + 1 != argc) {
		ni_error("wicked manager addpolicy: expected filename argument");
		return 1;
	}

	filename = argv[optind++];
	if ((policy_node = ni_ifpolicy_file_load(filename, &doc)) == NULL) {
		ni_error("unable to load policy file");
		return 1;
	}

	if ((name = xml_node_get_attr(policy_node, "name")) == NULL)
		name = "";

	if (!ni_manager_call_add_policy(name, policy_node))
		return 1;

	return 0;
}

/*
 * Install a user name/password
 */
static int
do_manager_addsecret(int argc, char **argv)
{
	const char *security_id, *path, *value;

	if (optind + 3 != argc) {
		ni_error("wicked manager addsecret: expected 3 arguments (security-id, path, value)");
		return 1;
	}

	security_id = argv[optind++];
	path = argv[optind++];
	value = argv[optind++];

	if (!ni_manager_call_add_secret(security_id, path, value))
		return 1;

	return 0;
}

/*
 * Force a re-check on a given interface
 */
static int
do_manager_recheck(int argc, char **argv)
{
	const char *ifname;

	if (optind + 1 != argc) {
		ni_error("wicked manager recheck: expected interface argument");
		return 1;
	}

	ifname = argv[optind++];
	ni_error("%s: not implemented yet", __func__);
	return 1;
}

int
do_manager(int argc, char **argv)
{
	static struct option manager_options[] = {
		{ NULL }
	};
	const char *command;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "+", manager_options, NULL)) != EOF) {
		switch (c) {
		default:
usage:
			fprintf(stderr,
				"wicked [options] manager subcommand [subcommand-options]\n"
				"\nSupported subcommands:\n"
				"  addpolicy <filename>\n"
				"  recheck <ifname>\n"
				"\nSupported ifup-options:\n"
				"  --ifconfig <pathname>\n"
				"      Read interface configuration(s) from file/directory rather than using system config\n"
				"  --ifpolicy <pathname>\n"
				"      Read interface policies from the given file/directory\n"
				"  --mode <label>\n"
				"      Only touch interfaces with matching control <mode>\n"
				"  --boot-stage <label>\n"
				"      Only touch interfaces with matching <boot-stage>\n"
				"  --skip-active\n"
				"      Do not touch running interfaces\n"
				"  --skip-origin <name>\n"
				"      Skip interfaces that have a configuration origin of <name>\n"
				"      Usually, you would use this with the name \"firmware\" to avoid\n"
				"      touching interfaces that have been set up via firmware (like iBFT) previously\n"
				"  --timeout <nsec>\n"
				"      Timeout after <nsec> seconds\n"
				);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing subcommand\n");
		goto usage;
	}

	argv += optind;
	argc -= optind;
	optind = 1;

	command = argv[0];
	if (ni_string_eq(command, "addpolicy"))
		return do_manager_addpolicy(argc, argv);
	if (ni_string_eq(command, "recheck"))
		return do_manager_recheck(argc, argv);
	if (ni_string_eq(command, "enable"))
		return do_manager_enable(argc, argv);
	if (ni_string_eq(command, "addsecret"))
		return do_manager_addsecret(argc, argv);
	
	ni_error("Unsupported manager subcommand \"%s\"", command);
	goto usage;
}

/*
 * Functions for communicating with the manager
 */
ni_dbus_client_t *
ni_manager_create_client(ni_dbus_object_t **root_p)
{
	static ni_dbus_client_t *client;
	static ni_dbus_object_t *root;

	if (root == NULL) {
		client = ni_create_dbus_client(NI_OBJECTMODEL_DBUS_BUS_NAME_MANAGER);
		if (!client)
			ni_fatal("Unable to connect to manager dbus service");

		root = ni_dbus_client_object_new(client,
					&ni_dbus_anonymous_class,
					NI_OBJECTMODEL_MANAGER_PATH,
					NI_OBJECTMODEL_MANAGER_INTERFACE,
					NULL);
	}

	if (root_p)
		*root_p = root;

	return client;
}

ni_bool_t
ni_manager_call_add_policy(const char *name, xml_node_t *node)
{
	ni_dbus_client_t *client;
	ni_dbus_object_t *root_object, *proxy;
	const char *relative_path;
	char *policy_path, *doc_string;
	int rv;

	client = ni_manager_create_client(&root_object);

	rv = ni_dbus_object_call_simple(root_object,
					NI_OBJECTMODEL_MANAGER_INTERFACE, "createPolicy",
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_OBJECT_PATH, &policy_path);
	
	if (rv == -NI_ERROR_POLICY_EXISTS) {
		/* Policy exists, update it transparently */
		char buffer[265];

		snprintf(buffer, sizeof(buffer), NI_OBJECTMODEL_MANAGED_POLICY_LIST_PATH "/%s", name);
		policy_path = strdup(buffer);
	} else
	if (rv < 0) {
		ni_error("Call to %s.createPolicy(%s) failed: %s",
				ni_dbus_object_get_path(root_object), name,
				ni_strerror(rv));
		return FALSE;
	}

	relative_path = ni_dbus_object_get_relative_path(root_object, policy_path);
	ni_assert(relative_path);

	proxy = ni_dbus_object_create(root_object, relative_path, NULL, NULL);

	if ((doc_string = xml_node_sprint(node)) == NULL) {
		ni_error("%s: unable to format <policy> node", __func__);
		return FALSE;
	}

	ni_trace("About to call %s.update()", ni_dbus_object_get_path(proxy));
	if ((rv = ni_dbus_object_call_simple(proxy,
					NI_OBJECTMODEL_MANAGED_POLICY_INTERFACE, "update",
					DBUS_TYPE_STRING, &doc_string,
					DBUS_TYPE_INVALID, NULL)) < 0) {
		ni_error("Call to ManagedPolicy.update() failed: %s", ni_strerror(rv));
		return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_manager_call_add_secret(const char *security_id, const char *path, const char *value)
{
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_client_t *client;
	ni_dbus_object_t *root_object;
	ni_dbus_variant_t argv[3];

	client = ni_manager_create_client(&root_object);

	memset(argv, 0, sizeof(argv));
	ni_dbus_variant_set_string(&argv[0], security_id);
	ni_dbus_variant_set_string(&argv[1], path);
	ni_dbus_variant_set_string(&argv[2], value);

	if (!ni_dbus_object_call_variant(root_object, NI_OBJECTMODEL_MANAGER_INTERFACE, "addSecret",
					3, argv, 0, NULL, &error)) {
		ni_dbus_print_error(&error, "call to addSecret failed");
		dbus_error_free(&error);
		return FALSE;
	}

	ni_dbus_variant_destroy(&argv[0]);
	ni_dbus_variant_destroy(&argv[1]);
	ni_dbus_variant_destroy(&argv[2]);

	return TRUE;
}

ni_dbus_object_t *
ni_manager_call_get_device(const char *ifname)
{
	ni_dbus_client_t *client;
	ni_dbus_object_t *root_object;
	const char *relative_path;
	char *object_path;
	int rv;

	client = ni_manager_create_client(&root_object);

	rv = ni_dbus_object_call_simple(root_object,
					NI_OBJECTMODEL_MANAGER_INTERFACE, "getDevice",
					DBUS_TYPE_STRING, &ifname,
					DBUS_TYPE_OBJECT_PATH, &object_path);
	
	if (rv < 0) {
		ni_error("Call to %s.getDevice(%s) failed: %s",
				ni_dbus_object_get_path(root_object), ifname,
				ni_strerror(rv));
		return NULL;
	}

	relative_path = ni_dbus_object_get_relative_path(root_object, object_path);
	ni_assert(relative_path);

	return ni_dbus_object_create(root_object, relative_path, NULL, NULL);
}

ni_bool_t
ni_manager_call_device_enable(const char *ifname)
{
	ni_dbus_object_t *object;
	int rv;

	if ((object = ni_manager_call_get_device(ifname)) == NULL)
		return FALSE;

	rv = ni_dbus_object_call_simple(object,
					NI_OBJECTMODEL_MANAGED_NETIF_INTERFACE, "enable",
					DBUS_TYPE_INVALID, NULL,
					DBUS_TYPE_INVALID, NULL);
	
	if (rv < 0) {
		ni_error("Call to %s.enable() failed: %s",
				ni_dbus_object_get_path(object), ni_strerror(rv));
		return FALSE;
	}

	return TRUE;
}
