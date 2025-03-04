/*
 *	wicked client nanny action and utilities
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Olaf Kirch <okir@suse.de>
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

#include "read-config.h"
#include "wicked-client.h"
#include "client/ifxml.h"

/*
 * Enable the given user interface
 */
static int
do_nanny_enable(int argc, char **argv)
{
	if (optind >= argc) {
		ni_error("wicked nanny enable: expected interface argument");
		return 1;
	}

	while (optind < argc)
		ni_nanny_call_device_enable(argv[optind++]);
	return 0;
}

static int
do_nanny_disable(int argc, char **argv)
{
	if (optind >= argc) {
		ni_error("wicked nanny disable: expected interface argument");
		return 1;
	}

	while (optind < argc)
		ni_nanny_call_device_disable(argv[optind++]);
	return 0;
}

/*
 * Install a policy
 */
static int
do_nanny_addpolicy(int argc, char **argv)
{
	xml_document_array_t docs = XML_DOCUMENT_ARRAY_INIT;
	unsigned int i;
	int rv = NI_WICKED_RC_USAGE;

	if (optind + 1 != argc) {
		ni_error("wicked nanny addpolicy: expected pathname argument");
		return rv;
	}

	while (optind < argc) {
		const char *path = argv[optind++];
		/*
		 * The `wicked:xml` is the default schema. When not specified
		 * differently in <$path>, ni_ifconfig_read will automatically
		 * qualify <$path> to the 'wicked:xml:<$path>' config origin.
		 */
		if (!ni_ifconfig_read(&docs, opt_global_rootdir, path,
					NI_IFCONFIG_KIND_POLICY, TRUE, FALSE)) {
			ni_error("Unable to read config source '%s'", path);
			xml_document_array_destroy(&docs);
			return NI_WICKED_RC_ERROR;
		}
	}

	/*
	 * Do not apply attic configurations to nanny, migrate them.
	 */
	if (ni_ifxml_migrate_docs(&docs))
		ni_debug_readwrite("Migrated %s to current schema",
			docs.count == 1 ? "policy" : "policies");

	for (i = 0; i < docs.count; i++) {
		xml_document_t *doc = docs.data[i];
		xml_node_t *root = xml_document_root(doc);
		const char *name = NULL;

		/*
		 * just empty or backend options documents
		 */
		if (!ni_ifxml_is_policy(root) && !ni_ifxml_is_config(root))
			continue;

		rv = ni_nanny_addpolicy(doc);

		/*
		 * document content has been converted
		 * from <interface> to <policy> root ...
		 */
		root = xml_document_root(doc);
		name = ni_ifpolicy_get_name(root);
		if (rv < 1) {
			ni_error("Unable to add '%s' %s from '%s' to nanny",
					name ? name : "<unnamed>",
					root->name, ni_ifpolicy_get_origin(root));
		} else {
			ni_note("Applied '%s' %s from '%s' to nanny",
					name ? name : "<unnamed>",
					root->name, ni_ifpolicy_get_origin(root));
		}
	}

	xml_document_array_destroy(&docs);
	return rv < 0 ? NI_WICKED_RC_ERROR : NI_WICKED_RC_SUCCESS;
}

/*
 * Delete policy
 */
static int
do_nanny_delpolicy(int argc, char **argv)
{
	int rv = NI_WICKED_RC_USAGE;

	if (optind + 1 != argc) {
		ni_error("nanny %s: expected policy name argument", argv[0]);
		return rv;
	}

	while (optind < argc) {
		const char *policy_name = argv[optind++];

		if (!ni_nanny_call_del_policy(policy_name)) {
			ni_error("Unable to delete policy named %s", policy_name);
			rv = NI_WICKED_RC_ERROR;
		}
	}

	return NI_WICKED_RC_SUCCESS;
}

/*
 * Install a user name/password
 */
static int
do_nanny_addsecret(int argc, char **argv)
{
	ni_security_id_t security_id = NI_SECURITY_ID_INIT;
	const char *path, *value;
	ni_bool_t rv = FALSE;

	if (optind + 3 != argc) {
		ni_error("wicked nanny addsecret: expected 3 arguments (security-id, path, value)");
		return 1;
	}

	if (!ni_security_id_parse(&security_id, argv[optind])) {
		ni_error("failed to parse security id \"%s\"", argv[optind]);
		goto out;
	}
	optind++;

	path = argv[optind++];
	value = argv[optind++];

	rv = ni_nanny_call_add_secret(&security_id, path, value);

out:
	ni_security_id_destroy(&security_id);
	return rv ? 0 : 1;
}

/*
 * Force a re-check on a given interface
 */
static int
do_nanny_recheck(int argc, char **argv)
{
	const char *ifname;

	if (optind + 1 != argc) {
		ni_error("wicked nanny recheck: expected interface argument");
		return 1;
	}

	ifname = argv[optind++];
	(void) ifname;
	ni_error("%s: not implemented yet", __func__);
	return 1;
}

int
do_nanny(int argc, char **argv)
{
	enum  { OPT_HELP, };
	static struct option nanny_options[] = {
		{ "help", no_argument, NULL, OPT_HELP },
		{ NULL }
	};
	const char *command;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "+", nanny_options, NULL)) != EOF) {
		switch (c) {
		case OPT_HELP:
		default:
usage:
			fprintf(stderr,
				"wicked [options] nanny <subcommand>\n"
				"\nSupported subcommands:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  enable <device>\n"
				"  disable <device>\n"
				"  addpolicy <filename>\n"
				"  delpolicy <policy name>\n"
				"  addsecret <security-id> <path> <value>\n"
				"  recheck <ifname>\n"
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
		return do_nanny_addpolicy(argc, argv);
	if (ni_string_eq(command, "delpolicy"))
		return do_nanny_delpolicy(argc, argv);
	if (ni_string_eq(command, "recheck"))
		return do_nanny_recheck(argc, argv);
	if (ni_string_eq(command, "enable"))
		return do_nanny_enable(argc, argv);
	if (ni_string_eq(command, "disable"))
		return do_nanny_disable(argc, argv);
	if (ni_string_eq(command, "addsecret"))
		return do_nanny_addsecret(argc, argv);

	ni_error("Unsupported nanny subcommand \"%s\"", command);
	goto usage;
}

/*
 * Add policy node
 *
 * return value:
 *  -1 - error
 *   0 - no policy added
 *   1 - success
 */
int
ni_nanny_addpolicy_node(const xml_node_t *pnode, const char *origin)
{
	const char *name;
	int count = 0;

	if (!pnode)
		return count;

	if (ni_string_empty(origin))
		origin = ni_ifpolicy_get_origin(pnode);

	if (!ni_ifxml_is_policy(pnode)) {
		ni_debug_ifconfig("Rejecting to add invalid policy from %s",
			ni_string_empty(origin) ? "unspecified origin" : origin);
		return -1;
	}
	name = ni_ifpolicy_get_name(pnode);
	if (!ni_ifpolicy_name_is_valid(name)) {
		ni_debug_ifconfig("Cannot add policy from %s without valid name",
			ni_string_empty(origin) ? "unspecified origin" : origin);
		return -1;
	}

	if (!ni_nanny_call_add_policy(name, pnode)) {
		ni_debug_ifconfig("Adding policy %s from %s file failed", name,
			ni_string_empty(origin) ? "unspecified origin" : origin);
		return -1;
	}

	return ++count;
}

/*
 * Add policy document
 *
 * return value:
 *      -1 - error
 *       0 - no policy added
 *   count - success
 */
int
ni_nanny_addpolicy(xml_document_t *doc)
{
	if (xml_document_is_empty(doc))
		return 0;

	if (!ni_convert_cfg_into_policy_doc(doc)) {
		xml_node_t *root = xml_document_root(doc);
		const char *origin = ni_ifconfig_get_origin(root);

		ni_debug_ifconfig("Unable to convert '%s' from '%s' to %s",
			root->name, origin, NI_NANNY_IFPOLICY);
		return -1;
	}
	return ni_nanny_addpolicy_node(xml_document_root(doc), NULL);
}

/*
 * Functions for communicating with nanny
 */
ni_dbus_client_t *
ni_nanny_create_client(ni_dbus_object_t **root_p)
{
	static ni_dbus_client_t *client;
	static ni_dbus_object_t *root;

	if (root == NULL) {
		client = ni_create_dbus_client(NI_OBJECTMODEL_DBUS_BUS_NAME_NANNY);
		if (!client)
			ni_fatal("Unable to connect to nanny dbus service");

		root = ni_dbus_client_object_new(client,
					&ni_dbus_anonymous_class,
					NI_OBJECTMODEL_NANNY_PATH,
					NI_OBJECTMODEL_NANNY_INTERFACE,
					NULL);
	}

	if (root_p)
		*root_p = root;

	return client;
}

static int
ni_nanny_call_create_policy(ni_dbus_object_t *root, const char *name, const char *policy_xml)
{
	char *policy_path = NULL;
	int rv;

	ni_debug_application("Calling %s.createPolicy(%s)", ni_dbus_object_get_path(root), name);
	rv = ni_dbus_object_call_simple(root, NI_OBJECTMODEL_NANNY_INTERFACE, "createPolicy",
					DBUS_TYPE_STRING, (void *)&policy_xml,
					DBUS_TYPE_OBJECT_PATH, &policy_path);
	if (rv < 0)
		ni_debug_application("Call to %s.createPolicy(%s) failed: %s",
				ni_dbus_object_get_path(root), name, ni_strerror(rv));
	else
		ni_debug_application("Successfully created nanny policy %s", policy_path);

	ni_string_free(&policy_path);
	return rv;
}

static int
ni_nanny_call_update_policy(ni_dbus_object_t *root, const char *name, const char *policy_xml)
{
	ni_dbus_object_t *proxy;
	char *policy_path = NULL;
	const char *relative_path = NULL;
	int rv;

	ni_string_printf(&policy_path, NI_OBJECTMODEL_MANAGED_POLICY_LIST_PATH "/%s", name);
	if (policy_path)
		relative_path = ni_dbus_object_get_relative_path(root, policy_path);

	if (ni_string_empty(relative_path)) {
		ni_debug_application("Cannot create relative path to update nanny policy %s", name);
		ni_string_free(&policy_path);
		return -NI_ERROR_DBUS_CALL_FAILED;
	}

	if (!(proxy = ni_dbus_object_create(root, relative_path, NULL, NULL))) {
		ni_debug_application("cannot create proxy object to update nanny policy %s", name);
		ni_string_free(&policy_path);
		return -NI_ERROR_DBUS_CALL_FAILED;
	}

	ni_debug_application("Calling %s.update()", ni_dbus_object_get_path(proxy));
	rv = ni_dbus_object_call_simple(proxy,
					NI_OBJECTMODEL_MANAGED_POLICY_INTERFACE, "update",
					DBUS_TYPE_STRING, (void *)&policy_xml,
					DBUS_TYPE_INVALID, NULL);
	if (rv < 0)
		ni_debug_application("Call to %s.update() failed: %s",
				ni_dbus_object_get_path(proxy), ni_strerror(rv));
	else
		ni_debug_application("Successfully updated nanny policy %s", policy_path);

	ni_dbus_object_free(proxy);
	ni_string_free(&policy_path);
	return rv;
}

ni_bool_t
ni_nanny_call_add_policy(const char *name, const xml_node_t *node)
{
	ni_dbus_object_t *root_object = NULL;
	char *policy_xml = NULL;
	int rv;

	if (!ni_nanny_create_client(&root_object) || !root_object) {
		ni_debug_application("Unable to create nanny client to add policy %s", name);
		return FALSE;
	}

	if ((policy_xml = xml_node_sprint(node)) == NULL) {
		ni_debug_application("Unable to format nanny policy %s", name);
		return FALSE;
	}

	rv = ni_nanny_call_create_policy(root_object, name, policy_xml);
	if (rv == -NI_ERROR_POLICY_EXISTS) {
		/* Policy exists, update it transparently */
		rv = ni_nanny_call_update_policy(root_object, name, policy_xml);
	}

	ni_string_free(&policy_xml);
	return rv == 0;
}

ni_bool_t
ni_nanny_call_del_policy(const char *name)
{
	ni_dbus_object_t *root_object;
	char *policy_path = NULL;
	int rv;

	ni_nanny_create_client(&root_object);

	rv = ni_dbus_object_call_simple(root_object,
				NI_OBJECTMODEL_NANNY_INTERFACE, "deletePolicy",
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_OBJECT_PATH, &policy_path);
	ni_string_free(&policy_path);
	if (rv < 0) {
		ni_debug_application("Call to %s.deletePolicy(%s) failed: %s",
			ni_dbus_object_get_path(root_object), name, ni_strerror(rv));
		return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_nanny_call_add_secret(const ni_security_id_t *security_id, const char *path, const char *value)
{
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_object_t *root_object;
	ni_dbus_variant_t argv[3];

	ni_nanny_create_client(&root_object);

	memset(argv, 0, sizeof(argv));
	ni_objectmodel_marshal_security_id(security_id, &argv[0]);
	ni_dbus_variant_set_string(&argv[1], path);
	ni_dbus_variant_set_string(&argv[2], value);

	if (!ni_dbus_object_call_variant(root_object, NI_OBJECTMODEL_NANNY_INTERFACE, "addSecret",
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
ni_nanny_call_get_device(const char *ifname)
{
	ni_dbus_object_t *root_object;
	ni_dbus_object_t *device_object;
	const char *relative_path;
	char *object_path = NULL;
	int rv;

	ni_nanny_create_client(&root_object);

	rv = ni_dbus_object_call_simple(root_object,
					NI_OBJECTMODEL_NANNY_INTERFACE, "getDevice",
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

	device_object = ni_dbus_object_create(root_object, relative_path, NULL, NULL);
	ni_string_free(&object_path);
	return device_object;
}

ni_bool_t
ni_nanny_call_device_void_method(const char *ifname, const char *method)
{
	ni_dbus_object_t *object;
	int rv;

	if ((object = ni_nanny_call_get_device(ifname)) == NULL)
		return FALSE;

	rv = ni_dbus_object_call_simple(object,
					NI_OBJECTMODEL_MANAGED_NETIF_INTERFACE, method,
					DBUS_TYPE_INVALID, NULL,
					DBUS_TYPE_INVALID, NULL);

	if (rv < 0) {
		ni_error("Call to %s.%s() failed: %s",
				ni_dbus_object_get_path(object), method, ni_strerror(rv));
		return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_nanny_call_device_enable(const char *ifname)
{
	return ni_nanny_call_device_void_method(ifname, "enable");
}

ni_bool_t
ni_nanny_call_device_disable(const char *ifname)
{
	return ni_nanny_call_device_void_method(ifname, "disable");
}

ni_bool_t
ni_nanny_call_recheck(const ni_string_array_t *names)
{
	ni_dbus_variant_t call_resp = NI_DBUS_VARIANT_INIT;
	ni_dbus_variant_t call_argv[1];
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_object_t *root_object = NULL;
	unsigned int i, count;
	ni_bool_t rv = FALSE;

	if (!ni_nanny_create_client(&root_object) || !root_object) {
		ni_debug_application("Unable to create nanny client");
		return FALSE;
	}

	memset(call_argv, 0, sizeof(call_argv));
	ni_dbus_variant_init_string_array(&call_argv[0]);
	count = names ? names->count : 0;
	for (i = 0; i < count; i++) {
		const char *name = names->data[i];
		if (ni_string_empty(name))
			continue;

		if  (!ni_dbus_variant_append_string_array(&call_argv[0], name)) {
			ni_debug_application("Unable to contstuct %s.recheck() arguments",
					ni_dbus_object_get_path(root_object));
			goto cleanup;
		}
	}

	ni_debug_application("Calling %s.recheck()", ni_dbus_object_get_path(root_object));
	if (!(rv = ni_dbus_object_call_variant(root_object,
					NI_OBJECTMODEL_NANNY_INTERFACE, "recheck",
					1, call_argv, 1, &call_resp, &error))) {
		if (dbus_error_is_set(&error)) {
			ni_debug_application("Call to %s.recheck() failed: %s: %s",
					ni_dbus_object_get_path(root_object),
					error.name, error.message);
		} else {
			ni_debug_application("Call to %s.recheck() failed.",
					ni_dbus_object_get_path(root_object));
		}
		dbus_error_free(&error);
	}

cleanup:
	ni_dbus_variant_destroy(&call_argv[0]);
	ni_dbus_variant_destroy(&call_resp);
	return rv;
}

