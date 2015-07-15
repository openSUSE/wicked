/*
 * This daemon manages interface policies.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/objectmodel.h>
#include <wicked/modem.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/fsm.h>

#include "util_priv.h"
#include "nanny.h"
#include "client/ifconfig.h"

ni_bool_t
ni_managed_policy_filename(const char *name, char *path, size_t size)
{
	if (path && !ni_string_empty(name)) {
		snprintf(path, size, "%s/%s.xml", ni_nanny_statedir(), name);
		return TRUE;
	}

	return FALSE;
}

static ni_bool_t
ni_managed_policy_save(const xml_node_t *pnode)
{
	char path[PATH_MAX] = {'\0'};
	char temp[PATH_MAX] = {'\0'};
	const char *pname;
	FILE *fp;
	int fd;

	if (xml_node_is_empty(pnode))
		return FALSE;

	pname = ni_ifpolicy_get_name(pnode);
	if (ni_string_empty(pname))
		return FALSE;

	ni_managed_policy_filename(pname, path, sizeof(path));
	snprintf(temp, sizeof(temp), "%s.XXXXXX", path);

	if ((fd = mkstemp(temp)) < 0) {
		ni_error("Cannot create %s policy temp file", path);
		return FALSE;
	}

	if (!(fp = fdopen(fd, "we"))) {
		close(fd);
		ni_error("Cannot create %s policy temp file", path);
		goto failure;
	}

	if (xml_node_print(pnode, fp) < 0) {
		ni_error("Cannot write into %s policy temp file", path);
		goto failure;
	}

	if (rename(temp, path) < 0) {
		ni_error("Cannot move temp file to policy file %s", path);
		goto failure;
	}

	fclose(fp);

	return TRUE;

failure:
	if (fp) {
		fclose(fp);
	}
	unlink(temp);
	return FALSE;
}

void
ni_objectmodel_managed_policy_init(ni_dbus_server_t *server)
{
	ni_dbus_object_t *root_object;

	ni_objectmodel_register_class(&ni_objectmodel_managed_policy_class);
	ni_objectmodel_register_service(&ni_objectmodel_managed_policy_service);

	root_object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_create(root_object, "Policy", NULL, NULL);
}

/*
 * managed_policy objects
 */
ni_managed_policy_t *
ni_managed_policy_new(ni_nanny_t *mgr, ni_fsm_policy_t *policy, xml_document_t *doc, uid_t caller_uid)
{
	ni_managed_policy_t *mpolicy;

	mpolicy = xcalloc(1, sizeof(*mpolicy));
	mpolicy->fsm_policy = policy;
	mpolicy->doc = doc;
	mpolicy->owner = caller_uid;

	mpolicy->next = mgr->policy_list;
	mgr->policy_list = mpolicy;
	return mpolicy;
}

void
ni_managed_policy_free(ni_managed_policy_t *mpolicy)
{
	if (mpolicy) {
		if (mpolicy->doc)
			xml_document_free(mpolicy->doc);
		memset(mpolicy, 0, sizeof(*mpolicy));
	}
	free(mpolicy);
}

void
ni_managed_policy_list_unlink(ni_nanny_t *mgr, ni_managed_policy_t *mpolicy)
{
	ni_managed_policy_t **pos, *cur;

	ni_assert(mgr);
	if (!mpolicy)
		return;

	for (pos = &mgr->policy_list; (cur = *pos); pos = &cur->next) {
		if (cur == mpolicy) {
			*pos = cur->next;
			break;
		}
	}
}

ni_managed_policy_t *
ni_managed_policy_by_policy(ni_nanny_t *mgr, const ni_fsm_policy_t *policy)
{
	ni_managed_policy_t *mpolicy;

	if (!policy)
		return NULL;

	for (mpolicy = mgr->policy_list; mpolicy; mpolicy = mpolicy->next) {
		if (mpolicy->fsm_policy == policy)
			return mpolicy;
	}

	return NULL;
}

ni_managed_policy_t *
ni_managed_policy_update(ni_managed_policy_t *mpolicy, xml_node_t *pnode, uid_t caller_uid)
{
	xml_document_t *doc;

	if (!mpolicy || !ni_ifpolicy_is_valid(pnode))
		return NULL;

	if (!ni_fsm_policy_update(mpolicy->fsm_policy, pnode)) {
		ni_error("Unable to update policy %s",
			ni_fsm_policy_name(mpolicy->fsm_policy));
		return NULL;
	}

	doc = xml_document_from_node(pnode);
	if (xml_document_is_empty(doc))
		return NULL;

	xml_document_free(mpolicy->doc);
	mpolicy->doc = doc;
	mpolicy->seqno++;
	mpolicy->owner = caller_uid;

	ni_managed_policy_save(pnode);
	return mpolicy;
}

ni_dbus_object_t *
ni_managed_policy_register(ni_nanny_t *mgr, ni_fsm_policy_t *policy, xml_node_t *pnode, uid_t caller_uid)
{
	ni_managed_policy_t *mpolicy;
	xml_document_t *doc;
	ni_dbus_object_t *po;

	ni_assert(mgr);
	if (!policy || !ni_ifpolicy_is_valid(pnode))
		return NULL;

	doc = xml_document_from_node(pnode);
	if (xml_document_is_empty(doc))
		return NULL;

	mpolicy = ni_managed_policy_new(mgr, policy, doc, caller_uid);
	po = ni_objectmodel_register_managed_policy(mgr->server, mpolicy);
	if (po)
		ni_managed_policy_save(pnode);
	else
		ni_managed_policy_free(mpolicy);

	return po;
}

/*
 * Create a dbus object representing the managed netdev
 */
ni_dbus_object_t *
ni_objectmodel_register_managed_policy(ni_dbus_server_t *server, ni_managed_policy_t *mpolicy)
{
	char relative_path[128];
	ni_dbus_object_t *object;

	snprintf(relative_path, sizeof(relative_path), "Policy/%s",
					ni_fsm_policy_name(mpolicy->fsm_policy));
	object = ni_dbus_server_register_object(server, relative_path, &ni_objectmodel_managed_policy_class, mpolicy);

	ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}

/*
 * Unregister a modem from our dbus server.
 */
dbus_bool_t
ni_objectmodel_unregister_managed_policy(ni_dbus_server_t *server, ni_managed_policy_t *mpolicy, const char *name)
{
	if (ni_dbus_server_unregister_object(server, mpolicy)) {
		ni_debug_dbus("unregistered policy %s", name);
		return TRUE;
	}

	return FALSE;
}

/*
 * Extract managed_policy handle from dbus object
 */
static ni_managed_policy_t *
ni_objectmodel_managed_policy_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_managed_policy_t *mpolicy = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_managed_policy_class))
		return mpolicy;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a managed policy)",
			object->path, object->class->name);
	return NULL;
}

/*
 * ManagedPolicy.update(s)
 */
static dbus_bool_t
ni_objectmodel_managed_policy_update(ni_dbus_object_t *object, const ni_dbus_method_t *method,
					unsigned int argc, const ni_dbus_variant_t *argv,
					uid_t caller_uid,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_managed_policy_t *mpolicy;
	xml_document_t *doc;
	const char *ifxml;
	xml_node_t *node;

	if ((mpolicy = ni_objectmodel_managed_policy_unwrap(object, error)) == NULL)
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_get_string(&argv[0], &ifxml))
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	doc = xml_document_from_string(ifxml, NULL);
	if (doc == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "Unable to parse document");
		return FALSE;
	}

	if (doc->root == NULL
	 || (node = doc->root->children) == NULL
	 || !ni_ifpolicy_is_valid(node)
	 || node->next != NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"XML document should contain exactly one <policy> element");
		xml_document_free(doc);
		return FALSE;
	}

	if (!ni_fsm_policy_update(mpolicy->fsm_policy, node)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Incorrect/incomplete policy in call to %s.%s",
				ni_dbus_object_get_path(object), method->name);
		xml_document_free(doc);
		return FALSE;
	}

	mpolicy->owner = caller_uid;
	if (mpolicy->doc)
		xml_document_free(mpolicy->doc);
	mpolicy->doc = doc;
	mpolicy->seqno++;

	ni_managed_policy_save(node);
	return TRUE;
}

static ni_dbus_method_t		ni_objectmodel_managed_policy_methods[] = {
	{ "update",		"s",		.handler_ex = ni_objectmodel_managed_policy_update	},
	{ NULL }
};

/*
 * ctor/dtor for the managed-policy class
 */
static void
ni_managed_policy_initialize(ni_dbus_object_t *object)
{
	ni_assert(object->handle == NULL);
}

static void
ni_managed_policy_destroy(ni_dbus_object_t *object)
{
	ni_managed_policy_t *policy;

	if (!(policy = ni_objectmodel_managed_policy_unwrap(object, NULL)))
		return;

	ni_managed_policy_free(policy);
}

ni_dbus_class_t			ni_objectmodel_managed_policy_class = {
	.name		= "managed-policy",
	.initialize	= ni_managed_policy_initialize,
	.destroy	= ni_managed_policy_destroy,
};

ni_dbus_service_t		ni_objectmodel_managed_policy_service = {
	.name		= NI_OBJECTMODEL_MANAGED_POLICY_INTERFACE,
	.compatible	= &ni_objectmodel_managed_policy_class,
	.methods	= ni_objectmodel_managed_policy_methods,
};

