/*
 * This daemon manages interface policies.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

#include "nanny.h"
#include "util_priv.h"
#include "client/ifconfig.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

const char *
ni_nanny_policy_location(char **location, const char *name)
{
	if (!location || ni_string_empty(name))
		return NULL;

	return ni_string_printf(location, "<%s>", name);
}

const char *
ni_nanny_policy_file_name(char **file, const char *name)
{
	if (!file || ni_string_empty(name))
		return NULL;

	return ni_string_printf(file, "%s" NI_NANNY_POLICY_XML, name);
}

const char *
ni_nanny_policy_file_path(char **path, const char *name)
{
	const char *dir = ni_nanny_statedir();

	if (!path || ni_string_empty(name) || ni_string_empty(dir))
		return NULL;

	return ni_string_printf(path, "%s/%s" NI_NANNY_POLICY_XML, dir, name);
}

ni_bool_t
ni_nanny_policy_drop(const char *name)
{
	char *path = NULL;

	if (!ni_nanny_policy_file_path(&path, name)) {
		ni_error("Cannot construct path to remove policy '%s'", name);
		return FALSE;
	}

	if (unlink(path) < 0 && errno != ENOENT) {
		ni_error("Cannot remove policy file '%s': %m", path);
		ni_string_free(&path);
		return FALSE;
	} else {
		ni_string_free(&path);
		return TRUE;
	}
}

ni_bool_t
ni_nanny_policy_save(const xml_node_t *policy, const char *path, const char *bak)
{
	char *tmp = NULL;
	char *old = NULL;
	FILE *fp = NULL;
	int fd = -1;

	if (xml_node_is_empty(policy) || ni_string_empty(path))
		return FALSE;

	if (!ni_string_empty(bak)) {
		if (!ni_string_printf(&old, "%s%s", path, bak)) {
			ni_error("Cannot construct policy backup file name '%s%s'",
					path, bak);
			goto failure;
		}
	}

	if (!ni_string_printf(&tmp, "%s.XXXXXX", path))
		goto failure;

	if ((fd = mkstemp(tmp)) < 0) {
		ni_error("Cannot create temporary policy file '%s': %m", path);
		goto failure;
	}

	if (!(fp = fdopen(fd, "we"))) {
		close(fd);
		ni_error("Cannot open temporary policy file '%s': %m", path);
		goto failure;
	}

	if (xml_node_print(policy, fp) < 0) {
		ni_error("Cannot write into temporary policy file '%s'", path);
		goto failure;
	} else {
		fclose(fp);
		fp = NULL;
	}

	if (old && rename(path, old) < 0 && errno != ENOENT)
		ni_warn("Cannot create policy backup file '%s': %m", old);

	if (rename(tmp, path) < 0) {
		ni_error("Cannot move temporary file to policy file '%s'", path);
		goto failure;
	}

	return TRUE;

failure:
	if (fp)
		fclose(fp);
	if (tmp)
		unlink(tmp);
	ni_string_free(&tmp);
	ni_string_free(&old);
	return FALSE;
}

static ni_bool_t
ni_managed_policy_save(const ni_managed_policy_t *mpolicy)
{
	const xml_node_t *policy;
	const char *name;
	char *path = NULL;
	ni_bool_t ret;

	if (!mpolicy)
		return FALSE;

	if (!(policy = ni_fsm_policy_node(mpolicy->fsm_policy)))
		return FALSE;

	name = ni_ifpolicy_get_name(policy);
	if (!(ni_nanny_policy_file_path(&path, name)))
		return FALSE;

	ret = ni_nanny_policy_save(policy, path, NULL);
	ni_string_free(&path);
	return ret;
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
 * managed policy list primitives
 */
static inline void
__ni_managed_policy_list_insert(ni_managed_policy_t **list, ni_managed_policy_t *mpolicy)
{
	mpolicy->pprev = list;
	mpolicy->next = *list;
	if (mpolicy->next)
		mpolicy->next->pprev = &mpolicy->next;
	*list = mpolicy;
}

static inline void
__ni_managed_policy_list_unlink(ni_managed_policy_t *mpolicy)
{
	ni_managed_policy_t **pprev, *next;

	pprev = mpolicy->pprev;
	next = mpolicy->next;
	if (pprev)
		*pprev = mpolicy->next;
	if (next)
		next->pprev = pprev;
	mpolicy->pprev = NULL;
	mpolicy->next = NULL;
}

/*
 * managed_policy objects
 */
ni_managed_policy_t *
ni_managed_policy_new(ni_nanny_t *mgr, ni_fsm_policy_t *policy)
{
	ni_managed_policy_t *mpolicy;

	if (!mgr || !policy)
		return NULL;

	mpolicy = xcalloc(1, sizeof(*mpolicy));
	mpolicy->refcount = 1;
	mpolicy->fsm_policy = ni_fsm_policy_ref(policy);

	__ni_managed_policy_list_insert(&mgr->policy_list, mpolicy);
	return mpolicy;
}

ni_managed_policy_t *
ni_managed_policy_ref(ni_managed_policy_t *mpolicy)
{
	if (mpolicy) {
		ni_assert(mpolicy->refcount);
		mpolicy->refcount++;
	}
	return mpolicy;
}

void
ni_managed_policy_free(ni_managed_policy_t *mpolicy)
{
	if (mpolicy) {
		ni_assert(mpolicy->refcount);
		mpolicy->refcount--;
		if (mpolicy->refcount == 0) {
			__ni_managed_policy_list_unlink(mpolicy);
			ni_fsm_policy_free(mpolicy->fsm_policy);
			free(mpolicy);
		}
	}
}

uid_t
ni_managed_policy_owner(const ni_managed_policy_t *mpolicy)
{
	return mpolicy ? ni_fsm_policy_owner(mpolicy->fsm_policy) : -1U;
}

ni_dbus_object_t *
ni_managed_policy_register(ni_nanny_t *mgr, ni_fsm_policy_t *policy)
{
	ni_managed_policy_t *mpolicy;
	ni_dbus_object_t *object;

	if (!mgr || !policy)
		return NULL;

	mpolicy = ni_managed_policy_new(mgr, policy);
	if (!mpolicy)
		return NULL;

	object = ni_objectmodel_register_managed_policy(mgr->server, mpolicy);
	if (!object)
		ni_managed_policy_free(mpolicy);

	return object;
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
	if (object)
		ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}

/*
 * Unregister a policy from our dbus server.
 */
dbus_bool_t
ni_objectmodel_unregister_managed_policy(ni_dbus_server_t *server, ni_managed_policy_t *mpolicy)
{
	ni_fsm_policy_t *policy;
	const char *name;

	if (!server || !mpolicy || !(policy = ni_fsm_policy_ref(mpolicy->fsm_policy)))
		return FALSE;

	name = ni_fsm_policy_name(policy);
	if (ni_dbus_server_unregister_object(server, mpolicy)) {
		ni_debug_dbus("policy \"%s\" unregistered", name);
		ni_fsm_policy_free(policy);
		return TRUE;
	} else {
		ni_debug_dbus("policy \"%s\" not registered", name);
		ni_fsm_policy_free(policy);
		return FALSE;
	}
}

/*
 * Extract managed_policy handle from dbus object
 */
static ni_managed_policy_t *
ni_objectmodel_managed_policy_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_managed_policy_t *mpolicy;

	if (!object)
		return FALSE;

	mpolicy = object->handle;
	if (ni_dbus_object_isa(object, &ni_objectmodel_managed_policy_class))
		return mpolicy;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a managed policy)",
			object->path, object->class->name);
	return NULL;
}

/*
 * Save managed_policy data from dbus object
 */
ni_bool_t
ni_objectmodel_managed_policy_save(ni_dbus_object_t *object)
{
	ni_managed_policy_t *mpolicy;

	if (!object)
		return FALSE;

	mpolicy = ni_objectmodel_managed_policy_unwrap(object, NULL);
	return ni_managed_policy_save(mpolicy);
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

	if ((mpolicy = ni_objectmodel_managed_policy_unwrap(object, error)) == NULL) {
		dbus_set_error_const(error, NI_DBUS_ERROR_POLICY_DOESNOTEXIST, NULL);
		return FALSE;
	}

	if (caller_uid != 0 && caller_uid != ni_managed_policy_owner(mpolicy)) {
		dbus_set_error_const(error, NI_DBUS_ERROR_PERMISSION_DENIED, NULL);
		return FALSE;
	}

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

	ni_ifpolicy_set_owner_uid(node, caller_uid);
	if (!ni_fsm_policy_update(mpolicy->fsm_policy, node)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Incorrect/incomplete policy in call to %s.%s",
				ni_dbus_object_get_path(object), method->name);
		xml_document_free(doc);
		return FALSE;
	}
	xml_document_free(doc);

	mpolicy->seqno++;

	if (!ni_managed_policy_save(mpolicy)) {
		ni_warn("Unable to save updated managed nanny policy %s",
			ni_dbus_object_get_path(object));
	}

	return TRUE;
}

static const ni_dbus_method_t	ni_objectmodel_managed_policy_methods[] = {
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

const ni_dbus_class_t		ni_objectmodel_managed_policy_class = {
	.name			= NI_OBJECTMODEL_MANAGED_POLICY_CLASS,
	.initialize		= ni_managed_policy_initialize,
	.destroy		= ni_managed_policy_destroy,
};

const ni_dbus_service_t		ni_objectmodel_managed_policy_service = {
	.name			= NI_OBJECTMODEL_MANAGED_POLICY_INTERFACE,
	.compatible		= &ni_objectmodel_managed_policy_class,
	.methods		= ni_objectmodel_managed_policy_methods,
};

