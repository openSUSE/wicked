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

#include "client/ifconfig.h"
#include "util_priv.h"
#include "nanny.h"

static void		ni_nanny_netif_state_change_signal_receive(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
#ifdef MODEM
static void		ni_nanny_modem_state_change_signal_receive(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
#endif

static void		__ni_nanny_user_free(ni_nanny_user_t *);
static int		ni_nanny_prompt(const ni_fsm_prompt_t *, xml_node_t *, void *);

/*
 * Initialize the manager objectmodel
 */
void
ni_objectmodel_nanny_init(ni_nanny_t *mgr)
{
	ni_dbus_object_t *root_object;

	ni_objectmodel_managed_policy_init(mgr->server);
	ni_objectmodel_managed_netif_init(mgr->server);
#ifdef MODEM
	ni_objectmodel_managed_modem_init(mgr->server);
#endif

	ni_objectmodel_register_service(&ni_objectmodel_nanny_service);

	root_object = ni_dbus_server_get_root_object(mgr->server);
	root_object->handle = mgr;
	root_object->class = &ni_objectmodel_nanny_class;
	ni_objectmodel_bind_compatible_interfaces(root_object);

	{
		unsigned int i;

		ni_debug_nanny("%s supports:", ni_dbus_object_get_path(root_object));
		for (i = 0; root_object->interfaces[i]; ++i) {
			const ni_dbus_service_t *service = root_object->interfaces[i];

			ni_debug_nanny("  %s", service->name);
		}
		ni_debug_nanny("(%u interfaces)", i);
	}
}

ni_nanny_t *
ni_nanny_new(void)
{
	ni_nanny_t *mgr;

	mgr = xcalloc(1, sizeof(*mgr));
	return mgr;
}

void
ni_nanny_start(ni_nanny_t *mgr)
{
	ni_nanny_devmatch_t *match;
	ni_dbus_client_t *client;

	mgr->server = ni_server_listen_dbus(NI_OBJECTMODEL_DBUS_BUS_NAME_NANNY);
	if (!mgr->server)
		ni_fatal("Cannot create server, giving up.");

	mgr->fsm = ni_fsm_new();
	mgr->fsm->worker_timeout = NI_IFWORKER_INFINITE_TIMEOUT;

	ni_fsm_set_user_prompt_fn(mgr->fsm, ni_nanny_prompt, mgr);

	ni_objectmodel_nanny_init(mgr);

	/* Resolve all class references in <enable> config elements,
	 * so that we don't have to do this again for every new device we
	 * discover.
	 */
	for (match = mgr->enable; match; match = match->next) {
		switch (match->type) {
		case NI_NANNY_DEVMATCH_CLASS:
			match->class = ni_objectmodel_get_class(match->value);
			if (!match->class)
				ni_error("cannot enable devices of class \"%s\" - no such class",
						match->value);
			break;
		}
	}

	if (ni_config_use_nanny()) {
		if (!(client = ni_fsm_create_client(mgr->fsm)))
			ni_fatal("Unable to create FSM client");

		ni_dbus_client_add_signal_handler(client, NULL, NULL,
				NI_OBJECTMODEL_NETIF_INTERFACE,
				ni_nanny_netif_state_change_signal_receive,
				mgr);
#ifdef MODEM
		ni_dbus_client_add_signal_handler(client, NULL, NULL,
				NI_OBJECTMODEL_MODEM_INTERFACE,
				ni_nanny_modem_state_change_signal_receive,
				mgr);
#endif
	}
}

void
ni_nanny_free(ni_nanny_t *mgr)
{
	if (mgr->users) {
		ni_nanny_user_t *user;

		while ((user = mgr->users) != NULL) {
			mgr->users = user->next;
			__ni_nanny_user_free(user);
		}
	}

	ni_fatal("%s(): incomplete", __func__);
}

/*
 * (Re-) check a device to see if the applicable policy changed.
 * This is a multi-stage process.
 * One, devices can be scheduled for a recheck explicitly (eg when they
 * appear via hotplug).
 *
 * Two, all enabled devices are checked when policies have been updated.
 *
 * Both checks happen once per mainloop iteration.
 */
void
ni_nanny_schedule_recheck(ni_ifworker_array_t *array, ni_ifworker_t *w)
{
	if (ni_ifworker_array_index(array, w) < 0)
		ni_ifworker_array_append(array, w);
}

void
ni_nanny_unschedule(ni_ifworker_array_t *array, ni_ifworker_t *w)
{
	ni_ifworker_array_remove_with_children(array, w);
}

/*
 * Check whether a given interface should be reconfigured
 */
static unsigned int
ni_nanny_recheck(ni_nanny_t *mgr, ni_ifworker_t *w)
{
	static const unsigned int MAX_POLICIES = 20;
	const ni_fsm_policy_t *policies[MAX_POLICIES];
	const ni_fsm_policy_t *policy;
	ni_managed_device_t *mdev;
	ni_managed_policy_t *mpolicy;
	unsigned int count;
	ni_bool_t factory_device = FALSE;

	mdev = ni_nanny_get_device(mgr, w);
	if (!mdev) {
		/* We have an ifworker for factory device - follow factory device path */
		if (ni_ifworker_is_factory_device(w))
			factory_device = TRUE;
		else if (w->pending || !w->device) {
			ni_error("%s: Unable to recheck non-factory worker - "
				"device is not present (pending=%s, device=%s)",
				w->name, ni_format_boolean(w->pending),
				ni_format_boolean(!!w->device));
			return -1;
		}
	}

	/* Note, we also check devices in state FAILED.
	 * ni_managed_device_apply_policy() will then check if the policy
	 * changed. If it did, then we give it another try.
	 */

	ni_debug_nanny("%s(%s)", __func__, w->name);
	w->use_default_policies = TRUE;
	if ((count = ni_fsm_policy_get_applicable_policies(mgr->fsm, w, policies, MAX_POLICIES)) == 0) {
		ni_debug_nanny("%s: no applicable policies", w->name);
		return count;
	}

	policy = policies[count-1];
	mpolicy = ni_nanny_get_policy(mgr, policy);

	if (factory_device)
		count += ni_factory_device_apply_policy(mgr->fsm, w, mpolicy);
	else
		count += ni_managed_device_apply_policy(mdev, mpolicy);

	return count;
}

unsigned int
ni_nanny_recheck_do(ni_nanny_t *mgr)
{
	unsigned int i, count = 0;
	ni_fsm_t *fsm = mgr->fsm;

	ni_assert(fsm);
#if 0
	if (ni_fsm_policies_changed_since(fsm, &mgr->last_policy_seq)) {
		ni_managed_device_t *mdev;

		for (mdev = mgr->device_list; mdev; mdev = mdev->next) {
			if (mdev->monitor) {
				ni_ifworker_t *w = ni_managed_device_get_worker(mdev);

				if (w)
					ni_nanny_schedule_recheck(&mgr->recheck, w);
		}
	}
#endif

	for (i = 0; i < mgr->recheck.count; ++i) {
		ni_ifworker_t *w = mgr->recheck.data[i];

		if (!w->failed && !w->done && !w->pending && !ni_ifworker_active(w))
			count += ni_nanny_recheck(mgr, w);
	}

	return count;
}

/*
 * Taking down an interface
 */
unsigned int
ni_nanny_down_do(ni_nanny_t *mgr)
{
	unsigned int i, count = 0;

	for (i = 0; i < mgr->down.count; ++i) {
		ni_ifworker_t *w = mgr->down.data[i];
		ni_managed_device_t *mdev;

		if ((mdev = ni_nanny_get_device(mgr, w)) != NULL) {
			ni_managed_device_down(mdev);
			count++;
		}
	}

	if (i > 0)
		ni_ifworker_array_destroy(&mgr->down);

	return count;
}

ni_managed_policy_t *
ni_nanny_get_policy(ni_nanny_t *mgr, const ni_fsm_policy_t *policy)
{
	ni_managed_policy_t *mpolicy;

	for (mpolicy = mgr->policy_list; mpolicy; mpolicy = mpolicy->next) {
		if (mpolicy->fsm_policy == policy)
			return mpolicy;
	}

	return NULL;
}

ni_bool_t
ni_nanny_remove_policy(ni_nanny_t *mgr, ni_managed_policy_t *mpolicy)
{
	ni_managed_policy_t **pos, *cur;

	ni_assert(mgr);
	for (pos = &mgr->policy_list; (cur = *pos); pos = &cur->next) {
		if (cur == mpolicy) {
			*pos = cur->next;
			ni_managed_policy_free(cur);
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Handle events from an rfkill switch
 */
void
ni_nanny_rfkill_event(ni_nanny_t *mgr, ni_rfkill_type_t type, ni_bool_t blocked)
{
	ni_managed_device_t *mdev;

	for (mdev = mgr->device_list; mdev; mdev = mdev->next) {
		ni_ifworker_t *w = ni_managed_device_get_worker(mdev);

		if (w && ni_ifworker_get_rfkill_type(w) == type) {
			mdev->rfkill_blocked = blocked;
			if (blocked) {
				ni_debug_nanny("%s: radio disabled", w->name);
			} else {
				/* Re-enable scanning */
				ni_debug_nanny("%s: radio re-enabled, resume monitoring", w->name);
				if (mdev->monitor) {
					ni_managed_netdev_enable(mdev);
#if 0
					ni_nanny_schedule_recheck(&mgr->recheck, w);
#endif
				}
			}
		}
	}
}

/*
 * Creates nanny policy and register managed policy interface.
 * Return:
 *     -1 - policy node does not exist or is errornous
 *      0 - policy already exists
 *      1 - policy created and registered
 */
int
ni_nanny_create_policy(ni_dbus_object_t **policy_object, ni_nanny_t *mgr, const char *doc_string, ni_bool_t schedule)
{
	xml_node_t *root, *pnode, *config = NULL;
	ni_fsm_policy_t *policy = NULL;
	xml_document_t *doc;
	const char *pname;
	ni_ifworker_t *w;
	ni_fsm_t *fsm;
	int rv = 1;

	fsm = mgr->fsm;
	ni_assert(fsm);

	doc = xml_document_from_string(doc_string, NULL);
	if (xml_document_is_empty(doc)) {
		ni_error("Unable to parse policy document %s", doc_string);
		goto error;
	}

	root = xml_document_root(doc);
	if (xml_node_is_empty(root->children)) {
		ni_error("Policy document is empty %s", doc_string);
		goto error;
	}

	if (!xml_node_is_empty(root->children->next)) {
		ni_error("Policy document contains more then one <policy> node %s",
			doc_string);
		goto error;
	}

	pnode = root->children;
	if (!ni_ifconfig_is_policy(pnode)) {
		ni_error("No valid policy document %s", doc_string);
		goto error;
	}

	pname = ni_ifpolicy_get_name(pnode);
	if (!ni_ifpolicy_name_is_valid(pname)) {
		ni_error("Invalid policy name \"%s\"", ni_print_suspect(pname,
			ni_string_len(pname)));
		goto error;
	}

	policy = ni_fsm_policy_by_name(fsm, pname);
	if (policy) {
		ni_debug_nanny("Policy \"%s\" already exists", pname);
		rv = 0;
	}
	else
		policy = ni_fsm_policy_new(fsm, pname, pnode);

	config = xml_node_new(NI_CLIENT_IFCONFIG, NULL);
	config = ni_fsm_policy_transform_document(config, &policy, 1);
	if (!config || !ni_fsm_workers_from_xml(fsm, config, ni_ifpolicy_get_origin(pnode))) {
		ni_error("Unable to extract config or update workers from policy %s",
			doc_string);
		goto error;
	}

	/* Rebuild the hierarchy cause new policy may hit some matches */
	ni_fsm_build_hierarchy(fsm, FALSE);

	w = ni_fsm_ifworker_by_policy_name(fsm, NI_IFWORKER_TYPE_NETDEV, pname);
	if (!w) {
		ni_error("%s: worker creation failed for policy %s", pname, doc_string);
		goto error;
	}

	/* Trigger recheck on factory devices or existing devices if schedule is set */
	if (!w->kickstarted) {
		if (ni_ifworker_is_factory_device(w))
			ni_nanny_schedule_recheck(&mgr->recheck, w);
		else if (schedule && w->device)
			ni_nanny_schedule_recheck(&mgr->recheck, w);
	}

	/* Register the policy */
	if (rv > 0) {
		ni_managed_policy_t *mpolicy;
		ni_dbus_object_t *po_tmp;

		mpolicy = ni_managed_policy_new(mgr, policy, NULL);
		po_tmp = ni_objectmodel_register_managed_policy(mgr->server, mpolicy);
		if (!po_tmp) {
			ni_error("%s: Unable to register managed policy", pname);
			ni_managed_policy_free(mpolicy);
			goto error;
		}

		if (policy_object)
			*policy_object = po_tmp;
	}

	return rv;

error:
	xml_node_free(config);
	ni_fsm_policy_free(policy);
	xml_document_free(doc);
	return -1;
}

static ni_bool_t
ni_managed_device_send_progress_info(ni_managed_device_t *mdev, ni_ifworker_t *w, ni_fsm_state_t state)
{
	ni_dbus_variant_t args = NI_DBUS_VARIANT_INIT;
	const char *interface = NI_OBJECTMODEL_MANAGED_NETIF_INTERFACE;
	const char *signal_name = "progressInfo";
	ni_dbus_server_t *server;
	ni_dbus_object_t *object;
	ni_bool_t ret;

	if (!mdev || !mdev->nanny || !mdev->nanny->server) {
		ni_error("%s: help! No dbus server handle! Cannot send signal.", __func__);
		return FALSE;
	}
	server = mdev->nanny->server;

	if (!mdev->object) {
		ni_error("%s: help! No dbus object handle! Cannot send signal.", __func__);
		return FALSE;
	}
	object = mdev->object;

	if (!ni_ifworker_is_valid_state(state) && state != NI_FSM_STATE_NONE) {
		ni_error("%s: Invalid state: %u", __func__, state);
		return FALSE;
	}

	ni_dbus_variant_init_dict(&args);
	ni_dbus_dict_add_uint32(&args, "current-state", state);
	ni_dbus_dict_add_uint32(&args, "target-state", w->target_state);
	ni_dbus_dict_add_string(&args, "ifname", w->name);

	ni_debug_dbus("sending event \"%s\"", signal_name);
	ret = ni_dbus_server_send_signal(server, object, interface, signal_name, 1, &args);
	if (!ret) {
		ni_error("%s: Cannot send signal %s", __func__, signal_name);
	}

	ni_dbus_variant_destroy(&args);
	return ret;
}

/*
 * Progress callback for bringup
 */
static void
ni_managed_device_progress(ni_ifworker_t *w, ni_fsm_state_t new_state)
{
	ni_managed_device_t *mdev = w->progress.user_data;
	(void)mdev;

	ni_trace("%s(%s) target(%s [%s..%s]), transition(%s => %s)",
			__func__, w->name,
			ni_ifworker_state_name(w->target_state),
			ni_ifworker_state_name(w->target_range.min),
			ni_ifworker_state_name(w->target_range.max),
			ni_ifworker_state_name(w->fsm.state),
			ni_ifworker_state_name(new_state));

	ni_managed_device_send_progress_info(mdev, w, new_state);
}

/*
 * Register a device
 */
void
ni_nanny_register_device(ni_nanny_t *mgr, ni_ifworker_t *w)
{
	ni_managed_device_t *mdev;
	const ni_dbus_class_t *dev_class = NULL;
	ni_nanny_devmatch_t *match;

	if (ni_nanny_get_device(mgr, w) != NULL)
		return;

	mdev = ni_managed_device_new(mgr, w->ifindex, &mgr->device_list);
	if (w->type == NI_IFWORKER_TYPE_NETDEV) {
		mdev->object = ni_objectmodel_register_managed_netdev(mgr->server, mdev);
		dev_class = ni_objectmodel_link_class(w->device->link.type);
	} else
	if (w->type == NI_IFWORKER_TYPE_MODEM) {
		mdev->object = ni_objectmodel_register_managed_modem(mgr->server, mdev);
		dev_class = ni_objectmodel_modem_get_class(w->modem->type);
	}


	for (match = mgr->enable; match; match = match->next) {
		switch (match->type) {
		case NI_NANNY_DEVMATCH_CLASS:
			if (match->class == NULL || dev_class == NULL
			 || !ni_dbus_class_is_subclass(dev_class, match->class))
				continue;
			ni_debug_nanny("devmatch class %s: %p", match->value, match->class);
			break;

		case NI_NANNY_DEVMATCH_DEVICE:
			if (!ni_string_eq(w->name, match->value))
				continue;
			break;
		}

		mdev->allowed = FALSE;
		if (match->auto_enable)
			mdev->monitor = TRUE;
	}

	ni_debug_nanny("new device %s, class %s%s%s", w->name,
			mdev->object->class->name,
			mdev->allowed? ", user control allowed" : "",
			mdev->monitor? ", monitored (auto-enabled)" : "");

	if (ni_fsm_exists_applicable_policy(mgr->fsm->policies, w))
		ni_nanny_schedule_recheck(&mgr->recheck, w);

	ni_ifworker_set_progress_callback(w, ni_managed_device_progress, mdev);
}

/*
 * Unregister a device
 */
void
ni_nanny_unregister_device(ni_nanny_t *mgr, ni_ifworker_t *w)
{
	ni_managed_device_t *mdev = NULL;

	if ((mdev = ni_nanny_get_device(mgr, w)) == NULL) {
		ni_error("%s: cannot unregister; device not known", w->name);
		return;
	}

	ni_nanny_remove_device(mgr, mdev);
	ni_objectmodel_unregister_managed_device(mdev);
	ni_nanny_unschedule(&mgr->recheck, w);
	ni_nanny_policy_drop(w->name);
}

/*
 * Handle prompting
 */
static ni_ifworker_t *
ni_nanny_identify_node_owner(ni_nanny_t *mgr, xml_node_t *node, ni_stringbuf_t *path)
{
	ni_managed_device_t *mdev;
	ni_ifworker_t *w = NULL;

	for (mdev = mgr->device_list; mdev; mdev = mdev->next) {
		if (mdev->selected_config == node) {
			w = ni_managed_device_get_worker(mdev);
			goto found;
		}
	}

	if (node != NULL)
		w = ni_nanny_identify_node_owner(mgr, node->parent, path);

found:
	if (w == NULL)
		return NULL;

	ni_stringbuf_putc(path, '/');
	ni_stringbuf_puts(path, node->name);
	return w;
}

int
ni_nanny_prompt(const ni_fsm_prompt_t *p, xml_node_t *node, void *user_data)
{
	ni_nanny_t *mgr = user_data;
	ni_stringbuf_t path_buf;
	ni_ifworker_t *w = NULL;
	ni_managed_device_t *mdev;
	ni_nanny_user_t *user;
	ni_secret_t *sec;
	int rv = -1;

	ni_debug_nanny("%s: type=%u string=%s id=%s", __func__, p->type, p->string, p->id);

	ni_stringbuf_init(&path_buf);

	w = ni_nanny_identify_node_owner(mgr, node, &path_buf);
	if (w == NULL) {
		ni_error("%s: unable to identify device owning this config", __func__);
		goto done;
	}

	if (!(mdev = ni_nanny_get_device(mgr, w))) {
		ni_error("%s: device not managed by us?!", w->name);
		goto done;
	}

	if (w->security_id.attributes.count == 0) {
		ni_error("%s: no security id set, cannot handle prompt for \"%s\"",
				w->name, path_buf.string);
		goto done;
	}

	if (mdev->selected_policy == NULL) {
		ni_error("%s: no policy set, cannot handle prompt for \"%s\"",
				w->name, path_buf.string);
		goto done;
	}
	if ((user = ni_nanny_get_user(mgr, mdev->selected_policy->owner)) == NULL) {
		ni_error("%s: policy not owned by anyone?!", w->name);
		goto done;
	}

	sec = ni_secret_db_find(user->secret_db, &w->security_id, path_buf.string);
	if (sec == NULL) {
		if (mdev->state == NI_MANAGED_STATE_BINDING) {
			mdev->missing_secrets = TRUE;

			/* Return retry-operation - this makes the validator ignore
			 * the missing secret. In this way, we can record all required
			 * secrets. */
			ni_secret_array_append(&mdev->secrets, sec);
			rv = -NI_ERROR_RETRY_OPERATION;
			goto done;
		}
#if 0
		/* FIXME: Send out event that we need this piece of information */
		ni_debug_nanny("%s: prompting for type=%u id=%s path=%s",
				w->name, p->type, w->security_id, path_buf.string);
#endif
		goto done;
	}

	xml_node_set_cdata(node, sec->value);
	rv = 0;

done:
	ni_stringbuf_destroy(&path_buf);
	return rv;
}

/*
 * Update a secret. If there's a device that has been waiting for this
 * update, recheck it now.
 */
void
ni_nanny_add_secret(ni_nanny_t *mgr, uid_t caller_uid,
			const ni_security_id_t *security_id, const char *path, const char *value)
{
	ni_managed_device_t *mdev;
	ni_nanny_user_t *user;

	if (!(user = ni_nanny_create_user(mgr, caller_uid)))
		return;

	ni_secret_db_update(user->secret_db, security_id, path, value);

	ni_debug_nanny("%s: secret for %s updated", ni_security_id_print(security_id), path);
	for (mdev = mgr->device_list; mdev; mdev = mdev->next) {
		const char *name = ni_managed_device_get_name(mdev);

		if (mdev->missing_secrets) {
			ni_secret_t *missing = NULL;
			unsigned int i;

			for (i = 0; i < mdev->secrets.count; ++i) {
				ni_secret_t *osec = mdev->secrets.data[i];
				if (osec->value == NULL)
					missing = osec;
			}

			if (missing) {
				ni_debug_nanny("%s: secret for %s still missing", name ? name : "anon", missing->path);
				continue;
			}

			ni_debug_nanny("%s: secret for %s updated, rechecking", name ? name : "anon", path);
#if 0
			ni_nanny_schedule_recheck(&mgr->recheck, w);
#endif
		}
	}
}

void
ni_nanny_clear_secrets(ni_nanny_t *mgr, const ni_security_id_t *security_id, const char *path)
{
	ni_nanny_user_t *user;

	for (user = mgr->users; user; user = user->next)
		ni_secret_db_drop(user->secret_db, security_id, path);
}

/*
 * Handle nanny_user objects
 */
ni_nanny_user_t *
ni_nanny_user_new(uid_t uid)
{
	ni_nanny_user_t *user;

	user = xcalloc(1, sizeof(*user));
	user->uid = uid;
	user->secret_db = ni_secret_db_new();
	return user;
}

void
__ni_nanny_user_free(ni_nanny_user_t *user)
{
	ni_secret_db_free(user->secret_db);
	user->secret_db = NULL;
	free(user);
}

static ni_nanny_user_t *
__ni_nanny_get_user(ni_nanny_t *mgr, uid_t uid, ni_bool_t create)
{
	ni_nanny_user_t **pos, *user;

	for (pos = &mgr->users; (user = *pos) != NULL; pos = &user->next) {
		if (user->uid == uid)
			return user;
	}

	if (create)
		*pos = user = ni_nanny_user_new(uid);

	return user;
}

ni_nanny_user_t *
ni_nanny_get_user(ni_nanny_t *mgr, uid_t uid)
{
	return __ni_nanny_get_user(mgr, uid, FALSE);
}

ni_nanny_user_t *
ni_nanny_create_user(ni_nanny_t *mgr, uid_t uid)
{
	return __ni_nanny_get_user(mgr, uid, TRUE);
}

/*
 * Extract fsm handle from dbus object
 */
static ni_nanny_t *
ni_objectmodel_nanny_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_nanny_t *mgr = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_nanny_class))
		return mgr;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s",
			object->path, object->class->name);
	return NULL;
}

/*
 * Wickedd is sending us a signal (such a linkUp/linkDown, or change in the set of
 * visible WLANs)
 */
void
ni_nanny_netif_state_change_signal_receive(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_nanny_t *mgr = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_event_t event;
	ni_managed_device_t *mdev;
	ni_ifworker_t *w;

	if (ni_objectmodel_signal_to_event(signal_name, &event) < 0) {
		ni_debug_nanny("received unknown signal \"%s\" from object \"%s\"",
				signal_name, object_path);
		return;
	}

	if (event == NI_EVENT_DEVICE_CREATE)
		return;

	if (event == NI_EVENT_DEVICE_READY) {
		if ((w = ni_fsm_recv_new_netif_path(mgr->fsm, object_path)))
			ni_nanny_register_device(mgr, w);
	}

	w = ni_fsm_ifworker_by_object_path(mgr->fsm, object_path);
	if (!w) {
		ni_warn("received signal \"%s\" from unknown object \"%s\"",
				signal_name, object_path);
		return;
	}

	if (event == NI_EVENT_DEVICE_DELETE) {
		ni_debug_nanny("%s: received signal \"%s\" from \"%s\"",
				w->name, signal_name, object_path);
		// delete the worker and the managed netif
		ni_nanny_unregister_device(mgr, w);
		return;
	}

	if (w->type != NI_IFWORKER_TYPE_NETDEV || w->device == NULL) {
		ni_error("%s: received signal \"%s\" from \"%s\" (not a managed network device)",
				w->name, signal_name, object_path);
		return;
	}

	if ((mdev = ni_nanny_get_device(mgr, w)) == NULL) {
		ni_debug_nanny("%s: received signal \"%s\" from \"%s\" (not a managed device)",
				w->name, signal_name, object_path);
		return;
	}

	ni_debug_nanny("%s: received signal %s; state=%s, policy=%s%s%s",
			w->name, signal_name,
			ni_managed_state_to_string(mdev->state),
			mdev->selected_policy? ni_fsm_policy_name(mdev->selected_policy->fsm_policy): "<none>",
			mdev->allowed? ", user control allowed" : "",
			mdev->monitor? ", monitored" : "");

	switch (event) {
	case NI_EVENT_DEVICE_READY:
#if 0
		ni_nanny_schedule_recheck(&mgr->recheck, w);
#endif
		break;

	case NI_EVENT_LINK_DOWN:
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
#if 0
		if (mdev->selected_policy != NULL && mdev->monitor)
			ni_nanny_schedule_recheck(&mgr->down, w);
#endif
#if 0
		ni_nanny_unschedule(&mgr->recheck, w);
#endif
		break;

	case NI_EVENT_LINK_ASSOCIATION_LOST:
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
#if 0
		if (mdev->selected_policy != NULL && mdev->monitor)
			ni_nanny_schedule_recheck(&mgr->recheck, w);
#endif
		break;

	case NI_EVENT_LINK_SCAN_UPDATED:
#if 0
		if (mdev->monitor)
			ni_nanny_schedule_recheck(&mgr->recheck, w);
#endif
		break;

	case NI_EVENT_LINK_UP:
		// Link detection - eg for ethernet
#if 0
		if (mdev->monitor)
			ni_nanny_schedule_recheck(&mgr->recheck, w);
#endif
		break;

	default: ;
	}
}

#ifdef MODEM
/*
 * Wickedd is sending us a modem signal (usually discovery or removal of a modem)
 */
void
ni_nanny_modem_state_change_signal_receive(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_nanny_t *mgr = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_event_t event;
	ni_ifworker_t *w;

	if (ni_objectmodel_signal_to_event(signal_name, &event) < 0) {
		ni_debug_nanny("received unknown signal \"%s\" from object \"%s\"",
				signal_name, object_path);
		return;
	}

	/* We receive a deviceCreate signal when a modem was plugged in */
	w = ni_fsm_ifworker_by_object_path(mgr->fsm, object_path);
	if (!w && event == NI_EVENT_DEVICE_CREATE) {
		if ((w = ni_fsm_recv_new_modem_path(mgr->fsm, object_path))) {
			ni_nanny_register_device(mgr, w);
#if 0
			ni_nanny_schedule_recheck(&mgr->recheck, w);
#endif
		}
		return;
	}
	if (!w) {
		ni_warn("received signal \"%s\" from unknown object \"%s\"",
				signal_name, object_path);
		return;
	}

	if (w->type != NI_IFWORKER_TYPE_MODEM || w->modem == NULL) {
		ni_error("%s: received signal \"%s\" from \"%s\" (not a managed modem device)",
				w->name, signal_name, object_path);
		return;
	}

	ni_debug_nanny("%s: received signal %s from %s", w->name, signal_name, object_path);
	if (event == NI_EVENT_DEVICE_DELETE) {
		// delete the worker and the managed modem
		ni_nanny_unregister_device(mgr, w);
	} else if (event == NI_EVENT_DEVICE_READY) {
#if 0
		ni_nanny_schedule_recheck(&mgr->recheck, w);
#endif
		;
	} else {
		// ignore
	}
}
#endif

/*
 * Nanny.getDevice(devname)
 */
static dbus_bool_t
ni_objectmodel_nanny_get_device(ni_dbus_object_t *object, const ni_dbus_method_t *method,
					unsigned int argc, const ni_dbus_variant_t *argv,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_nanny_t *mgr;
	const char *ifname;
	ni_ifworker_t *w;
	ni_managed_device_t *mdev = NULL;

	if ((mgr = ni_objectmodel_nanny_unwrap(object, error)) == NULL)
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_get_string(&argv[0], &ifname))
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	/* XXX: scalability. Use ni_call_identify_device() */
	w = ni_fsm_ifworker_by_name(mgr->fsm, NI_IFWORKER_TYPE_NETDEV, ifname);

	if (w)
		mdev = ni_nanny_get_device(mgr, w);

	if (mdev == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_DEVICE_NOT_KNOWN, "No such device: %s", ifname);
		return FALSE;
	} else {
		ni_netdev_t *dev = ni_ifworker_get_netdev(w);
		char object_path[128];

		snprintf(object_path, sizeof(object_path),
				NI_OBJECTMODEL_MANAGED_NETIF_LIST_PATH "/%u",
				dev->link.ifindex);

		ni_dbus_message_append_object_path(reply, object_path);
	}
	return TRUE;
}

/*
 * Nanny.createPolicy()
 */
static dbus_bool_t
ni_objectmodel_nanny_create_policy(ni_dbus_object_t *object, const ni_dbus_method_t *method,
					unsigned int argc, const ni_dbus_variant_t *argv,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_object_t *policy_object;
	const char *doc_string;
	ni_nanny_t *mgr;
	ni_fsm_t *fsm;
	int rv;

	if ((mgr = ni_objectmodel_nanny_unwrap(object, error)) == NULL)
		return FALSE;

	fsm = mgr->fsm;
	ni_assert(fsm);

	if (argc != 1 || !ni_dbus_variant_get_string(&argv[0], &doc_string) || ni_string_empty(doc_string))
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	rv = ni_nanny_create_policy(&policy_object, mgr, doc_string, FALSE);
	if (rv < 0) {
		dbus_set_error(error, NI_DBUS_ERROR_POLICY_DOESNOTEXIST,
			"Policy \"%s\" creation failed in call to %s.%s",
			doc_string, ni_dbus_object_get_path(object), method->name);
		return FALSE;
	}
	else if (0 == rv) {
		dbus_set_error(error, NI_DBUS_ERROR_POLICY_EXISTS,
			"Policy \"%s\" already exists in call to %s.%s",
			doc_string, ni_dbus_object_get_path(object), method->name);
		return FALSE;
	}

	return ni_dbus_message_append_object_path(reply, ni_dbus_object_get_path(policy_object));
}

ni_bool_t
ni_nanny_policy_drop(const char *pname)
{
	char path[PATH_MAX] = {'\0'};

	ni_managed_policy_filename(pname, path, sizeof(path));

	if (unlink(path) < 0) {
		if (errno == ENOENT)
			return TRUE;

		ni_error("Cannot remove policy file '%s': %m", path);
		return FALSE;
	}
	return TRUE;
}

/*
 * Nanny.deletePolicy()
 */
static dbus_bool_t
ni_objectmodel_nanny_delete_policy(ni_dbus_object_t *object, const ni_dbus_method_t *method,
					unsigned int argc, const ni_dbus_variant_t *argv,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_fsm_policy_t *policy;
	const char *name;
	ni_nanny_t *mgr;

	if ((mgr = ni_objectmodel_nanny_unwrap(object, error)) == NULL)
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_get_string(&argv[0], &name))
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	ni_debug_nanny("Attempting to delete policy %s", name);

	/* Unregistering Policy dbus object */
	if ((policy = ni_fsm_policy_by_name(mgr->fsm, name))) {
		ni_managed_policy_t **pos, *cur;

		for (pos = &mgr->policy_list; (cur = *pos); pos = &cur->next) {
			if (cur->fsm_policy == policy) {
				ni_dbus_server_t *server;
				ni_ifworker_t *w = NULL;

				if (!ni_fsm_policy_remove(mgr->fsm, policy))
					return FALSE;

				ni_debug_nanny("Removed FSM policy %s", name);

				w = ni_fsm_ifworker_by_policy_name(mgr->fsm, NI_IFWORKER_TYPE_NETDEV, name);
				if (w != NULL) {
					ni_managed_device_t *mdev = ni_nanny_get_device(mgr, w);
					if (mdev != NULL)
						ni_managed_device_set_policy(mdev, NULL, NULL);

					w->config.node = NULL;
				}

				*pos = cur->next;
				server = ni_dbus_object_get_server(object);
				if (!ni_objectmodel_unregister_managed_policy(server, cur, name))
					return FALSE;

				ni_nanny_policy_drop(name);

				ni_dbus_message_append_object_path(reply,
					ni_dbus_object_get_path(object));

				return TRUE;
			}
		}
	}

	dbus_set_error(error, NI_DBUS_ERROR_POLICY_DOESNOTEXIST,
		"Policy \"%s\" does not exist in call to %s.%s",
		(ni_string_empty(name) ? "none" : name),
		ni_dbus_object_get_path(object), method->name);

	return FALSE;
}

/*
 * Nanny.addSecret(security-id, path, value)
 * The security-id is an identifier that is derived from eg the modem's IMEI,
 * or the wireless ESSID.
 */
static dbus_bool_t
ni_objectmodel_nanny_set_secret(ni_dbus_object_t *object, const ni_dbus_method_t *method,
					unsigned int argc, const ni_dbus_variant_t *argv,
					uid_t caller_uid,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_security_id_t security_id = NI_SECURITY_ID_INIT;
	const char *element_path, *value;
	ni_nanny_t *mgr;

	if ((mgr = ni_objectmodel_nanny_unwrap(object, error)) == NULL)
		return FALSE;

	if (argc != 3
	 || !ni_objectmodel_unmarshal_security_id(&security_id, &argv[0])
	 || !ni_dbus_variant_get_string(&argv[1], &element_path)
	 || !ni_dbus_variant_get_string(&argv[2], &value)) {
		ni_security_id_destroy(&security_id);
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);
	}

	ni_nanny_add_secret(mgr, caller_uid, &security_id, element_path, value);
	ni_security_id_destroy(&security_id);
	return TRUE;
}

static ni_dbus_method_t		ni_objectmodel_nanny_methods[] = {
	{ "getDevice",		"s",		ni_objectmodel_nanny_get_device	},
	{ "createPolicy",	"s",		ni_objectmodel_nanny_create_policy	},
	{ "deletePolicy",	"s",		ni_objectmodel_nanny_delete_policy	},
	{ "addSecret",		"a{sv}ss",	.handler_ex = ni_objectmodel_nanny_set_secret	},
	{ NULL }
};

ni_dbus_class_t			ni_objectmodel_nanny_class = {
	.name		= "nanny",
};

ni_dbus_service_t		ni_objectmodel_nanny_service = {
	.name		= NI_OBJECTMODEL_NANNY_INTERFACE,
	.compatible	= &ni_objectmodel_nanny_class,
	.methods	= ni_objectmodel_nanny_methods
};
