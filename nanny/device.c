/*
 * Generic device management functions
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
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
#include <wicked/client.h>
#include "manager.h"


static const char *	ni_managed_device_get_essid(xml_node_t *);

/*
 * List handling functions
 */
static inline void
ni_managed_device_list_append(ni_managed_device_t **list, ni_managed_device_t *mdev)
{
	ni_managed_device_t *next;

	if ((next = *list) != NULL)
		next->prev = &mdev->next;
	mdev->next = *list;
	mdev->prev = list;
	*list = mdev;
}

static inline void
ni_managed_device_list_unlink(ni_managed_device_t *mdev)
{
	ni_managed_device_t **prev, *next;

	prev = mdev->prev;
	next = mdev->next;

	if (prev)
		*prev = next;
	if (next)
		next->prev = prev;
	mdev->prev = NULL;
	mdev->next = NULL;
}

/*
 * create a new managed_device object
 */
ni_managed_device_t *
ni_managed_device_new(ni_manager_t *mgr, ni_ifworker_t *w, ni_managed_device_t **list)
{
	ni_managed_device_t *mdev;

	mdev = calloc(1, sizeof(*mdev));
	mdev->manager = mgr;
	mdev->worker = ni_ifworker_get(w);

	if (list)
		ni_managed_device_list_append(list, mdev);

	return mdev;
}

void
ni_managed_device_free(ni_managed_device_t *mdev)
{
	ni_debug_nanny("%s(%s): obj=%p", __func__,
			mdev->worker? mdev->worker->name : "anon",
			mdev->object);
	ni_assert(mdev->object == NULL);

	if (mdev->worker) {
		ni_ifworker_release(mdev->worker);
		mdev->worker = NULL;
	}

	ni_secret_array_destroy(&mdev->secrets);
	free(mdev);
}

ni_ifworker_type_t
ni_managed_device_type(const ni_managed_device_t *mdev)
{
	return mdev->worker->type;
}

void
ni_managed_device_set_policy(ni_managed_device_t *mdev, ni_managed_policy_t *mpolicy, xml_node_t *config)
{
	if (mdev->selected_config)
		xml_node_free(mdev->selected_config);
	mdev->selected_config = config;

	mdev->selected_policy = mpolicy;
	mdev->selected_policy_seq = mpolicy? mpolicy->seqno : 0;
}

void
ni_managed_device_set_security_id(ni_managed_device_t *mdev, const char *security_id)
{
	ni_ifworker_t *w = mdev->worker;

	if (!ni_string_eq(w->security_id, security_id))
		ni_secret_array_destroy(&mdev->secrets);
	ni_string_dup(&w->security_id, security_id);
}

/*
 * Apply policy to a device
 */
void
ni_managed_device_apply_policy(ni_managed_device_t *mdev, ni_managed_policy_t *mpolicy)
{
	ni_ifworker_t *w = mdev->worker;
	const char *type_name;
	const ni_fsm_policy_t *policy = mpolicy->fsm_policy;
	xml_node_t *config = NULL;

	if (mdev->state == NI_MANAGED_STATE_FAILED)
		return; // we shouldn't have gotten here?

	/* If the device is up and running, do not reconfigure unless the policy
	 * has really changed */
	if (mdev->state != NI_MANAGED_STATE_STOPPED) {
		if (mdev->selected_policy == mpolicy && mdev->selected_policy_seq == mpolicy->seqno) {
			ni_debug_nanny("%s: keep using policy %s", w->name, ni_fsm_policy_name(policy));
			return;
		}

		/* Just install the new policy and reconfigure. */
	}

	ni_debug_nanny("%s: using policy %s", w->name, ni_fsm_policy_name(policy));

	/* This returns "modem" or "interface" */
	type_name = ni_ifworker_type_to_string(w->type);

	config = xml_node_new(type_name, NULL);
	xml_node_new_element("name", config, w->name);

	config = ni_fsm_policy_transform_document(config, &policy, 1);
	if (config == NULL) {
		ni_error("%s: error when applying policy to %s document", w->name, type_name);
		if (mdev->state != NI_MANAGED_STATE_STOPPED)
			ni_manager_schedule_down(mdev->manager, w);
		return;
	}
	ni_debug_nanny("%s: using device config", w->name);
	xml_node_print_debug(config, 0);

	ni_managed_device_set_policy(mdev, mpolicy, config);

	/* Now do the fandango */
	ni_managed_device_up(mdev);
}

/*
 * Completion callback for bringup
 */
static void
ni_managed_device_up_done(ni_ifworker_t *w)
{
	ni_manager_t *mgr = w->completion.user_data;
	ni_managed_device_t *mdev;

	if ((mdev = ni_manager_get_device(mgr, w)) == NULL) {
		ni_error("%s: no managed device for worker %s", __func__, w->name);
		return;
	}

	if (w->failed) {
		mdev->fail_count++;
		if (w->dead) {
			ni_error("%s: failed to bring up device, device about to be removed", w->name);
		} else
		if (mdev->fail_count < mdev->max_fail_count) {
			ni_error("%s: failed to bring up device, still continuing", w->name);
			mdev->state = NI_MANAGED_STATE_LIMBO;
			ni_manager_schedule_recheck(mgr, w);
		} else {
			/* Broadcast an error and take down the device
			 * for good. */
			/* FIXME TBD */
			mdev->state = NI_MANAGED_STATE_FAILED;
		}

		/* A wrong PIN or password may have triggered the problem;
		 * for now better play it safe and wipe all secrets for this
		 * device. Using the wrong PIN repeatedly may end up locking
		 * the device. */
		if (w->security_id)
			ni_manager_clear_secrets(mgr, w->security_id, NULL);
	} else {
		ni_ifworker_reset(w);
		mdev->fail_count = 0;
		mdev->state = NI_MANAGED_STATE_RUNNING;
	}
}

/*
 * Bring up the device
 */
void
ni_managed_device_up(ni_managed_device_t *mdev)
{
	ni_fsm_t *fsm = mdev->manager->fsm;
	ni_ifworker_t *w = mdev->worker;
	unsigned int target_state;
	char security_id[256];
	int rv;

	ni_ifworker_reset(w);

	switch (w->type) {
	case NI_IFWORKER_TYPE_NETDEV:
		mdev->max_fail_count = 3;
		if (w->device->link.type == NI_IFTYPE_WIRELESS) {
			const char *essid;

			if ((essid = ni_managed_device_get_essid(mdev->selected_config)) != NULL) {
				snprintf(security_id, sizeof(security_id), "wireless:%s", essid);
				ni_managed_device_set_security_id(mdev, security_id);
			}
		}

		target_state = NI_FSM_STATE_ADDRCONF_UP;
		break;

	case NI_IFWORKER_TYPE_MODEM:
		mdev->max_fail_count = 1;
		snprintf(security_id, sizeof(security_id), "modem:%s", w->modem->identify.equipment);
		ni_managed_device_set_security_id(mdev, security_id);

		target_state = NI_FSM_STATE_LINK_UP;
		break;

	default:
		return;
	}

	ni_ifworker_set_completion_callback(w, ni_managed_device_up_done, mdev->manager);

	ni_ifworker_set_config(w, mdev->selected_config, "manager");
	w->target_range.min = target_state;
	w->target_range.max = __NI_FSM_STATE_MAX;

	/* Binding: this validates the XML configuration document,
	 * resolves any references to other devices (if there are any),
	 * and retrieves any keys/passwords etc via the prompt callback.
	 * Inside the prompt callback, we record all secrets for tracking
	 */
	ni_secret_array_destroy(&mdev->secrets);
	mdev->state = NI_MANAGED_STATE_BINDING;
	if ((rv = ni_ifworker_bind_early(w, fsm, TRUE)) < 0)
		goto failed;
	if (mdev->state == NI_MANAGED_STATE_MISSING_SECRETS) {
		/* FIXME: Emit an event listing the secrets we're missing.
		 */
		return;
	}

	mdev->state = NI_MANAGED_STATE_STARTING;
	if ((rv = ni_ifworker_start(fsm, w, fsm->worker_timeout)) < 0)
		goto failed;

	return;

failed:
	ni_error("%s: cannot start device: %s", w->name, ni_strerror(rv));
	mdev->state = NI_MANAGED_STATE_FAILED;
}

/*
 * Helper function: given the config document, find out which essid we are
 * about to configure.
 */
const char *
ni_managed_device_get_essid(xml_node_t *config)
{
	xml_node_t *node;

	if (config == NULL)
		return NULL;

	if (!(node = xml_node_get_child(config, "wireless"))
	 || !(node = xml_node_get_child(node, "essid")))
		return NULL;

	return node->cdata;
}

/*
 * Completion callback for shutdown
 */
static void
ni_managed_device_down_done(ni_ifworker_t *w)
{
	ni_manager_t *mgr = w->completion.user_data;
	ni_managed_device_t *mdev;

	if ((mdev = ni_manager_get_device(mgr, w)) == NULL) {
		ni_error("%s: no managed device for worker %s", __func__, w->name);
		return;
	}

	if (w->failed) {
		mdev->fail_count++;
		if (w->dead) {
			/* Quietly ignore the problem */
			ni_debug_nanny("%s: failed to shut down device, device about to be removed", w->name);
		} else {
			ni_error("%s: failed to shut down device", w->name);
			mdev->state = NI_MANAGED_STATE_FAILED;
		}
	} else {
		ni_ifworker_reset(w);
		mdev->state = NI_MANAGED_STATE_STOPPED;
	}
	ni_managed_device_set_policy(mdev, NULL, NULL);

	if (mdev->user_controlled && w->type == NI_IFWORKER_TYPE_NETDEV) {
		/* Re-enable wireless scanning and ethernet link status monitoring */
		ni_managed_netdev_enable(mdev);
	}
}

/*
 * Bring up the device
 */
void
ni_managed_device_down(ni_managed_device_t *mdev)
{
	ni_fsm_t *fsm = mdev->manager->fsm;
	ni_ifworker_t *w = mdev->worker;
	int rv;

	ni_ifworker_reset(w);

	ni_ifworker_set_completion_callback(w, ni_managed_device_down_done, mdev->manager);

	ni_ifworker_set_config(w, mdev->selected_config, "manager");
	w->target_range.min = NI_FSM_STATE_NONE;
	w->target_range.max = NI_FSM_STATE_DEVICE_EXISTS;

	if ((rv = ni_ifworker_start(fsm, w, fsm->worker_timeout)) >= 0) {
		mdev->state = NI_MANAGED_STATE_STOPPING;
	} else {
		ni_error("%s: cannot stop device: %s", w->name, ni_strerror(rv));
		mdev->state = NI_MANAGED_STATE_FAILED;
	}
}

/*
 * Print managed_state names
 */
static ni_intmap_t	__managed_state_names[] = {
	{ "stopped",	NI_MANAGED_STATE_STOPPED	},
	{ "starting",	NI_MANAGED_STATE_STARTING	},
	{ "running",	NI_MANAGED_STATE_RUNNING	},
	{ "stopping",	NI_MANAGED_STATE_STOPPING	},
	{ "limbo",	NI_MANAGED_STATE_LIMBO		},
	{ "failed",	NI_MANAGED_STATE_FAILED		},
	{ NULL }
};

const char *
ni_managed_state_to_string(ni_managed_state_t state)
{
	const char *name;

	if ((name = ni_format_int_mapped(state, __managed_state_names)) == NULL)
		name = "unknown";
	return name;
}

/*
 * Look up managed device for a given ifworker
 */
ni_managed_device_t *
ni_manager_get_device(ni_manager_t *mgr, ni_ifworker_t *w)
{
	ni_managed_device_t *mdev;

	ni_assert(w);

	for (mdev = mgr->device_list; mdev; mdev = mdev->next) {
		if (mdev->worker == w)
			return mdev;
	}
	return NULL;
}

void
ni_manager_remove_device(ni_manager_t *mgr, ni_managed_device_t *mdev)
{
	ni_managed_device_list_unlink(mdev);
}

void
ni_objectmodel_unregister_managed_device(ni_managed_device_t *mdev)
{
	if (mdev->object) {
		ni_dbus_object_free(mdev->object);
		mdev->object = NULL;
	}
}

