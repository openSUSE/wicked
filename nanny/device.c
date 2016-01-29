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
#include "util_priv.h"
#include "nanny.h"


static const char *	ni_managed_device_get_essid(xml_node_t *);

static int		ni_managed_device_up(ni_managed_device_t *, const char *);
static int		ni_factory_device_up(ni_fsm_t *, ni_ifworker_t *);

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
ni_managed_device_new(ni_nanny_t *mgr, unsigned int ifindex, ni_managed_device_t **list)
{
	ni_managed_device_t *mdev;

	mdev = xcalloc(1, sizeof(*mdev));
	mdev->nanny = mgr;
	mdev->ifindex = ifindex;

	if (list)
		ni_managed_device_list_append(list, mdev);

	return mdev;
}

void
ni_managed_device_free(ni_managed_device_t *mdev)
{
	ni_ifworker_t *w = ni_managed_device_get_worker(mdev);

	ni_debug_nanny("%s(%s): obj=%p", __func__, w ? w->name : "anon", mdev->object);
	ni_assert(mdev->object == NULL);

	ni_secret_array_destroy(&mdev->secrets);
	free(mdev);
}

ni_ifworker_type_t
ni_managed_device_type(const ni_managed_device_t *mdev)
{
	ni_ifworker_t *w = ni_managed_device_get_worker(mdev);

	return w ? w->type : NI_IFWORKER_TYPE_NONE;
}

void
ni_managed_device_set_policy(ni_managed_device_t *mdev, ni_managed_policy_t *mpolicy, xml_node_t *config)
{
	xml_node_free(mdev->selected_config);
	mdev->selected_config = xml_node_clone_ref(config);

	ni_managed_policy_free(mdev->selected_policy);
	mdev->selected_policy = ni_managed_policy_ref(mpolicy);

	mdev->selected_policy_seq = mpolicy ? mpolicy->seqno : 0;
}

void
ni_managed_device_set_security_id(ni_managed_device_t *mdev, const ni_security_id_t *security_id)
{
	ni_ifworker_t *w;

	if ((w = ni_managed_device_get_worker(mdev))) {
		if (!ni_security_id_equal(&w->security_id, security_id))
			ni_secret_array_destroy(&mdev->secrets);
		ni_security_id_set(&w->security_id, security_id);
	}
}

ni_ifworker_t *
ni_managed_device_get_worker(const ni_managed_device_t *mdev)
{
	ni_fsm_t *fsm;
	ni_ifworker_t *w;

	if (!mdev || !mdev->nanny || !(fsm = mdev->nanny->fsm))
		return NULL;

	if (!(w = ni_fsm_ifworker_by_ifindex(fsm, mdev->ifindex)))
		ni_debug_nanny("%s: no corresponding worker for ifindex %d", __func__, mdev->ifindex);

	return w;
}

char *
ni_managed_device_get_name(ni_managed_device_t *mdev)
{
	ni_ifworker_t *w;

	if (!(w = ni_managed_device_get_worker(mdev)))
		return NULL;

	return w->name;
}

static int
ni_factory_device_up(ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_ifworker_array_t ifmarked = NI_IFWORKER_ARRAY_INIT;
	ni_ifmarker_t ifmarker;

	ni_assert(fsm && w);
	memset(&ifmarker, 0, sizeof(ifmarker));

	ifmarker.target_range.min = __NI_FSM_STATE_MAX - 1;
	ifmarker.target_range.max = __NI_FSM_STATE_MAX;
	ifmarker.persistent = w->control.persistent;

	ni_ifworker_array_append(&ifmarked, w);
	ni_fsm_mark_matching_workers(fsm, &ifmarked, &ifmarker);
	ni_ifworker_array_destroy(&ifmarked);

	return 0;
}

/*
 * Apply policy to a virtual (factory) device
 */
int
ni_factory_device_apply_policy(ni_fsm_t *fsm, ni_ifworker_t *w, ni_managed_policy_t *mpolicy)
{
	const char *type_name;
	ni_fsm_policy_t *policy = mpolicy->fsm_policy;
	xml_node_t *config = NULL;

	if (!policy)
		return -1;

	ni_debug_nanny("%s: configuring factory device using policy %s",
		w->name, ni_fsm_policy_name(policy));

	/* This returns "modem" or "interface" */
	type_name = ni_ifworker_type_to_string(w->type);

	config = xml_node_new(type_name, NULL);
	xml_node_new_element("name", config, w->name);

	config = ni_fsm_policy_transform_document(config, &policy, 1);
	if (config == NULL) {
		ni_error("%s: error when applying policy to %s document",
			w->name, type_name);
		return -1;
	}
	ni_debug_nanny("%s: using device config", w->name);
	xml_node_print_debug(config, 0);

	ni_ifworker_set_config(w, config, ni_fsm_policy_get_origin(policy));
	xml_node_free(config);

	/* Now do the fandango */
	return ni_factory_device_up(fsm, w);
}


/*
 * Apply policy to a device
 */
int
ni_managed_device_apply_policy(ni_managed_device_t *mdev, ni_managed_policy_t *mpolicy)
{
	ni_ifworker_t *w;
	const char *type_name;
	ni_fsm_policy_t *policy = mpolicy->fsm_policy;
	xml_node_t *config = NULL;

	if (!policy || !(w = ni_managed_device_get_worker(mdev)))
		return -1;

	/* If the device is up and running, do not reconfigure unless the policy
	 * has really changed */
	switch (mdev->state) {
	case NI_MANAGED_STATE_STOPPING:
	case NI_MANAGED_STATE_STOPPED:
	case NI_MANAGED_STATE_LIMBO:
		/* Just install the new policy and reconfigure. */
		break;

	case NI_MANAGED_STATE_STARTING:
	case NI_MANAGED_STATE_RUNNING:
	case NI_MANAGED_STATE_FAILED:
		if (mdev->selected_policy == mpolicy && mdev->selected_policy_seq == mpolicy->seqno) {
			ni_debug_nanny("%s: keep using policy %s", w->name, ni_fsm_policy_name(policy));
			return -1;
		}

		/* Just install the new policy and reconfigure. */
		break;

	case NI_MANAGED_STATE_BINDING:
		ni_error("%s(%s): should not get here in state %s",
				__func__, w->name, ni_managed_state_to_string(mdev->state));
		return -1;
	}

	ni_debug_nanny("%s: using policy %s", w->name, ni_fsm_policy_name(policy));

	/* This returns "modem" or "interface" */
	type_name = ni_ifworker_type_to_string(w->type);

	config = xml_node_new(type_name, NULL);
	xml_node_new_element("name", config, w->name);

	config = ni_fsm_policy_transform_document(config, &policy, 1);
	if (config == NULL) {
		ni_error("%s: error when applying policy to %s document", w->name, type_name);
		return -1;
	}
	ni_debug_nanny("%s: using device config", w->name);
	xml_node_print_debug(config, 0);

	ni_managed_device_set_policy(mdev, mpolicy, config);
	xml_node_free(config);

	/* Now do the fandango */
	return ni_managed_device_up(mdev, ni_fsm_policy_get_origin(policy));
}

/*
 * Completion callback for bringup
 */
static void
ni_managed_device_up_done(ni_ifworker_t *w)
{
	ni_nanny_t *mgr = w->completion.user_data;
	ni_managed_device_t *mdev;

	if ((mdev = ni_nanny_get_device(mgr, w)) == NULL) {
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
		if (ni_security_id_valid(&w->security_id))
			ni_nanny_clear_secrets(mgr, &w->security_id, NULL);
	} else {
		mdev->fail_count = 0;
		mdev->state = NI_MANAGED_STATE_RUNNING;
	}
}

/*
 * Bring up the device
 */
static int
ni_managed_device_up(ni_managed_device_t *mdev, const char *origin)
{
	ni_fsm_t *fsm = mdev->nanny->fsm;
	ni_ifworker_t *w;
	unsigned int previous_state;
	unsigned int target_state;
	ni_security_id_t security_id = NI_SECURITY_ID_INIT;
	ni_ifworker_array_t ifmarked = NI_IFWORKER_ARRAY_INIT;
	ni_ifmarker_t ifmarker;
	int rv = -NI_ERROR_DEVICE_NOT_COMPATIBLE;

	if (!(w = ni_managed_device_get_worker(mdev)))
		goto failed;

	memset(&ifmarker, 0, sizeof(ifmarker));

	switch (w->type) {
	case NI_IFWORKER_TYPE_NETDEV:
		mdev->max_fail_count = 3;
		if (w->device->link.type == NI_IFTYPE_WIRELESS) {
			const char *essid;

			ni_security_id_init(&security_id, "wireless");
			if ((essid = ni_managed_device_get_essid(mdev->selected_config)) != NULL)
				ni_security_id_set_attr(&security_id, "essid", essid);
		}

		target_state = __NI_FSM_STATE_MAX - 1;
		break;

	case NI_IFWORKER_TYPE_MODEM:
		mdev->max_fail_count = 1;

		ni_security_id_init(&security_id, "modem");
		if (w->modem->identify.equipment)
			ni_security_id_set_attr(&security_id, "equipment-id", w->modem->identify.equipment);

		target_state = NI_FSM_STATE_LINK_UP;
		break;

	default:
		goto failed;
	}

	if (ni_security_id_valid(&security_id))
		ni_managed_device_set_security_id(mdev, &security_id);

	ni_ifworker_set_completion_callback(w, ni_managed_device_up_done, mdev->nanny);

	ni_ifworker_set_config(w, mdev->selected_config, origin);

	ifmarker.target_range.min = target_state;
	ifmarker.target_range.max = __NI_FSM_STATE_MAX;
	ifmarker.persistent = w->control.persistent;

	ni_ifworker_array_append(&ifmarked, w);

	/* Binding: this validates the XML configuration document,
	 * resolves any references to other devices (if there are any),
	 * and retrieves any keys/passwords etc via the prompt callback.
	 * Inside the prompt callback, we record all secrets for tracking
	 */
	ni_secret_array_destroy(&mdev->secrets);

	previous_state = mdev->state;
	mdev->state = NI_MANAGED_STATE_BINDING;
	if ((rv = ni_ifworker_bind_early(w, fsm, TRUE)) < 0) {
		ni_ifworker_array_destroy(&ifmarked);
		goto failed;
	}

	if (mdev->missing_secrets) {
		/* FIXME: Emit an event listing the secrets we're missing.
		 */
		mdev->state = previous_state;
		ni_ifworker_array_destroy(&ifmarked);
		return -1;
	}

	mdev->state = NI_MANAGED_STATE_STARTING;
	ni_fsm_mark_matching_workers(fsm, &ifmarked, &ifmarker);
	ni_ifworker_array_destroy(&ifmarked);

	return 0;

failed:
	ni_error("%s: cannot start device: %s", w->name, ni_strerror(rv));
	mdev->state = NI_MANAGED_STATE_FAILED;
	return -1;
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
	ni_nanny_t *mgr = w->completion.user_data;
	ni_managed_device_t *mdev;

	if ((mdev = ni_nanny_get_device(mgr, w)) == NULL) {
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
		mdev->state = NI_MANAGED_STATE_STOPPED;
	}
	ni_managed_device_set_policy(mdev, NULL, NULL);

	if (mdev->monitor && w->type == NI_IFWORKER_TYPE_NETDEV) {
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
	ni_fsm_t *fsm = mdev->nanny->fsm;
	ni_ifworker_t *w;
	int rv;

	if (!(w = ni_managed_device_get_worker(mdev)))
		return;

	ni_ifworker_set_completion_callback(w, ni_managed_device_down_done, mdev->nanny);

	ni_ifworker_set_config(w, mdev->selected_config, w->config.meta.origin);
	w->target_range.min = NI_FSM_STATE_NONE;
	w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;

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

	if ((name = ni_format_uint_mapped(state, __managed_state_names)) == NULL)
		name = "unknown";
	return name;
}

/*
 * Look up managed device for a given ifindex
 */
ni_managed_device_t *
ni_nanny_get_device_by_ifindex(ni_nanny_t *mgr, unsigned int ifindex)
{
	ni_managed_device_t *mdev;

	for (mdev = mgr->device_list; mdev; mdev = mdev->next) {
		if (mdev->ifindex == ifindex)
			return mdev;
	}

	return NULL;
}

void
ni_nanny_remove_device(ni_nanny_t *mgr, ni_managed_device_t *mdev)
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

