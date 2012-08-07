/*
 * This daemon manages interfaces in response to link up/down
 * events, WLAN network reachability, etc.
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
#include <wicked/fsm.h>
#include "manager.h"

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_FOREGROUND,
	OPT_NOMODEMMGR,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "foreground",		no_argument,		NULL,	OPT_FOREGROUND },
	{ "no-modem-manager",	no_argument,		NULL,	OPT_NOMODEMMGR },

	{ NULL }
};

static const char *	program_name;
static int		opt_foreground = 0;
static int		opt_no_modem_manager = 0;

static void		interface_manager(void);
static void		ni_manager_discover_state(ni_manager_t *);
static void		ni_manager_netif_state_change_signal_receive(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
//static void		handle_interface_event(ni_netdev_t *, ni_event_t);
//static void		handle_modem_event(ni_modem_t *, ni_event_t);

int
main(int argc, char **argv)
{
	int c;

	program_name = ni_basename(argv[0]);

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"%s [options]\n"
				"This command understands the following options\n"
				"  --config filename\n"
				"        Read configuration file <filename> instead of system default.\n"
				"  --foreground\n"
				"        Run as a foreground process, rather than as a daemon.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n",
				program_name
			       );
			return 1;

		case OPT_CONFIGFILE:
			ni_set_global_config_path(optarg);
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help(stdout);
				return 0;
			}
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				return 1;
			}
			break;

		case OPT_FOREGROUND:
			opt_foreground = 1;
			break;

		case OPT_NOMODEMMGR:
			opt_no_modem_manager = 1;
			break;
		}
	}

	if (ni_init() < 0)
		return 1;

	if (optind != argc)
		goto usage;

	interface_manager();
	return 0;
}

ni_manager_t *
ni_manager_new(void)
{
	ni_manager_t *mgr;

	mgr = calloc(1, sizeof(*mgr));

	mgr->server = ni_server_listen_dbus(NI_OBJECTMODEL_DBUS_BUS_NAME_MANAGER);
	if (!mgr->server)
		ni_fatal("Cannot create server, giving up.");

	mgr->fsm = ni_fsm_new();
	ni_objectmodel_manager_init(mgr);
	ni_objectmodel_register_all();

	return mgr;
}

void
ni_manager_schedule_recheck(ni_manager_t *mgr, ni_ifworker_t *w)
{
	if (ni_ifworker_array_index(&mgr->recheck, w) < 0)
		ni_ifworker_array_append(&mgr->recheck, w);
}

void
ni_manager_schedule_down(ni_manager_t *mgr, ni_ifworker_t *w)
{
	if (ni_ifworker_array_index(&mgr->down, w) < 0)
		ni_ifworker_array_append(&mgr->down, w);
}

ni_managed_netdev_t *
ni_manager_get_netdev(ni_manager_t *mgr, ni_netdev_t *dev)
{
	ni_managed_netdev_t *mdev;

	for (mdev = mgr->netdev_list; mdev; mdev = mdev->next) {
		if (mdev->dev == dev)
			return mdev;
	}
	return NULL;
}

ni_managed_policy_t *
ni_manager_get_policy(ni_manager_t *mgr, const ni_fsm_policy_t *policy)
{
	ni_managed_policy_t *mpolicy;

	for (mpolicy = mgr->policy_list; mpolicy; mpolicy = mpolicy->next) {
		if (mpolicy->fsm_policy == policy)
			return mpolicy;
	}
	return NULL;
}

/*
 * Implement service for configuring the system's network interfaces
 */
void
interface_manager(void)
{
	ni_manager_t *mgr;

	mgr = ni_manager_new();

	if (!opt_foreground) {
		if (ni_server_background(program_name) < 0)
			ni_fatal("unable to background server");
		ni_log_destination_syslog(program_name);
	}

	ni_manager_discover_state(mgr);

	while (!ni_caught_terminal_signal()) {
		static unsigned int policy_seq = 0;
		long timeout;

		if (ni_fsm_policies_changed_since(mgr->fsm, &policy_seq)) {
			ni_managed_netdev_t *mdev;

			for (mdev = mgr->netdev_list; mdev; mdev = mdev->next) {
				ni_ifworker_t *w;

				if (!mdev->user_controlled)
					continue;

				w = ni_fsm_ifworker_by_netdev(mgr->fsm, mdev->dev);
				if (w)
					ni_manager_schedule_recheck(mgr, w);
			}
		}

		if (mgr->recheck.count != 0) {
			unsigned int i;

			ni_fsm_refresh_state(mgr->fsm);

			for (i = 0; i < mgr->recheck.count; ++i)
				ni_manager_recheck(mgr, mgr->recheck.data[i]);
			ni_ifworker_array_destroy(&mgr->recheck);
		}

		if (mgr->down.count != 0) {
			unsigned int i;

			for (i = 0; i < mgr->down.count; ++i)
				; // ni_manager_down(mgr, mgr->down.data[i]);
			ni_ifworker_array_destroy(&mgr->down);
		}

		ni_fsm_do(mgr->fsm, &timeout);
		if (ni_socket_wait(timeout) < 0)
			ni_fatal("ni_socket_wait failed");
	}

	exit(0);
}

/*
 * At startup, discover current configuration.
 * If we have any live leases, restart address configuration for them.
 * This allows a daemon restart without losing lease state.
 */
void
ni_manager_discover_state(ni_manager_t *mgr)
{
	ni_dbus_client_t *client;
	unsigned int i;

	if (!(client = ni_fsm_create_client(mgr->fsm)))
		ni_fatal("Unable to create FSM client");

	ni_dbus_client_add_signal_handler(client, NULL, NULL,
			NI_OBJECTMODEL_NETIF_INTERFACE,
			ni_manager_netif_state_change_signal_receive,
			mgr);

	ni_fsm_refresh_state(mgr->fsm);

	for (i = 0; i < mgr->fsm->workers.count; ++i) {
		ni_ifworker_t *w = mgr->fsm->workers.data[i];

		if (w->type == NI_IFWORKER_TYPE_NETDEV) {
			ni_managed_netdev_t *mdev;

			mdev = ni_managed_netdev_new(mgr, w);
			ni_objectmodel_register_managed_netdev(mgr->server, mdev);
#ifdef notyet
		} else
		if (w->type == NI_IFWORKER_TYPE_MODEM) {
			ni_objectmodel_register_managed_modem(mgr->server,
					ni_managed_modem_new(mgr, w->modem));
#endif
		}
	}
}

/*
 * Wickedd is sending us a signal (such a linkUp/linkDown, or change in the set of
 * visible WLANs)
 */
void
ni_manager_netif_state_change_signal_receive(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_manager_t *mgr = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_managed_netdev_t *mdev;
	ni_ifworker_t *w;

	if ((w = ni_fsm_ifworker_by_object_path(mgr->fsm, object_path)) == NULL) {
		ni_warn("received signal \"%s\" from unknown object \"%s\"",
				signal_name, object_path);
		return;
	}

	ni_trace("%s: received signal %s from %s", w->name, signal_name, object_path);
	ni_assert(w->device);

	if (ni_string_eq(signal_name, "deviceDown")) {
		// XXX: delete the worker and the managed netif
	} else
	if (ni_string_eq(signal_name, "linkDown")) {
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
		if ((mdev = ni_manager_get_netdev(mgr, w->device)) != NULL
		 && mdev->selected_policy != NULL
		 && mdev->user_controlled)
			ni_manager_schedule_down(mgr, w);
	} else
	if (ni_string_eq(signal_name, "linkAssociationLost")) {
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
		if ((mdev = ni_manager_get_netdev(mgr, w->device)) != NULL
		 && mdev->selected_policy != NULL
		 && mdev->user_controlled)
			ni_manager_schedule_down(mgr, w);
	} else
	if (ni_string_eq(signal_name, "deviceUp")) {
		// A new device was added. Could be a virtual device like
		// a VLAN or vif, or a hotplug modem or NIC
		// Create a worker and a managed_netif for this device.
		switch (w->type) {
		case NI_IFWORKER_TYPE_NETDEV:
			if (ni_manager_get_netdev(mgr, w->device) == NULL)
				ni_objectmodel_register_managed_netdev(mgr->server,
						ni_managed_netdev_new(mgr, w));
			break;

#ifdef notyet
		case NI_IFWORKER_TYPE_MODEM:
			if (ni_manager_get_modem(mgr, w->modem) == NULL)
				ni_objectmodel_register_managed_modem(mgr->server,
						ni_managed_modem_new(mgr, w->modem));
			break;
#endif

		default: ;
		}
	} else
	if (ni_string_eq(signal_name, "linkUp")) {
		// Link detection - eg for ethernet
		if ((mdev = ni_manager_get_netdev(mgr, w->device)) != NULL
		 && mdev->selected_policy == NULL
		 && mdev->user_controlled)
			ni_manager_schedule_recheck(mgr, w);
	} else {
		// ignore
	}
}

/*
 * Check whether a given interface should be reconfigured
 */
void
ni_manager_recheck(ni_manager_t *mgr, ni_ifworker_t *w)
{
	static const unsigned int MAX_POLICIES = 20;
	ni_managed_netdev_t *mdev;
	const ni_fsm_policy_t *policies[MAX_POLICIES];
	unsigned int count;
	const ni_fsm_policy_t *policy;
	ni_managed_policy_t *mpolicy;
	xml_node_t *config;

	if ((mdev = ni_manager_get_netdev(mgr, w->device)) == NULL)
		return;

	ni_trace("%s(%s)", __func__, w->name);
	w->use_default_policies = TRUE;
	if ((count = ni_fsm_policy_get_applicable_policies(mgr->fsm, w, policies, MAX_POLICIES)) == 0) {
		ni_trace("%s: no applicable policies", w->name);
		return;
	}

	policy = policies[count-1];
	mpolicy = ni_manager_get_policy(mgr, policy);

	if (mdev->selected_policy == mpolicy) {
		ni_trace("%s: keep using policy %s", w->name, ni_fsm_policy_name(policy));
		return;
	}

	ni_trace("%s: using policy %s", w->name, ni_fsm_policy_name(policy));
	config = xml_node_new("interface", NULL);
	xml_node_new_element("name", config, w->name);

	config = ni_fsm_policy_transform_document(config, &policy, 1);
	if (config == NULL) {
		ni_error("%s: error when applying policy to interface document", w->name);
		return;
	}

	ni_trace("%s: using device config", w->name);
	xml_node_print(config, NULL);
	if (mdev->selected_config)
		xml_node_free(mdev->selected_config);
	mdev->selected_config = config;
	mdev->selected_policy = mpolicy;
	mdev->timeout = mgr->fsm->worker_timeout;

	/* Now do the fandango */
	ni_managed_netdev_up(mdev, NI_FSM_STATE_ADDRCONF_UP);
}
