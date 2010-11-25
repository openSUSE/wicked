/*
 * No REST for the wicked!
 *
 * This command line utility provides an interface to the network
 * configuration/information facilities.
 *
 * It uses a RESTful interface (even though it's a command line utility).
 * The idea is to make it easier to extend this to some smallish daemon
 * with a AF_LOCAL socket interface.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <mcheck.h>
#include <stdlib.h>
#include <getopt.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/addrconf.h>
#include <wicked/bonding.h>
#include <wicked/bridge.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_DRYRUN,
	OPT_ROOTDIR,
	OPT_LINK_TIMEOUT,
	OPT_NOPROGMETER,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "dryrun",		no_argument,		NULL,	OPT_DRYRUN },
	{ "dry-run",		no_argument,		NULL,	OPT_DRYRUN },
	{ "link-timeout",	required_argument,	NULL,	OPT_LINK_TIMEOUT },
	{ "no-progress-meter",	no_argument,		NULL,	OPT_NOPROGMETER },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "root-directory",	required_argument,	NULL,	OPT_ROOTDIR },

	{ NULL }
};

static int		opt_dryrun = 0;
static char *		opt_rootdir = NULL;
static unsigned int	opt_link_timeout = 10;
static int		opt_progressmeter = 1;

static int		do_rest(const char *, int, char **);
static int		do_xpath(int, char **);
static int		do_ifup(int, char **);
static int		do_ifdown(int, char **);

int
main(int argc, char **argv)
{
	char *cmd;
	int c;

	mtrace();
	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"./wicked [options] cmd path\n"
				"This command understands the following options\n"
				"  --config filename\n"
				"        Use alternative configuration file.\n"
				"  --dry-run\n"
				"        Do not change the system in any way.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
				"\n"
				"Supported commands:\n"
				"  ifup [--boot] [--file xmlspec] ifname\n"
				"  ifdown [--delete] ifname\n"
				"  get /config/interface\n"
				"  get /config/interface/ifname\n"
				"  put /config/interface/ifname < cfg.xml\n"
				"  get /system/interface\n"
				"  get /system/interface/ifname\n"
				"  put /system/interface/ifname < cfg.xml\n"
				"  delete /config/interface/ifname\n"
				"  delete /system/interface/ifname\n"
				"  xpath [options] expr ...\n"
			       );
			return 1;

		case OPT_CONFIGFILE:
			ni_set_global_config_path(optarg);
			break;

		case OPT_DRYRUN:
			opt_dryrun = 1;
			break;

		case OPT_ROOTDIR:
			opt_rootdir = optarg;
			break;

		case OPT_LINK_TIMEOUT:
			if (ni_parse_int(optarg, &opt_link_timeout) < 0)
				ni_fatal("unable to parse link timeout value");
			break;

		case OPT_NOPROGMETER:
			opt_progressmeter = 0;
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

		}
	}

	if (ni_init() < 0)
		return 1;

	if (optind >= argc) {
		fprintf(stderr, "Missing command\n");
		goto usage;
	}

	cmd = argv[optind++];

	if (!strcmp(cmd, "xpath"))
		return do_xpath(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "ifup"))
		return do_ifup(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "ifdown"))
		return do_ifdown(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "get")
	 || !strcmp(cmd, "put")
	 || !strcmp(cmd, "post")
	 || !strcmp(cmd, "delete"))
		return do_rest(cmd, argc - optind + 1, argv + optind - 1);

	fprintf(stderr, "Unsupported command %s\n", cmd);
	goto usage;
}

static int
__wicked_request(int rest_op, const char *path,
		/* const */ xml_node_t *send_xml,
		xml_node_t **recv_xml)
{
	ni_wicked_request_t req;
	int rv;

	if (opt_dryrun && rest_op != NI_REST_OP_GET) {
		printf("Would send request %s %s\n",
				ni_wicked_rest_op_print(rest_op), path);
		if (send_xml)
			xml_node_print(send_xml, stdout);
		return 0;
	}

	ni_wicked_request_init(&req);
	req.cmd = rest_op;
	req.path = strdup(path);
	req.xml_in = send_xml;

	if (opt_rootdir)
		ni_wicked_request_add_option(&req, "Root", opt_rootdir);

	rv = ni_wicked_call_indirect(&req);
	if (rv < 0) {
		ni_error("%s", req.error_msg);
	} else if (recv_xml) {
		*recv_xml = req.xml_out;
		req.xml_out = NULL;
	}

	ni_wicked_request_destroy(&req);
	return rv;
}

enum {
	STATE_UNKNOWN = 0,
	STATE_DEVICE_DOWN,
	STATE_DEVICE_UP,
	STATE_LINK_UP,
	STATE_NETWORK_UP,
};

/*
 * Interface state information
 */
typedef struct ni_interface_state ni_interface_state_t;

typedef struct ni_interface_state_array {
	unsigned int		count;
	ni_interface_state_t **	data;
} ni_interface_state_array_t;

struct ni_interface_state {
	unsigned int		refcount;

	int			state;
	char *			ifname;
	ni_interface_t *	config;
	unsigned int		done      : 1,
				error     : 1,
				is_slave  : 1,
				is_policy : 1,
				waiting   : 1;

	int			next_state;
	int			want_state;
	int			have_state;
	unsigned int		timeout;
	ni_ifaction_t		behavior;

	ni_interface_state_t *	parent;
	ni_interface_state_array_t children;
};

static ni_interface_state_t *ni_interface_state_array_find(ni_interface_state_array_t *, const char *);
static void	ni_interface_state_array_append(ni_interface_state_array_t *, ni_interface_state_t *);
static void	ni_interface_state_array_destroy(ni_interface_state_array_t *);

static ni_intmap_t __state_names[] = {
	{ "unknown",		STATE_UNKNOWN		},
	{ "device-down",	STATE_DEVICE_DOWN	},
	{ "device-up",		STATE_DEVICE_UP		},
	{ "link-up",		STATE_LINK_UP		},
	{ "network-up",		STATE_NETWORK_UP	},

	{ NULL }
};

const char *
ni_interface_state_name(int state)
{
	return ni_format_int_mapped(state, __state_names);
}

static ni_interface_state_t *
ni_interface_state_new(const char *name, ni_interface_t *dev)
{
	ni_interface_state_t *state;

	state = calloc(1, sizeof(*state));
	ni_string_dup(&state->ifname, name);
	if (dev)
		state->config = ni_interface_get(dev);
	return state;
}

ni_interface_state_t *
ni_interface_state_add_child(ni_interface_state_t *parent, const char *slave_name, ni_interface_t *slave_dev)
{
	ni_interface_state_t *slave_state;

	if ((slave_state = ni_interface_state_array_find(&parent->children, slave_name)) == NULL) {
		slave_state = ni_interface_state_new(slave_name, slave_dev);
		ni_interface_state_array_append(&parent->children, slave_state);
	}

	if (parent->behavior.mandatory)
		slave_state->behavior.mandatory = 1;
	slave_state->is_slave = 1;

	return slave_state;
}

static void
ni_interface_state_free(ni_interface_state_t *state)
{
	ni_string_free(&state->ifname);
	if (state->config)
		ni_interface_put(state->config);
	ni_interface_state_array_destroy(&state->children);
}

static inline void
ni_interface_state_release(ni_interface_state_t *state)
{
	if (--(state->refcount) == 0)
		ni_interface_state_free(state);
}

static void
ni_interface_state_array_append(ni_interface_state_array_t *array, ni_interface_state_t *state)
{
	array->data = realloc(array->data, (array->count + 1) * sizeof(array->data[0]));
	array->data[array->count++] = state;
	state->refcount++;
}

static ni_interface_state_t *
ni_interface_state_array_find(ni_interface_state_array_t *array, const char *ifname)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		ni_interface_state_t *state = array->data[i];

		if (!strcmp(state->ifname, ifname))
			return state;
	}
	return NULL;
}

static void
ni_interface_state_array_destroy(ni_interface_state_array_t *array)
{
	while (array->count)
		ni_interface_state_release(array->data[--(array->count)]);
	free(array->data);
	array->data = NULL;
}

static int
ni_build_partial_topology2(ni_handle_t *config, int filter, ni_evaction_t ifaction, ni_interface_state_array_t *result)
{
	ni_interface_state_array_t state_array = { 0, NULL };
	ni_interface_t *pos = NULL, *ifp;
	int want_state;

	want_state = (ifaction == NI_INTERFACE_START)? STATE_NETWORK_UP : STATE_DEVICE_DOWN;

	for (ifp = ni_interface_first(config, &pos); ifp; ifp = ni_interface_next(config, &pos)) {
		const ni_ifaction_t *ifa = &ifp->startmode.ifaction[filter];
		ni_interface_state_t *state;

		if (ifa->action != ifaction)
			continue;

		state = ni_interface_state_new(ifp->name, ifp);
		state->want_state = want_state;
		state->behavior = *ifa;

		if (ifaction == NI_INTERFACE_START
		 && ifp->startmode.ifaction[NI_IFACTION_LINK_UP].action == NI_INTERFACE_START) {
			ni_debug_wicked("%s: interface has auto-start mode", ifp->name);
			ifp->ifflags |= (NI_IFF_DEVICE_UP | NI_IFF_LINK_UP | NI_IFF_NETWORK_UP);
			state->is_policy = 1;
		}

		ni_interface_state_array_append(&state_array, state);
	}

	for (ifp = ni_interface_first(config, &pos); ifp; ifp = ni_interface_next(config, &pos)) {
		ni_interface_state_t *master_state, *slave_state;
		ni_interface_t *slave;
		const char *slave_name;
		ni_bonding_t *bond;
		ni_bridge_t *bridge;
		ni_vlan_t *vlan;
		unsigned int i;

		master_state = ni_interface_state_array_find(&state_array, ifp->name);
		assert(master_state->config == ifp);

		switch (ifp->type) {
		case NI_IFTYPE_VLAN:
			if ((vlan = ifp->vlan) == NULL)
				continue;

			slave_name = vlan->interface_name;

			slave = ni_interface_by_name(config, slave_name);
			if (slave != NULL) {
				/* VLANs are special, real device must be an ether device,
				 * and can be referenced by more than one vlan */
				if (slave->type != NI_IFTYPE_ETHERNET) {
					ni_error("vlan interface %s references non-ethernet device", ifp->name);
					goto failed;
				}
			}

			slave_state = ni_interface_state_add_child(master_state, slave_name, slave);
			if (slave_state->parent)
				goto multiple_masters;
			slave_state->want_state = want_state;
			break;

		case NI_IFTYPE_BOND:
			if ((bond = ifp->bonding) == NULL)
				continue;

			for (i = 0; i < bond->slave_names.count; ++i) {
				slave_name = bond->slave_names.data[i];

				slave = ni_interface_by_name(config, slave_name);

				slave_state = ni_interface_state_add_child(master_state, slave_name, slave);
				if (slave_state->parent)
					goto multiple_masters;
				slave_state->parent = master_state;

				/* Whatever we do, bonding slave devices should never have their network configured. */
				slave_state->want_state = (want_state == STATE_NETWORK_UP)? STATE_LINK_UP : want_state;
			}
			break;

		case NI_IFTYPE_BRIDGE:
			if ((bridge = ifp->bridge) == NULL)
				continue;

			for (i = 0; i < bridge->ports.count; ++i) {
				ni_bridge_port_t *port = bridge->ports.data[i];

				slave = ni_interface_by_name(config, port->name);

				slave_state = ni_interface_state_add_child(master_state, port->name, slave);
				if (slave_state->parent)
					goto multiple_masters;
				slave_state->parent = master_state;
				slave_state->want_state = want_state;
			}
			break;

		default:
			break;

		multiple_masters:
			ni_error("interface %s used by more than one device (%s and %s)",
					slave_state->ifname, master_state->ifname,
					slave_state->parent->ifname);
		failed:
			ni_interface_state_array_destroy(&state_array);
			return -1;
		}
	}

	{
		unsigned int i;

		for (i = 0; i < state_array.count; ++i) {
			ni_interface_state_t *state = state_array.data[i];

			if (!state->is_slave)
				ni_interface_state_array_append(result, state);
		}
	}

	ni_interface_state_array_destroy(&state_array);
	return 0;
}

/*
 * Check whether we have all requested leases
 */
static int
ni_interface_network_is_up_afinfo(const char *ifname, const ni_afinfo_t *cfg_afi, const ni_afinfo_t *cur_afi)
{
	unsigned int type;

	for (type = 0; type < __NI_ADDRCONF_MAX; ++type) {
		if (type == NI_ADDRCONF_STATIC || !ni_afinfo_addrconf_test(cfg_afi, type))
			continue;
		if (!ni_afinfo_addrconf_test(cur_afi, type)) {
			ni_debug_wicked("%s: addrconf mode %s/%s not enabled", ifname,
					ni_addrfamily_type_to_name(cfg_afi->family),
					ni_addrconf_type_to_name(type));
			return 0;
		}
		if (!ni_addrconf_lease_is_valid(cur_afi->lease[type])) {
			ni_debug_wicked("%s: addrconf mode %s/%s enabled; no lease yet", ifname,
					ni_addrfamily_type_to_name(cfg_afi->family),
					ni_addrconf_type_to_name(type));
			return 0;
		}
	}

	return 1;
}

static void
interface_update_state(ni_interface_state_t *state, const ni_interface_t *have)
{
	ni_interface_t *want = state->config;
	int new_state = STATE_DEVICE_DOWN;

	if (!(have->ifflags & NI_IFF_DEVICE_UP))
		goto out;

	if (want != NULL) {
		/* FIXME: here we should check the ethernet/link/bond/bridge
		 * composition. */
	}

	new_state = STATE_DEVICE_UP;
	if (!(have->ifflags & NI_IFF_LINK_UP))
		goto out;

	new_state = STATE_LINK_UP;
	if (!(have->ifflags & NI_IFF_NETWORK_UP))
		goto out;

	if (want != NULL) {
		if (!ni_interface_network_is_up_afinfo(want->name, &want->ipv4, &have->ipv4)
		 || !ni_interface_network_is_up_afinfo(want->name, &want->ipv6, &have->ipv6))
			goto out;
	}

	new_state = STATE_NETWORK_UP;

out:
	if (state->have_state != new_state)
		ni_debug_wicked("%s: state changed from %s to %s",
				state->ifname,
				ni_interface_state_name(state->have_state),
				ni_interface_state_name(new_state));

	state->have_state = new_state;
}

static void
print_message(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);

	printf("\n");
}

static int
interface_update(ni_interface_state_t *state, ni_handle_t *system, ni_interface_t **ifpp)
{
	ni_interface_t *ifp;

	/* Interface may not be present yet (eg for bridge or bond interfaces) */
	if ((ifp = ni_interface_by_name(system, state->ifname)) != NULL)
		interface_update_state(state, ifp);
	*ifpp = ifp;

	ni_debug_wicked("%s: state is current=%s, next=%s, wanted=%s%s", state->ifname,
			ni_interface_state_name(state->have_state),
			ni_interface_state_name(state->next_state),
			ni_interface_state_name(state->want_state),
			state->waiting? ", waiting": "");

	/* Were we waiting to get to the next state? */
	if (state->waiting) {
		if (state->next_state == state->have_state
		 || state->want_state == state->have_state) {
			state->waiting = 0;
		 } else {
			return 0;
		}
	}

	return !state->waiting;
}

static int
interface_change(ni_interface_state_t *state, ni_handle_t *system, ni_interface_t *ifp,
			int next_state, unsigned int timeout)
{
	unsigned int ifflags;

	switch (next_state) {
	case STATE_DEVICE_DOWN:
		ni_debug_wicked("%s: trying to shut down device", state->ifname);
		ifflags = 0;
		break;

	case STATE_DEVICE_UP:
		ni_debug_wicked("%s: trying to bring device up", state->ifname);
		ifflags = NI_IFF_DEVICE_UP;
		break;

	case STATE_LINK_UP:
		ni_debug_wicked("%s: trying to bring link up", state->ifname);
		ifflags = NI_IFF_DEVICE_UP | NI_IFF_LINK_UP;
		break;

	case STATE_NETWORK_UP:
		ni_debug_wicked("%s: trying to bring network up", state->ifname);
		ifflags = NI_IFF_DEVICE_UP | NI_IFF_LINK_UP | NI_IFF_NETWORK_UP;
		break;

	default:
		ni_error("%s: bad next_state=%s", state->ifname,
				ni_interface_state_name(next_state));
		return -1;
	}

	/* If we're trying to go to the final desired state, use the config
	 * object if there is one. */
	if (next_state == state->want_state && state->config)
		ifp = state->config;
	if (ifp == NULL) {
		ni_error("%s: unknown device", state->ifname);
		return -1;
	}

	ifp->ifflags &= ~(NI_IFF_DEVICE_UP | NI_IFF_LINK_UP | NI_IFF_NETWORK_UP);
	ifp->ifflags |= ifflags;

	if (ni_interface_configure(system, ifp) < 0) {
		ni_error("%s: unable to configure", ifp->name);
		return -1;
	}

	state->waiting = 1;
	state->next_state = next_state;
	state->timeout = timeout;
	if (state->timeout == 0)
		state->timeout = 10;

	return 0;
}

static int
send_policy(ni_interface_state_t *state, ni_handle_t *system, ni_interface_t *ifp)
{
	ni_policy_t policy;

	memset(&policy, 0, sizeof(policy));
	policy.event = NI_EVENT_LINK_UP;
	policy.interface = ifp;
	return ni_policy_update(system, &policy);
}

static int
interface_failed(ni_interface_state_t *state, const char *how)
{
	print_message("%s: %s", state->ifname, how?: "failed");
	state->done = 1;
	state->error = 1;
	return -1;
}

static int
ni_topology_update(ni_interface_state_array_t *state_array, ni_handle_t *system, unsigned int waited)
{
	unsigned int i;
	int rv, ready = 1;

	ni_debug_wicked("%s() called", __FUNCTION__);
	for (i = 0; i < state_array->count; ++i) {
		ni_interface_state_t *state = state_array->data[i];
		ni_interface_t *ifp;

again:
		if (state->done)
			continue;

		if (state->waiting) {
			if (waited > state->timeout) {
				ni_debug_wicked("%s: TIMEOUT: state is current=%s, next=%s, wanted=%s%s", state->ifname,
						ni_interface_state_name(state->have_state),
						ni_interface_state_name(state->next_state),
						ni_interface_state_name(state->want_state),
						state->behavior.only_if_link? " (only-if-link)" : "");

				if (state->behavior.only_if_link
				 && state->have_state == STATE_DEVICE_UP
				 && state->next_state == STATE_LINK_UP) {
					/* Dang, link didn't come up. We're supposed to bring up
					 * the network later, when the link comes up, so trigger that now. */
					print_message("%s: no link", state->ifname);
					state->done = 1;
					continue;
				}

				ready = 0;

				interface_failed(state, "timed out");
				if (state->behavior.mandatory)
					return -1;

				continue;
			}
		}

		if (!interface_update(state, system, &ifp)) {
			ready = 0;
			continue;
		}

		if (state->want_state == STATE_DEVICE_DOWN) {
			/* Bring down devices - first shut down parent device, then
			 * go for the subordinate devices. */
			if (state->want_state == state->have_state) {
				rv = ni_topology_update(&state->children, system, waited);
				if (rv < 0)
					return interface_failed(state, NULL);
				if (rv == 0)
					ready = 0;

				if (state->next_state != STATE_UNKNOWN) {
					print_message("%s: %s", state->ifname,
							ni_interface_state_name(state->have_state));
					state->done = 1;
					continue;
				}
				continue;
			}
		} else {
			/* Bring up devices - first bring up subordinate devices,
			 * then do the parent devices.
			 */
			if (state->want_state == state->have_state) {
				/* Even if the device is already up, we should send it our
				 * desired configuration at least once... */
				if (state->next_state != STATE_UNKNOWN) {
					print_message("%s: %s", state->ifname,
							ni_interface_state_name(state->have_state));
					state->done = 1;
					continue;
				}
			} else
			if (state->children.count) {
				rv = ni_topology_update(&state->children, system, waited);
				if (rv < 0)
					return interface_failed(state, NULL);
				if (rv == 0) {
					ready = 0;
					continue;
				}
			}
		}

		ready = 0;

		/* Try to reach the next state, which by default is our
		 * final desired state.
		 * The sole exception is if we want to bring up a device which
		 * is down; here we first go to an intermediate state to see
		 * whether the link is ready.
		 */
		if (state->want_state == STATE_NETWORK_UP && state->is_policy) {
			if (state->next_state == STATE_UNKNOWN) {
				rv = send_policy(state, system, state->config);
				if (rv < 0)
					return rv;
			}
			if (state->have_state >= STATE_LINK_UP) {
				state->next_state = STATE_NETWORK_UP;
				state->timeout = state->behavior.wait;
				state->waiting = 1;
				continue;
			}
		}

		if (state->want_state == STATE_NETWORK_UP
		 && state->have_state < STATE_LINK_UP
		 && state->is_policy) {
			ni_interface_t *cfg;

			/* Send the device our desired device configuration.
			 * This includes VLAN, bridge and bonding topology info, as
			 * well as ethtool settings etc, but none of the network config.
			 */
			if ((cfg = state->config) != NULL) {
				if (cfg->ethernet)
					ni_interface_set_ethernet(ifp, ni_ethernet_clone(cfg->ethernet));
				if (cfg->vlan)
					ni_interface_set_vlan(ifp, ni_vlan_clone(cfg->vlan));
				if (cfg->bridge)
					ni_interface_set_bridge(ifp, ni_bridge_clone(cfg->bridge));
				if (cfg->bonding)
					ni_interface_set_bonding(ifp, ni_bonding_clone(cfg->bonding));
			}
			rv = interface_change(state, system, ifp, STATE_LINK_UP, opt_link_timeout);
		} else {
			rv = interface_change(state, system, ifp, state->want_state, state->behavior.wait);
		}

		if (rv < 0)
			return rv;

		if (interface_update(state, system, &ifp))
			goto again;
	}
	return ready;
}

static int
ni_interfaces_wait(ni_handle_t *system, ni_interface_state_array_t *state_array)
{
	static const unsigned int TEST_FREQ = 4;
	static const char rotate[4] = "-\\|/";
	unsigned int waited = 0, dots = 0;
	int rv;

	setvbuf(stdout, NULL,_IONBF,  0);
	while (1) {
		if ((rv = ni_refresh(system)) < 0) {
			ni_error("failed to get system state");
			return -1;
		}

		if (ni_topology_update(state_array, system, waited / TEST_FREQ))
			return 0;

		usleep(1000000 / TEST_FREQ);
		if (opt_progressmeter)
			printf("%c\r", rotate[dots%4]);
		waited++;
		dots++;
	}

	return 0;
}

/*
 * Handle "ifup" command
 */
int
do_ifup(int argc, char **argv)
{
	static struct option ifup_options[] = {
		{ "file", required_argument, NULL, 'f' },
		{ NULL }
	};
	ni_interface_state_array_t state_array = { 0 };
	const char *ifname = NULL;
	const char *opt_file = NULL;
	unsigned int ifevent = NI_IFACTION_MANUAL_UP;
	ni_handle_t *config = NULL;
	ni_handle_t *system = NULL;
	int c, rv = -1;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case 'f':
			opt_file = optarg;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifup [ifup-options] all\n"
				"wicked [options] ifup [ifup-options] <ifname>\n"
				"\nSupported ifup-options:\n"
				"  --file <filename>\n"
				"      Read interface configuration(s) from file rather than using system config\n"
				"  --boot\n"
				"      Ignore interfaces with startmode != boot\n"
				);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "Bad number of arguments\n");
		goto usage;
	}
	ifname = argv[optind++];

	if (!strcmp(ifname, "boot")) {
		ifevent = NI_IFACTION_BOOT;
		ifname = "all";
	}

	/* Using --file means, read the interface definition from a local file.
	 * Otherwise, first retrieve /config/interface/<ifname> from the server,
	 * change <status> to up, and send it back.
	 */
	if (opt_file) {
		ni_syntax_t *syntax = ni_syntax_new("netcf", opt_file);

		config = ni_netconfig_open(syntax);
		if ((rv = ni_refresh(config)) < 0) {
			ni_error("unable to load interface definition from %s", opt_file);
			goto failed;
		}
	} else {
		config = ni_indirect_open("/config");
		if (!strcmp(ifname, "all")) {
			rv = ni_refresh(config);
		} else {
			rv = ni_interface_refresh_one(config, ifname);
		}

		if (rv < 0) {
			ni_error("unable to obtain interface configuration");
			goto failed;
		}
	}

	system = ni_indirect_open("/system");
	if ((rv = ni_refresh(system)) < 0) {
		ni_error("cannot refresh interface state");
		goto failed;
	}

	if (!strcmp(ifname, "all")) {
		if (ni_build_partial_topology2(config, ifevent, NI_INTERFACE_START, &state_array) < 0) {
			ni_error("failed to build interface hierarchy");
			goto failed;
		}
	} else {
		ni_interface_state_t *state;
		ni_interface_t *ifp;

		if (!(ifp = ni_interface_by_name(config, ifname))) {
			ni_error("cannot find interface %s in interface description", ifname);
			goto failed;
		}

		state = ni_interface_state_new(ifname, ifp);
		state->behavior = ifp->startmode.ifaction[ifevent];
		state->behavior.only_if_link = 0;
		state->want_state = STATE_NETWORK_UP;
		ni_interface_state_array_append(&state_array, state);
	}

	rv = ni_interfaces_wait(system, &state_array);

failed:
	if (config)
		ni_close(config);
	if (system)
		ni_close(system);
	ni_interface_state_array_destroy(&state_array);
	return (rv == 0);
}

/*
 * Handle "ifdown" command
 */
int
do_ifdown(int argc, char **argv)
{
	static struct option ifdown_options[] = {
		{ "delete", no_argument, NULL, 'd' },
		{ NULL }
	};
	int opt_delete = 0;
	const char *ifname = NULL;
	unsigned int ifevent = NI_IFACTION_MANUAL_DOWN;
	ni_handle_t *system = NULL;
	ni_interface_state_array_t state_array = { 0 };
	int c, rv;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifdown_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			opt_delete = 1;
			break;

		default:
usage:
			fprintf(stderr,
				"Usage:\n"
				"wicked [options] ifdown [ifdown-options] all\n"
				"wicked [options] ifdown [ifdown-options] <ifname>\n"
				"\nSupported ifdown-options:\n"
				"  --delete\n"
				"      Delete virtual interfaces in addition to shutting them down\n"
				);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "Bad number of arguments\n");
		goto usage;
	}
	ifname = argv[optind++];

	/* Otherwise, first retrieve /system/interface/<ifname> from the server,
	 * change <status> to down, and send it back.
	 */
	{
		system = ni_indirect_open("/system");
		if (!strcmp(ifname, "all") || !strcmp(ifname, "shutdown")) {
			rv = ni_refresh(system);
		} else {
			rv = ni_interface_refresh_one(system, ifname);
		}

		if (rv < 0) {
			ni_error("unable to obtain interface configuration");
			goto failed;
		}
	}

	ifevent = NI_IFACTION_MANUAL_DOWN;
	if (!strcmp(ifname, "shutdown")) {
		ifevent = NI_IFACTION_SHUTDOWN;
		ifname = "all";
	}

	if (!strcmp(ifname, "all")) {
		if (ni_build_partial_topology2(system, ifevent, NI_INTERFACE_STOP, &state_array) < 0) {
			ni_error("failed to build interface hierarchy");
			goto failed;
		}
	} else {
		ni_interface_state_t *state;
		ni_interface_t *ifp;

		if (!(ifp = ni_interface_by_name(system, ifname))) {
			ni_error("cannot find interface %s in interface description", ifname);
			goto failed;
		}

		state = ni_interface_state_new(ifname, ifp);
		state->behavior = ifp->startmode.ifaction[ifevent];
		state->want_state = STATE_DEVICE_DOWN;
		ni_interface_state_array_append(&state_array, state);
	}

	/* For VLAN, bridge, bonding and other virtual devices, implement delete */
	if (opt_delete)
		ni_warn("FIXME: --delete currently not supported");

	rv = ni_interfaces_wait(system, &state_array);

failed:
	if (system)
		ni_close(system);
	ni_interface_state_array_destroy(&state_array);
	return (rv == 0);
}

/*
 * We also allow the user to send raw REST commands to the server,
 * if s/he so desires
 */
static int
do_rest(const char *cmd, int argc, char **argv)
{
	xml_node_t *send_xml = NULL, *recv_xml = NULL, **recvp = NULL;
	int rest_op;
	char *path;

	if (argc != 2) {
		ni_error("Missing path name\n");
		fprintf(stderr,
			"Usage:\n"
			"wicked [options] get /path\n"
			"wicked [options] put /path\n"
			"wicked [options] post /path\n"
			"wicked [options] delete /path\n"
			"\nput and post commands expect an XML document on standard input\n");
		return 1;
	}

	path = argv[1];

	rest_op = ni_wicked_rest_op_parse(cmd);
	if (rest_op < 0)
		return 1;

	if (rest_op == NI_REST_OP_PUT || rest_op == NI_REST_OP_POST) {
		send_xml = xml_node_scan(stdin);
		if (send_xml == NULL) {
			ni_error("unable to read XML from standard input");
			return 1;
		}
	}
	if (rest_op != NI_REST_OP_DELETE)
		recvp = &recv_xml;
	if (__wicked_request(rest_op, path, send_xml, recvp) < 0)
		return 1;

	if (recv_xml)
		xml_node_print(recv_xml, stdout);

	if (send_xml)
		xml_node_free(send_xml);
	if (recv_xml)
		xml_node_free(recv_xml);

	return 0;
}

/*
 * xpath
 * This is a utility that can be used by network scripts to extracts bits and
 * pieces of information from an XML file.
 * This is still a bit inconvenient, especially if you need to extract more than
 * one of two elements, since we have to parse and reparse the XML file every
 * time you invoke this program.
 * On the other hand, there's a few rather nifty things you can do. For instance,
 * the following will extract addres/prefixlen pairs for every IPv4 address
 * listed in an XML network config:
 *
 * wicked xpath \
 *	--reference "interface/protocol[@family = 'ipv4']/ip" \
 *	--file vlan.xml \
 *	'%{@address}/%{@prefix}'
 *
 * The "reference" argument tells wicked to look up the <protocol>
 * element with a "family" attribute of "ipv4", and within that,
 * any <ip> elements. For each of these, it obtains the address
 * and prefix attribute, and prints it separated by a slash.
 */
int
do_xpath(int argc, char **argv)
{
	static struct option xpath_options[] = {
		{ "reference", required_argument, NULL, 'r' },
		{ "file", required_argument, NULL, 'f' },
		{ NULL }
	};
	const char *opt_reference = NULL, *opt_file = "-";
	xpath_result_t *input;
	xml_document_t *doc;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", xpath_options, NULL)) != EOF) {
		switch (c) {
		case 'r':
			opt_reference = optarg;
			break;

		case 'f':
			opt_file = optarg;
			break;

		default:
			fprintf(stderr,
				"wicked [options] xpath [--reference <expr>] [--file <path>] expr ...\n");
			return 1;
		}
	}

	doc = xml_document_read(opt_file);
	if (!doc) {
		fprintf(stderr, "Error parsing XML document %s\n", opt_file);
		return 1;
	}

	if (opt_reference) {
		xpath_enode_t *enode;

		enode = xpath_expression_parse(opt_reference);
		if (!enode) {
			fprintf(stderr, "Error parsing XPATH expression %s\n", opt_reference);
			return 1;
		}

		input = xpath_expression_eval(enode, doc->root);
		if (!input) {
			fprintf(stderr, "Error evaluating XPATH expression\n");
			return 1;
		}

		if (input->type != XPATH_ELEMENT) {
			fprintf(stderr, "Failed to look up reference node - returned non-element result\n");
			return 1;
		}
		if (input->count == 0) {
			fprintf(stderr, "Failed to look up reference node - returned empty list\n");
			return 1;
		}
		xpath_expression_free(enode);
	} else {
		input = xpath_result_new(XPATH_ELEMENT);
		xpath_result_append_element(input, doc->root);
	}

	while (optind < argc) {
		const char *expression = argv[optind++];
		ni_string_array_t result;
		xpath_format_t *format;
		unsigned int n;

		format = xpath_format_parse(expression);
		if (!format) {
			fprintf(stderr, "Error parsing XPATH format string %s\n", expression);
			return 1;
		}

		ni_string_array_init(&result);
		for (n = 0; n < input->count; ++n) {
			xml_node_t *refnode = input->node[n].value.node;

			if (!xpath_format_eval(format, refnode, &result)) {
				fprintf(stderr, "Error evaluating XPATH expression\n");
				ni_string_array_destroy(&result);
				return 1;
			}
		}

		for (n = 0; n < result.count; ++n)
			printf("%s\n", result.data[n]);

		ni_string_array_destroy(&result);
		xpath_format_free(format);
	}

	return 0;
}
