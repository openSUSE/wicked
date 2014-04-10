/*
 *	wicked client ifstatus action and utilities
 *
 *	Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
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
#include <net/if_arp.h>
#include <netlink/netlink.h>

#include <wicked/wicked.h>
#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/route.h>
#include <wicked/bonding.h>
#include <wicked/bridge.h>
#include <wicked/vlan.h>
#include <wicked/fsm.h>

#include "wicked-client.h"
#include "ifup.h"
#include "ifcheck.h"

/*
 * ifstatus code matrix + mapped lsb exit code.
 * [without the transient / in-progress states]
 *
 * cfg  dev  mand  state  ifup  status       lsb  comment
 * --------------------------------------------------------------------------------------
 * no   no   --    --     --    NO_CONFIG    0    we do not manage it, so not an err.
 * yes  no   no    --     --    NO_DEVICE    0    not mandatory, do not complain
 * yes  no   yes   --     --    NO_DEVICE    2    failure as it is a mandatory one
 *
 * yes  yes  no    down   no    NOT_STARTED  0    configured & not started [+down]
 * yes  yes  no    up     no    NOT_STARTED  0    configured & not started [+up]
 * yes  yes  yes   down   no    NOT_STARTED  3    mandatory & not started [+down]
 * yes  yes  yes   up     no    NOT_STARTED  3    mandatory & not started [+up]
 *
 * no   yes  no    down   no    NOT_STARTED  0    not configured & not started [+down]
 * no   yes  no    up     no    NOT_STARTED  0    not confiured & not started [+link-up]
 * no   yes  yes   down   no    NOT_STARTED  3    mandatory, not started, not running
 * no   yes  yes   up     no    NOT_STARTED  3    mandatory, not started but link up
 *
 * yes  yes  no    down   yes   NOT_RUNNING  0    configured & started, some failure
 * yes  yes  no    up     yes   OK           0    configured & started & no failure
 * yes  yes  yes   down   yes   NOT_RUNNING  2    mandatory  & started, some failure
 * yes  yes  yes   up     yes   OK           0    mandatory  & started & no failure

 * no   yes  no    down   yes   NOT_RUNNING  0    started & failed, but not mandatory
 * no   yes  yes   down   yes   NOT_RUNNING  2    mandatory, started but some failure
 * no   yes  no    up     yes   CHANGED_CFG  0    started, up [no failure], config deleted
 * no   yes  yes   up     yes   CHANGED_CFG  0    mandatory, started, no failure, config deleted
 */

const char *
ni_ifstatus_code_name(unsigned int status)
{
	static const ni_intmap_t        __status_name_map[] = {
		{ "device-not-enabled",		NI_WICKED_ST_DISABLED		},
		{ "device-unconfigured",	NI_WICKED_ST_UNCONFIGURED	},
		{ "no-device",			NI_WICKED_ST_NO_DEVICE		},
		{ "device-not-running",		NI_WICKED_ST_NOT_RUNNING	},
		{ "no-config",			NI_WICKED_ST_NO_CONFIG		},
		{ "setup-in-progress",		NI_WICKED_ST_IN_PROGRESS	},
		{ "config-changed",		NI_WICKED_ST_CHANGED_CONFIG	},
		{ "up",				NI_WICKED_ST_OK			},

		{ NULL,				~0				}
	};
	return ni_format_uint_mapped(status, __status_name_map);
}

void
__ifstatus_of_device_leases(ni_netdev_t *dev, unsigned int *st)
{
	ni_addrconf_lease_t *lease;

	if (!dev || !st)
		return;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (lease->state == NI_ADDRCONF_STATE_NONE)
			continue;

		if (lease->state == NI_ADDRCONF_STATE_RELEASING ||
		    lease->state == NI_ADDRCONF_STATE_REQUESTING) {
			*st = NI_WICKED_ST_IN_PROGRESS;
		}

		if (lease->state == NI_ADDRCONF_STATE_FAILED) {
			*st = NI_WICKED_ST_NOT_RUNNING;
			break;
		}
	}
}

void
__ifstatus_of_device_addrs(ni_netdev_t *dev, unsigned int *st)
{
	ni_address_t *ap;

	if (!dev || !st)
		return;

	for (ap = dev && st ? dev->addrs : NULL; ap; ap = ap->next) {
		if (ni_address_is_deprecated(ap))
			continue;

		if (ni_address_is_tentative(ap))
			*st = NI_WICKED_ST_IN_PROGRESS;

		if (ni_address_is_duplicate(ap)) {
			*st = NI_WICKED_ST_NOT_RUNNING;
			break;
		}
	}
}

unsigned int
__ifstatus_of_device(ni_netdev_t *dev)
{
	unsigned int st = NI_WICKED_ST_OK;

	if (!ni_ifcheck_device_is_up(dev))
		return NI_WICKED_ST_NOT_RUNNING;

	if (!ni_ifcheck_device_link_is_up(dev))
		return NI_WICKED_ST_IN_PROGRESS;

	__ifstatus_of_device_leases(dev, &st);
	if (st != NI_WICKED_ST_NOT_RUNNING)
		__ifstatus_of_device_addrs(dev, &st);

	return st;
}

unsigned int
ni_ifstatus_of_device(ni_netdev_t *dev, ni_bool_t *mandatory)
{
	if (mandatory) {
		*mandatory = ni_ifcheck_device_is_persistent(dev);
	}

	if (!dev)
		return NI_WICKED_ST_NO_DEVICE;

	if (!ni_ifcheck_device_configured(dev))
		return NI_WICKED_ST_UNCONFIGURED;

	return __ifstatus_of_device(dev);
}

unsigned int
ni_ifstatus_of_worker(ni_ifworker_t *w, ni_bool_t *mandatory)
{
	ni_netdev_t *dev = w ? w->device : NULL;
	unsigned int st;

	if (mandatory) {
		*mandatory = ni_ifcheck_device_is_persistent(dev) ||
			ni_ifcheck_worker_device_link_required(w);
	}

	if (!ni_ifcheck_worker_device_exists(w)) {
		if (!ni_ifcheck_worker_config_exists(w))
			return NI_WICKED_ST_NO_CONFIG;
		return NI_WICKED_ST_NO_DEVICE;
	}

	if (!ni_ifcheck_device_configured(dev))
		return NI_WICKED_ST_UNCONFIGURED;

	st = __ifstatus_of_device(dev);
	if (st == NI_WICKED_ST_OK) {
		if (!ni_ifcheck_worker_config_exists(w))
			return NI_WICKED_ST_CHANGED_CONFIG;
	}

	return st;
}

static void
if_printf(const char *dev, const char *tag, const char *fmt, ...)
{
	va_list ap;

	if (!ni_string_empty(dev)) {
		printf("%-15s", dev);
	} else {
		printf("%-6s", "");
	}
	if (!ni_string_empty(tag)) {
		printf("%-8s ", tag);
	}
	if (!ni_string_empty(fmt)) {
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

static inline void
ni_ifstatus_show_iflink(const ni_netdev_t *dev, ni_bool_t verbose)
{
	if_printf("", "link:", "#%u, state %s", dev->link.ifindex,
		((dev->link.ifflags & NI_IFF_NETWORK_UP) ? "up" :
		 (dev->link.ifflags & NI_IFF_LINK_UP) ? "link-up" :
		 (dev->link.ifflags & NI_IFF_DEVICE_UP) ? "device-up" :
		 "down"));

	if (dev->link.mtu > 0 && dev->link.mtu < 65536)
		printf(", mtu %d", dev->link.mtu);
	if (!ni_string_empty(dev->link.alias))
		printf(", alias %s", dev->link.alias);
	if (!ni_string_empty(dev->link.masterdev.name))
		printf(", master %s", dev->link.masterdev.name);
	printf("\n");
}

static inline void
ni_ifstatus_show_iftype(const ni_netdev_t *dev, ni_bool_t verbose)
{
	(void)verbose;	/* currently unused */

	if_printf("", "type:", "%s", ni_linktype_type_to_name(dev->link.type));

	switch(dev->link.type) {
	case NI_IFTYPE_VLAN:
		if (dev->vlan) {
			printf(" %s[%u]", dev->link.lowerdev.name, dev->vlan->tag);
			if (dev->vlan->protocol != NI_VLAN_PROTOCOL_8021Q)
				printf(", protocol %s",
					ni_vlan_protocol_to_name(dev->vlan->protocol));
		}
		break;

	case NI_IFTYPE_BOND:
		if (dev->bonding) {
			printf(", mode %s",
				ni_bonding_mode_type_to_name(dev->bonding->mode));
		}
		break;

	default:
		/* ... */
		break;
	}

	/* TODO: provide complete hwaddr (with type) over dbus,
	 *       fix the error which may be triggered here
	 */
	if (dev->link.hwaddr.len) {
		const char *hwaddr;
		if ((hwaddr = ni_link_address_print(&dev->link.hwaddr)))
			printf(", hwaddr %s", hwaddr);
	}
	printf("\n");
}

static inline void
ni_ifstatus_show_addrs(const ni_netdev_t *dev, ni_bool_t verbose)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_address_t *ap;

	for (ap = dev->addrs; ap; ap = ap->next) {
		if (ni_address_is_duplicate(ap))
			continue;
		if (ni_address_is_deprecated(ap))
			continue;
		if (ni_address_is_linklocal(ap) && !verbose)
			continue;
		if (!ni_sockaddr_is_specified(&ap->local_addr))
			continue;

		if_printf("", "addr:", "%s %s/%u",
			ni_addrfamily_type_to_name(ap->family),
			ni_sockaddr_print(&ap->local_addr), ap->prefixlen);

		if (verbose) {
			if (!ni_string_empty(ap->label) &&
			    !ni_string_eq(ap->label, dev->name))
				printf(" label %s", ap->label);

			if (ap->family == AF_INET6) {
				if (ap->ipv6_cache_info.valid_lft == -1U) {
					ni_stringbuf_puts(&buf, "infinite");
					printf("%s", buf.string);
				} else {
					ni_stringbuf_printf(&buf, "%u",
						ap->ipv6_cache_info.valid_lft);
					ni_stringbuf_puts(&buf, "/");
					ni_stringbuf_printf(&buf, "%u",
						ap->ipv6_cache_info.preferred_lft);
				}
				if (buf.string)
					printf("lifetime %s", buf.string);
				ni_stringbuf_destroy(&buf);
			}
		}
		printf("\n");
	}
}

static inline void
ni_ifstatus_show_routes(const ni_netdev_t *dev, ni_bool_t verbose)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_route_table_t *tab;
	ni_route_t *rp;
	unsigned int i;

	for (tab = dev->routes; tab; tab = tab->next) {
		for (i = 0; i < tab->routes.count; ++i) {
			rp = tab->routes.data[i];
			if (verbose) {
				ni_route_print(&buf, rp);
				if_printf("", "route:", "%s\n", buf.string);
			} else {
				if (!(rp->table == RT_TABLE_MAIN))
					continue;
				if (!(rp->type == RTN_UNICAST || rp->type == RTN_LOCAL))
					continue;
				if (!ni_sockaddr_is_specified(&rp->nh.gateway))
					continue;

				if_printf("", "route:", "%s",
					ni_addrfamily_type_to_name(rp->family));

				if (ni_sockaddr_is_specified(&rp->destination)) {
					printf(" %s/%u", ni_sockaddr_print(&rp->destination),
						rp->prefixlen);
				} else {
					printf(" default");
				}

				if (ni_sockaddr_is_specified(&rp->nh.gateway)) {
					printf(" via %s%s", ni_sockaddr_print(&rp->nh.gateway),
							rp->nh.next ? ",..." : "");
				}

				printf("\n");
			}
			ni_stringbuf_destroy(&buf);
		}
	}
}

static inline void
ni_ifstatus_show_config(const ni_netdev_t *dev, ni_bool_t verbose)
{
	ni_device_clientinfo_t *ci = dev->client_info;

	/* currently the runtime config only ... */
	if (ci && !ni_string_empty(ci->config_origin)) {
		if_printf("", "config:", "%s", ci->config_origin);

		if (verbose && !ni_uuid_is_null(&ci->config_uuid)) {
			printf(",\n");
			if_printf("", " ", "uuid: %s\n",
				ni_uuid_print(&ci->config_uuid));
		} else {
			printf("\n");
		}
	} else if (verbose) {
		if_printf("", "config:", "none\n");
	}
}

static inline void
__show_leases_by_family(const ni_netdev_t *dev, ni_bool_t verbose, sa_family_t family)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (lease->family != family)
			continue;

		if (lease->state == NI_ADDRCONF_STATE_NONE ||
		    lease->state == NI_ADDRCONF_STATE_RELEASED)
			continue;

		ni_stringbuf_printf(&buf, "%s%s %s %s",
			buf.string ? ", " : "",
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_type_to_name(lease->type),
			ni_addrconf_state_to_name(lease->state));
	}
	if (buf.string)
		if_printf("", "leases:", "%s\n", buf.string);
	ni_stringbuf_destroy(&buf);
}

static inline void
ni_ifstatus_show_leases(const ni_netdev_t *dev, ni_bool_t verbose)
{
	__show_leases_by_family(dev, verbose, AF_INET);
	__show_leases_by_family(dev, verbose, AF_INET6);
}

static inline void
ni_ifstatus_show_cstate(const ni_netdev_t *dev, ni_bool_t verbose)
{
	ni_device_clientinfo_t *ci = dev->client_info;
	ni_client_state_t *cs = dev->client_state;

	if (ci && !ni_string_empty(ci->state)) {
		if_printf("", "cstate:", "%s%s\n", ci->state,
			(verbose && cs && cs->persistent) ?
				", persistent" : "");
	} else if (verbose) {
		if_printf("", "cstate:", "none\n");
	}
}

void
ni_ifstatus_show_status(const char *ifname, unsigned int status)
{
	if_printf(ifname, "", "%s\n", ni_ifstatus_code_name(status));
}

int
ni_ifstatus_to_retcode(int status, ni_bool_t mandatory)
{
	switch (status) {
	case NI_WICKED_ST_NO_DEVICE:
	case NI_WICKED_ST_NOT_RUNNING:
		return mandatory ? NI_WICKED_ST_FAILED : NI_WICKED_ST_OK;

	case NI_WICKED_ST_UNCONFIGURED:
		return mandatory ? NI_WICKED_ST_UNUSED : NI_WICKED_ST_OK;

	default:
		return NI_WICKED_ST_OK;
	}
}

int
ni_do_ifstatus(int argc, char **argv)
{
	enum  { OPT_QUIET, OPT_BRIEF, OPT_NORMAL, OPT_VERBOSE,
		OPT_HELP, OPT_SHOW, OPT_IFCONFIG, OPT_NOTRANSIENT };
	static struct option ifcheck_options[] = {
		{ "help",         no_argument,       NULL, OPT_HELP        },
		{ "quiet",        no_argument,       NULL, OPT_QUIET       },
		{ "brief",        no_argument,       NULL, OPT_BRIEF       },
		{ "verbose",      no_argument,       NULL, OPT_VERBOSE     },
		{ "ifconfig",     required_argument, NULL, OPT_IFCONFIG    },
		{ "no-transient", no_argument,       NULL, OPT_NOTRANSIENT },

		{ NULL,           no_argument,       NULL, 0               }
	};
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	unsigned int      opt_verbose  = OPT_NORMAL;
	ni_bool_t         opt_transient = TRUE;
	int               c, status = NI_WICKED_ST_USAGE;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	ni_uint_array_t   stcodes = NI_UINT_ARRAY_INIT;
	ni_uint_array_t   stflags = NI_UINT_ARRAY_INIT;
	ni_bool_t         multiple = FALSE;
	ni_bool_t         check_config;
	ni_ifmatcher_t    ifmatch;
	ni_fsm_t *        fsm;
	unsigned int      i;

	/* Allow ifcheck on persistent, unconfigured interfaces */
	memset(&ifmatch, 0, sizeof(ifmatch));
	ifmatch.require_configured = FALSE;
	ifmatch.allow_persistent = TRUE;
	ifmatch.require_config = FALSE;

	/* Allocate fsm and set to read-only */
	fsm = ni_fsm_new();
	fsm->readonly = TRUE;

	/*
	 * Parse config files in ifstatus mode, show deals with
	 * runtime configuration of (existing) interfaces only.
	 *
	 * Further, the system configs are parsed and only for
	 * root, as they're not readable for normal users.
	 */
	check_config = ni_string_eq(argv[0], "ifstatus") && geteuid() == 0;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifcheck_options, NULL)) != EOF) {
		switch (c) {
		case OPT_HELP:
			status = NI_WICKED_ST_OK;
		default:
		usage:
			fprintf(stderr,
				"wicked %s [options] <ifname ...>|all\n"
				"\nSupported options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --quiet\n"
				"      Return exit status only\n"
				"  --brief\n"
				"      Show only a brief status, no additional info\n"
				"\n"
				"  --ifconfig <filename>\n"
				"      Read interface configuration(s) from file\n"
				"  --no-transient\n"
				"      Discard transient interface status codes\n"
				, argv[0]
			);
			goto cleanup;

		case OPT_QUIET:
		case OPT_BRIEF:
		case OPT_VERBOSE:
			opt_verbose = c;
			break;

		case OPT_IFCONFIG:
			ni_string_array_append(&opt_ifconfig, optarg);
			break;

		case OPT_NOTRANSIENT:
			opt_transient = FALSE;
			break;
		}
	}

	/* at least one argument is required */
	if (optind >= argc) {
		goto usage;
	} else for (c = optind; c < argc; ++c) {
		if (ni_string_empty(argv[c]))
			goto usage;
	}

	if (!ni_fsm_create_client(fsm)) {
		/* Severe error we always explicitly return */
		status = NI_WICKED_ST_ERROR;
		goto cleanup;
	}

	if (!ni_fsm_refresh_state(fsm)) {
		/* Severe error we always explicitly return */
		status = NI_WICKED_ST_ERROR;
		goto cleanup;
	}

	if (check_config && opt_ifconfig.count == 0) {
		const ni_string_array_t *sources = ni_config_sources("ifconfig");

		if (sources && sources->count)
			ni_string_array_copy(&opt_ifconfig, sources);
	}

	if (!ni_ifconfig_load(fsm, opt_global_rootdir, &opt_ifconfig, TRUE)) {
		status = NI_WICKED_ST_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_ST_OK;
	for (c = optind; c < argc; ++c) {
		ni_ifworker_array_t marked = { 0, NULL };
		unsigned int st = NI_WICKED_ST_NO_DEVICE;
		ni_bool_t mandatory = TRUE;

		ifmatch.name = argv[c];
		if (ni_string_eq(ifmatch.name, "all")) {
			ifmatch.name = NULL;
			multiple = TRUE;
		}

		ni_fsm_get_matching_workers(fsm, &ifmatch, &marked);
		for (i = 0; i < marked.count; ++i) {
			ni_ifworker_t *w = marked.data[i];
			ni_netdev_t *dev = w->device;

			if (ni_string_array_index(&ifnames, w->name) != -1)
				continue;

			multiple = ifnames.count ? TRUE : multiple;
			ni_string_array_append(&ifnames, w->name);

			if (check_config) {
				st = ni_ifstatus_of_worker(w, &mandatory);
			} else {
				st = ni_ifstatus_of_device(dev, &mandatory);
			}
			ni_uint_array_append(&stcodes, st);
			ni_uint_array_append(&stflags, mandatory);

			if (i && opt_verbose > OPT_BRIEF)
				printf("\n");

			if (opt_verbose > OPT_QUIET)
				ni_ifstatus_show_status(w->name, st);

			if (opt_verbose <= OPT_BRIEF)
				continue;

			if (dev) {
				ni_ifstatus_show_iflink (dev, opt_verbose > OPT_NORMAL);
				ni_ifstatus_show_iftype (dev, opt_verbose > OPT_NORMAL);

				/* TODO: Hmm... this is the running config only;
				 *              show current config info too?
				 */
				ni_ifstatus_show_cstate (dev, opt_verbose > OPT_NORMAL);
				ni_ifstatus_show_config (dev, opt_verbose > OPT_NORMAL);
				ni_ifstatus_show_leases (dev, opt_verbose > OPT_NORMAL);

				ni_ifstatus_show_addrs  (dev, opt_verbose > OPT_NORMAL);
				ni_ifstatus_show_routes (dev, opt_verbose > OPT_NORMAL);
			}
		}

		if (ifmatch.name && !marked.count &&
		    ni_string_array_index(&ifnames, ifmatch.name) == -1) {

			multiple = ifnames.count ? TRUE : multiple;
			ni_string_array_append(&ifnames, ifmatch.name);
			ni_uint_array_append(&stcodes, st);
			ni_uint_array_append(&stflags, mandatory);

			if (c > optind && opt_verbose > OPT_BRIEF)
				printf("\n");

			if (opt_verbose > OPT_QUIET)
				ni_ifstatus_show_status(ifmatch.name, st);
		}
	}

	if (!stcodes.count) {
		if (status == NI_WICKED_ST_OK) {
			status = NI_WICKED_ST_UNUSED;
		}
	} else
	if (!multiple) {
		status = stcodes.data[0];
		if (!opt_transient) {
			switch (status) {
			case NI_WICKED_ST_NO_DEVICE:
			case NI_WICKED_ST_UNCONFIGURED:
			case NI_WICKED_ST_NOT_RUNNING:
			default:
				status = NI_WICKED_ST_OK;
				break;
			}
		}
	} else
	for (i = 0; i < stcodes.count && i < stflags.count; ++i) {
		unsigned int st = stcodes.data[i];
		unsigned int fl = stflags.data[i];
		int rc = ni_ifstatus_to_retcode(st, fl);
		if (rc == NI_WICKED_ST_FAILED)
			status = rc;
	}

cleanup:
	ni_uint_array_destroy(&stcodes);
	ni_uint_array_destroy(&stflags);
	ni_string_array_destroy(&ifnames);
	ni_string_array_destroy(&opt_ifconfig);
	return status;
}
