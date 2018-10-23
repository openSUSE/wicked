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
#include "appconfig.h"
#include "ifcheck.h"
#include "ifstatus.h"

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

static const char *
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
		{ "enslaved",			NI_WICKED_ST_ENSLAVED		},
		{ "up",				NI_WICKED_ST_OK			},

		{ NULL,				~0				}
	};
	return ni_format_uint_mapped(status, __status_name_map);
}

static const ni_addrconf_lease_t *
__find_grouped_lease(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	const ni_addrconf_lease_t *other;

	if (!ni_addrconf_flag_bit_is_set(lease->flags, NI_ADDRCONF_FLAGS_GROUP))
		return NULL;

	switch (lease->family) {
	case AF_INET:
		other = ni_netdev_get_lease(dev, AF_INET6, lease->type);
		break;
	case AF_INET6:
		other = ni_netdev_get_lease(dev, AF_INET,  lease->type);
		break;
	default:
		return NULL;
	}

	if (!other)
		return NULL;

	if (!ni_addrconf_flag_bit_is_set(other->flags, NI_ADDRCONF_FLAGS_GROUP))
		return NULL;

	if (ni_log_level_at(NI_LOG_DEBUG1)) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

		ni_addrconf_flags_format(&buf, other->flags, "|");
		ni_debug_application("%s: grouped lease %s:%s, state=%s, flags=%s",
				dev->name,
				ni_addrfamily_type_to_name(other->family),
				ni_addrconf_type_to_name(other->type),
				ni_addrconf_state_to_name(other->state),
				buf.string);
		ni_stringbuf_destroy(&buf);
	}

	return other;
}

static inline unsigned int
__find_grouped_lease_state(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	const ni_addrconf_lease_t *other;

	other = __find_grouped_lease(dev, lease);
	return other ? other->state : lease->state;
}

static void
__ifstatus_of_device_lease(ni_netdev_t *dev, ni_addrconf_lease_t *lease, unsigned int *st)
{
	/*
	 * Note:
	 * NI_ADDRCONF_STATE_RELEASING means, a release has been requested;
	 * NI_ADDRCONF_STATE_RELEASED is set while it has been released, but
	 * removal from system is running -- consider it happened already...
	 */
	switch (lease->state) {
	case NI_ADDRCONF_STATE_APPLYING:
	case NI_ADDRCONF_STATE_RELEASING:
	case NI_ADDRCONF_STATE_REQUESTING:
		switch (__find_grouped_lease_state(dev, lease)) {
		case NI_ADDRCONF_STATE_GRANTED:
			/* progress or granted  -> granted  */
			break;
		default:
			/* progress or progress -> progress */
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
					"%s: applying in-progress status",
					dev->name);
			*st = NI_WICKED_ST_IN_PROGRESS;
			break;
		}
		break;

	case NI_ADDRCONF_STATE_FAILED:
		switch (__find_grouped_lease_state(dev, lease)) {
		case NI_ADDRCONF_STATE_GRANTED:
			/* failure or granted   -> granted  */
			break;

		case NI_ADDRCONF_STATE_APPLYING:
		case NI_ADDRCONF_STATE_RELEASING:
		case NI_ADDRCONF_STATE_REQUESTING:
			/* failure  or progress -> progress */
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
					"%s: applying in-progress status",
					dev->name);
			*st = NI_WICKED_ST_IN_PROGRESS;
			break;

		default:
			/* failure  or failure  -> failure  */
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
					"%s: applying not-running status",
					dev->name);
			*st = NI_WICKED_ST_NOT_RUNNING;
			break;
		}
		break;

	default:
		/* granted/released -> done / do not apply errors */
		break;
	}
}

static void
__ifstatus_of_device_leases(ni_netdev_t *dev, unsigned int *st)
{
	ni_addrconf_lease_t *lease;

	if (!dev || !st)
		return;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (ni_log_level_at(NI_LOG_DEBUG1)) {
			ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

			ni_addrconf_flags_format(&buf, lease->flags, "|");
			ni_debug_application("%s: checking lease %s:%s, "
						"state=%s, flags=%s",
				dev->name,
				ni_addrfamily_type_to_name(lease->family),
				ni_addrconf_type_to_name(lease->type),
				ni_addrconf_state_to_name(lease->state),
				buf.string);
			ni_stringbuf_destroy(&buf);
		}

		/* skip optional "nice to have leases" */
		if (ni_addrconf_flag_bit_is_set(lease->flags,
					NI_ADDRCONF_FLAGS_OPTIONAL))
			continue;

		__ifstatus_of_device_lease(dev, lease, st);
	}
}

#if 0
/*
 * duplicate addresses are not always a failure:
 * dhcpv6 gets an address from dhcp-server. when the kernel
 * finds out it is a duplicate and reports it, dhcpv6 will
 * automatically try to decline it and get another address.
 * wickedd will revert the lease state from applying back
 * to requesting state and the lease gets not granted then.
 * similar with tentative.
 * => the lease state reflects the current status to use.
 */
static void
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
#endif

static unsigned int
__ifstatus_of_device(ni_netdev_t *dev)
{
	unsigned int st = NI_WICKED_ST_OK;

	if (!ni_ifcheck_device_is_up(dev))
		return NI_WICKED_ST_NOT_RUNNING;

	/* device is at least up, check if it is a slave device */
	if (!ni_string_empty(dev->link.masterdev.name))
		return NI_WICKED_ST_ENSLAVED;

	if (!ni_ifcheck_device_link_is_up(dev) &&
	    ni_ifcheck_device_link_required(dev))
		return NI_WICKED_ST_IN_PROGRESS;

	__ifstatus_of_device_leases(dev, &st);
#if 0
	if (st != NI_WICKED_ST_NOT_RUNNING)
		__ifstatus_of_device_addrs(dev, &st);

#endif
	return st;
}

static unsigned int
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

static unsigned int
ni_ifstatus_of_worker(ni_ifworker_t *w, ni_bool_t *mandatory)
{
	ni_netdev_t *dev = w ? w->device : NULL;
	unsigned int st;

	st = ni_ifstatus_of_device(dev, mandatory);

	if (mandatory) {
		if (ni_ifcheck_worker_device_link_required(w))
			*mandatory = TRUE;
	}

	return st;
}

static void
if_printf(const char *dev, const char *tag, const char *fmt, ...)
{
	va_list ap;

	if (!ni_string_empty(dev)) {
		printf("%-16s", dev);
	} else {
		printf("%-6s", "");
	}
	if (!ni_string_empty(tag)) {
		printf("%-9s ", tag);
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
		const char *hwpeer;
		if ((hwaddr = ni_link_address_print(&dev->link.hwaddr))) {
			switch (dev->link.hwaddr.type) {
			case ARPHRD_SIT:
			case ARPHRD_IPGRE:
			case ARPHRD_TUNNEL:
				printf(", local-address %s", hwaddr);
				if (dev->link.hwpeer.len &&
					(hwpeer = ni_link_address_print(&dev->link.hwpeer)))
					printf(", remote-address %s", hwpeer);
				break;
			default:
				printf(", hwaddr %s", hwaddr);
				break;
			}

		}

	}
	printf("\n");
}

static inline void
ni_ifstatus_show_addrs(ni_netdev_t *dev, ni_bool_t verbose)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_address_t *ap;

	for (ap = dev->addrs; ap; ap = ap->next) {
		const char *owner;

		if (!ni_sockaddr_is_specified(&ap->local_addr))
			continue;
		if (ni_address_is_linklocal(ap) && !verbose)
			continue;

		if (verbose) {
			ni_address_print(&buf, ap);
		} else {
			ni_stringbuf_printf(&buf, "%s %s/%u",
				ni_addrfamily_type_to_name(ap->family),
				ni_sockaddr_print(&ap->local_addr), ap->prefixlen);
		}

		if ((owner = ni_addrconf_type_to_name(ap->owner)))
			ni_stringbuf_printf(&buf, " [%s]", owner);
		else
		if (ap->family == AF_INET6 && ni_address_is_temporary(ap)) {
			/*
			 * we currently do not track all the temporary/privacy
			 * autoconf addresses, but mngtmpaddr only, so assume
			 * it is from autoconf as even dhcp6 would request one,
			 * it would also track it.
			 */
			if (ni_netdev_get_lease(dev, ap->family, NI_ADDRCONF_AUTOCONF)
			&&  (owner = ni_addrconf_type_to_name(NI_ADDRCONF_AUTOCONF)))
				ni_stringbuf_printf(&buf, " [%s]", owner);
		}

		if_printf("", "addr:", "%s\n", buf.string);
		ni_stringbuf_destroy(&buf);
	}
}

static inline void
ni_ifstatus_show_routes(const ni_netdev_t *dev, ni_bool_t verbose)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_route_table_t *tab;
	ni_route_t *rp;
	unsigned int i;
	const char *ptr;

	for (tab = dev->routes; tab; tab = tab->next) {
		for (i = 0; i < tab->routes.count; ++i) {
			rp = tab->routes.data[i];
			if (verbose) {
				ni_route_print(&buf, rp);

				if ((ptr = ni_addrconf_type_to_name(rp->owner)))
					ni_stringbuf_printf(&buf, " [%s]", ptr);

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

				if (rp->priority)
					printf(" metric %u", rp->priority);

				if ((ptr = ni_addrconf_type_to_name(rp->owner)))
					printf(" [%s]", ptr);
				else
				if ((ptr = ni_route_protocol_type_to_name(rp->protocol)))
					printf(" proto %s", ptr);

				printf("\n");
			}
			ni_stringbuf_destroy(&buf);
		}
	}
}

static inline void
ni_ifstatus_show_config(const ni_netdev_t *dev, ni_bool_t verbose)
{
	ni_client_state_t *cs = dev->client_state;

	/* currently the runtime config only ... */
	if (cs && !ni_string_empty(cs->config.origin)) {
		if_printf("", "config:", "%s", cs->config.origin);

		if (verbose && !ni_uuid_is_null(&cs->config.uuid)) {
			printf(",\n");
			if_printf("", " ", "uuid: %s\n",
				ni_uuid_print(&cs->config.uuid));
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

		if (verbose && lease->flags) {
			ni_stringbuf_puts(&buf, " [");
			ni_addrconf_flags_format(&buf, lease->flags, ",");
			ni_stringbuf_puts(&buf, "]");
		}
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
ni_ifstatus_show_control(const ni_netdev_t *dev, ni_bool_t verbose)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_client_state_t *cs;

	if (!verbose || !dev || !ni_client_state_is_valid((cs = dev->client_state)))
		return;

	if (cs->control.persistent)
		ni_stringbuf_printf(&buf, "persistent");

	if (cs->control.usercontrol) {
		ni_stringbuf_printf(&buf, "%susercontrol",
			cs->control.persistent ? ", " : "");
	}

	if (ni_stringbuf_empty(&buf))
		ni_stringbuf_printf(&buf, "none");

	if_printf("", "control:", "%s\n", buf.string);
}

static void
ni_ifstatus_show_status(const char *ifname, unsigned int status)
{
	if_printf(ifname, "", "%s\n", ni_ifstatus_code_name(status));
}

static int
ni_ifstatus_to_retcode(int status, ni_bool_t mandatory)
{
	switch (status) {
	case NI_WICKED_ST_NO_DEVICE:
	case NI_WICKED_ST_NOT_RUNNING:
		return mandatory ? NI_WICKED_ST_FAILED : NI_WICKED_ST_OK;

	case NI_WICKED_ST_UNCONFIGURED:
		return mandatory ? NI_WICKED_ST_UNUSED : NI_WICKED_ST_OK;

	case NI_WICKED_ST_IN_PROGRESS:
		return mandatory ? NI_WICKED_ST_IN_PROGRESS : NI_WICKED_ST_OK;

	default:
		return NI_WICKED_ST_OK;
	}
}

int
ni_do_ifstatus(int argc, char **argv)
{
	enum  { OPT_QUIET, OPT_BRIEF, OPT_NORMAL, OPT_VERBOSE,
		OPT_HELP, OPT_SHOW, OPT_IFCONFIG, OPT_TRANSIENT };
	static struct option ifcheck_options[] = {
		{ "help",         no_argument,       NULL, OPT_HELP        },
		{ "quiet",        no_argument,       NULL, OPT_QUIET       },
		{ "brief",        no_argument,       NULL, OPT_BRIEF       },
		{ "verbose",      no_argument,       NULL, OPT_VERBOSE     },
		{ "ifconfig",     required_argument, NULL, OPT_IFCONFIG    },
		{ "transient",    no_argument,       NULL, OPT_TRANSIENT },

		{ NULL,           no_argument,       NULL, 0               }
	};
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	unsigned int      opt_verbose  = OPT_NORMAL;
	int               c, status = NI_WICKED_ST_USAGE;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	ni_uint_array_t   stcodes = NI_UINT_ARRAY_INIT;
	ni_uint_array_t   stflags = NI_UINT_ARRAY_INIT;
	ni_bool_t         multiple = FALSE;
	ni_bool_t         all = FALSE;
	ni_bool_t         opt_transient = FALSE;
	ni_bool_t         check_config;
	ni_fsm_t *        fsm;
	unsigned int      i, nmarked;

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
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"wicked %s [options] <ifname ...>|all\n"
				"\nSupported options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --transient\n"
				"      Enable transient interface return codes\n"
				"  --quiet\n"
				"      Return exit status only\n"
				"  --brief\n"
				"      Show only a brief status, no additional info\n"
				"  --verbose\n"
				"      Show a more detailed information\n"
				"\n"
				"  --ifconfig <filename>\n"
				"      Read interface configuration(s) from file\n"
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

		case OPT_TRANSIENT:
			opt_transient = TRUE;
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

	if (!ni_ifconfig_load(fsm, opt_global_rootdir, &opt_ifconfig, TRUE, TRUE)) {
		status = NI_WICKED_ST_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_ST_OK;
	for (c = optind; c < argc; ++c) {
		char *ifname = argv[c];

		if (ni_string_eq(ifname, "all")) {
			ni_string_array_destroy(&ifnames);
			all = TRUE;
			break;
		}

		if (ni_string_array_index(&ifnames, ifname) == -1)
			ni_string_array_append(&ifnames, ifname);
	}

	if (ifnames.count > 1 || all)
		multiple = TRUE;

	for (i = 0, nmarked = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];
		ni_netdev_t *dev = w->device;
		unsigned int st = NI_WICKED_ST_NO_DEVICE;
		ni_bool_t mandatory = TRUE;

		if (!all) {
			if (ni_string_array_index(&ifnames, w->name) == -1)
				continue;
		}

		if (nmarked && opt_verbose > OPT_BRIEF)
			printf("\n");

		if (check_config) {
			st = ni_ifstatus_of_worker(w, &mandatory);
		} else {
			st = ni_ifstatus_of_device(dev, &mandatory);
		}
		ni_uint_array_append(&stcodes, st);
		ni_uint_array_append(&stflags, mandatory);
		nmarked++;

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
			ni_ifstatus_show_control (dev, opt_verbose > OPT_NORMAL);
			ni_ifstatus_show_config (dev, opt_verbose > OPT_NORMAL);
			ni_ifstatus_show_leases (dev, opt_verbose > OPT_NORMAL);

			ni_ifstatus_show_addrs  (dev, opt_verbose > OPT_NORMAL);
			ni_ifstatus_show_routes (dev, opt_verbose > OPT_NORMAL);
		}
	}

	if (nmarked == 0) {
		if (opt_verbose > OPT_QUIET)
			printf("ifstatus: no matching interfaces\n");
		status = NI_WICKED_ST_NO_DEVICE;
		goto cleanup;
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
			case NI_WICKED_ST_IN_PROGRESS:
				break;
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

int
ni_ifstatus_shutdown_result(ni_fsm_t *fsm, ni_string_array_t *names, ni_ifworker_array_t *marked)
{
	unsigned int i;

	ni_assert(fsm);
	for (i = 0; i < fsm->workers.count; i++) {
		const ni_ifworker_t *w = fsm->workers.data[i];

		if (!w || ni_string_empty(w->name))
			continue;

		if (!w->kickstarted)
			continue;

		if (marked && ni_ifworker_array_index(marked, w) < 0)
			continue;

		if (names && names->count != 0 &&
		    ni_string_array_index(names, w->name) < 0) {
			continue;
		}

		if (!ni_ifworker_is_valid_state(w->fsm.state))
			continue;

		if_printf(w->name, "", "%s\n", ni_ifworker_state_name(w->fsm.state));
	}

	if (ni_fsm_fail_count(fsm))
		return NI_WICKED_RC_ERROR;

	return NI_WICKED_RC_SUCCESS;
}

int
ni_ifstatus_display_result(ni_fsm_t *fsm, ni_string_array_t *names, ni_ifworker_array_t *marked, ni_bool_t opt_transient)
{
	ni_uint_array_t stcodes = NI_UINT_ARRAY_INIT;
	ni_uint_array_t stflags = NI_UINT_ARRAY_INIT;
	int status = NI_WICKED_ST_OK;
	ni_bool_t multiple;
	unsigned int i;

	ni_assert(fsm);
	if (!ni_fsm_refresh_state(fsm)) {
		/* Severe error we always explicitly return */
		return NI_WICKED_ST_ERROR;
	}

	if (names && names->count == 1)
		multiple = FALSE;
	else if (marked && marked->count == 1)
		multiple = FALSE;
	else
		multiple = TRUE;

	for (i = 0; i < fsm->workers.count; i++ ) {
		ni_ifworker_t *w = fsm->workers.data[i];
		unsigned int st = NI_WICKED_ST_NO_DEVICE;
		ni_bool_t mandatory = TRUE;

		if (!w || ni_string_empty(w->name))
			continue;

		if (marked && ni_ifworker_array_index(marked, w) < 0)
			continue;

		if (names && names->count != 0 &&
		    ni_string_array_index(names, w->name) < 0) {
			continue;
		}

		st = ni_ifstatus_of_worker(w, &mandatory);
		ni_uint_array_append(&stcodes, st);
		ni_uint_array_append(&stflags, mandatory);

		ni_ifstatus_show_status(w->name, st);
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
			case NI_WICKED_ST_IN_PROGRESS:
				break;
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

	return status;
}
