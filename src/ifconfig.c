/*
 * Things to do when bringing an interface up or down
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *
 * Link layer:
 *  - handle ethtool options
 *  - set device MTU
 *  - set link layer addr
 *  - set other LL options
 *  - bring up link layer
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netlink/msg.h>
#include <netlink/errno.h>
#include <time.h>

#include <wicked/netinfo.h>
#include <wicked/route.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/team.h>
#include <wicked/vlan.h>
#include <wicked/macvlan.h>
#include <wicked/system.h>
#include <wicked/wireless.h>
#include <wicked/infiniband.h>
#include <wicked/tuntap.h>
#include <wicked/ppp.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/lldp.h>
#include <wicked/tunneling.h>

#if defined(HAVE_RTA_MARK)
#  include <netlink/netlink.h>
#elif defined(HAVE_LINUX_RTNETLINK_H) && defined(HAVE_LINUX_RTA_MARK)
#  include <linux/rtnetlink.h>
#  define  HAVE_RTA_MARK HAVE_LINUX_RTA_MARK
#endif

#if defined(HAVE_IFLA_VLAN_PROTOCOL)
#  ifndef	ETH_P_8021Q
#  define	ETH_P_8021Q	0x8100
#  endif
#  ifndef	ETH_P_8021AD
#  define	ETH_P_8021AD	0x88A8
#  endif
#endif

#if !defined(MACVLAN_FLAG_NOPROMISC)
#  if defined(HAVE_MACVLAN_FLAG_NOPROMISC)
#    include <linux/if_link.h>
#  else
#    include "linux/if_link.h"
#  endif
#endif
#include <linux/if_tunnel.h>
#include <linux/fib_rules.h>

#include "netinfo_priv.h"
#include "util_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "appconfig.h"
#include "process.h"
#include "debug.h"
#include "modprobe.h"
#include "pppd.h"
#include "teamd.h"
#include "ovs.h"

#ifndef SIT_TUNNEL_MODULE_NAME
#define SIT_TUNNEL_MODULE_NAME "sit"
#endif
#ifndef GRE_TUNNEL_MODULE_NAME
#define GRE_TUNNEL_MODULE_NAME "ip_gre"
#endif
#ifndef IPIP_TUNNEL_MODULE_NAME
#define IPIP_TUNNEL_MODULE_NAME "ipip"
#endif
#ifndef TUNNEL4_MODULE_NAME
#define TUNNEL4_MODULE_NAME "tunnel4"
#endif
#ifndef DUMMY_MODULE_NAME
#define DUMMY_MODULE_NAME "dummy"
#endif
#ifndef DUMMY_MODULE_OPTS
#define DUMMY_MODULE_OPTS "numdummies=0"
#endif

#ifndef	BOND_MAX_ARP_TARGETS
#define	BOND_MAX_ARP_TARGETS		16
#endif
#ifndef	BOND_DEFAULT_MIIMON
#define	BOND_DEFAULT_MIIMON		100
#endif

static int	__ni_netdev_update_addrs(ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_addrconf_lease_t       *new_lease);
static int	__ni_netdev_update_routes(ni_netconfig_t *nc, ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_addrconf_lease_t       *new_lease);
static int	__ni_netdev_update_rules(ni_netconfig_t *nc, ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_addrconf_lease_t       *new_lease);
static int	__ni_netdev_update_mtu(ni_netconfig_t *nc, ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_addrconf_lease_t       *new_lease);

static int	__ni_rtnl_link_create(ni_netconfig_t *nc, const ni_netdev_t *cfg);
static int	__ni_rtnl_link_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg);

static int	__ni_rtnl_link_change_mtu(ni_netdev_t *dev, unsigned int mtu);
static int	__ni_rtnl_link_change_hwaddr(ni_netdev_t *dev, const ni_hwaddr_t *hwaddr);

static int	__ni_rtnl_link_up(const ni_netdev_t *, const ni_netdev_req_t *);
static int	__ni_rtnl_link_down(const ni_netdev_t *);
static int	__ni_rtnl_link_delete(const ni_netdev_t *);

static int	__ni_rtnl_link_add_port_up(const ni_netdev_t *, const char *, unsigned int);
static int	__ni_rtnl_link_add_slave_down(const ni_netdev_t *, const char *, unsigned int);

static int	__ni_rtnl_send_deladdr(ni_netdev_t *, const ni_address_t *);
static int	__ni_rtnl_send_newaddr(ni_netdev_t *, const ni_address_t *, int);
static int	__ni_rtnl_send_delroute(ni_netdev_t *, ni_route_t *);
static int	__ni_rtnl_send_newroute(ni_netdev_t *, ni_route_t *, int);
static int	__ni_rtnl_send_newrule(const ni_rule_t *, int);
static int	__ni_rtnl_send_delrule(const ni_rule_t *);

static int	__ni_system_netdev_create(ni_netconfig_t *nc,
					const char *ifname, unsigned int ifindex,
					ni_iftype_t iftype, ni_netdev_t **dev_ret);

static int
ni_system_interface_enslave(ni_netdev_t *master, ni_netdev_t *dev, const ni_netdev_req_t *req)
{
	int ret = -1;

	if (!master || !dev || !req)
		return -1;

	if (dev->link.masterdev.index) {
		if (dev->link.masterdev.index == master->link.ifindex) {
			ni_debug_ifconfig("%s: already enslaved into %s[#%u]",
					dev->name, dev->link.masterdev.name,
					dev->link.masterdev.index);
			return 0;
		} else {
			ni_error("%s: already enslaved into %s[#%u]",
					dev->name, dev->link.masterdev.name,
					dev->link.masterdev.index);
			return -1;
		}
	}

	switch (master->link.type) {
	case NI_IFTYPE_BOND:
		ret = __ni_rtnl_link_add_slave_down(dev, master->name,
						master->link.ifindex);
		if (ret == 0) {
			ni_netdev_ref_set(&dev->link.masterdev,
					master->name, master->link.ifindex);
		}
		break;
	case NI_IFTYPE_TEAM:
		if (!ni_config_teamd_enabled())
			return -1;

		if (req->port && master->link.type != req->port->type) {
			ni_error("%s: port configuration type mismatch", dev->name);
			return -1;
		}
		ret = ni_teamd_port_enslave(master, dev, req->port ? &req->port->team : NULL);

		if (ret == 0) {
			ni_netdev_ref_set(&dev->link.masterdev,
					master->name, master->link.ifindex);

		}

		/* refresh master - also when enslave fails... */
		ni_teamd_discover(master);
		break;
	case NI_IFTYPE_BRIDGE:
		ret = __ni_rtnl_link_add_port_up(dev, master->name,
						master->link.ifindex);
		if (ret == 0) {
			ni_netdev_ref_set(&dev->link.masterdev,
					master->name, master->link.ifindex);

			if (dev->link.type == NI_IFTYPE_WIRELESS)
				ni_wireless_connect(dev);
		}
		break;
	case NI_IFTYPE_OVS_SYSTEM:
		if (!req->port || req->port->type != NI_IFTYPE_OVS_BRIDGE) {
			ni_error("%s: port configuration type mismatch", dev->name);
			return -1;
		}
		if (ni_string_empty(req->port->ovsbr.bridge.name)) {
			ni_error("%s: missing ovs-bridge name in port config", dev->name);
			return -1;
		}

		ret = ni_ovs_vsctl_bridge_port_add(dev->name, &req->port->ovsbr, TRUE);
		if (ret == 0)  {
			ni_netdev_ref_set(&dev->link.masterdev,
					master->name, master->link.ifindex);
		} else {
			/* TODO */
			ret = -1;
		}
		break;
	default:
		break;
	}
	return ret;
}

int
ni_system_interface_link_change(ni_netdev_t *dev, const ni_netdev_req_t *ifp_req)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *master;
	unsigned int ifflags;

	if (dev == NULL)
		return -NI_ERROR_INVALID_ARGS;

	ni_debug_ifconfig("%s(%s)", __func__, dev->name);

	/* FIXME: perform sanity check on configuration data,
	 *        cleanup the tweaks we've added
	 */
	ifflags = ifp_req? ifp_req->ifflags : 0;
	if (ifflags & (NI_IFF_DEVICE_UP|NI_IFF_LINK_UP|NI_IFF_NETWORK_UP)) {
		/*
		 * master manages the link of a slave, redirect to enslave
		 * when there is a master set.
		 */
		if (dev->link.masterdev.index) {
			if (!dev->link.masterdev.name)
				ni_netdev_ref_bind_ifname(&dev->link.masterdev, nc);

			ni_debug_ifconfig("%s: already enslaved in master %s[#%u]",
					dev->name, dev->link.masterdev.name ?
					dev->link.masterdev.name : "",
					dev->link.masterdev.index);

			master = ni_netdev_by_index(nc, dev->link.masterdev.index);
			if (master && master->link.type == NI_IFTYPE_TEAM && ni_config_teamd_enabled()) {
				if (ifp_req->port && master->link.type == ifp_req->port->type)
					ni_teamd_port_enslave(master, dev, &ifp_req->port->team);

				ni_teamd_discover(master);
			}
			if (master && master->link.type == NI_IFTYPE_OVS_SYSTEM) {
				if (ifp_req->port && ifp_req->port->type == NI_IFTYPE_OVS_BRIDGE &&
				    !ni_string_empty(ifp_req->port->ovsbr.bridge.name)) {
					ni_ovs_vsctl_bridge_port_add(dev->name, &ifp_req->port->ovsbr, TRUE);
				}
			}

			if (ni_netdev_device_is_up(dev))
				return 0;

			if (master &&  (master->link.type == NI_IFTYPE_BOND ||
					master->link.type == NI_IFTYPE_TEAM))
				return 0;
		} else
		/* config lookup for master and redirect to master's enslave */
		if (ifp_req && !ni_string_empty(ifp_req->master.name)) {
			int ret;

			master = ni_netdev_by_name(nc, ifp_req->master.name);
			ret = ni_system_interface_enslave(master, dev, ifp_req);
			if (!master || master->link.type != NI_IFTYPE_OVS_SYSTEM)
				return ret;
		}

		ni_debug_ifconfig("bringing up %s", dev->name);

		if (__ni_rtnl_link_up(dev, ifp_req)) {
			ni_error("%s: failed to bring up interface (rtnl error)",
					dev->name);
			return -1;
		}

		if (dev->link.type == NI_IFTYPE_WIRELESS)
			ni_wireless_connect(dev);
	} else {
		/* FIXME: Shut down any addrconf services on this interface?
		 * We should expect these services to detect the link down event...
		 */

		if (dev->link.type == NI_IFTYPE_WIRELESS)
			ni_wireless_disconnect(dev);

		/* If an LLDP agent is active for this interface, shut it down, too */
		ni_system_lldp_down(dev);

		/* Now take down the link for real */
		ni_debug_ifconfig("shutting down interface %s", dev->name);
		if (__ni_rtnl_link_down(dev)) {
			ni_error("unable to shut down interface %s", dev->name);
			return -1;
		}

		/* link is down, remove all addrs and routes */
		__ni_system_interface_flush_addrs(NULL, dev);
		__ni_system_interface_flush_routes(NULL, dev);
		/* a safeguard in case there are still some */
		ni_addrconf_lease_list_destroy(&dev->leases);
	}

	/* TODO: still needed? */
	__ni_global_seqno++;

	return 0;
}

int
__ni_system_interface_flush_addrs(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	ni_address_t *ap;

	 if (!dev || (!nc && !(nc = ni_global_state_handle(0))))
		 return -1;

	 /* TODO: ni_rtnl_query_addr_info + del without to parse */
	__ni_system_refresh_interface_addrs(nc, dev);
	for (ap = dev->addrs; ap; ap = ap->next) {
		__ni_rtnl_send_deladdr(dev, ap);
	}
	__ni_system_refresh_interface_addrs(nc, dev);
	return dev->addrs == NULL ? 0 : 1;
}

int
__ni_system_interface_flush_routes(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	ni_route_table_t *tab;
	ni_route_t *rp;
	 unsigned int i;

	 if (!dev || (!nc && !(nc = ni_global_state_handle(0))))
		 return -1;

	 /* TODO: ni_rtnl_query_route_info + del without to parse */
	 __ni_system_refresh_interface_routes(nc, dev);
	 for (tab = dev->routes; tab; tab = tab->next) {
		 for (i = 0; i < tab->routes.count; ++i) {
			if (!(rp = tab->routes.data[i]))
				continue;
			__ni_rtnl_send_delroute(dev, rp);
		}
	 }
	 __ni_system_refresh_interface_routes(nc, dev);
	 return dev->routes == NULL ? 0 : 1;
}

int
ni_system_interface_link_monitor(ni_netdev_t *dev)
{
	int rv;

	if (dev == NULL)
		return -NI_ERROR_INVALID_ARGS;

	ni_debug_ifconfig("%s(%s)", __func__, dev->name);

	if ((rv = __ni_rtnl_link_up(dev, NULL)) < 0) {
		ni_error("%s: failed to bring up interface (rtnl error)", dev->name);
		return rv;
	}

	if (dev->link.type == NI_IFTYPE_WIRELESS
	 && (rv = ni_wireless_interface_set_scanning(dev, TRUE)) < 0) {
		/* Take it down again? */
		return rv;
	}
	return 0;
}

/*
 * system interface lease updater actions
 */
static int
__ni_addrconf_action_mtu_apply(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);

	__ni_netdev_update_mtu(nc, dev, lease->old, lease);
	/* On failure, error is logged already -- do not abort:
	 *    there is still pmtu done if mtu was smaller,
	 *    not applying jumbo MTU is also not critical.
	 */
	return 0;

}

static int
__ni_addrconf_action_addrs_apply(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	int res;

	if ((res = __ni_netdev_update_addrs(dev, lease->old, lease)) < 0)
		return res;

	return 0;
}

static int
__ni_addrconf_action_addrs_verify_check(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_address_t *ap;

	if (lease->family != AF_INET6)
		return 0;

	/*
	 * returns:
	 *      1 if lease or link-local addresses are still tentative and
	 *      0 they're not tentative any more
	 *     -1 if they're duplicate.
	 */
	for (ap = dev->addrs; ap; ap = ap->next) {
		if (ap->family != AF_INET6)
			continue;

		if (ap->owner == NI_ADDRCONF_NONE) {
			if (!ni_address_list_find(lease->addrs, &ap->local_addr)
			&&  !ni_address_is_linklocal(ap))
				continue;
		} else
		if (ap->owner != lease->type)
			continue;

		if (ni_address_is_duplicate(ap)) {
			ni_warn("%s: lease %s:%s address %s is duplicate",
					dev->name,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_sockaddr_print(&ap->local_addr));
			/*
			 * DHCPv6 monitors dad state and declines automatically
			 */
			if (lease->type != NI_ADDRCONF_DHCP)
				lease->state = NI_ADDRCONF_STATE_REQUESTING;
			else
				lease->state = NI_ADDRCONF_STATE_FAILED;

			return -1;	/* abort */
		} else
		if (ni_address_is_tentative(ap)) {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: lease %s:%s address %s is tentative",
					dev->name,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_sockaddr_print(&ap->local_addr));
			return 1;	/* defer */
		}
	}

	return 0;
}

static int
__ni_addrconf_action_addrs_verify(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	unsigned int loops = 50;
	int res;

	/*
	 * TODO: instead to loop here, return 1 to go into background
	 *       and continue to apply when address update event with
	 *       the final tentative/dadfailed flags arrived.
	 */
	do {
		if ((res = __ni_system_refresh_interface_addrs(nc, dev)) < 0)
			return res;

		if ((res = __ni_addrconf_action_addrs_verify_check(dev, lease)) <= 0)
			return res;

		/* In case the client is configured to ignore link-up
		 * and sets IPs already at device-up [without waiting
		 * for link detection], we detect dadfailed above, but
		 * do not wait util the kernel verified the addresses:
		 * kernel will not even set link local or start dad
		 * without link-up [detected carrier / lower UP] ...
		 */
		if (!ni_netdev_link_is_up(dev))
			break;

		usleep(250000);
	} while (res && loops-- > 0);

	return 0;
}

static int
__ni_addrconf_action_routes_apply(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	int res;

	if ((res = __ni_system_refresh_interface_routes(nc, dev)) < 0)
		return res;

	if ((res = __ni_netdev_update_routes(nc, dev, lease->old, lease)) < 0)
		return res;

	if ((res = __ni_netdev_update_rules(nc, dev, lease->old, lease)) < 0)
		return res;

	if ((res = __ni_system_refresh_interface_routes(nc, dev)) < 0)
		return res;

	return 0;
}

static int
__ni_addrconf_action_system_update(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	lease->update &= ni_config_addrconf_update_mask(lease->type, lease->family);
	ni_system_update_from_lease(lease, dev->link.ifindex, dev->name);
	return 0;
}

static int
__ni_addrconf_action_addrs_remove(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	int res;

	if ((res = __ni_netdev_update_addrs(dev, lease->old, NULL)) < 0)
		return res;

	if ((res = __ni_system_refresh_interface_addrs(nc, dev)) < 0)
		return res;

	return 0;
}

static int
__ni_addrconf_action_routes_remove(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	int res;

	if ((res = __ni_system_refresh_interface_routes(nc, dev)) < 0)
		return res;

	if ((res = __ni_netdev_update_routes(nc, dev, lease->old, NULL)) < 0)
		return res;

	if ((res = __ni_netdev_update_rules(nc, dev, lease->old, NULL)) < 0)
		return res;

	if ((res = __ni_system_refresh_interface_routes(nc, dev)) < 0)
		return res;

	return 0;
}

static int
__ni_addrconf_action_mtu_restore(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);

	__ni_netdev_update_mtu(nc, dev, lease->old, NULL);
	/* On failure, error is logged already -- do not abort:
	 *    there is still pmtu done if mtu was smaller,
	 *    not applying jumbo MTU is also not critical.
	 */
	return 0;

}

typedef struct ni_addrconf_action ni_addrconf_action_t;

struct ni_addrconf_action {
	int		(*func)(ni_netdev_t *dev, ni_addrconf_lease_t *lease);
	const char *	info;
};

struct ni_addrconf_updater {
	/* do we need some data here ? */
	const ni_addrconf_action_t *action;
};


static const ni_addrconf_action_t	__applying_actions[] = {
	{ __ni_addrconf_action_mtu_apply,	"adjusting mtu"		},
	{ __ni_addrconf_action_addrs_apply,	"applying addresses"	},
	{ __ni_addrconf_action_addrs_verify,	"verifying adressses"	},
	{ __ni_addrconf_action_routes_apply,	"applying routes"	},
	{ __ni_addrconf_action_system_update,	"applying system config"},
	{ NULL,	NULL }
};

static const ni_addrconf_action_t	__removing_actions[] = {
	{ __ni_addrconf_action_addrs_remove,	"removing addresses"	},
	{ __ni_addrconf_action_routes_remove,	"removing routes"	},
	{ __ni_addrconf_action_system_update,	"removing system config"},
	{ __ni_addrconf_action_mtu_restore,	"reverting mtu change"	},
	{ NULL,		NULL						}
};

static ni_addrconf_updater_t *
ni_addrconf_updater_new(const ni_addrconf_action_t *action)
{
	ni_addrconf_updater_t *updater;

	updater = xcalloc(1, sizeof(*updater));
	updater->action = action;
	return updater;
}

void
ni_addrconf_updater_free(ni_addrconf_updater_t **updater)
{
	if (updater && *updater) {
		free(*updater);
		*updater = NULL;
	}
}

int
ni_addrconf_updater_execute(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_addrconf_updater_t *updater;
	int res = 0;

	if (!dev || !lease)
		return 0;

	while ((updater = lease->updater) != NULL) {
		if (!updater->action || !updater->action->func) {
			ni_addrconf_updater_free(&lease->updater);
			break;
		}
		/*
		 * res > 1 could be used to defer into bg,
		 * but currently we just wait for addrs
		 * and use success/failure codes only.
		 */
		res = updater->action->func(dev, lease);
		if (updater->action->info) {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
					"%s: %s for %s:%s lease in state %s: %s [%u]",
					dev->name, updater->action->info,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_state_to_name(lease->state),
					(res < 0 ? "failed" : "success"), res);
		}
		if (res)
			break;
		updater->action++;
	}
	return res;
}

/*
 * An address configuration agent sends a lease update.
 */
int
__ni_system_interface_update_lease(ni_netdev_t *dev, ni_addrconf_lease_t **lease_p)
{
	ni_addrconf_lease_t *lease = *lease_p;
	int res;

	ni_debug_ifconfig("%s: received %s:%s lease update in state %s",
			dev->name,
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_type_to_name(lease->type),
			ni_addrconf_state_to_name(lease->state));

	/* Use the existing lease handle to identify those addresses already
	 * owned by this addrconf protocol.
	 * While we're getting the old lease, detach it from the interface
	 * (but don't delete it yet).
	 */
	lease->old = __ni_netdev_find_lease(dev, lease->family, lease->type, 1);
	if (lease->old) {
		ni_addrconf_updater_free(&lease->old->updater);
	}
	if (lease->state == NI_ADDRCONF_STATE_GRANTED) {
		/* lease apply on ifup success/update */
		lease->state = NI_ADDRCONF_STATE_APPLYING;
		ni_netdev_set_lease(dev, lease);
		*lease_p = NULL;

		lease->updater = ni_addrconf_updater_new(__applying_actions);
		res = ni_addrconf_updater_execute(dev, lease);

		/* we do not need the old lease any more */
		if (lease->old) {
			ni_addrconf_lease_free(lease->old);
			lease->old = NULL;
		}
		if (res == 0 && lease->state == NI_ADDRCONF_STATE_APPLYING)
			lease->state = NI_ADDRCONF_STATE_GRANTED;
	} else
	if (lease->state == NI_ADDRCONF_STATE_FAILED) {
		/* lease drop on ifup failure */
		ni_netdev_set_lease(dev, lease);
		*lease_p = NULL;

		/* there is an (empty) old lease in requesting state
		 * or even in granted when e.g. dhcp rebind fails...
		 * if not, we have nothing what we could revert.
		 */
		if (lease->old) {
			lease->updater = ni_addrconf_updater_new(__removing_actions);
			res = ni_addrconf_updater_execute(dev, lease);

			/* we do not need the old lease any more */
			ni_addrconf_lease_free(lease->old);
			lease->old = NULL;
		}
		res = 0; /* any reason to fail? */
		lease->state = NI_ADDRCONF_STATE_FAILED;
	} else {
		/* lease drop on ifdown */
		if (lease->old) {
			lease->updater = ni_addrconf_updater_new(__removing_actions);
			ni_addrconf_updater_execute(dev, lease);
		}
		/*
		 * we were unable to update the system properly -- is there
		 * any reason to fail or to not drop the lease?
		 */
		res = 0;
	}
	/* we do not defer updater into background yet */
	ni_addrconf_updater_free(&lease->updater);

	if (res < 0) {
		ni_error("%s: error updating interface config from %s:%s lease",
				dev->name,
				ni_addrfamily_type_to_name(lease->family),
				ni_addrconf_type_to_name(lease->type));
	}
	return res;
}

/*
 * Delete the given interface
 * ni_system_interface_delete
 */
int
ni_system_interface_delete(ni_netconfig_t *nc, const char *ifname)
{
	ni_netdev_t *dev;

	ni_debug_ifconfig("ni_system_interface_delete(%s)", ifname);

	/* FIXME: perform sanity check on configuration data */

	dev = ni_netdev_by_name(nc, ifname);
	if (dev == NULL) {
		ni_error("cannot delete interface %s - not known", ifname);
		return -1;
	}

	switch (dev->link.type) {
	case NI_IFTYPE_LOOPBACK:
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_WIRELESS:
	case NI_IFTYPE_INFINIBAND:
		ni_error("cannot destroy %s interfaces", ni_linktype_type_to_name(dev->link.type));
		return -1;

	case NI_IFTYPE_INFINIBAND_CHILD:
		if (ni_system_infiniband_child_delete(dev) < 0)
			return -1;
		break;

	case NI_IFTYPE_DUMMY:
	case NI_IFTYPE_VLAN:
	case NI_IFTYPE_MACVLAN:
	case NI_IFTYPE_MACVTAP:
	case NI_IFTYPE_TUN:
	case NI_IFTYPE_TAP:
		if (__ni_rtnl_link_delete(dev)) {
			ni_error("could not destroy %s interface %s",
				ni_linktype_type_to_name(dev->link.type), dev->name);
			return -1;
		}
		break;

	case NI_IFTYPE_BRIDGE:
		if (__ni_brioctl_del_bridge(dev->name) < 0) {
			ni_error("could not destroy bridge interface %s", dev->name);
			return -1;
		}
		break;

	case NI_IFTYPE_BOND:
		if (ni_sysfs_bonding_delete_master(dev->name) < 0) {
			ni_error("could not destroy bonding interface %s", dev->name);
			return -1;
		}
		break;

	default:
		ni_error("%s not implemented for link type %u (%s)",
				__func__, dev->link.type,
				ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	ni_client_state_drop(dev->link.ifindex);
	return 0;
}

/*
 * Create a VLAN interface
 */
int
ni_system_vlan_create(ni_netconfig_t *nc, const ni_netdev_t *cfg,
						ni_netdev_t **dev_ret)
{
	ni_netdev_t *dev;

	if (!nc || !dev_ret || !cfg || !cfg->name || !cfg->vlan
	||  !cfg->link.lowerdev.name || !cfg->link.lowerdev.index)
		return -1;

	*dev_ret = NULL;

	dev = ni_netdev_by_vlan_name_and_tag(nc, cfg->link.lowerdev.name, cfg->vlan->tag);
	if (dev != NULL) {
		/* This is not necessarily an error */

		*dev_ret = dev;
		return -NI_ERROR_DEVICE_EXISTS;
	}

	ni_debug_ifconfig("%s: creating VLAN device", cfg->name);
	if (__ni_rtnl_link_create(nc, cfg)) {
		ni_error("unable to create vlan interface %s", cfg->name);
		return -1;
	}

	return __ni_system_netdev_create(nc, cfg->name, 0, NI_IFTYPE_VLAN, dev_ret);
}

int
ni_system_vlan_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	return __ni_rtnl_link_change(nc, dev, cfg);
}

int
ni_system_macvlan_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	return __ni_rtnl_link_change(nc, dev, cfg);
}

/*
 * Delete a VLAN interface
 */
int
ni_system_vlan_delete(ni_netdev_t *dev)
{
	if (__ni_rtnl_link_delete(dev)) {
		ni_error("could not destroy VLAN interface %s", dev->name);
		return -1;
	}
	return 0;
}

/*
 * Create a macvlan/macvtap interface
 */
int
ni_system_macvlan_create(ni_netconfig_t *nc, const ni_netdev_t *cfg,
						ni_netdev_t **dev_ret)
{
	ni_netdev_t *dev;
	const char *cfg_iftype = NULL;

	if (!nc || !dev_ret || !cfg || !cfg->name || !cfg->macvlan
	||  !cfg->link.lowerdev.name || !cfg->link.lowerdev.index)
		return -1;

	*dev_ret = NULL;

	dev = ni_netdev_by_name(nc, cfg->name);
	if (dev != NULL) {
		const char *dev_iftype = ni_linktype_type_to_name(dev->link.type);
		/* This is not necessarily an error */
		if (dev->link.type == cfg->link.type) {
			ni_debug_ifconfig("A %s interface %s already exists",
					dev_iftype, dev->name);
			*dev_ret = dev;
		} else {
			ni_error("A %s interface with the name %s already exists",
				dev_iftype, dev->name);
		}
		return -NI_ERROR_DEVICE_EXISTS;
	}

	cfg_iftype = ni_linktype_type_to_name(cfg->link.type);
	ni_debug_ifconfig("%s: creating %s interface", cfg->name, cfg_iftype);

	if (__ni_rtnl_link_create(nc, cfg)) {
		ni_error("unable to create %s interface %s",
			cfg_iftype, cfg->name);
		return -1;
	}

	return __ni_system_netdev_create(nc, cfg->name, 0, cfg->link.type, dev_ret);
}

/*
 * Delete a macvlan/macvtap interface
 */
int
ni_system_macvlan_delete(ni_netdev_t *dev)
{
	if (__ni_rtnl_link_delete(dev)) {
		ni_error("could not destroy macvlan interface %s", dev->name);
		return -1;
	}
	return 0;
}

/*
 * Create a dummy interface
 */
int
ni_system_dummy_create(ni_netconfig_t *nc, const ni_netdev_t *cfg,
						ni_netdev_t **dev_ret)
{
	ni_netdev_t *dev;
	int err;

	if (!nc || !dev_ret || !cfg || !cfg->name)
		return -1;

	*dev_ret = NULL;

	dev = ni_netdev_by_name(nc, cfg->name);
	if (dev != NULL) {
		/* This is not necessarily an error */
		if (dev->link.type == NI_IFTYPE_DUMMY) {
			ni_debug_ifconfig("A dummy interface %s already exists",
					dev->name);
			*dev_ret = dev;
		} else {
			ni_error("A %s interface with the name %s already exists",
				ni_linktype_type_to_name(dev->link.type), dev->name);
		}
		return -NI_ERROR_DEVICE_EXISTS;
	}

	if (ni_modprobe(DUMMY_MODULE_NAME, DUMMY_MODULE_OPTS) < 0)
		ni_warn("failed to load %s network driver module", DUMMY_MODULE_NAME);

	ni_debug_ifconfig("%s: creating dummy interface", cfg->name);

	if ((err = __ni_rtnl_link_create(nc, cfg)) && abs(err) != NLE_EXIST) {
		ni_error("unable to create dummy interface %s", cfg->name);
		return err;
	}

	return __ni_system_netdev_create(nc, cfg->name, 0, NI_IFTYPE_DUMMY, dev_ret);
}

int
ni_system_dummy_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	return __ni_rtnl_link_change(nc, dev, cfg);
}

/*
 * Delete a dummy interface
 */
int
ni_system_dummy_delete(ni_netdev_t *dev)
{
	if (__ni_rtnl_link_delete(dev)) {
		ni_error("could not destroy dummy interface %s", dev->name);
		return -1;
	}
	return 0;
}


/*
 * Setup infiniband interface
 */
int
__ni_system_infiniband_setup(const char *ifname, unsigned int mode, unsigned int umcast)
{
	const char *mstr = ni_infiniband_get_mode_name(mode);
	int ret = 0;

	if (mstr &&
	    ni_sysfs_netif_put_string(ifname, "mode", mstr) < 0) {
		ni_error("%s: Cannot set infiniband IPoIB connection-mode '%s'",
			ifname, mstr);
		ret = -1;
	}

	if ((umcast == 0 || umcast == 1) &&
	    ni_sysfs_netif_put_uint(ifname, "umcast", umcast) < 0) {
		ni_error("%s: Cannot set infiniband IPoIB user-multicast '%s' (%u)",
			ifname, ni_infiniband_get_umcast_name(umcast), umcast);
		ret = -1;
	}

	return ret;
}

int
ni_system_infiniband_setup(ni_netconfig_t *nc, ni_netdev_t *dev,
				const ni_netdev_t *cfg)
{
	ni_infiniband_t *ib;

	if (!cfg || !(ib = cfg->infiniband)) {
		ni_error("Cannot setup infiniband interface without config");
		return -1;
	}
	if (!dev || !dev->name) {
		ni_error("Cannot setup infiniband interface without name");
		return -1;
	}
	if (dev->link.type != NI_IFTYPE_INFINIBAND &&
	    dev->link.type != NI_IFTYPE_INFINIBAND_CHILD) {
		ni_error("%s: %s is not infiniband interface", __func__, dev->name);
		return -1;
	}

	return __ni_system_infiniband_setup(dev->name, ib->mode, ib->umcast);
}

/*
 * Create infinband child interface
 */
int
ni_system_infiniband_child_create(ni_netconfig_t *nc,
		const ni_netdev_t *cfg, ni_netdev_t **dev_ret)
{
	ni_infiniband_t *ib;
	unsigned int i, success = 0;
	char *tmpname = NULL;

	if (!cfg || ni_string_empty(cfg->name) || !(ib = cfg->infiniband)) {
		ni_error("Cannot create infiniband child interface without config");
		return -1;
	}
	if (ni_string_empty(cfg->link.lowerdev.name)) {
		ni_error("%s: Invalid parent reference in infiniband child config",
			cfg->name);
		return -1;
	}

	if (!ni_string_printf(&tmpname, "%s.%04x", cfg->link.lowerdev.name, ib->pkey)) {
		ni_error("%s: Unable to construct temporary interface name", cfg->name);
		return -1;
	}

	if (ni_sysfs_netif_printf(cfg->link.lowerdev.name, "create_child", "0x%04x", ib->pkey) < 0) {
		ni_error("%s: Cannot create infiniband child interface", cfg->name);
		ni_string_free(&tmpname);
		return -1;
	}

	/* TODO: Avoid to wait for interface to appear ...
	 *       but we need it for object path in factory.
	 */
	for (i = 0; i < 400; ++i) {
		if (!ni_netdev_name_to_index(tmpname))
			usleep(25000);
		success = 1;
		break;
	}
	if (!success) {
		ni_error("%s: Infiniband child %s did not appear after 10 sec",
			cfg->name, tmpname);
		ni_string_free(&tmpname);
		return -1;
	} else
	/* rename just returns when the name equals */
	if (__ni_netdev_rename(tmpname, cfg->name) < 0) {
		/* error reported */
		ni_string_free(&tmpname);
		return -1;
	}
	ni_string_free(&tmpname);

	ni_debug_ifconfig("%s: infiniband child interface created", cfg->name);

	if (__ni_system_infiniband_setup(cfg->name, ib->mode, ib->umcast) < 0)
		return -1; /* error reported */

	return __ni_system_netdev_create(nc, cfg->name, 0, NI_IFTYPE_INFINIBAND_CHILD, dev_ret);
}

/*
 * Delete infinband child interface
 */
int
ni_system_infiniband_child_delete(ni_netdev_t *dev)
{
	ni_infiniband_t *ib = dev ? dev->infiniband : NULL;

	if (!ib || !dev->link.lowerdev.name || dev->link.type != NI_IFTYPE_INFINIBAND_CHILD) {
		ni_error("Cannot destroy infiniband child interface without parent and key name");
		return -1;
	}

	if (ni_sysfs_netif_printf(dev->link.lowerdev.name, "delete_child", "0x%04x", ib->pkey) < 0) {
		ni_error("%s: Cannot destroy infiniband child interface (parent %s, key %04x)",
			dev->name, dev->link.lowerdev.name, ib->pkey);
		return -1;
	}
	return 0;
}


/*
 * Create a bridge interface
 */
int
ni_system_bridge_create(ni_netconfig_t *nc, const char *ifname,
			const ni_bridge_t *cfg_bridge, ni_netdev_t **dev_ret)
{
	ni_netdev_t *dev;

	*dev_ret = NULL;

	if ((dev = ni_netdev_by_name(nc, ifname))) {
		*dev_ret = dev;
		return -NI_ERROR_DEVICE_EXISTS;
	}

	ni_debug_ifconfig("%s: creating bridge interface", ifname);
	if (__ni_brioctl_add_bridge(ifname) < 0) {
		ni_error("__ni_brioctl_add_bridge(%s) failed", ifname);
		return -1;
	}

	return __ni_system_netdev_create(nc, ifname, 0, NI_IFTYPE_BRIDGE, dev_ret);
}

/*
 * Given data provided by the user, update the bridge config
 */
int
ni_system_bridge_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_bridge_t *bcfg /*, ni_bool_t add_only */)
{
#if 0
	unsigned int i;
#endif

	if (dev->link.type != NI_IFTYPE_BRIDGE) {
		ni_error("%s: %s is not a bridge interface", __func__, dev->name);
		return -1;
	}

	if (ni_sysfs_bridge_update_config(dev->name, bcfg) < 0) {
		ni_error("%s: failed to update sysfs attributes for %s", __func__, dev->name);
		return -1;
	}
#if 0
	/* Add ports not yet used in bridge */
	for (i = 0; i < bcfg->ports.count; ++i) {
		ni_bridge_port_t *port = bcfg->ports.data[i];

		if (!port || ni_system_bridge_add_port(nc, dev, port) < 0)
			continue;
	}
#endif
	/* Remove not configured ports */
#if 0	/* FIXME: Disabled for now, it would break vm ports */
	for (i = 0; i < dev->bridge->ports.count; ++i) {
		ni_bridge_port_t *port = dev->bridge->ports.data[i];

		if (port && ni_bridge_port_by_name(bcfg, port->ifname) == NULL) {
			if ((ret = ni_system_bridge_remove_port(nc, dev, port->ifindex)) < 0)
				goto done;
		}
	}
#endif

	return 0;
}

/*
 * Shutdown a bridge interface
 */
int
ni_system_bridge_shutdown(ni_netdev_t *dev)
{
	ni_bridge_t *bridge = dev->bridge;
	unsigned int i;

	if (!bridge)
		return -1;

	for (i = 0; i < bridge->ports.count; ++i) {
		ni_bridge_port_t *port = bridge->ports.data[i];
		if (ni_system_bridge_remove_port(dev, port->ifindex) < 0)
			continue;
	}

	return 0;
}

/*
 * Delete a bridge interface
 */
int
ni_system_bridge_delete(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	if (__ni_brioctl_del_bridge(dev->name) < 0) {
		ni_error("could not destroy bridge interface %s", dev->name);
		return -1;
	}
	return 0;
}

/*
 * Add a port to a bridge interface
 */
int
ni_system_bridge_add_port(ni_netconfig_t *nc, ni_netdev_t *brdev, const ni_bridge_port_t *port)
{
	ni_bridge_t *bridge = ni_netdev_get_bridge(brdev);
	ni_netdev_t *pif = NULL;
	ni_bridge_port_t *new_port;
	int rv;

	if (port->ifindex)
		pif = ni_netdev_by_index(nc, port->ifindex);
	else if (port->ifname)
		pif = ni_netdev_by_name(nc, port->ifname);

	if (pif == NULL) {
		ni_error("%s: cannot add port - interface not known",
			brdev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}
	if (!ni_netdev_device_is_ready(pif)) {
		ni_error("%s: cannot add port %s - interface is not ready",
			brdev->name, pif->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}
	if (pif->link.ifindex == 0) {
		ni_error("%s: cannot add port - %s has no ifindex?!",
			brdev->name, pif->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	/* This should be a more elaborate check - neither device can be an ancestor of
	 * the other, or we create a loop.
	 */
	if (pif == brdev) {
		ni_error("%s: cannot add interface as its own bridge port",
			brdev->name);
		return -NI_ERROR_DEVICE_BAD_HIERARCHY;
	}

	if (pif->link.masterdev.index &&
			pif->link.masterdev.index != brdev->link.ifindex) {
		ni_error("%s: interface %s already has a master",
			brdev->name, pif->name);
		return -NI_ERROR_DEVICE_BAD_HIERARCHY;
	}

	if (pif->link.masterdev.index &&
			pif->link.masterdev.index == brdev->link.ifindex) {
		/* already a port of this bridge -- make sure the device is up */
		if (!ni_netdev_device_is_up(pif) && __ni_rtnl_link_up(pif, NULL) < 0) {
			ni_warn("%s: Cannot set up link on bridge port %s",
				brdev->name, pif->name);
		}
		return 0; /* part of the bridge and hopefully up now */
	}

	if (__ni_rtnl_link_add_port_up(pif, brdev->name, brdev->link.ifindex) == 0) {
		ni_netdev_ref_set(&pif->link.masterdev, brdev->name,
				brdev->link.ifindex);
		return 0;
	}

	if (!ni_netdev_device_is_up(pif) && __ni_rtnl_link_up(pif, NULL) < 0) {
		ni_warn("%s: Cannot set up link on bridge port %s",
			brdev->name, pif->name);
	}

	if ((rv = __ni_brioctl_add_port(brdev->name, pif->link.ifindex)) < 0) {
		ni_error("%s: cannot add port %s: %s", brdev->name, pif->name,
				ni_strerror(rv));
		return rv;
	}

	/* Now configure the newly added port */
	if ((rv = ni_sysfs_bridge_port_update_config(pif->name, port)) < 0) {
		ni_error("%s: failed to configure port %s: %s",
			brdev->name, pif->name, ni_strerror(rv));
		return rv;
	}

	/* when this fails, next event will update/add it... */
	new_port = ni_bridge_port_clone(port);
	new_port->ifindex = pif->link.ifindex;
	if (!ni_string_eq(new_port->ifname, pif->name))
		ni_string_dup(&new_port->ifname, pif->name);

	if (!ni_bridge_add_port(bridge, new_port))
		ni_bridge_port_free(new_port);
	return 0;
}

/*
 * Remove a port from a bridge interface
 * ni_system_bridge_remove_port
 */
int
ni_system_bridge_remove_port(ni_netdev_t *dev, unsigned int port_ifindex)
{
	ni_bridge_t *bridge = ni_netdev_get_bridge(dev);
	int rv;

	if (port_ifindex == 0) {
		ni_error("%s: cannot remove port: bad ifindex", dev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	if ((rv = __ni_brioctl_del_port(dev->name, port_ifindex)) < 0) {
		ni_error("%s: cannot remove port: %s", dev->name, ni_strerror(rv));
		return rv;
	}

	ni_bridge_del_port_ifindex(bridge, port_ifindex);
	return 0;
}

/*
 * OVS bridge system operations
 */
int
ni_system_ovs_bridge_create(ni_netconfig_t *nc, const ni_netdev_t *cfg, ni_netdev_t **dev_ret)
{
	ni_netdev_t *dev;
	unsigned int i;
	int ret;

	if (!cfg || cfg->link.type != NI_IFTYPE_OVS_BRIDGE || !cfg->name)
		return -1;

	*dev_ret = NULL;
	if ((dev = ni_netdev_by_name(nc, cfg->name))) {
		if (dev->link.type != NI_IFTYPE_OVS_BRIDGE) {
			*dev_ret = dev;
			return -NI_ERROR_DEVICE_EXISTS;
		}
	}

	if (ni_ovs_vsctl_bridge_add(cfg, TRUE))
		return -1;

	/* Wait for sysfs to appear */
	for (i = 0; i < 400; ++i) {
		if (ni_netdev_name_to_index(cfg->name))
			break;
		usleep(25000);
	}

	ret = __ni_system_netdev_create(nc, cfg->name, dev ? dev->link.ifindex : 0,
					NI_IFTYPE_OVS_BRIDGE, dev_ret);
	return ret;
}

int
ni_system_ovs_bridge_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	if (!dev || dev->link.type != NI_IFTYPE_OVS_BRIDGE)
		return -1;
	return 0; /* currently nothing */
}

int
ni_system_ovs_bridge_shutdown(ni_netdev_t *dev)
{
	if (!dev || dev->link.type != NI_IFTYPE_OVS_BRIDGE)
		return -1;
	return 0; /* currently nothing */
}

int
ni_system_ovs_bridge_delete(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	if (!dev || dev->link.type != NI_IFTYPE_OVS_BRIDGE)
		return -1;

	return ni_ovs_vsctl_bridge_del(dev->name) ? -1 : 0;
}

/*
 * Create a bonding device
 */
static int
ni_system_bond_create_sysfs(ni_netconfig_t *nc, const ni_netdev_t *cfg, ni_netdev_t **dev_ret)
{
	int ret;

	if (!ni_sysfs_bonding_available()) {
		unsigned int i, success = 0;

		/* Load the bonding module */
		if (ni_bonding_load(NULL) < 0)
			return -1;

		/* FIXME: Wait for bonding_masters to appear */
		for (i = 0; i < 400; ++i) {
			if ((success = ni_sysfs_bonding_available()) != 0)
				break;
			usleep(25000);
		}
		if (!success) {
			ni_error("unable to load bonding module - couldn't find bonding_masters");
			return -1;
		}
	}

	if (!ni_sysfs_bonding_is_master(cfg->name)) {
		int success = 0;

		ni_debug_ifconfig("%s: creating bond master", cfg->name);
		if (ni_sysfs_bonding_add_master(cfg->name) >= 0) {
			unsigned int i;

			/* Wait for bonding_masters to appear */
			for (i = 0; i < 400; ++i) {
				if ((success = ni_sysfs_bonding_is_master(cfg->name)) != 0)
					break;
				usleep(25000);
			}
		}

		if (!success) {
			ni_error("unable to create bonding device %s", cfg->name);
			return -1;
		}
	}

	ret = __ni_system_netdev_create(nc, cfg->name, 0, NI_IFTYPE_BOND, dev_ret);
	if (ret == 0 /* && cfg->bonding */)
		ni_system_bond_setup(nc, *dev_ret, cfg);

	return ret;
}

int
ni_system_bond_create_netlink(ni_netconfig_t *nc, const ni_netdev_t *cfg, ni_netdev_t **dev_ret)
{
	int ret;

	/* Load the bonding module */
	if (ni_bonding_load(NULL) < 0)
		return -1;

	if ((ret = __ni_rtnl_link_create(nc, cfg)))
		return -NI_ERROR_CANNOT_CONFIGURE_DEVICE;

	return __ni_system_netdev_create(nc, cfg->name, 0, NI_IFTYPE_BOND, dev_ret);
}

int
ni_system_bond_create(ni_netconfig_t *nc, const ni_netdev_t *cfg, ni_netdev_t **dev_ret)
{
	const char *complaint;

	if (!nc || !dev_ret || !cfg || cfg->link.type != NI_IFTYPE_BOND || ni_string_empty(cfg->name))
		return -NI_ERROR_INVALID_ARGS;

	complaint = ni_bonding_validate(cfg->bonding);
	if (complaint != NULL) {
		ni_error("%s: cannot set up bonding device: %s", cfg->name, complaint);
		return -NI_ERROR_INVALID_ARGS;
	}

	switch (ni_config_bonding_ctl()) {
	case NI_CONFIG_BONDING_CTL_SYSFS:
		return ni_system_bond_create_sysfs(nc, cfg, dev_ret);

	case NI_CONFIG_BONDING_CTL_NETLINK:
	default:
		return ni_system_bond_create_netlink(nc, cfg, dev_ret);
	}
}

/*
 * Set up a bonding device
 */
static int
ni_system_bond_setup_sysfs(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	ni_bonding_t *bond;
	ni_bool_t is_up;

	if ((bond = ni_netdev_get_bonding(dev)) == NULL) {
		ni_error("%s: not a bonding interface ", dev->name);
		return -1;
	}

	is_up = ni_netdev_device_is_up(dev);
	ni_bonding_parse_sysfs_attrs(dev->name, bond);

	ni_debug_ifconfig("%s: configuring bonding device (stage 0.%u.%u)",
			dev->name, is_up, bond->slaves.count);
	if (ni_bonding_write_sysfs_attrs(dev->name, cfg->bonding, bond,
					is_up, bond->slaves.count > 0) < 0) {
		ni_error("%s: cannot configure bonding device (stage 0.%u.%u)",
			dev->name, is_up, bond->slaves.count);
		return -1;
	}
	ni_bonding_parse_sysfs_attrs(dev->name, bond);

	return 0;
}

int
ni_system_bond_setup_netlink(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	int ret;

	if ((ret = __ni_rtnl_link_change(nc, dev, cfg)) < 0) {
		/*
		 * kernel reports -errno, libnl translates them:
		 *
		 * errno	 libnl			reason
		 * [13]EACCES    [27]NLE_NOACCESS	option not supported in mode
		 *               [01]NLE_FAILURE	(EACCESS mapped to FAILURE?)
		 * [39]ENOTEMPTY [01]NLE_FAILURE	bond with slaves, cannot set
		 * [16]EBUSY	 [25]NLE_BUSY		bond is up, cannot set
		 * [22]EINVAL	 [07]NLE_INVAL		unknown option, other errors
		 *
		 * we try to not run in all the constraints ...
		 */
		(void)__ni_system_refresh_interface(nc, dev);
		return -NI_ERROR_CANNOT_CONFIGURE_DEVICE;
	}

	return 0;
}

int
ni_system_bond_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	const char *complaint;

	if (!nc || !dev || !cfg || cfg->link.type != NI_IFTYPE_BOND)
		return -NI_ERROR_INVALID_ARGS;

	complaint = ni_bonding_validate(cfg->bonding);
	if (complaint != NULL) {
		ni_error("%s: cannot set up bonding device: %s", dev->name, complaint);
		return -NI_ERROR_INVALID_ARGS;
	}

	switch (ni_config_bonding_ctl()) {
	case NI_CONFIG_BONDING_CTL_SYSFS:
		return ni_system_bond_setup_sysfs(nc, dev, cfg);

	case NI_CONFIG_BONDING_CTL_NETLINK:
	default:
		return ni_system_bond_setup_netlink(nc, dev, cfg);
	}
}

/*
 * Shutdown a bonding device
 */
int
ni_system_bond_shutdown(ni_netdev_t *dev)
{
	ni_string_array_t list = NI_STRING_ARRAY_INIT;
	unsigned int i;
	int rv = 0;

	if ((rv = ni_sysfs_bonding_get_slaves(dev->name, &list)))
		goto cleanup;

	for (i = 0; i < list.count; i++) {
		if ((rv = ni_sysfs_bonding_delete_slave(dev->name, list.data[i])))
			goto cleanup;
	}

cleanup:
	ni_string_array_destroy(&list);
	return rv;
}

/*
 * Delete a bonding device
 */
int
ni_system_bond_delete(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	if (ni_sysfs_bonding_delete_master(dev->name) < 0) {
		ni_error("could not destroy bonding interface %s", dev->name);
		return -1;
	}
	return 0;
}

/*
 * Add slave to a bond
 */
int
ni_system_bond_add_slave(ni_netconfig_t *nc, ni_netdev_t *dev, unsigned int slave_idx)
{
	ni_string_array_t slave_names = NI_STRING_ARRAY_INIT;
	ni_bonding_t *bond = dev->bonding;
	ni_netdev_t *slave_dev;

	if (bond == NULL) {
		ni_error("%s: %s is not a bonding device", __func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_COMPATIBLE;
	}

	slave_dev = ni_netdev_by_index(nc, slave_idx);
	if (slave_dev == NULL) {
		ni_error("%s: trying to add unknown interface to bond %s",
			__func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	if (!ni_netdev_device_is_ready(slave_dev)) {
		ni_error("%s: trying to enslave %s, which is not ready",
			dev->name, slave_dev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	if (ni_netdev_network_is_up(slave_dev)) {
		ni_error("%s: trying to enslave %s, which is in use",
			dev->name, slave_dev->name);
		return -NI_ERROR_DEVICE_NOT_DOWN;
	}

	/* Silently ignore duplicate slave attach */
	if (ni_bonding_has_slave(bond, slave_dev->name))
		return 0;

	ni_bonding_get_slave_names(bond, &slave_names);
	ni_string_array_append(&slave_names, slave_dev->name);
	if (ni_sysfs_bonding_set_list_attr(dev->name, "slaves", &slave_names) < 0) {
		ni_string_array_destroy(&slave_names);
		ni_error("%s: could not update list of slaves", dev->name);
		return -NI_ERROR_PERMISSION_DENIED;
	}
	ni_string_array_destroy(&slave_names);
	ni_bonding_add_slave(bond, slave_dev->name);

	return 0;
}

/*
 * Remove a slave from a bond
 */
int
ni_system_bond_remove_slave(ni_netconfig_t *nc, ni_netdev_t *dev, unsigned int slave_idx)
{
	ni_string_array_t slave_names = NI_STRING_ARRAY_INIT;
	ni_bonding_t *bond = dev->bonding;
	ni_netdev_t *slave_dev;
	unsigned int idx;

	if (bond == NULL) {
		ni_error("%s: %s is not a bonding device", __func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_COMPATIBLE;
	}

	slave_dev = ni_netdev_by_index(nc, slave_idx);
	if (slave_dev == NULL) {
		ni_error("%s: trying to add unknown interface to bond %s", __func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	/* Silently ignore duplicate slave removal */
	if ((idx = ni_bonding_slave_array_index_by_ifindex(&bond->slaves, slave_idx)) == -1U) {
		if ((idx = ni_bonding_slave_array_index_by_ifname( &bond->slaves, slave_dev->name)) == -1U)
			return 0;
	}

	ni_bonding_slave_array_delete(&bond->slaves, idx);
	ni_bonding_get_slave_names(bond, &slave_names);
	if (ni_sysfs_bonding_set_list_attr(dev->name, "slaves", &slave_names) < 0) {
		ni_string_array_destroy(&slave_names);
		ni_error("%s: could not update list of slaves", dev->name);
		return -NI_ERROR_PERMISSION_DENIED;
	}
	ni_string_array_destroy(&slave_names);

	return 0;
}

/*
 * Create a team device
 */
int
ni_system_team_create(ni_netconfig_t *nc, const ni_netdev_t *cfg, ni_netdev_t **dev_ret)
{
	unsigned int i;
	int ret;

	if (!cfg || cfg->link.type != NI_IFTYPE_TEAM || !cfg->team || !ni_config_teamd_enabled())
		return -1;

	if (ni_teamd_service_start(cfg))
		return -1;

	/* Wait for sysfs to appear */
	for (i = 0; i < 400; ++i) {
		if (ni_netdev_name_to_index(cfg->name))
			break;
		usleep(25000);
	}

	ret = __ni_system_netdev_create(nc, cfg->name, 0, NI_IFTYPE_TEAM, dev_ret);
	if (dev_ret && *dev_ret) {
		ni_teamd_discover(*dev_ret);
	}
	return ret;
}

int
ni_system_team_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	ni_team_t *team = dev ? ni_netdev_get_team(dev) : NULL;

	if (team && cfg && cfg->link.type == NI_IFTYPE_TEAM && ni_config_teamd_enabled()) {
		/* does teamd not support reload / changes of the team device config
		 * so we can't reconfigure it at all and just discover the state. */
		ni_teamd_discover(dev);
		return 0;
	}

	return -1;
}

int
ni_system_team_shutdown(ni_netdev_t *dev)
{
	if (!dev || dev->link.type != NI_IFTYPE_TEAM)
		return -1;

	return 0;
}

int
ni_system_team_delete(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	if (!dev || dev->link.type != NI_IFTYPE_TEAM)
		return -1;

	return ni_teamd_service_stop(dev->name) ? -1 : 0;
}

/*
 * Set up an ethernet device
 */
int
ni_system_ethernet_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	if (!dev || !cfg || !cfg->ethernet)
		return -1;

	__ni_system_ethernet_update(dev, cfg->ethernet);
	return 0;
}

/*
 * Create a tun/tap interface
 */
int
ni_system_tuntap_create(ni_netconfig_t *nc, const ni_netdev_t *cfg, ni_netdev_t **dev_ret)
{
	const char *iftype_name;
	ni_netdev_t *dev;
	ni_assert(cfg && dev_ret);

	*dev_ret = NULL;
	iftype_name = ni_linktype_type_to_name(cfg->link.type);

	dev = ni_netdev_by_name(nc, cfg->name);
	if (dev != NULL) {
		/* This is not necessarily an error */
		if (dev->link.type == cfg->link.type) {
			ni_debug_ifconfig("A %s interface %s already exists", iftype_name,
				dev->name);
			*dev_ret = dev;
		} else {
			ni_error("A %s interface with the name %s already exists",
				ni_linktype_type_to_name(dev->link.type), dev->name);
		}
		return -NI_ERROR_DEVICE_EXISTS;
	}

	ni_debug_ifconfig("%s: creating %s interface", iftype_name, cfg->name);
	if (__ni_tuntap_create(cfg) < 0) {
		ni_error("__ni_tuntap_create(%s) failed for %s interface ", cfg->name,
			iftype_name);
		return -1;
	}

	return __ni_system_netdev_create(nc, cfg->name, 0, cfg->link.type, dev_ret);
}

int
ni_system_tap_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	return __ni_rtnl_link_change(nc, dev, cfg);
}

/*
 * Delete a tun/tap interface
 */
int
ni_system_tuntap_delete(ni_netdev_t *dev)
{
	if (__ni_rtnl_link_delete(dev)) {
		ni_error("could not destroy tun/tap interface %s", dev->name);
		return -1;
	}
	return 0;
}

/*
 * Create a ppp device
 */
int
ni_system_ppp_create(ni_netconfig_t *nc, const ni_netdev_t *cfg, ni_netdev_t **dev_ret)
{
	unsigned int i;
	int ret;

	if (!cfg || cfg->link.type != NI_IFTYPE_PPP || !cfg->ppp)
		return -1;

	if (ni_pppd_service_start(cfg))
		return -1;

	/* Wait for sysfs to appear */
	for (i = 0; i < 400; ++i) {
		if (ni_netdev_name_to_index(cfg->name))
			break;
		usleep(25000);
	}

	ret = __ni_system_netdev_create(nc, cfg->name, 0, NI_IFTYPE_PPP, dev_ret);
	if (ret < 0)
		ni_pppd_config_file_remove(cfg->name);
	else if (dev_ret && *dev_ret) {
		ni_pppd_discover(*dev_ret, nc);
	}

	return ret;
}

int
ni_system_ppp_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	ni_ppp_t *ppp = dev ? ni_netdev_get_ppp(dev) : NULL;

	if (ppp && cfg && cfg->link.type == NI_IFTYPE_PPP) {
		ni_pppd_discover(dev, nc);
		return 0;
	}

	return -1;
}

int
ni_system_ppp_shutdown(ni_netdev_t *dev)
{
	if (!dev || dev->link.type != NI_IFTYPE_PPP)
		return -1;

	return 0;
}

/*
 * Delete a ppp interface
 */
int
ni_system_ppp_delete(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	if (!dev || dev->link.type != NI_IFTYPE_PPP)
		return -1;

	return ni_pppd_service_stop(dev->name) ? -1 : 0;
}

static int
__ni_system_tunnel_load_modules(unsigned int type)
{
	int mod_load_ret = 0;

	/* Modules may need to be loaded (if support not compiled directly into
	 * the kernel) in order to first bring up base devices.
	 * If support compiled in kernel, modprobe should not fail
	 * either, simply not load the module. -1 return code is
	 * thus valid.
	 */
	switch (type) {
	case NI_IFTYPE_GRE:
		if (ni_modprobe(GRE_TUNNEL_MODULE_NAME, NULL) < 0) {
			ni_error("failed to load %s module",
				GRE_TUNNEL_MODULE_NAME);
			mod_load_ret = -1;
		}
		break;

	case NI_IFTYPE_SIT:
		if (ni_modprobe(TUNNEL4_MODULE_NAME, NULL) < 0) {
			ni_error("failed to load %s module",
				TUNNEL4_MODULE_NAME);
			mod_load_ret = -1;
		}
		if (ni_modprobe(SIT_TUNNEL_MODULE_NAME, NULL) < 0) {
			ni_error("failed to load %s module",
				SIT_TUNNEL_MODULE_NAME);
			mod_load_ret = -1;
		}
		break;

	case NI_IFTYPE_IPIP:
		if (ni_modprobe(TUNNEL4_MODULE_NAME, NULL) < 0) {
			ni_error("failed to load %s module",
				TUNNEL4_MODULE_NAME);
			mod_load_ret = -1;
		}
		if (ni_modprobe(IPIP_TUNNEL_MODULE_NAME, NULL) < 0) {
			ni_error("failed to load %s module",
				IPIP_TUNNEL_MODULE_NAME);
			mod_load_ret = -1;
		}
		break;

	default:
		break;
	}

	return mod_load_ret;
}

/*
 * Create a sit/ipip/gre tunnel
 */
int
ni_system_tunnel_create(ni_netconfig_t *nc, const ni_netdev_t *cfg,
		ni_netdev_t **dev_ret, unsigned int type)
{
	ni_netdev_t *dev;

	if (!nc || !dev_ret || !cfg || !cfg->name)
		return -1;

	*dev_ret = NULL;

	dev = ni_netdev_by_name(nc, cfg->name);
	if (dev != NULL) {
		/* This is not necessarily an error */
		if (dev->link.type == type) {
			ni_debug_ifconfig("A %s tunnel %s already exists",
					ni_linktype_type_to_name(type),
					dev->name);
			*dev_ret = dev;
		} else {
			ni_error("A %s interface with the name %s already exists",
				ni_linktype_type_to_name(dev->link.type), dev->name);
		}
		return -NI_ERROR_DEVICE_EXISTS;
	}

	ni_debug_ifconfig("%s: creating %s tunnel", cfg->name,
			ni_linktype_type_to_name(type));

	if (__ni_system_tunnel_load_modules(type) < 0) {
		ni_error("aborting %s tunnel creation",
			ni_linktype_type_to_name(type));
		return -1;
	}

	if (__ni_rtnl_link_create(nc, cfg)) {
		ni_error("unable to create %s tunnel %s", ni_linktype_type_to_name(type),
			cfg->name);
		return -1;
	}

	return __ni_system_netdev_create(nc, cfg->name, 0, cfg->link.type, dev_ret);
}

/*
 * Change a sit/ipip/gre tunnel
 */
int
ni_system_tunnel_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	return __ni_rtnl_link_change(nc, dev, cfg);
}

/*
 * Delete a sit/ipip/gre tunnel
 */
int
ni_system_tunnel_delete(ni_netdev_t *dev, unsigned int type)
{
	if (__ni_rtnl_link_delete(dev)) {
		ni_error("could not destroy %s tunnel %s",
			ni_linktype_type_to_name(type), dev->name);
		return -1;
	}

	return 0;
}

/*
 * Update the IPv4 sysctl settings for the given interface
 */
int
ni_system_ipv4_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_ipv4_devconf_t *ipv4)
{
	return ni_system_ipv4_devinfo_set(dev, ipv4);
}

/*
 * Update the IPv6 sysctl settings for the given interface
 */
int
ni_system_ipv6_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_ipv6_devconf_t *ipv6)
{
	int brought_up = 0;
	int rv = -1;

	/* You can confuse the kernel IPv6 code to a degree that it will
	 * remove /proc/sys/ipv6/conf/<ifname> completely. dhcpcd in particular
	 * seems rather good at that. 
	 * The only way to recover from that is by upping the interface briefly.
	 */
	if (ni_ipv6_supported() && !ni_sysctl_ipv6_ifconfig_is_present(dev->name)) {
		if (__ni_rtnl_link_up(dev, NULL) >= 0) {
			unsigned int count = 100;

			while (count-- && !ni_sysctl_ipv6_ifconfig_is_present(dev->name))
				usleep(100000);
			brought_up = 1;
		}
	}

	rv = ni_system_ipv6_devinfo_set(dev, ipv6);

	if (brought_up)
		__ni_rtnl_link_down(dev);
	return rv;
}

int
ni_system_hwaddr_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_hwaddr_t *hwaddr)
{
	(void)nc;

	if (hwaddr->len) {
		if (hwaddr->type != dev->link.hwaddr.type) {
			ni_debug_ifconfig("%s: hwaddr type %s does not match device type %s",
				dev->name,
				ni_arphrd_type_to_name(hwaddr->type),
				ni_arphrd_type_to_name(dev->link.hwaddr.type));
			return -1;
		}

		if (dev->link.hwaddr.len != hwaddr->len) {
			ni_debug_ifconfig("%s: hwaddr len %u does not match device len %u",
					dev->name, hwaddr->len, dev->link.hwaddr.len);
			return -1;
		}

		if (ni_link_address_equal(hwaddr, &dev->link.hwaddr))
			return 0;

		return __ni_rtnl_link_change_hwaddr(dev, hwaddr);
	}
	return 1;
}

int
ni_system_mtu_change(ni_netconfig_t *nc, ni_netdev_t *dev, unsigned int mtu)
{
	(void)nc;

	if (mtu) {
		if (mtu == dev->link.mtu)
			return 0;

		return __ni_rtnl_link_change_mtu(dev, mtu);
	}
	return 1;
}

/*
 * __ni_rtnl_link_create/change utilities
 */
static int
__ni_rtnl_link_put_ifname(struct nl_msg *msg,	const char *ifname)
{
	size_t len;

	len = ni_string_len(ifname) + 1;
	if (len == 1 || len > IFNAMSIZ) {
		ni_error("\"%s\" is not a valid device name", ifname);
		return -1;
	}

	NLA_PUT_STRING(msg, IFLA_IFNAME, ifname);
	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_hwaddr(struct nl_msg *msg,	const ni_hwaddr_t *hwaddr)
{
	if (hwaddr->len) {
		NLA_PUT(msg, IFLA_ADDRESS, hwaddr->len, hwaddr->data);
	}
	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_mtu(struct nl_msg *msg,	unsigned int mtu)
{
	if (mtu) {
		NLA_PUT_U32(msg, IFLA_MTU, mtu);
	}
	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_bond_arp_ip_targets(struct nl_msg *msg, const char *ifname,
				const char *name, unsigned int attr,
				const ni_string_array_t *conf, ni_string_array_t *bond)
{
	struct nlattr *arp_ip_tgts;
	unsigned int i, todo, done;
	unsigned int limit = BOND_MAX_ARP_TARGETS;
	const char *target;
	ni_sockaddr_t addr;

	if (ni_string_array_eq(conf, bond)) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: skip attr %s=[%s]",
				ifname, name, conf->count ? "..." : "");
		return 1;
	}

	if (!(arp_ip_tgts = nla_nest_start(msg, attr)))
		return -1;

	todo = conf->count < limit ? conf->count : limit;
	for (done = i = 0; i < todo; ++i) {
		target = conf->data[i];

		if (ni_sockaddr_parse(&addr, target, AF_INET) < 0)
			continue;

		if (nla_put_u32(msg, done, addr.sin.sin_addr.s_addr) != 0)
			continue;

		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
			"%s: set  attr %s[%u]=%s", ifname, name, done, target);
		done++;
	}
	nla_nest_end(msg, arp_ip_tgts);

	if (done == 0) {
		/* a reset with an empty nested attr data array
		 * on arp to mii monitoring reconfigure request */
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: set  attr %s=[]", ifname, name);
	}

	return 0;
}

static int
__ni_rtnl_link_put_bond_opt_debug(const char *ifname, const char *name,
				int ret, unsigned int val, const char *str)
{
	unsigned int level = NI_LOG_DEBUG + ret;

	if (str) {
		ni_debug_verbose(level, NI_TRACE_IFCONFIG, "%s: %s attr %s=%u (%s)",
				ifname, ret ? "skip" : "set ", name, val, str);
	} else {
		ni_debug_verbose(level, NI_TRACE_IFCONFIG, "%s: %s attr %s=%u",
				ifname, ret ? "skip" : "set ", name, val);
	}
	return ret;
}

static int
__ni_rtnl_link_put_bond_opt(ni_netconfig_t *nc,	struct nl_msg *msg, const char *ifname,
				unsigned int attr, const char *name,
				const ni_bonding_t *conf, ni_bonding_t *bond)
{
	unsigned int num_peer_notif;
	ni_netdev_t *slave;
	int ret = 1;

	switch (attr) {
	case IFLA_BOND_MODE:
		if (conf->mode != bond->mode) {
			NLA_PUT_U8 (msg, attr, conf->mode);
			bond->mode = conf->mode;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->mode,
				ni_bonding_mode_type_to_name(conf->mode));

	case IFLA_BOND_MIIMON:
		if (conf->miimon.frequency != bond->miimon.frequency && conf->miimon.frequency) {
			NLA_PUT_U32(msg, attr, conf->miimon.frequency);
			bond->monitoring = NI_BOND_MONITOR_MII;
			bond->miimon.frequency = conf->miimon.frequency;
			bond->arpmon.interval = 0;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->miimon.frequency, NULL);

	case IFLA_BOND_UPDELAY:
		if (conf->miimon.updelay != bond->miimon.updelay &&
		    bond->monitoring == NI_BOND_MONITOR_MII) {
			NLA_PUT_U32(msg, attr, conf->miimon.updelay);
			bond->miimon.updelay = conf->miimon.updelay;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->miimon.updelay, NULL);

	case IFLA_BOND_DOWNDELAY:
		if (conf->miimon.downdelay != bond->miimon.downdelay &&
		    bond->monitoring == NI_BOND_MONITOR_MII) {
			NLA_PUT_U32(msg, attr, conf->miimon.downdelay);
			bond->miimon.downdelay = conf->miimon.downdelay;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->miimon.downdelay, NULL);

	case IFLA_BOND_USE_CARRIER:
		if (conf->miimon.carrier_detect != bond->miimon.carrier_detect &&
		    bond->monitoring == NI_BOND_MONITOR_MII) {
			NLA_PUT_U8 (msg, attr, conf->miimon.carrier_detect);
			bond->miimon.carrier_detect = conf->miimon.carrier_detect;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->miimon.carrier_detect,
				ni_bonding_mii_carrier_detect_name(conf->miimon.carrier_detect));

	case IFLA_BOND_ARP_INTERVAL:
		if (conf->arpmon.interval != bond->arpmon.interval && conf->arpmon.interval) {
			NLA_PUT_U32(msg, attr, conf->arpmon.interval);
			bond->monitoring = NI_BOND_MONITOR_ARP;
			bond->arpmon.interval = conf->arpmon.interval;
			bond->miimon.frequency = 0;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->arpmon.interval, NULL);

	case IFLA_BOND_ARP_VALIDATE:
		if (conf->arpmon.validate != bond->arpmon.validate &&
		    bond->monitoring == NI_BOND_MONITOR_ARP) {
			NLA_PUT_U32(msg, attr, conf->arpmon.validate);
			bond->arpmon.validate = conf->arpmon.validate;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->arpmon.validate,
				ni_bonding_arp_validate_type_to_name(conf->arpmon.validate));

	case IFLA_BOND_ARP_ALL_TARGETS:
		if (conf->arpmon.validate_targets != bond->arpmon.validate_targets &&
		    bond->monitoring == NI_BOND_MONITOR_ARP) {
			NLA_PUT_U32(msg, attr, conf->arpmon.validate_targets);
			bond->arpmon.validate_targets = conf->arpmon.validate_targets;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->arpmon.validate_targets,
				ni_bonding_arp_validate_targets_to_name(conf->arpmon.validate_targets));

	case IFLA_BOND_ARP_IP_TARGET:
		if ((ret = __ni_rtnl_link_put_bond_arp_ip_targets(msg, ifname, name, attr,
					&conf->arpmon.targets, &bond->arpmon.targets)) < 0)
			goto nla_put_failure;
		else if (ret == 0)
			ni_string_array_copy(&bond->arpmon.targets, &conf->arpmon.targets);
		return ret;

	case IFLA_BOND_PRIMARY:
		if (ni_string_empty(conf->primary_slave.name))
			return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret, 0, NULL);

		slave = ni_netdev_by_name(nc, conf->primary_slave.name);
		if (!ni_netdev_device_is_ready(slave)) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: primary slave device %s is not yet ready",
					ifname, conf->primary_slave.name);

			return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
					slave ? slave->link.ifindex : 0,
					conf->primary_slave.name);
		}

		if (slave->link.ifindex && slave->link.ifindex != bond->primary_slave.index) {
			NLA_PUT_U32(msg, attr, slave->link.ifindex);
			ni_netdev_ref_set(&bond->primary_slave, conf->primary_slave.name,
								slave->link.ifindex);
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				slave->link.ifindex, conf->primary_slave.name);

	case IFLA_BOND_PRIMARY_RESELECT:
		if (conf->primary_reselect != bond->primary_reselect) {
			NLA_PUT_U32(msg, attr, conf->primary_reselect);
			bond->primary_reselect = bond->primary_reselect;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->primary_reselect,
				ni_bonding_primary_reselect_name(conf->primary_reselect));

	case IFLA_BOND_ACTIVE_SLAVE:
		if (ni_string_empty(conf->active_slave.name))
			return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret, 0, NULL);

		slave = ni_netdev_by_name(nc, conf->active_slave.name);
		if (!ni_netdev_device_is_ready(slave)) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
						"%s: active slave device %s is not yet ready",
						ifname, conf->active_slave.name);

			return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
					slave ? slave->link.ifindex : 0,
					conf->active_slave.name);
		}

		if (slave->link.ifindex && slave->link.ifindex != bond->active_slave.index) {
			NLA_PUT_U32(msg, attr, slave->link.ifindex);
			ni_netdev_ref_set(&bond->active_slave, conf->active_slave.name,
								slave->link.ifindex);
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				slave->link.ifindex, conf->active_slave.name);

	case IFLA_BOND_FAIL_OVER_MAC:
		if (conf->fail_over_mac != bond->fail_over_mac) {
			NLA_PUT_U8 (msg, attr, conf->fail_over_mac);
			bond->fail_over_mac = conf->fail_over_mac;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->fail_over_mac,
				ni_bonding_fail_over_mac_name(conf->fail_over_mac));

	case IFLA_BOND_XMIT_HASH_POLICY:
		if (conf->xmit_hash_policy != bond->xmit_hash_policy) {
			NLA_PUT_U8 (msg, attr, conf->xmit_hash_policy);
			bond->xmit_hash_policy = conf->xmit_hash_policy;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->xmit_hash_policy,
				ni_bonding_xmit_hash_policy_to_name(conf->xmit_hash_policy));

	case IFLA_BOND_RESEND_IGMP:
		if (conf->resend_igmp != bond->resend_igmp) {
			NLA_PUT_U32(msg, attr, conf->resend_igmp);
			bond->resend_igmp = conf->resend_igmp;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->resend_igmp, NULL);

	case IFLA_BOND_NUM_PEER_NOTIF:
		num_peer_notif = bond->num_unsol_na;
		if (conf->num_unsol_na != bond->num_unsol_na) {
			NLA_PUT_U8 (msg, attr, conf->num_unsol_na);
			num_peer_notif = conf->num_unsol_na;
			bond->num_grat_arp = num_peer_notif;
			bond->num_unsol_na = num_peer_notif;
			ret = 0;
		} else
		if (conf->num_grat_arp != bond->num_grat_arp) {
			NLA_PUT_U8 (msg, attr, conf->num_grat_arp);
			num_peer_notif = conf->num_grat_arp;
			bond->num_grat_arp = num_peer_notif;
			bond->num_unsol_na = num_peer_notif;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				num_peer_notif, NULL);

	case IFLA_BOND_ALL_SLAVES_ACTIVE:
		if (conf->all_slaves_active != bond->all_slaves_active) {
			NLA_PUT_U8 (msg, attr, conf->all_slaves_active);
			bond->all_slaves_active = conf->all_slaves_active;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->all_slaves_active,
				conf->all_slaves_active ? "on" : "off");

	case IFLA_BOND_MIN_LINKS:
		if (conf->min_links != bond->min_links) {
			NLA_PUT_U32(msg, attr, conf->min_links);
			bond->min_links = conf->min_links;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->min_links, NULL);

	case IFLA_BOND_LP_INTERVAL:
		if (conf->lp_interval != bond->lp_interval) {
			NLA_PUT_U32(msg, attr, conf->lp_interval);
			bond->lp_interval = conf->lp_interval;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->lp_interval, NULL);

	case IFLA_BOND_PACKETS_PER_SLAVE:
		if (conf->packets_per_slave != bond->packets_per_slave) {
			NLA_PUT_U32(msg, attr, conf->packets_per_slave);
			bond->packets_per_slave = conf->packets_per_slave;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->packets_per_slave, NULL);

	case IFLA_BOND_TLB_DYNAMIC_LB:
		if (conf->tlb_dynamic_lb != bond->tlb_dynamic_lb) {
			NLA_PUT_U8 (msg, attr, conf->tlb_dynamic_lb ? 1 : 0);
			bond->tlb_dynamic_lb = conf->tlb_dynamic_lb;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->tlb_dynamic_lb,
				conf->tlb_dynamic_lb ? "on" : "off");

	case IFLA_BOND_AD_LACP_RATE:
		if (conf->lacp_rate != bond->lacp_rate) {
			NLA_PUT_U8 (msg, attr, conf->lacp_rate);
			bond->lacp_rate = conf->lacp_rate;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->lacp_rate,
				ni_bonding_lacp_rate_name(conf->lacp_rate));

	case IFLA_BOND_AD_SELECT:
		if (conf->ad_select != bond->ad_select) {
			NLA_PUT_U8 (msg, attr, conf->ad_select);
			bond->ad_select = conf->ad_select;
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				conf->ad_select,
				ni_bonding_ad_select_name(conf->ad_select));

	case IFLA_BOND_AD_USER_PORT_KEY:
		if (conf->ad_user_port_key != bond->ad_user_port_key) {
			NLA_PUT_U16(msg, attr, conf->ad_user_port_key);
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				0, "a key");

	case IFLA_BOND_AD_ACTOR_SYS_PRIO:
		if (conf->ad_actor_sys_prio != bond->ad_actor_sys_prio) {
			NLA_PUT_U16(msg, attr, conf->ad_actor_sys_prio);
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				0, "a prio");

	case IFLA_BOND_AD_ACTOR_SYSTEM:
		if (conf->ad_actor_system.len &&
		    !ni_link_address_is_invalid(&conf->ad_actor_system) &&
		    !ni_link_address_equal(&conf->ad_actor_system, &bond->ad_actor_system)) {
			NLA_PUT(msg, attr, conf->ad_actor_system.len, conf->ad_actor_system.data);
			ret = 0;
		}
		return __ni_rtnl_link_put_bond_opt_debug(ifname, name, ret,
				0, "a mac");

	default:
		ret = -1;
	}

nla_put_failure:
	ni_error("%s: unable format bonding master attr %s", ifname, name);
	return -1;
}

static int
__ni_rtnl_link_put_bond(ni_netconfig_t *nc,	struct nl_msg *msg, ni_netdev_t *dev,
			const char *ifname, const ni_netdev_t *cfg)
{
	static const struct ni_bonding_opt {
		const char *	name;		/* netlink attribute as string     */
		unsigned int	attr;		/* netlink attribute constant      */
		unsigned int	modes;		/* bonding mode constraint mask    */
		int		bstate;		/* <0: bond down, >0: bond up      */
		int		slaves;		/* <0: no slaves, >0: wants slaves */
	} ni_bonding_opt_table[] = {
#define map_opt(opt,args...)	{ .name = #opt, .attr = opt, ##args }
		map_opt(IFLA_BOND_MODE,			.bstate = -1, .slaves = -1),
		map_opt(IFLA_BOND_MIIMON),
		map_opt(IFLA_BOND_UPDELAY),
		map_opt(IFLA_BOND_DOWNDELAY),
		map_opt(IFLA_BOND_USE_CARRIER),
		map_opt(IFLA_BOND_ARP_IP_TARGET),
		map_opt(IFLA_BOND_ARP_INTERVAL,		.modes =~(NI_BIT(NI_BOND_MODE_802_3AD)
								| NI_BIT(NI_BOND_MODE_BALANCE_ALB)
								| NI_BIT(NI_BOND_MODE_BALANCE_TLB))),
		map_opt(IFLA_BOND_ARP_VALIDATE,		.modes =~(NI_BIT(NI_BOND_MODE_802_3AD)
								| NI_BIT(NI_BOND_MODE_BALANCE_ALB)
								| NI_BIT(NI_BOND_MODE_BALANCE_TLB))),
		map_opt(IFLA_BOND_ARP_ALL_TARGETS),
		map_opt(IFLA_BOND_AD_LACP_RATE,		.modes  = NI_BIT(NI_BOND_MODE_802_3AD),
							.bstate = -1),
		map_opt(IFLA_BOND_AD_SELECT,		.modes  = NI_BIT(NI_BOND_MODE_802_3AD),
							.bstate = -1),
		map_opt(IFLA_BOND_AD_ACTOR_SYS_PRIO,	.modes  = NI_BIT(NI_BOND_MODE_802_3AD),
							.bstate = -1),
		map_opt(IFLA_BOND_AD_USER_PORT_KEY,	.modes  = NI_BIT(NI_BOND_MODE_802_3AD),
							.bstate = -1),
		map_opt(IFLA_BOND_AD_ACTOR_SYSTEM,	.modes  = NI_BIT(NI_BOND_MODE_802_3AD),
							.bstate = -1),
		map_opt(IFLA_BOND_XMIT_HASH_POLICY,	.modes  = NI_BIT(NI_BOND_MODE_802_3AD)
								| NI_BIT(NI_BOND_MODE_BALANCE_XOR)
								| NI_BIT(NI_BOND_MODE_BALANCE_TLB)),
		map_opt(IFLA_BOND_PRIMARY,		.modes  = NI_BIT(NI_BOND_MODE_ACTIVE_BACKUP)
								| NI_BIT(NI_BOND_MODE_BALANCE_ALB)
								| NI_BIT(NI_BOND_MODE_BALANCE_TLB)),
		map_opt(IFLA_BOND_PRIMARY_RESELECT),
		map_opt(IFLA_BOND_ACTIVE_SLAVE,		.modes  = NI_BIT(NI_BOND_MODE_ACTIVE_BACKUP)
								| NI_BIT(NI_BOND_MODE_BALANCE_ALB)
								| NI_BIT(NI_BOND_MODE_BALANCE_TLB),
							.bstate = 1, .slaves = 1),
		map_opt(IFLA_BOND_TLB_DYNAMIC_LB,	.modes  = NI_BIT(NI_BOND_MODE_BALANCE_TLB),
							.bstate = -1),
		map_opt(IFLA_BOND_MIN_LINKS),
		map_opt(IFLA_BOND_FAIL_OVER_MAC,	.slaves = -1),
		map_opt(IFLA_BOND_ALL_SLAVES_ACTIVE),
		map_opt(IFLA_BOND_PACKETS_PER_SLAVE,	.modes  = NI_BIT(NI_BOND_MODE_BALANCE_RR)),
		map_opt(IFLA_BOND_RESEND_IGMP),
		map_opt(IFLA_BOND_LP_INTERVAL),
		map_opt(IFLA_BOND_NUM_PEER_NOTIF),
#undef  map_opt
		{ NULL,	IFLA_BOND_UNSPEC, 0, 0, 0 }
	};
	const struct ni_bonding_opt *opt;
	struct nlattr *		linkinfo;
	struct nlattr *		infodata;
	const ni_bonding_t *	conf;
	ni_bonding_t *		bond;
	ni_bool_t		is_up;
	unsigned int		count;
	int			ret;

	if (!cfg || !cfg->bonding || ni_string_empty(ifname))
		return -1;

	conf = cfg->bonding;
	bond = dev && dev->bonding ? ni_bonding_clone(dev->bonding) : ni_bonding_new();
	ni_debug_ifconfig("%s(%s)", __func__, ifname);

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "bond");

	if (!(infodata = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	is_up = ni_netdev_device_is_up(dev);
	for (count = 0, opt = ni_bonding_opt_table; opt->name; opt++) {
		if (opt->modes && !(opt->modes & NI_BIT(bond->mode))) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: skip attr %s -- bond in mode %s", ifname, opt->name,
					ni_bonding_mode_type_to_name(bond->mode));
			continue;
		}
		if (opt->bstate < 0 && is_up) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: skip attr %s -- bond is up", ifname, opt->name);
			continue;
		}
		if (opt->bstate > 0 && !is_up) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: skip attr %s -- bond is down", ifname, opt->name);
			continue;
		}
		if (opt->slaves < 0 && bond->slaves.count) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: skip attr %s -- bond has %u slave%s", ifname, opt->name,
					bond->slaves.count, bond->slaves.count > 1 ? "s" : "");
			continue;
		}
		if (opt->slaves > 0 && !bond->slaves.count) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: skip attr %s -- bond has no slaves yet", ifname, opt->name);
			continue;
		}

		if ((ret = __ni_rtnl_link_put_bond_opt(nc, msg, ifname, opt->attr, opt->name, conf, bond)) < 0)
			goto nla_put_failure;
		else if (ret == 0)
			count++;
	}

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
			"%s: sending %u bond master option%s", ifname, count, count == 1 ? "" : "s");

	nla_nest_end(msg, infodata);
	nla_nest_end(msg, linkinfo);

	if (dev)
		ni_netdev_set_bonding(dev, bond);
	else
		ni_bonding_free(bond);
	return 0;

nla_put_failure:
	ni_bonding_free(bond);
	return -1;
}


static int
__ni_rtnl_link_put_vlan(struct nl_msg *msg,	const ni_netdev_t *cfg)
{
	struct nlattr *linkinfo;
	struct nlattr *infodata;

	if (!cfg->link.lowerdev.index || !cfg->vlan)
		return -1;

	/* VLAN:
	 *  INFO_KIND must be "vlan"
	 *  INFO_DATA must contain VLAN_ID
	 *  LINK must contain the link ID of the real ethernet device
	 */
	ni_debug_ifconfig("%s(%s, vlan, %u, %s[%u])",
			__func__, cfg->name, cfg->vlan->tag,
			cfg->link.lowerdev.name,
			cfg->link.lowerdev.index);

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		return -1;
	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "vlan");

	if (!(infodata = nla_nest_start(msg, IFLA_INFO_DATA)))
		return -1;

	NLA_PUT_U16(msg, IFLA_VLAN_ID, cfg->vlan->tag);
#ifdef HAVE_IFLA_VLAN_PROTOCOL
	switch (cfg->vlan->protocol) {
	case NI_VLAN_PROTOCOL_8021Q:
		NLA_PUT_U16(msg, IFLA_VLAN_PROTOCOL, htons(ETH_P_8021Q));
		break;

	case NI_VLAN_PROTOCOL_8021AD:
		NLA_PUT_U16(msg, IFLA_VLAN_PROTOCOL, htons(ETH_P_8021AD));
		break;
	}
#endif
	nla_nest_end(msg, infodata);
	nla_nest_end(msg, linkinfo);

	/* Note, IFLA_LINK must be outside of IFLA_LINKINFO */
	NLA_PUT_U32(msg, IFLA_LINK, cfg->link.lowerdev.index);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_macvlan(struct nl_msg *msg,	const ni_netdev_t *cfg)
{
	struct nlattr *linkinfo;
	struct nlattr *infodata;

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;
	NLA_PUT_STRING(msg, IFLA_INFO_KIND,
		ni_linktype_type_to_name(cfg->link.type));

	if (!(infodata = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (cfg->macvlan->mode)
		NLA_PUT_U32(msg, IFLA_MACVLAN_MODE, cfg->macvlan->mode);
	if (cfg->macvlan->flags)
		NLA_PUT_U16(msg, IFLA_MACVLAN_FLAGS, cfg->macvlan->flags);

	nla_nest_end(msg, infodata);
	nla_nest_end(msg, linkinfo);

	/* Note, IFLA_LINK must be outside of IFLA_LINKINFO */
	NLA_PUT_U32(msg, IFLA_LINK, cfg->link.lowerdev.index);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_dummy(struct nl_msg *msg, const ni_netdev_t *cfg)
{
	struct nlattr *linkinfo;

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "dummy");

	nla_nest_end(msg, linkinfo);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_tunnel(struct nl_msg *msg, const ni_linkinfo_t *link,
			const ni_tunnel_t *tunnel, unsigned int type)
{
	uint32_t *local_ip;
	uint32_t *remote_ip;
	uint8_t pmtudisc;

	local_ip = (uint32_t *)link->hwaddr.data;
	remote_ip = (uint32_t *)link->hwpeer.data;

	switch(type) {
	case NI_IFTYPE_IPIP:
	case NI_IFTYPE_SIT:
		if (type == NI_IFTYPE_SIT)
			NLA_PUT_U8(msg, IFLA_IPTUN_PROTO, IPPROTO_IPV6);
#if 0
		else
			/*
			 * (ipv4) ipip isn't using the IFLA_IPTUN_PROTO
			 * attr, but sets it always to IPPROTO_IPIP
			 */
			NLA_PUT_U8(msg, IFLA_IPTUN_PROTO, IPPROTO_IPIP);
#endif
		NLA_PUT_U32(msg, IFLA_IPTUN_LINK, link->lowerdev.index);
		NLA_PUT_U32(msg, IFLA_IPTUN_LOCAL, *local_ip);
		NLA_PUT_U32(msg, IFLA_IPTUN_REMOTE, *remote_ip);
		NLA_PUT_U8(msg, IFLA_IPTUN_TTL, tunnel->ttl);
		NLA_PUT_U8(msg, IFLA_IPTUN_TOS, tunnel->tos);
		pmtudisc = tunnel->pmtudisc ? 1 : 0;
		NLA_PUT_U8(msg, IFLA_IPTUN_PMTUDISC, pmtudisc);
		NLA_PUT_U16(msg, IFLA_IPTUN_FLAGS, tunnel->iflags);

		break;

	case NI_IFTYPE_GRE:
		NLA_PUT_U32(msg, IFLA_GRE_LINK, link->lowerdev.index);
		NLA_PUT_U32(msg, IFLA_GRE_LOCAL, *local_ip);
		NLA_PUT_U32(msg, IFLA_GRE_REMOTE, *remote_ip);
		NLA_PUT_U8(msg, IFLA_GRE_TTL, tunnel->ttl);
		NLA_PUT_U8(msg, IFLA_GRE_TOS, tunnel->tos);
		pmtudisc = tunnel->pmtudisc ? 1 : 0;
		NLA_PUT_U8(msg, IFLA_GRE_PMTUDISC, pmtudisc);

		break;

	default:
		break;
	}

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_sit(struct nl_msg *msg, const ni_netdev_t *cfg)
{
	struct nlattr *linkinfo;
	struct nlattr *infodata;

	if (!cfg->sit || !(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "sit");

	if (!(infodata = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (cfg->sit->isatap)
		cfg->sit->tunnel.iflags |= SIT_ISATAP;

	if (__ni_rtnl_link_put_tunnel(msg, &cfg->link, &cfg->sit->tunnel, NI_IFTYPE_SIT) < 0)
		goto nla_put_failure;

	nla_nest_end(msg, infodata);
	nla_nest_end(msg, linkinfo);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_ipip(struct nl_msg *msg, const ni_netdev_t *cfg)
{
	struct nlattr *linkinfo;
	struct nlattr *infodata;

	if (!cfg->ipip || !(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "ipip");

	if (!(infodata = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (__ni_rtnl_link_put_tunnel(msg, &cfg->link, &cfg->ipip->tunnel, NI_IFTYPE_IPIP) < 0)
		goto nla_put_failure;

	nla_nest_end(msg, infodata);
	nla_nest_end(msg, linkinfo);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_gre(struct nl_msg *msg, const ni_netdev_t *cfg)
{
	struct nlattr *linkinfo;
	struct nlattr *infodata;
	uint32_t *ipaddr;
	uint16_t flags;

	if (!cfg->gre || !(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "gre");

	if (!(infodata = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (__ni_rtnl_link_put_tunnel(msg, &cfg->link, &cfg->gre->tunnel, NI_IFTYPE_GRE) < 0)
		goto nla_put_failure;

	flags = 0;
	if (cfg->gre->flags & NI_BIT(NI_GRE_FLAG_IKEY))
		flags |= GRE_KEY;
	if (cfg->gre->flags & NI_BIT(NI_GRE_FLAG_ISEQ))
		flags |= GRE_SEQ;
	if (cfg->gre->flags & NI_BIT(NI_GRE_FLAG_ICSUM))
		flags |= GRE_CSUM;

	ipaddr = (uint32_t *)cfg->link.hwpeer.data;
	if (!cfg->gre->ikey.s_addr && IN_MULTICAST(ntohl(*ipaddr))) {
		cfg->gre->ikey.s_addr = *ipaddr;
		flags |= GRE_KEY;
	}

	NLA_PUT_U16(msg, IFLA_GRE_IFLAGS, flags);
	NLA_PUT_U32(msg, IFLA_GRE_IKEY, cfg->gre->ikey.s_addr);

	flags = 0;
	if (cfg->gre->flags & NI_BIT(NI_GRE_FLAG_OKEY))
		flags |= GRE_KEY;
	if (cfg->gre->flags & NI_BIT(NI_GRE_FLAG_OSEQ))
		flags |= GRE_SEQ;
	if (cfg->gre->flags & NI_BIT(NI_GRE_FLAG_OCSUM))
		flags |= GRE_CSUM;

	ipaddr = (uint32_t *)cfg->link.hwpeer.data;
	if (!cfg->gre->okey.s_addr && IN_MULTICAST(ntohl(*ipaddr))) {
		cfg->gre->okey.s_addr = *ipaddr;
		flags |= GRE_KEY;
	}

	NLA_PUT_U16(msg, IFLA_GRE_OFLAGS, flags);
	NLA_PUT_U32(msg, IFLA_GRE_OKEY, cfg->gre->okey.s_addr);

#if 0	/* does not work up to leap kernel */
	switch (cfg->gre->encap.type) {
	case NI_GRE_ENCAP_TYPE_FOU:
		NLA_PUT_U16(msg, IFLA_GRE_ENCAP_TYPE, TUNNEL_ENCAP_FOU);
		break;
	case NI_GRE_ENCAP_TYPE_GUE:
		NLA_PUT_U16(msg, IFLA_GRE_ENCAP_TYPE, TUNNEL_ENCAP_GUE);
		break;
	case NI_GRE_ENCAP_TYPE_NONE:
	default:
		NLA_PUT_U16(msg, IFLA_GRE_ENCAP_TYPE, TUNNEL_ENCAP_NONE);
		break;
	}

	flags = 0;
	if (cfg->gre->encap.flags & NI_BIT(NI_GRE_ENCAP_FLAG_CSUM))
		flags |= TUNNEL_ENCAP_FLAG_CSUM;
	if (cfg->gre->encap.flags & NI_BIT(NI_GRE_ENCAP_FLAG_CSUM6))
		flags |= TUNNEL_ENCAP_FLAG_CSUM6;
	if (cfg->gre->encap.flags & NI_BIT(NI_GRE_ENCAP_FLAG_REMCSUM))
		flags |= TUNNEL_ENCAP_FLAG_REMCSUM;

	NLA_PUT_U16(msg, IFLA_GRE_ENCAP_FLAGS, flags);
	NLA_PUT_U16(msg, IFLA_GRE_ENCAP_SPORT, htons(cfg->gre->encap.sport));
	NLA_PUT_U16(msg, IFLA_GRE_ENCAP_DPORT, htons(cfg->gre->encap.dport));
#endif

	nla_nest_end(msg, infodata);
	nla_nest_end(msg, linkinfo);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_create(ni_netconfig_t *nc, const ni_netdev_t *cfg)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;
	int err = -1;

	if (!nc || !cfg || ni_string_empty(cfg->name))
		return -1;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (__ni_rtnl_link_put_ifname(msg, cfg->name) < 0)
		goto nla_put_failure;

	switch (cfg->link.type) {
	case NI_IFTYPE_VLAN:
		if (__ni_rtnl_link_put_vlan(msg, cfg) < 0)
			goto nla_put_failure;

		if (__ni_rtnl_link_put_hwaddr(msg, &cfg->link.hwaddr) < 0)
			goto nla_put_failure;

		break;

	case NI_IFTYPE_MACVLAN:
	case NI_IFTYPE_MACVTAP:
		if (__ni_rtnl_link_put_macvlan(msg, cfg) < 0)
			goto nla_put_failure;

		if (__ni_rtnl_link_put_hwaddr(msg, &cfg->link.hwaddr) < 0)
			goto nla_put_failure;

		break;

	case NI_IFTYPE_DUMMY:
		if (__ni_rtnl_link_put_dummy(msg, cfg) < 0)
			goto nla_put_failure;

		if (__ni_rtnl_link_put_hwaddr(msg, &cfg->link.hwaddr) < 0)
			goto nla_put_failure;

		break;

	case NI_IFTYPE_SIT:
		ifi.ifi_flags |= IFF_POINTOPOINT;

		if (__ni_rtnl_link_put_sit(msg, cfg) < 0)
			goto nla_put_failure;
		break;

	case NI_IFTYPE_IPIP:
		ifi.ifi_flags |= IFF_POINTOPOINT;

		if (__ni_rtnl_link_put_ipip(msg, cfg) < 0)
			goto nla_put_failure;
		break;

	case NI_IFTYPE_GRE:
		ifi.ifi_flags |= IFF_POINTOPOINT;

		if (__ni_rtnl_link_put_gre(msg, cfg) < 0)
			goto nla_put_failure;
		break;

	case NI_IFTYPE_BOND:
		if (__ni_rtnl_link_put_bond(nc, msg, NULL, cfg->name, cfg) < 0)
			goto nla_put_failure;
		break;

	default:
		/* unknown one, case not (yet) there... */
		ni_error("BUG: unable to create %s interface", cfg->name);
		goto failed;
	}

	/* Actually capture the netlink -error code for use by callers. */
	if ((err = ni_nl_talk(msg, NULL)))
		goto failed;

	ni_debug_ifconfig("successfully created interface %s", cfg->name);
	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink message to create %s", cfg->name);
failed:
	nlmsg_free(msg);
	return err;
}

int
__ni_rtnl_link_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;

	if (!nc || !dev || !cfg)
		return -1;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = dev->link.ifindex;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST);
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (!ni_netdev_link_is_up(dev)) {
		if (!ni_string_empty(cfg->name) && !ni_string_eq(dev->name, cfg->name) &&
				__ni_rtnl_link_put_ifname(msg, cfg->name) < 0)
			goto nla_put_failure;
	}

	switch (cfg->link.type) {
	case NI_IFTYPE_VLAN:
		if (__ni_rtnl_link_put_vlan(msg, cfg) < 0)
			goto nla_put_failure;
		break;

	case NI_IFTYPE_MACVLAN:
	case NI_IFTYPE_MACVTAP:
		if (__ni_rtnl_link_put_macvlan(msg, cfg) < 0)
			goto nla_put_failure;
		break;

	case NI_IFTYPE_DUMMY:
		if (__ni_rtnl_link_put_dummy(msg, cfg) < 0)
			goto nla_put_failure;
		break;

	case NI_IFTYPE_SIT:
		if (__ni_rtnl_link_put_sit(msg, cfg) < 0)
			goto nla_put_failure;
		break;

	case NI_IFTYPE_IPIP:
		if (__ni_rtnl_link_put_ipip(msg, cfg) < 0)
			goto nla_put_failure;
		break;

	case NI_IFTYPE_GRE:
		if (__ni_rtnl_link_put_gre(msg, cfg) < 0)
			goto nla_put_failure;
		break;

	case NI_IFTYPE_BOND:
		if (__ni_rtnl_link_put_bond(nc, msg, dev, dev->name, cfg) < 0)
			goto nla_put_failure;
		break;

	default:
		break;
	}

	if (ni_nl_talk(msg, NULL))
		goto failed;

	ni_debug_ifconfig("successfully modified interface %s", dev->name);
	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink message to change %s", dev->name);
failed:
	nlmsg_free(msg);
	return -1;
}

int
__ni_rtnl_link_change_hwaddr(ni_netdev_t *dev, const ni_hwaddr_t *hwaddr)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;

	if (!dev || !hwaddr)
		return -1;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = dev->link.ifindex;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST);
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (__ni_rtnl_link_put_hwaddr(msg, hwaddr) < 0)
		goto nla_put_failure;

	if (ni_nl_talk(msg, NULL))
		goto failed;

	ni_debug_ifconfig("successfully modified interface %s hwaddr %s",
			dev->name, ni_link_address_print(hwaddr));
	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr to modify interface %s hwaddr",
			dev->name);
failed:
	nlmsg_free(msg);
	return -1;
}

int
__ni_rtnl_link_change_mtu(ni_netdev_t *dev, unsigned int mtu)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;

	if (!dev || !mtu)
		return -1;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = dev->link.ifindex;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST);
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (__ni_rtnl_link_put_mtu(msg, mtu) < 0)
		goto nla_put_failure;

	if (ni_nl_talk(msg, NULL))
		goto failed;

	ni_debug_ifconfig("successfully modified interface %s mtu to %u",
			dev->name, mtu);
	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr to modify interface %s mtu",
			dev->name);
failed:
	nlmsg_free(msg);
	return -1;
}

int
__ni_rtnl_link_rename(unsigned int ifindex, const char *oldname, const char *newname)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;
	int err = -1;

	if (ifindex == 0 || ni_string_empty(newname))
		return -1;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = ifindex;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST);
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if ((err = __ni_rtnl_link_put_ifname(msg, newname)) < 0)
		goto nla_put_failure;

	if ((err = ni_nl_talk(msg, NULL)))
		goto failed;

	ni_debug_ifconfig("%s[%u]: successfully renamed device to %s",
			oldname ? oldname : "", ifindex, newname);

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("%s[%u]: failed to encode netlink message to rename device to %s",
			oldname ? oldname : "", ifindex, newname);
failed:
	nlmsg_free(msg);
	return err;
}

/*
 * Simple rtnl message without attributes
 */
static inline int
__ni_rtnl_simple(int msgtype, unsigned int flags, void *data, size_t len)
{
	struct nl_msg *msg;
	int rv = -1;

	msg = nlmsg_alloc_simple(msgtype, flags);

	if ((rv = nlmsg_append(msg, data, len, NLMSG_ALIGNTO))) {
		ni_error("%s: nlmsg_append failed: %s", __func__,  nl_geterror(rv));
	} else
	if ((rv = ni_nl_talk(msg, NULL))) {
		ni_debug_ifconfig("%s: rtnl_talk failed: %s", __func__,  nl_geterror(rv));
	}

	nlmsg_free(msg);
	return rv;
}

/*
 * Set the interface link down
 */
static int
__ni_rtnl_link_down(const ni_netdev_t *dev)
{
	struct ifinfomsg ifi;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = dev->link.ifindex;
	ifi.ifi_change = IFF_UP;

	return __ni_rtnl_simple(RTM_NEWLINK, 0, &ifi, sizeof(ifi));
}

/*
 * Delete the interface
 */
static int
__ni_rtnl_link_delete(const ni_netdev_t *dev)
{
	struct ifinfomsg ifi;
	int rv;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = dev->link.ifindex;
	ifi.ifi_change = IFF_UP;

	rv = __ni_rtnl_simple(RTM_DELLINK, 0, &ifi, sizeof(ifi));
	switch (abs(rv))  {
	case NLE_SUCCESS:
	case NLE_NODEV:
		return 0;
	default:
		return rv;
	}
}

/*
 * Bring up an interface and enslave (bridge port) to master
 */
int
__ni_rtnl_link_add_port_up(const ni_netdev_t *port, const char *mname, unsigned int mindex)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;

	if (!port || !mname || !mindex)
		return -1;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = port->link.ifindex;
	ifi.ifi_change = IFF_UP;
	ifi.ifi_flags = IFF_UP;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST);
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	NLA_PUT_U32(msg, IFLA_MASTER, mindex);

	if (ni_nl_talk(msg, NULL))
		goto failed;

	ni_debug_ifconfig("successfully added port %s into master %s",
			port->name, mname);
	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink message to add port %s into %s",
			port->name, mname);
failed:
	nlmsg_free(msg);
	return -1;
}

/*
 * Bring down an interface and enslave (bond slave) to master
 */
int
__ni_rtnl_link_add_slave_down(const ni_netdev_t *slave, const char *mname, unsigned int mindex)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;

	if (!slave || !mname || !mindex)
		return -1;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = slave->link.ifindex;
	ifi.ifi_change = IFF_UP;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST);
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	NLA_PUT_U32(msg, IFLA_MASTER, mindex);

	if (ni_nl_talk(msg, NULL) < 0)
		goto failed;

	ni_debug_ifconfig("successfully enslaved %s into master %s", slave->name, mname);
	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink message to enslave %s into %s", slave->name, mname);
failed:
	nlmsg_free(msg);
	return -1;
}

/*
 * (Re-)configure an interface
 */
static int
__ni_rtnl_link_up(const ni_netdev_t *dev, const ni_netdev_req_t *cfg)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;
	int rv = -1;

	if (dev->link.ifindex == 0) {
		ni_error("%s: bad interface index for %s", __func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	NI_TRACE_ENTER_ARGS("%s, idx=%d", dev->name, dev->link.ifindex);
	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = dev->link.ifindex;
	ifi.ifi_change = IFF_UP;
	ifi.ifi_flags = IFF_UP;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_CREATE);

	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0) {
		ni_error("failed to encode netlink attr");
		goto nla_put_failure;
	}

	if (cfg) {
		if (cfg->mtu && cfg->mtu != dev->link.mtu)
			NLA_PUT_U32(msg, IFLA_MTU, cfg->mtu);

		if (cfg->txqlen && cfg->txqlen != dev->link.txqlen)
			NLA_PUT_U32(msg, IFLA_TXQLEN, cfg->txqlen);

		if (cfg->alias && !ni_string_eq(dev->link.alias, cfg->alias))
			NLA_PUT_STRING(msg, IFLA_IFALIAS, cfg->alias);

		/* FIXME: handle COST, QDISC, MASTER */
	}

	if ((rv = ni_nl_talk(msg, NULL)) < 0) {
		if (errno == ERFKILL)
			rv = -NI_ERROR_RADIO_DISABLED;
		else
			rv = -NI_ERROR_GENERAL_FAILURE;
		ni_debug_ifconfig("%s: rtnl_talk failed", __func__);
	}

out:
	nlmsg_free(msg);
	return rv;

nla_put_failure:
	rv = -NI_ERROR_GENERAL_FAILURE;
	goto out;
}

static inline int
addattr_sockaddr(struct nl_msg *msg, int type, const ni_sockaddr_t *addr)
{
	unsigned int offset, len;

	if (!ni_af_sockaddr_info(addr->ss_family, &offset, &len))
		return -1;

	return nla_put(msg, type, len, ((const caddr_t) addr) + offset);
}

static ni_address_t *
__ni_netdev_address_in_list(ni_address_t *list, const ni_address_t *ap)
{
	ni_address_t *ap2;

	if (ap->local_addr.ss_family == AF_INET) {
		const struct sockaddr_in *sin1, *sin2;

		sin1 = &ap->local_addr.sin;
		for (ap2 = list; ap2; ap2 = ap2->next) {
			if (ap2->local_addr.ss_family != AF_INET)
				continue;
			sin2 = &ap2->local_addr.sin;
			if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr)
				continue;

			if (!ni_sockaddr_equal(&ap->peer_addr, &ap2->peer_addr))
				continue;

			return ap2;
		}
	}

	if (ap->local_addr.ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin1, *sin2;

		sin1 = &ap->local_addr.six;
		for (ap2 = list; ap2; ap2 = ap2->next) {
			if (ap2->local_addr.ss_family != AF_INET6)
				continue;
			sin2 = &ap2->local_addr.six;
			if (!memcmp(&sin1->sin6_addr, &sin2->sin6_addr, 16))
				return ap2;
		}
	}

	return NULL;
}

static int
__ni_rtnl_send_newaddr(ni_netdev_t *dev, const ni_address_t *ap, int flags)
{
	struct ifaddrmsg ifa;
	struct nl_msg *msg;
	int err;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__,
			ni_sockaddr_print(&ap->local_addr), ap->prefixlen);

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_index = dev->link.ifindex;
	ifa.ifa_family = ap->family;
	ifa.ifa_prefixlen = ap->prefixlen;

	/* Handle ifa_scope */
	if (ap->scope >= 0)
		ifa.ifa_scope = ap->scope;
	else if (ni_address_is_loopback(ap))
		ifa.ifa_scope = RT_SCOPE_HOST;
	else
		ifa.ifa_scope = RT_SCOPE_UNIVERSE;

	msg = nlmsg_alloc_simple(RTM_NEWADDR, flags);
	if (nlmsg_append(msg, &ifa, sizeof(ifa), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (addattr_sockaddr(msg, IFA_LOCAL, &ap->local_addr) < 0)
		goto nla_put_failure;

	if (ap->peer_addr.ss_family != AF_UNSPEC) {
		if (addattr_sockaddr(msg, IFA_ADDRESS, &ap->peer_addr) < 0)
			goto nla_put_failure;
	} else {
		if (addattr_sockaddr(msg, IFA_ADDRESS, &ap->local_addr) < 0)
			goto nla_put_failure;
	}

	if (ap->bcast_addr.ss_family == AF_INET
	 && !ni_sockaddr_equal(&ap->bcast_addr, &ap->local_addr)
	 && addattr_sockaddr(msg, IFA_BROADCAST, &ap->bcast_addr) < 0)
		goto nla_put_failure;

	if (ap->anycast_addr.ss_family != AF_UNSPEC
	 && addattr_sockaddr(msg, IFA_ANYCAST, &ap->anycast_addr) < 0)
		goto nla_put_failure;

	if (ap->family == AF_INET && ap->label) {
		if (!ni_netdev_alias_label_is_valid(dev->name, ap->label)) {
			ni_info("%s: skipping invalid ipv4 address alias label '%s'",
					dev->name, ap->label);
		} else if (!strncmp(ap->label, dev->name, strlen(dev->name))) {
			NLA_PUT_STRING(msg, IFA_LABEL, ap->label);
		} else {
			char label[IFNAMSIZ] = {'\0'};

			snprintf(label, sizeof(label), "%s:%s", dev->name, ap->label);
			NLA_PUT_STRING(msg, IFA_LABEL, label);
		}
	}

	if (ap->family == AF_INET6
		&& ap->ipv6_cache_info.valid_lft
		&& ap->ipv6_cache_info.preferred_lft)
	{
		struct ifa_cacheinfo ci;

		memset(&ci, 0, sizeof(ci));
		ci.ifa_valid = ap->ipv6_cache_info.valid_lft;
		ci.ifa_prefered = ap->ipv6_cache_info.preferred_lft;

		if (ci.ifa_prefered > ci.ifa_valid) {
			ni_error("ipv6 address prefered lifetime %u cannot "
				 " be greater than the valid lifetime %u",
				 ci.ifa_prefered, ci.ifa_valid);
			goto failed;
		}

		if (nla_put(msg, IFA_CACHEINFO, sizeof(ci), &ci) < 0)
			goto nla_put_failure;
	}

	if ((err = ni_nl_talk(msg, NULL)) && abs(err) != NLE_EXIST) {
		ni_error("%s(%s/%u): ni_nl_talk failed [%s]", __func__,
				ni_sockaddr_print(&ap->local_addr),
				ap->prefixlen,  nl_geterror(err));
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -1;
}

static int
__ni_rtnl_send_deladdr(ni_netdev_t *dev, const ni_address_t *ap)
{
	struct ifaddrmsg ifa;
	struct nl_msg *msg;
	int err;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_sockaddr_print(&ap->local_addr), ap->prefixlen);

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_index = dev->link.ifindex;
	ifa.ifa_family = ap->family;
	ifa.ifa_prefixlen = ap->prefixlen;

	msg = nlmsg_alloc_simple(RTM_DELADDR, 0);
	if (nlmsg_append(msg, &ifa, sizeof(ifa), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (addattr_sockaddr(msg, IFA_LOCAL, &ap->local_addr))
		goto nla_put_failure;

	if (ap->peer_addr.ss_family != AF_UNSPEC) {
		if (addattr_sockaddr(msg, IFA_ADDRESS, &ap->peer_addr))
			goto nla_put_failure;
	} else {
		if (addattr_sockaddr(msg, IFA_ADDRESS, &ap->local_addr))
			goto nla_put_failure;
	}

	if ((err = ni_nl_talk(msg, NULL)) < 0) {
		ni_error("%s(%s/%u): rtnl_talk failed: %s", __func__,
				ni_sockaddr_print(&ap->local_addr),
				ap->prefixlen,  nl_geterror(err));
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -1;
}

/*
 * Add a static route
 */
static int
__ni_rtnl_send_newroute(ni_netdev_t *dev, ni_route_t *rp, int flags)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	struct rtmsg rt;
	struct nl_msg *msg;
	int err;

	ni_debug_ifconfig("%s(%s%s)", __FUNCTION__,
			flags & NLM_F_REPLACE ? "replace " :
			flags & NLM_F_CREATE  ? "create " : "",
			ni_route_print(&buf, rp));
	ni_stringbuf_destroy(&buf);

	memset(&rt, 0, sizeof(rt));

	rt.rtm_family = rp->family;
	rt.rtm_dst_len = rp->prefixlen;
	rt.rtm_tos = rp->tos;

	rt.rtm_type = RTN_UNICAST;
	if (rp->type != RTN_UNSPEC && rp->type < __RTN_MAX)
		rt.rtm_type = rp->type;

	rt.rtm_scope = RT_SCOPE_UNIVERSE;
	if (ni_route_is_valid_scope(rp->scope)) {
		rt.rtm_scope = rp->scope;
	} else {
		rt.rtm_scope = ni_route_guess_scope(rp);
	}

	rt.rtm_protocol = RTPROT_BOOT;
	if (ni_route_is_valid_protocol(rp->protocol))
		rt.rtm_protocol = rp->protocol;

	rt.rtm_table = RT_TABLE_MAIN;
	if (ni_route_is_valid_table(rp->table)) {
		if (rp->table > RT_TABLE_LOCAL)
			rt.rtm_table = RT_TABLE_COMPAT;
		else
			rt.rtm_table = rp->table;
	} else {
		rt.rtm_table = ni_route_guess_table(rp);
	}

	msg = nlmsg_alloc_simple(RTM_NEWROUTE, flags);
	if (nlmsg_append(msg, &rt, sizeof(rt), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (rp->destination.ss_family == AF_UNSPEC) {
		/* default destination, just leave RTA_DST blank */
	} else if (addattr_sockaddr(msg, RTA_DST, &rp->destination))
		goto nla_put_failure;

	if (rp->nh.next == NULL) {
		if (rp->nh.gateway.ss_family != AF_UNSPEC &&
		    addattr_sockaddr(msg, RTA_GATEWAY, &rp->nh.gateway))
			goto nla_put_failure;

		switch (rt.rtm_type) {
		case RTN_UNREACHABLE:
		case RTN_BLACKHOLE:
		case RTN_PROHIBIT:
		case RTN_THROW:
			break;
		default:
			if (rp->nh.device.index)
				NLA_PUT_U32(msg, RTA_OIF, rp->nh.device.index);
			else
			if (dev && ni_string_eq(rp->nh.device.name, dev->name))
				NLA_PUT_U32(msg, RTA_OIF, dev->link.ifindex);
			else
				goto failed; /* apply to other device? */
			break;
		}

		if (rp->realm)
			NLA_PUT_U32(msg, RTA_FLOW, rp->realm);
	} else {
		struct nlattr *mp_head;
		struct rtnexthop *rtnh;
		ni_route_nexthop_t *nh;
		ni_netconfig_t *nc = NULL;

		mp_head = nla_nest_start(msg, RTA_MULTIPATH);
		if (mp_head == NULL)
			goto nla_put_failure;

		for (nh = &rp->nh; nh; nh = nh->next) {
			rtnh = nlmsg_reserve(msg, sizeof(*rtnh), NLMSG_ALIGNTO);
			if (rtnh == NULL)
				goto nla_put_failure;

			memset(rtnh, 0, sizeof(*rtnh));
			rtnh->rtnh_flags = nh->flags & 0xFF;
			rtnh->rtnh_hops = nh->weight ? nh->weight - 1 : 0;

			if (nh->device.index) {
				rtnh->rtnh_ifindex = nh->device.index;
			} else
			if (dev && ni_string_eq(rp->nh.device.name, dev->name)) {
				rtnh->rtnh_ifindex = dev->link.ifindex;
			} else
			if (rp->nh.device.name) {
				/* TODO: multi-device hops not supported yet */
				ni_netdev_t *other;

				if (!nc || !(nc = ni_global_state_handle(0)))
					goto failed;
				if (!(other = ni_netdev_by_name(nc, rp->nh.device.name)))
					goto failed;

				rtnh->rtnh_ifindex = other->link.ifindex;
			} else
			if (!ni_sockaddr_is_specified(&nh->gateway)) {
				/* hop without gw and device? */
				goto failed;
			}

			if (ni_sockaddr_is_specified(&nh->gateway) &&
			    addattr_sockaddr(msg, RTA_GATEWAY, &nh->gateway))
				goto nla_put_failure;

			if (nh->realm)
				NLA_PUT_U32(msg, RTA_FLOW, nh->realm);

			rtnh->rtnh_len = nlmsg_tail(nlmsg_hdr(msg)) - (void *)rtnh;
		}
		nla_nest_end(msg, mp_head);
	}

	if (ni_sockaddr_is_specified(&rp->pref_src) &&
	    addattr_sockaddr(msg, RTA_PREFSRC, &rp->pref_src))
		goto nla_put_failure;

	if (rt.rtm_table == RT_TABLE_COMPAT && rp->table != RT_TABLE_COMPAT)
		NLA_PUT_U32(msg, RTA_TABLE, rp->table);

	if (rp->priority)
		NLA_PUT_U32(msg, RTA_PRIORITY, rp->priority);

#ifdef HAVE_RTA_MARK
	if (rp->mark)
		NLA_PUT_U32(msg, RTA_MARK, rp->mark);
#endif


	/* Add metrics if needed */
	if (rp->mtu || rp->window || rp->rtt || rp->rttvar || rp->ssthresh ||
	    rp->cwnd || rp->advmss || rp->reordering || rp->hoplimit ||
	    rp->initcwnd || rp->features || rp->rto_min || rp->initrwnd) {

		struct nlattr *mxrta;

		mxrta = nla_nest_start(msg, RTA_METRICS);
		if (mxrta == NULL)
			goto nla_put_failure;

		if (rp->lock)
			NLA_PUT_U32(msg, RTAX_LOCK, rp->lock);
		if (rp->mtu)
			NLA_PUT_U32(msg, RTAX_MTU, rp->mtu);
		if (rp->window)
			NLA_PUT_U32(msg, RTAX_WINDOW, rp->window);
		if (rp->rtt)
			NLA_PUT_U32(msg, RTAX_RTT, rp->rtt);
		if (rp->rttvar)
			NLA_PUT_U32(msg, RTAX_RTTVAR, rp->rttvar);
		if (rp->ssthresh)
			NLA_PUT_U32(msg, RTAX_SSTHRESH, rp->ssthresh);
		if (rp->cwnd)
			NLA_PUT_U32(msg, RTAX_CWND, rp->cwnd);
		if (rp->advmss)
			NLA_PUT_U32(msg, RTAX_ADVMSS, rp->advmss);
		if (rp->reordering)
			NLA_PUT_U32(msg, RTAX_REORDERING, rp->reordering);
		if (rp->hoplimit)
			NLA_PUT_U32(msg, RTAX_HOPLIMIT, rp->hoplimit);
		if (rp->initcwnd)
			NLA_PUT_U32(msg, RTAX_INITCWND, rp->initcwnd);
		if (rp->features)
			NLA_PUT_U32(msg, RTAX_FEATURES, rp->features);
		if (rp->rto_min)
			NLA_PUT_U32(msg, RTAX_RTO_MIN, rp->rto_min);
#ifdef RTAX_INITRWND
		if (rp->initrwnd)
			NLA_PUT_U32(msg, RTAX_INITRWND, rp->initrwnd);
#endif

		nla_nest_end(msg, mxrta);
	}

	if ((err = ni_nl_talk(msg, NULL)) && abs(err) != NLE_EXIST) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
		ni_error("%s(%s): ni_nl_talk failed [%s]", __FUNCTION__,
				ni_route_print(&buf, rp),  nl_geterror(err));
		ni_stringbuf_destroy(&buf);
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -NI_ERROR_CANNOT_CONFIGURE_ROUTE;
}

static int
__ni_rtnl_send_delroute(ni_netdev_t *dev, ni_route_t *rp)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	struct rtmsg rt;
	struct nl_msg *msg;

	ni_debug_ifconfig("%s(%s)", __FUNCTION__, ni_route_print(&buf, rp));
	ni_stringbuf_destroy(&buf);

	memset(&rt, 0, sizeof(rt));
	rt.rtm_family = rp->family;
	rt.rtm_table = RT_TABLE_MAIN;
	rt.rtm_protocol = RTPROT_BOOT;
	rt.rtm_scope = RT_SCOPE_NOWHERE;
	rt.rtm_type = RTN_UNICAST;
	rt.rtm_tos = rp->tos;

	rt.rtm_dst_len = rp->prefixlen;

	msg = nlmsg_alloc_simple(RTM_DELROUTE, 0);
	if (nlmsg_append(msg, &rt, sizeof(rt), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	/* For the default route, just leave RTA_DST blank */
	if (rp->destination.ss_family != AF_UNSPEC
	 && addattr_sockaddr(msg, RTA_DST, &rp->destination))
		goto nla_put_failure;

	if (rp->nh.gateway.ss_family != AF_UNSPEC
	 && addattr_sockaddr(msg, RTA_GATEWAY, &rp->nh.gateway))
		goto nla_put_failure;

	NLA_PUT_U32(msg, RTA_OIF, dev->link.ifindex);

	if (ni_nl_talk(msg, NULL) < 0) {
		ni_error("%s(%s): rtnl_talk failed", __FUNCTION__, ni_route_print(&buf, rp));
		ni_stringbuf_destroy(&buf);
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -1;
}

static int
ni_rtnl_rule_msg_put(struct nl_msg *msg, const ni_rule_t *rule)
{
	if (ni_route_is_valid_table(rule->table))
		NLA_PUT_U32(msg, FRA_TABLE, rule->table);

	if (rule->set & NI_RULE_SET_PREF)
		NLA_PUT_U32(msg, FRA_PRIORITY, rule->pref);

	if (rule->fwmark)
		NLA_PUT_U32(msg, FRA_FWMARK, rule->fwmark);

	if (rule->fwmask)
		NLA_PUT_U32(msg, FRA_FWMASK, rule->fwmask);

	if (rule->realm)
		NLA_PUT_U32(msg, FRA_FLOW, rule->realm);

	if (rule->action == NI_RULE_ACTION_GOTO)
		NLA_PUT_U32(msg, FRA_GOTO, rule->target);

	if (!ni_string_empty(rule->iif.name))
		NLA_PUT_STRING(msg, FRA_IIFNAME, rule->iif.name);

	if (!ni_string_empty(rule->oif.name))
		NLA_PUT_STRING(msg, FRA_OIFNAME, rule->oif.name);

	if (rule->dst.len && !ni_sockaddr_is_unspecified(&rule->dst.addr) &&
			addattr_sockaddr(msg, FRA_DST, &rule->dst.addr))
		goto nla_put_failure;

	if (rule->src.len && !ni_sockaddr_is_unspecified(&rule->src.addr) &&
			addattr_sockaddr(msg, FRA_SRC, &rule->src.addr))
		goto nla_put_failure;

	if (rule->suppress_ifgroup && rule->suppress_ifgroup != -1U)
		NLA_PUT_U32(msg, FRA_SUPPRESS_IFGROUP, rule->suppress_ifgroup);

	if (rule->suppress_prefixlen && rule->suppress_prefixlen != -1U)
		NLA_PUT_U32(msg, FRA_SUPPRESS_PREFIXLEN, rule->suppress_prefixlen);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_send_newrule(const ni_rule_t *rule, int flags)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	struct nl_msg *msg;
	struct fib_rule_hdr frh;
	int err;

	ni_debug_ifconfig("%s(%s%s)", __FUNCTION__,
			flags & NLM_F_REPLACE ? "replace " :
			flags & NLM_F_CREATE  ? "create " : "",
			ni_rule_print(&buf, rule));
	ni_stringbuf_destroy(&buf);

	memset(&frh, 0, sizeof(frh));
	frh.family = rule->family;
	frh.action = rule->action;
	frh.table = rule->table > RT_TABLE_LOCAL ? RT_TABLE_UNSPEC : rule->table;
	frh.dst_len = rule->dst.len && !ni_sockaddr_is_unspecified(&rule->dst.addr) ? rule->dst.len : 0;
	frh.src_len = rule->src.len && !ni_sockaddr_is_unspecified(&rule->src.addr) ? rule->src.len : 0;
	if (rule->flags & NI_BIT(NI_RULE_INVERT))
		frh.flags |= FIB_RULE_INVERT;
	frh.tos = rule->tos;

	msg = nlmsg_alloc_simple(RTM_NEWRULE, NLM_F_REQUEST | flags);
	if (nlmsg_append(msg, &frh, sizeof(frh), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (ni_rtnl_rule_msg_put(msg, rule) < 0)
		goto nla_put_failure;

	if ((err = ni_nl_talk(msg, NULL)) && abs(err) != NLE_EXIST) {
		ni_error("%s(%s): rtnl_talk failed", __FUNCTION__, ni_rule_print(&buf, rule));
		ni_stringbuf_destroy(&buf);
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink NEWRULE message attribute");
failed:
	nlmsg_free(msg);
	return -1;
}

static int
__ni_rtnl_send_delrule(const ni_rule_t *rule)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	struct fib_rule_hdr frh;
	struct nl_msg *msg;
	int err;

	ni_debug_ifconfig("%s(%s)", __FUNCTION__, ni_rule_print(&buf, rule));
	ni_stringbuf_destroy(&buf);

	memset(&frh, 0, sizeof(frh));
	frh.family = rule->family;
	frh.action = rule->action;
	frh.table = rule->table > RT_TABLE_LOCAL ? RT_TABLE_UNSPEC : rule->table;
	frh.dst_len = rule->dst.len && !ni_sockaddr_is_unspecified(&rule->dst.addr) ? rule->dst.len : 0;
	frh.src_len = rule->src.len && !ni_sockaddr_is_unspecified(&rule->src.addr) ? rule->src.len : 0;
	if (rule->flags & NI_BIT(NI_RULE_INVERT))
		frh.flags |= FIB_RULE_INVERT;
	frh.tos = rule->tos;

	msg = nlmsg_alloc_simple(RTM_DELRULE, NLM_F_REQUEST);
	if (nlmsg_append(msg, &frh, sizeof(frh), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (ni_rtnl_rule_msg_put(msg, rule) < 0)
		goto nla_put_failure;

	if ((err = ni_nl_talk(msg, NULL)) && abs(err) != NLE_OBJ_NOTFOUND) {
		ni_error("%s(%s): rtnl_talk failed", __FUNCTION__, ni_rule_print(&buf, rule));
		ni_stringbuf_destroy(&buf);
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink DELRULE message attribute");
failed:
	nlmsg_free(msg);
	return -1;
}

static void
__ni_netdev_addr_complete(ni_netdev_t *dev, ni_address_t *ap)
{
	/*
	 * some code [e.g. getbroadcastnets() in glibc] expects,
	 * that the broadcast address is always set, so we have
	 * to calculate it ...
	 */
	if (dev->link.ifflags & NI_IFF_BROADCAST_ENABLED &&
	    ap->family == AF_INET && ap->prefixlen < 31 &&
	    ni_sockaddr_is_specified(&ap->local_addr) &&
	    ni_sockaddr_is_unspecified(&ap->bcast_addr)) {
		ap->bcast_addr = ap->local_addr;
		ap->bcast_addr.sin.sin_addr.s_addr |= htonl(0xFFFFFFFFUL >> ap->prefixlen);
	}
}

static ni_bool_t
__ni_netdev_addr_needs_update(const char *ifname, ni_address_t *o, ni_address_t *n)
{
	if (n->scope != -1 && o->scope != n->scope)
		return TRUE;

	if (o->prefixlen != n->prefixlen)
		return TRUE;

	if (!ni_sockaddr_equal(&o->local_addr, &n->local_addr))
		return TRUE;

	if (!ni_sockaddr_equal(&o->peer_addr, &n->peer_addr))
		return TRUE;

	if (!ni_sockaddr_equal(&o->bcast_addr, &n->bcast_addr))
		return TRUE;

	if (!ni_sockaddr_equal(&o->anycast_addr, &n->anycast_addr))
		return TRUE;

	switch (o->family) {
	case AF_INET:
		if (n->label && !ni_string_eq(o->label, n->label))
			return TRUE;	/* request to set it */
		if (!n->label && !ni_string_eq(o->label, ifname))
			return TRUE;	/* request to remove */
		break;

	case AF_INET6:
	{
		ni_ipv6_cache_info_t olft, nlft;
		struct timeval now;

		ni_timer_get_time(&now);
		ni_ipv6_cache_info_rebase(&olft, &o->ipv6_cache_info, &now);
		ni_ipv6_cache_info_rebase(&nlft, &n->ipv6_cache_info, &now);

		/* (invalid) 0 lifetimes mean unset/not provided by the lease;
		 * kernel uses ~0 (infinity) / permanent address when omitted */
		if ((nlft.valid_lft || nlft.preferred_lft) &&
		    (olft.valid_lft     != nlft.valid_lft ||
		     olft.preferred_lft != nlft.preferred_lft))
			return TRUE;
	}	break;

	default:
		break;
	}
	return FALSE;
}

static ni_bool_t
__ni_netdev_addr_can_replace(ni_address_t *o, ni_address_t *n)
{
	if (o->prefixlen != n->prefixlen)
		return FALSE;

	if (!ni_sockaddr_equal(&o->local_addr, &n->local_addr))
		return FALSE;

	if (!ni_sockaddr_equal(&o->peer_addr, &n->peer_addr))
		return FALSE;

	if (!ni_sockaddr_equal(&o->bcast_addr, &n->bcast_addr))
		return FALSE;

	if (!ni_sockaddr_equal(&o->anycast_addr, &n->anycast_addr))
		return FALSE;

	return TRUE;
}

/*
 * Update the addresses and routes assigned to an interface
 * for a given addrconf method
 */
static ni_bool_t
__ni_netdev_call_arp_util(ni_netdev_t *dev, ni_address_t *ap, ni_bool_t verify)
{
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	ni_bool_t rv;
	int ret;

	if (dev->link.hwaddr.type != ARPHRD_ETHER)
		return TRUE;

	/* In case the client is configured to ignore link-up
	 * and sets IPs already at device-up [without waiting
	 * for link detection], we cannot detect duplicate IPs
	 * or anounce them.
	 */
	if (!ni_netdev_link_is_up(dev))
		return TRUE;

	if (dev->link.ifflags & NI_IFF_POINT_TO_POINT)
		return TRUE;

	if (!(dev->link.ifflags & (NI_IFF_ARP_ENABLED|NI_IFF_BROADCAST_ENABLED)))
		return TRUE;

	/*
	 * This is a hack to validate it this way...
	 */
	cmd = ni_shellcmd_parse(WICKED_SBINDIR"/wicked");
	if (!cmd) {
		ni_warn("%s: cannot construct command to %s address '%s'",
			dev->name, verify ? "verify address" : "notify about",
			ni_sockaddr_print(&ap->local_addr));
		return TRUE;
	}
	ni_shellcmd_add_arg(cmd, "arp");
	if (verify) {
		ni_shellcmd_add_arg(cmd, "--verify");
		ni_shellcmd_add_arg(cmd, "3");
		ni_shellcmd_add_arg(cmd, "--notify");
		ni_shellcmd_add_arg(cmd, "0");
	} else {
		ni_shellcmd_add_arg(cmd, "--verify");
		ni_shellcmd_add_arg(cmd, "0");
		ni_shellcmd_add_arg(cmd, "--notify");
		ni_shellcmd_add_arg(cmd, "1");
	}
	ni_shellcmd_add_arg(cmd, dev->name);
	ni_shellcmd_add_arg(cmd, ni_sockaddr_print(&ap->local_addr));

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
			"%s: using new address %s cmd: %s",
			dev->name, verify ? "verify" : "notify", cmd->command);

	if ((pi = ni_process_new(cmd)) == NULL) {
		ni_warn("%s: cannot prepare process to %s address '%s'",
			dev->name, verify ? "verify" : "notify about",
			ni_sockaddr_print(&ap->local_addr));
		ni_shellcmd_release(cmd);
		return TRUE;
	}
	ni_shellcmd_release(cmd);

	rv  = FALSE;
	ret = ni_process_run_and_wait(pi);
	if (ret >= 0) {
		if (ret == NI_WICKED_RC_NOT_ALLOWED) {
			ni_warn("%s: address '%s' is already in use",
				dev->name, ni_sockaddr_print(&ap->local_addr));
		} else
		if (ret != NI_WICKED_RC_SUCCESS) {
			ni_warn("%s: address %s returned with status %d",
				dev->name, verify ? "verify" : "notify", ret);
		} else {
			ni_info("%s: successfully %s address '%s'",
				dev->name, verify ? "verified" : "notified about",
				ni_sockaddr_print(&ap->local_addr));
			rv = TRUE;
		}
	} else if(ret) {
		ni_warn("%s: address %s execution failed",
			dev->name, verify ? "verify" : "notify");
	}
	ni_process_free(pi);
	return rv;
}

static ni_bool_t
__ni_netdev_new_addr_verify(ni_netdev_t *dev, ni_address_t *ap)
{
	ni_ipv4_devinfo_t *ipv4;

	if (ap->family != AF_INET)
		return TRUE;

	if (ni_address_is_duplicate(ap))
		return FALSE;

	if (!ni_address_is_tentative(ap))
		return TRUE;

	ipv4 = ni_netdev_get_ipv4(dev);
	if (ipv4 && !ni_tristate_is_enabled(ipv4->conf.arp_verify)) {
		ni_address_set_tentative(ap, FALSE);
		return TRUE;
	}

	if (__ni_netdev_call_arp_util(dev, ap, TRUE)) {
		ni_address_set_tentative(ap, FALSE);
		return TRUE;
	} else {
		ni_address_set_duplicate(ap, TRUE);
		return FALSE;
	}
}

static ni_bool_t
__ni_netdev_new_addr_notify(ni_netdev_t *dev, ni_address_t *ap)
{
#if !defined(NI_IPV4_ARP_NOTIFY_IN_KERNEL)
	ni_ipv4_devinfo_t *ipv4;

	if (ap->family != AF_INET)
		return TRUE;

	if (ni_address_is_duplicate(ap))
		return FALSE;

	switch (dev->link.hwaddr.type) {
	case ARPHRD_LOOPBACK:
	case ARPHRD_IEEE1394:
		return TRUE;
	default: ;
	}

	ipv4 = ni_netdev_get_ipv4(dev);
	if (!ipv4 || ni_tristate_is_disabled(ipv4->conf.arp_notify))
		return TRUE;

	/* default/unset is "auto" -> same as verify */
	if (!ni_tristate_is_set(ipv4->conf.arp_notify) &&
	    !ni_tristate_is_enabled(ipv4->conf.arp_verify))
		return TRUE;

	return __ni_netdev_call_arp_util(dev, ap, FALSE);
#else
	return TRUE;
#endif
}

static int
__ni_netdev_update_addrs(ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_addrconf_lease_t       *new_lease)
{
	ni_addrconf_mode_t owner = NI_ADDRCONF_NONE;
	unsigned int family = AF_UNSPEC;
	ni_address_t *ap, *next;
	unsigned int minprio;
	int rv;

	do {
		__ni_global_seqno++;
	} while (!__ni_global_seqno);

	if (new_lease) {
		family = new_lease->family;
		owner = new_lease->type;
		for (ap = new_lease->addrs; ap; ap = ap->next)
			ap->owner = owner;
	} else
	if (old_lease) {
		family = old_lease->family;
		owner = old_lease->type;
	}

	for (ap = dev->addrs; ap; ap = next) {
		ni_address_t *new_addr;

		next = ap->next;
		if (family != ap->family)
			continue;

		/* See if the config list contains the address we've found in the
		 * system. */
		new_addr = new_lease ? __ni_netdev_address_in_list(new_lease->addrs, ap) : NULL;

		/* Do not touch addresses not managed by us. */
		if (ap->owner == NI_ADDRCONF_NONE) {
			if (new_addr == NULL)
				continue;

			/* Address was assigned to device, but we did not track it.
			 * Could be due to a daemon restart - simply assume this
			 * is ours now. */
			ap->owner = owner;
		}
		minprio = ni_addrconf_lease_get_priority(ni_netdev_get_lease(dev,
							ap->family, ap->owner));

		/* If the address was managed by us (ie its owned by a lease with
		 * the same family/addrconf mode), then we want to check whether
		 * it's co-owned by any other lease. It's possible that an address
		 * is configured through several different protocols, and we don't
		 * want to delete such an address until the last of these protocols
		 * has shut down. */
		if (ap->owner == owner) {
			ni_addrconf_lease_t *other;

			if ((other = __ni_netdev_address_to_lease(dev, ap, minprio)) != NULL)
				ap->owner = other->type;
		}

		if (ap->owner != owner) {
			/* The existing address is managed by a different
			 * addrconf mode.
			 *
			 * FIXME: auto6 lease steals all addrs of dhcp6.
			 */
			if (new_addr != NULL) {
				ni_warn("%s: address %s covered by a %s lease",
					dev->name,
					ni_sockaddr_print(&ap->local_addr),
					ni_addrconf_type_to_name(ap->owner));
			}

			continue;
		}

		if (new_addr != NULL) {
			/* mark it to skip in add loop */
			new_addr->seq = __ni_global_seqno;

			/* Check whether we need to update */
			__ni_netdev_addr_complete(dev, new_addr);
			if (!__ni_netdev_addr_needs_update(dev->name, ap, new_addr)) {
				ni_debug_ifconfig("%s: address %s/%u exists; no need to reconfigure",
					dev->name,
					ni_sockaddr_print(&ap->local_addr), ap->prefixlen);
				continue;
			}

			ni_debug_ifconfig("%s: existing address %s/%u needs to be reconfigured",
					dev->name,
					ni_sockaddr_print(&ap->local_addr), ap->prefixlen);

			if (!__ni_netdev_addr_can_replace(ap, new_addr))
				__ni_rtnl_send_deladdr(dev, ap);

			if ((rv = __ni_rtnl_send_newaddr(dev, new_addr, NLM_F_REPLACE)) < 0)
				return rv;

			new_addr->owner = new_lease->type;
			ni_address_copy(ap, new_addr);
		} else {
			if ((rv = __ni_rtnl_send_deladdr(dev, ap)) < 0)
				return rv;
		}
	}

	/* Loop over all addresses in the configuration and create
	 * those that don't exist yet.
	 */
	for (ap = new_lease ? new_lease->addrs : NULL ; ap; ap = ap->next) {
		if (ap->seq == __ni_global_seqno)
			continue;

		if (!__ni_netdev_new_addr_verify(dev, ap))
			continue;

		ni_debug_ifconfig("Adding new interface address %s/%u",
				ni_sockaddr_print(&ap->local_addr),
				ap->prefixlen);

		__ni_netdev_addr_complete(dev, ap);
		if ((rv = __ni_rtnl_send_newaddr(dev, ap, NLM_F_CREATE)) < 0)
			return rv;

		ap->owner = new_lease->type;
		__ni_netdev_new_addr_notify(dev, ap);
	}

	return 0;
}

/*
 * Check if a route already exists.
 */
static ni_route_t *
__ni_netdev_route_table_contains(ni_route_table_t *tab, const ni_route_t *rp)
{
	unsigned int i;
	ni_route_t *rp2;

	for (i = 0; i < tab->routes.count; ++i) {
		if ((rp2 = tab->routes.data[i]) == NULL)
			continue;

		if (rp->table != rp2->table)
			continue;

		if (ni_route_equal_destination(rp, rp2))
			return rp2;
	}

	return NULL;
}

static ni_route_t *
__ni_skip_conflicting_route(ni_netconfig_t *nc, ni_netdev_t *our_dev,
		ni_addrconf_lease_t *our_lease, ni_route_t *our_rp)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_netdev_t *dev;
	ni_route_table_t *tab;
	ni_route_t *rp;
	unsigned int i;

	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next) {
		if (!dev->routes)
			continue;

		if (!(tab = ni_route_tables_find(dev->routes, our_rp->table)))
			continue;

		for (i = 0; i < tab->routes.count; ++i) {
			rp = tab->routes.data[i];
			if (!rp || !ni_route_equal_destination(rp, our_rp))
				continue;

			ni_debug_ifconfig("%s: skipping conflicting %s:%s route: %s",
					our_dev->name,
					ni_addrfamily_type_to_name(our_lease->family),
					ni_addrconf_type_to_name(our_lease->type),
					ni_route_print(&buf, rp));
			ni_stringbuf_destroy(&buf);

			return rp;
		}
	}
	return NULL;
}

static int
__ni_netdev_update_routes(ni_netconfig_t *nc, ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_addrconf_lease_t       *new_lease)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_mode_t old_type = NI_ADDRCONF_NONE;
	unsigned int family = AF_UNSPEC;
	ni_route_table_t *tab, *cfg_tab;
	ni_route_t *rp, *new_route;
	unsigned int minprio, i;
	int rv = 0;

	do {
		__ni_global_seqno++;
	} while (!__ni_global_seqno);

	if (new_lease) {
		family = new_lease->family;
	} else
	if (old_lease) {
		family = old_lease->family;
		old_type = old_lease->type;
	}

	/* Loop over all tables and routes currently assigned to the interface.
	 * If the configuration no longer specifies it, delete it.
	 * We need to mimic the kernel's matching behavior when modifying
	 * the configuration of existing routes.
	 */
	for (tab = dev->routes; tab; tab = tab->next) {
		for (i = 0; i < tab->routes.count; ++i) {
			if ((rp = tab->routes.data[i]) == NULL)
				continue;

			if (family != rp->family)
				continue;

			/* See if the config list contains the route we've
			 * found in the system. */
			cfg_tab = new_lease ? ni_route_tables_find(new_lease->routes, rp->table) : NULL;
			if (cfg_tab)
				new_route = __ni_netdev_route_table_contains(cfg_tab, rp);
			else
				new_route = NULL;

			/* Do not touch route if not managed by us. */
			if (rp->owner == NI_ADDRCONF_NONE) {
				if (new_route == NULL)
					continue;

				/* Address was assigned to device, but we did not track it.
				 * Could be due to a daemon restart - simply assume this
				 * is ours now. */
				rp->owner = old_type;
			}
			minprio = ni_addrconf_lease_get_priority(ni_netdev_get_lease(dev, rp->family, rp->owner));

			/* If the route was managed by us (ie its owned by a lease with
			 * the same family/addrconf mode), then we want to check whether
			 * it's owned by any other lease. It's possible that a route
			 * is configured through different protocols. */
			if (rp->owner == old_type) {
				ni_addrconf_lease_t *other;

				if ((other = __ni_netdev_route_to_lease(dev, rp, minprio)) != NULL)
					rp->owner = other->type;
			}

			if (rp->owner != old_type) {
				/* The existing route is managed by a different
				 * addrconf mode.
				 */
				if (new_route != NULL) {
					ni_warn("route %s covered by a %s:%s lease",
						ni_route_print(&buf, rp),
						ni_addrfamily_type_to_name(rp->family),
						ni_addrconf_type_to_name(rp->owner));
					ni_stringbuf_destroy(&buf);
				}
				continue;
			}

			if (new_route != NULL) {
				if (__ni_rtnl_send_newroute(dev, new_route, NLM_F_REPLACE) >= 0) {
					ni_debug_ifconfig("%s: successfully updated existing route %s",
							dev->name, ni_route_print(&buf, rp));
					ni_stringbuf_destroy(&buf);
					new_route->owner = new_lease->type;
					new_route->seq = __ni_global_seqno;
					ni_netconfig_route_add(nc, new_route, dev);

					continue;
				}

				ni_error("%s: failed to update route %s",
					dev->name, ni_route_print(&buf, rp));
				ni_stringbuf_destroy(&buf);
			}

			ni_debug_ifconfig("%s: trying to delete existing route %s",
					dev->name, ni_route_print(&buf, rp));
			ni_stringbuf_destroy(&buf);

			if ((rv = __ni_rtnl_send_delroute(dev, rp)) < 0)
				return rv;
		}
	}

	/* Loop over all tables and routes in the configuration
	 * and create those that don't exist yet.
	 */
	for (tab = new_lease ? new_lease->routes : NULL; tab; tab = tab->next) {
		for (i = 0; i < tab->routes.count; ++i) {
			if ((rp = tab->routes.data[i]) == NULL)
				continue;

			if (rp->seq == __ni_global_seqno)
				continue;

			if (__ni_skip_conflicting_route(nc, dev, new_lease, rp))
				continue;

			ni_debug_ifconfig("%s: adding new %s:%s lease route %s",
					ni_addrfamily_type_to_name(new_lease->family),
					ni_addrconf_type_to_name(new_lease->type),
					dev->name, ni_route_print(&buf, rp));
			ni_stringbuf_destroy(&buf);

			if ((rv = __ni_rtnl_send_newroute(dev, rp, NLM_F_CREATE)) < 0)
				return rv;

			rp->owner = new_lease->type;
			rp->seq = __ni_global_seqno;
			ni_netconfig_route_add(nc, rp, dev);
		}
	}

	return rv;
}

const ni_addrconf_lease_t *
ni_netdev_find_rule_uuid_owner(ni_netdev_t *dev, ni_rule_t *rule, unsigned int minprio)
{
	const ni_addrconf_lease_t *lease;

	if (!dev || !rule || ni_uuid_is_null(&rule->owner))
		return NULL;

	if (!(lease = ni_netdev_get_lease_by_uuid(dev, &rule->owner)))
		return NULL;

	if (lease->family != rule->family)
		return NULL;

	if (lease->state != NI_ADDRCONF_STATE_GRANTED)
		return NULL;

	if (ni_addrconf_lease_get_priority(lease) < minprio)
		return NULL;

	if (!ni_rule_array_find_match(lease->rules, rule, ni_rule_equal))
		return NULL;

	return lease;
}

const ni_addrconf_lease_t *
ni_netdev_find_rule_lost_owner(ni_netdev_t *dev, ni_rule_t *rule, unsigned int minprio)
{
	const ni_addrconf_lease_t *found = NULL;
	const ni_addrconf_lease_t *lease;
	unsigned int prio;

	if (!dev || !rule)
		return NULL;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (lease->family != rule->family)
			continue;

		if (lease->state != NI_ADDRCONF_STATE_GRANTED)
			continue;

		if ((prio = ni_addrconf_lease_get_priority(lease)) < minprio)
			continue;

		if (!ni_rule_array_find_match(lease->rules, rule, ni_rule_equal))
			continue;

		if (!found || prio > ni_addrconf_lease_get_priority(found))
			found = lease;
	}

	return found;
}

static const ni_addrconf_lease_t *
ni_netinfo_find_rule_uuid_owner(ni_netconfig_t *nc, ni_rule_t *rule, unsigned int minprio)
{
	const ni_addrconf_lease_t *found = NULL;
	const ni_addrconf_lease_t *lease;
	unsigned int prio;
	ni_netdev_t *dev;

	if (!nc || !rule || ni_uuid_is_null(&rule->owner))
		return NULL;

	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next) {
		if (!(lease = ni_netdev_find_rule_uuid_owner(dev, rule, minprio)))
			continue;

		prio = ni_addrconf_lease_get_priority(lease);
		if (!found || prio > ni_addrconf_lease_get_priority(found))
			found = lease;
	}

	if (found) {
		ni_trace("found uuid rule owner");
	}
	return found;
}

static const ni_addrconf_lease_t *
ni_netinfo_find_rule_lost_owner(ni_netconfig_t *nc, ni_rule_t *rule, unsigned int minprio)
{
	const ni_addrconf_lease_t *found = NULL;
	const ni_addrconf_lease_t *lease;
	unsigned int prio;
	ni_netdev_t *dev;

	if (!nc || !rule)
		return NULL;

	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next) {
		if (!(lease = ni_netdev_find_rule_lost_owner(dev, rule, minprio)))
			continue;

		prio = ni_addrconf_lease_get_priority(lease);
		if (!found || prio > ni_addrconf_lease_get_priority(found))
			found = lease;
	}

	if (found) {
		ni_trace("found lost rule owner");
	}
	return found;
}

static const ni_addrconf_lease_t *
ni_netinfo_find_rule_owner(ni_netconfig_t *nc, ni_rule_t *rule, unsigned int minprio)
{
	const ni_addrconf_lease_t *found;

	if ((found = ni_netinfo_find_rule_uuid_owner(nc, rule, minprio)))
		return found;

	return ni_netinfo_find_rule_lost_owner(nc, rule, minprio);
}

static int
__ni_netdev_update_rules(ni_netconfig_t *nc, ni_netdev_t *dev,
			const ni_addrconf_lease_t *old_lease,
			ni_addrconf_lease_t       *new_lease)
{
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;
	ni_rule_array_t del_rules = NI_RULE_ARRAY_INIT;
	ni_rule_array_t mod_rules = NI_RULE_ARRAY_INIT;
	const ni_addrconf_lease_t *lease;
	ni_rule_array_t *old_rules;
	ni_rule_array_t *new_rules;
	ni_rule_t *rule, *r;
	unsigned int prio;
	unsigned int i;

	do {
		__ni_global_seqno++;
	} while (!__ni_global_seqno);

	if (new_lease && (new_rules = new_lease->rules)) {
		old_rules = old_lease ? old_lease->rules : NULL;

		for (i = 0; i < new_rules->count; ++i) {
			rule = new_rules->data[i];

			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG|NI_TRACE_ROUTE,
					"%s: checking new lease rule %s",
					dev->name, ni_rule_print(&out, rule));
			ni_stringbuf_destroy(&out);

			if (!rule || ni_rule_array_index(&mod_rules, rule) != -1U)
				continue;

			r = ni_rule_array_find_match(old_rules, rule, ni_rule_equal);
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG|NI_TRACE_ROUTE,
					"%s: rule to %s: %s", dev->name,
					r ? "update" : "create",
					ni_rule_print(&out, rule));
			ni_stringbuf_destroy(&out);

			rule->seq = r ? __ni_global_seqno : 0;
			ni_rule_array_append(&mod_rules, ni_rule_ref(rule));
		}
	} else {
		ni_trace("%s: no new lease rules", dev->name);
	}

	if (old_lease && (old_rules = old_lease->rules)) {
		new_rules = new_lease ? new_lease->rules : NULL;

		for (i = 0; i < old_rules->count; ++i) {
			rule = old_rules->data[i];

			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG|NI_TRACE_ROUTE,
					"%s: checking old lease rule %s",
					dev->name, ni_rule_print(&out, rule));
			ni_stringbuf_destroy(&out);

			if (!rule || ni_rule_array_index(&del_rules, rule) != -1U)
				continue;

			if (ni_rule_array_find_match(&mod_rules, rule, ni_rule_equal))
				continue;

			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG|NI_TRACE_ROUTE,
					"%s: rule to delete: %s",
					dev->name, ni_rule_print(&out, rule));
			ni_stringbuf_destroy(&out);

			ni_rule_array_append(&del_rules, ni_rule_ref(rule));
		}
	} else {
		ni_trace("%s: no old lease rules", dev->name);
	}

	for (i = 0; i < del_rules.count; ++i) {
		rule = del_rules.data[i];

		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG|NI_TRACE_ROUTE,
				"%s: about to modify rule %s",
				dev->name, ni_rule_print(&out, rule));
		ni_stringbuf_destroy(&out);

		if ((r = ni_netconfig_rule_find(nc, rule))) {
			const char *is_ours = "";

			if (ni_uuid_is_null(&r->owner) && ni_uuid_equal(&old_lease->uuid, &r->owner))
				is_ours = "is ours ";

			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG|NI_TRACE_ROUTE,
					"%s: rule to delete exist: %s <owner uuid %s%s>",
					dev->name, ni_rule_print(&out, r),
					ni_uuid_print(&r->owner), is_ours);

			if ((lease = ni_netinfo_find_rule_owner(nc, r, 0))) {
				ni_trace("%s: keeping rule, lease %s:%s uuid %s prio %u provides the rule",
						dev->name,
						ni_addrfamily_type_to_name(lease->family),
						ni_addrconf_type_to_name(lease->type),
						ni_uuid_print(&lease->uuid),
						ni_addrconf_lease_get_priority(lease));
				ni_trace("%s: taking over rule lease owner", dev->name);
				r->owner = lease->uuid;
				continue;
			}

			/* OK to delete -- no other lease provides it */
			if (__ni_rtnl_send_delrule(rule) < 0)
				continue;

			ni_netconfig_rule_del(nc, rule, NULL);
		}
	}

	for (i = 0; i < mod_rules.count; ++i) {
		rule = mod_rules.data[i];

		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG|NI_TRACE_ROUTE,
				"%s: about to apply rule %s",
				dev->name, ni_rule_print(&out, rule));
		ni_stringbuf_destroy(&out);

		if ((r = ni_netconfig_rule_find(nc, rule))) {
			const char *is_ours = "";

			if (old_lease && ni_uuid_is_null(&r->owner) && ni_uuid_equal(&old_lease->uuid, &r->owner))
				is_ours = "is ours ";

			prio = ni_addrconf_lease_get_priority(new_lease);
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG|NI_TRACE_ROUTE,
					"%s: rule to apply exist: %s <owner uuid %s%s> check minprio %u owner>",
					dev->name, ni_rule_print(&out, r),
					ni_uuid_print(&r->owner), is_ours, prio);

			if ((lease = ni_netinfo_find_rule_owner(nc, r, prio))) {
				ni_trace("%s: keeping rule lease %s:%s owner %s prio %u (ours %u)",
						dev->name,
						ni_addrfamily_type_to_name(lease->family),
						ni_addrconf_type_to_name(lease->type),
						ni_uuid_print(&lease->uuid),
						ni_addrconf_lease_get_priority(lease), prio);
			} else {
				ni_trace("%s: taking over rule lease owner", dev->name);
				r->owner = new_lease->uuid;
			}
			continue;
		} else {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG|NI_TRACE_ROUTE,
					"%s: applying new rule %s",
					dev->name, ni_rule_print(&out, rule));
			ni_stringbuf_destroy(&out);
		}

		if (!(r = ni_rule_clone(rule))) {
			ni_error("%s: unable to clone rule: %s", dev->name,
					ni_rule_print(&out, rule));
			ni_stringbuf_destroy(&out);
			continue;
		}

		r->seq = __ni_global_seqno;
		r->owner = new_lease->uuid;
		if (__ni_rtnl_send_newrule(r, NLM_F_REPLACE) < 0) {
			ni_rule_free(r);
		} else {
			ni_netconfig_rule_add(nc, r);
		}
	}

	return 0;
}


/*
 * Get the MTU specified by this lease
 */
static ni_bool_t
__ni_lease_get_mtu(const ni_addrconf_lease_t *lease, unsigned int *mtu_p)
{
	if (lease->type != NI_ADDRCONF_DHCP || lease->family != AF_INET)
		return 0;

	if (!(lease->update & (1 << NI_ADDRCONF_UPDATE_MTU)))
		return 0;

	*mtu_p = lease->dhcp4.mtu;
	if (*mtu_p == 0)
		return 0;

	return 1;
}

static ni_bool_t
__ni_netdev_get_minimum_lease_mtu(const ni_netdev_t *dev, unsigned int *mtu_p)
{
	ni_addrconf_lease_t *lp;
	unsigned int min_mtu;

	min_mtu = 65535;
	for (lp = dev->leases; lp; lp = lp->next) {
		unsigned int lease_mtu;

		if (__ni_lease_get_mtu(lp, &lease_mtu) && lease_mtu < min_mtu)
			min_mtu = lease_mtu;
	}

	*mtu_p = min_mtu;
	return min_mtu < 65535;
}

/*
 * Update the MTU of an interface based on the data we received
 * through some addrconf protocol.
 * Currently, only DHCP4 provides this sort of information.
 */
static int
__ni_netdev_update_mtu(ni_netconfig_t *nc, ni_netdev_t *dev,
			const ni_addrconf_lease_t *old_lease,
			ni_addrconf_lease_t       *new_lease)
{
	unsigned int req_mtu, req_mtu_min;

	if (new_lease != NULL) {
		/* New lease granted */
		if (!__ni_lease_get_mtu(new_lease, &req_mtu)) {
			/* FIXME: the device may be in a misconfigured state
			 * due to somebody messing with the MTU.
			 * We should really set the MTU to a sane value here,
			 * e.g. like:
			 *
			 * req_mtu = ni_netdev_default_mtu(dev);
			 *
			 * where ni_netdev_default_mtu specifies some sane default
			 * MTU based on dev->link.type.
			 */
			return 0;
		}

		/* No matter what we do, save the current device MTU value for later */
		if (dev->link.saved_mtu == 0)
			dev->link.saved_mtu = dev->link.mtu;

		/* If more than one lease specifies a MTU, pick the minimum value given */
		if (__ni_netdev_get_minimum_lease_mtu(dev, &req_mtu_min) && req_mtu_min < req_mtu)
			return 0;
	} else {
		/* Lease is being revoked.
		 * Restore the MTU to the minimum of all MTUs specified by
		 * leases, and the saved device MTU
		 */
		if (dev->link.saved_mtu == 0)
			return 0;

		__ni_netdev_get_minimum_lease_mtu(dev, &req_mtu);
		if (dev->link.saved_mtu < req_mtu)
			req_mtu = dev->link.saved_mtu;
	}

	return __ni_rtnl_link_change_mtu(dev, req_mtu);
}


/*
 * Initialialize a netdev of a just created inteface.
 *
 * The purpose of this function is to initialize the interface
 * just after it's creation with a _known_ interface name.
 *
 * We add it to list of known interfaces, mark created (dirty)
 * and wait for the NEWLINK event to update the rest.
 */
static int
__ni_system_netdev_create(ni_netconfig_t *nc,
				const char *ifname, unsigned int ifindex,
				ni_iftype_t iftype, ni_netdev_t **dev_ret)
{
	const char *type = ni_linktype_type_to_name(iftype);
	ni_netdev_t *dev;

	if (!ifname || !type || iftype == NI_IFTYPE_UNKNOWN) {
		ni_error("Rejecting to create an unknown interface %s index %u",
				ifname, ifindex);
		return -1;
	}

	if (!ifindex && !(ifindex = if_nametoindex(ifname))) {
		ni_error("%s: created %s interface, but can't find it's index",
				ifname, type);
		return -1;
	}

	if ((dev = ni_netdev_by_index(nc, ifindex))) {
		if (dev->link.type != iftype) {
			ni_error("%s: created %s interface, but found a %s type at index %u",
					ifname, type, ni_linktype_type_to_name(dev->link.type),
					ifindex);
		}
		*dev_ret = dev;
		return -NI_ERROR_DEVICE_EXISTS;
	}

	if (!(dev = ni_netdev_new(ifname, ifindex))) {
		ni_error("%s: unable to allocate %s netdev structure for index %u: %m",
				ifname, type, ifindex);
		return -1;
	}


	/* Hmm... init just the base link properties (e.g. type) or
	 * do we required to discover furher things (vlan,bridge)?
	 */
	__ni_device_refresh_link_info(nc, &dev->link);

	/* Mark to emit device-create in next newlink event later */
	dev->created = 1;
	/* Remove all flags, we have to emit them too */
	dev->link.ifflags &= ~(NI_IFF_DEVICE_UP | NI_IFF_LINK_UP | NI_IFF_NETWORK_UP);
	ni_netconfig_device_append(nc, ni_netdev_get(dev));

	if (dev->link.type != iftype) {
		ni_error("%s: created %s interface, but found a %s type at index %u",
				ifname, type, ni_linktype_type_to_name(dev->link.type),
				ifindex);
		*dev_ret = dev;
		return -NI_ERROR_DEVICE_EXISTS;
	}

	*dev_ret = dev;
	ni_debug_ifconfig("%s: created %s interface with index %u",
				ifname, type, ifindex);
	return 0;
}
