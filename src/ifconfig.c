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

#include "netinfo_priv.h"
#include "util_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "appconfig.h"
#include "process.h"
#include "debug.h"
#include "modprobe.h"

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

static int	__ni_netdev_update_addrs(ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_addrconf_lease_t       *new_lease);
static int	__ni_netdev_update_routes(ni_netconfig_t *nc, ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_addrconf_lease_t       *new_lease);
static int	__ni_netdev_update_mtu(ni_netconfig_t *nc, ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_addrconf_lease_t       *new_lease);

static int	__ni_rtnl_link_create(const ni_netdev_t *cfg);
static int	__ni_rtnl_link_change(ni_netdev_t *dev, const ni_netdev_t *cfg);

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

static int	__ni_system_netdev_create(ni_netconfig_t *nc,
					const char *ifname, unsigned int ifindex,
					ni_iftype_t iftype, ni_netdev_t **dev_ret);

static int
ni_system_interface_enslave(ni_netdev_t *master, ni_netdev_t *dev)
{
	int ret = -1;

	if (!master || !dev)
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
	case NI_IFTYPE_BRIDGE:
		ret = __ni_rtnl_link_add_port_up(dev, master->name,
						master->link.ifindex);
		if (ret == 0) {
			ni_netdev_ref_set(&dev->link.masterdev,
					master->name, master->link.ifindex);
		}
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

	/* FIXME: perform sanity check on configuration data */

	ifflags = ifp_req? ifp_req->ifflags : 0;
	if (ifflags & (NI_IFF_DEVICE_UP|NI_IFF_LINK_UP|NI_IFF_NETWORK_UP)) {
		/*
		 * master manages the link of a slave, redirect to enslave
		 * when there is a master set.
		 */
		if (dev->link.masterdev.index) {
			if (!dev->link.masterdev.name)
				ni_netdev_ref_bind_ifname(&dev->link.masterdev, nc);
			ni_debug_ifconfig("%s: already enslaved in master %s[#%u] -- skipping linkUp",
					dev->name, dev->link.masterdev.name ?
					dev->link.masterdev.name : "",
					dev->link.masterdev.index);
			return 0;
		}
		/* config lookup for master and redirect to master's enslave */
		if (ifp_req && !ni_string_empty(ifp_req->master.name)) {
			master = ni_netdev_by_name(nc, ifp_req->master.name);
			return ni_system_interface_enslave(master, dev);
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
	if (__ni_rtnl_link_create(cfg)) {
		ni_error("unable to create vlan interface %s", cfg->name);
		return -1;
	}

	return __ni_system_netdev_create(nc, cfg->name, 0, NI_IFTYPE_VLAN, dev_ret);
}

int
ni_system_vlan_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	return __ni_rtnl_link_change(dev, cfg);
}

int
ni_system_macvlan_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	return __ni_rtnl_link_change(dev, cfg);
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

	if (__ni_rtnl_link_create(cfg)) {
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

	if ((err = __ni_rtnl_link_create(cfg)) && abs(err) != NLE_EXIST) {
		ni_error("unable to create dummy interface %s", cfg->name);
		return err;
	}

	return __ni_system_netdev_create(nc, cfg->name, 0, NI_IFTYPE_DUMMY, dev_ret);
}

int
ni_system_dummy_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	return __ni_rtnl_link_change(dev, cfg);
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
		if (!ni_sysfs_netif_exists(tmpname, "ifindex"))
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
	unsigned int i;

	if (dev->link.type != NI_IFTYPE_BRIDGE) {
		ni_error("%s: %s is not a bridge interface", __func__, dev->name);
		return -1;
	}

	if (ni_sysfs_bridge_update_config(dev->name, bcfg) < 0) {
		ni_error("%s: failed to update sysfs attributes for %s", __func__, dev->name);
		return -1;
	}

	/* Add ports not yet used in bridge */
	for (i = 0; i < bcfg->ports.count; ++i) {
		ni_bridge_port_t *port = bcfg->ports.data[i];

		if (!port || ni_system_bridge_add_port(nc, dev, port) < 0)
			continue;
	}
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
 * Create a bonding device
 */
int
ni_system_bond_create(ni_netconfig_t *nc, const char *ifname, const ni_bonding_t *bond, ni_netdev_t **dev_ret)
{
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

	if (!ni_sysfs_bonding_is_master(ifname)) {
		int success = 0;

		ni_debug_ifconfig("%s: creating bond master", ifname);
		if (ni_sysfs_bonding_add_master(ifname) >= 0) {
			unsigned int i;

			/* Wait for bonding_masters to appear */
			for (i = 0; i < 400; ++i) {
				if ((success = ni_sysfs_bonding_is_master(ifname)) != 0)
					break;
				usleep(25000);
			}
		}

		if (!success) {
			ni_error("unable to create bonding device %s", ifname);
			return -1;
		}
	}

	return __ni_system_netdev_create(nc, ifname, 0, NI_IFTYPE_BOND, dev_ret);
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
 * Set up a bonding device
 */
int
ni_system_bond_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_bonding_t *bond_cfg)
{
	const char *complaint;
	ni_bonding_t *bond;
	ni_string_array_t enslaved;
	ni_string_array_t slaves;
	ni_bool_t is_up;
	ni_bool_t has_slaves;
	unsigned int i;

	complaint = ni_bonding_validate(bond_cfg);
	if (complaint != NULL) {
		ni_error("%s: cannot set up bonding device: %s", dev->name, complaint);
		return -NI_ERROR_INVALID_ARGS;
	}

	if ((bond = ni_netdev_get_bonding(dev)) == NULL) {
		ni_error("%s: not a bonding interface ", dev->name);
		return -1;
	}

	/* Fetch the number of currently active slaves */
	ni_string_array_init(&slaves);
	ni_string_array_init(&enslaved);
	ni_sysfs_bonding_get_slaves(dev->name, &enslaved);
	has_slaves = enslaved.count > 0;

	is_up = ni_netdev_device_is_up(dev);
	if (!has_slaves) {
		/*
		 * Stage 0 -- pre-enslave:
		 *
		 * Most attributes need to be written prior to adding the first slave
		 * or bringing up the bonding interface ...
		 */
		ni_debug_ifconfig("%s: configuring bonding device (stage 0.%u.%u)",
				dev->name, is_up, has_slaves);
		if (ni_bonding_write_sysfs_attrs(dev->name, bond_cfg, bond,
						is_up, has_slaves) < 0) {
			ni_error("%s: cannot configure bonding device (stage 0.%u.%u)",
				dev->name, is_up, has_slaves);
			return -1;
		}
	}

	/* Filter out only currently available slaves */
	for (i = 0; i < bond_cfg->slave_names.count; ++i) {
		const char *name = bond_cfg->slave_names.data[i];
		ni_netdev_t *sdev;

		if (name && (sdev = ni_netdev_by_name(nc, name))) {
			int ret;

			if (!ni_netdev_device_is_ready(sdev)) {
				ni_error("%s: cannot enslave %s, device is not ready",
					dev->name, sdev->name);
				continue;
			}

			if (sdev->link.masterdev.index) {
				if (sdev->link.masterdev.index == dev->link.ifindex)
					continue;

				ni_error("%s: cannot enslave %s, already enslaved in %s[%u]",
					dev->name, sdev->name, sdev->link.masterdev.name ?
					sdev->link.masterdev.name : "", sdev->link.masterdev.index);
				continue; /* ? */
			} else
			if (ni_string_array_index(&enslaved, name) != -1)
				continue;

			ret = __ni_rtnl_link_add_slave_down(sdev, dev->name, dev->link.ifindex);
			if (ret == 0) {
				ni_netdev_ref_set(&sdev->link.masterdev,
						dev->name, dev->link.ifindex);
			} else {
				__ni_rtnl_link_down(sdev);
				ni_string_array_append(&slaves, name);
			}
		}
	}

	if (slaves.count > 0) {
		/*
		 * Stage 1 -- enslave:
		 */
		ni_debug_ifconfig("%s: configuring bonding slaves (stage 1.%u.%u)",
				dev->name, is_up, has_slaves);

		/* Update the list of slave devices */
		if (ni_sysfs_bonding_set_list_attr(dev->name, "slaves", &slaves) < 0) {
			ni_string_array_destroy(&slaves);

			ni_error("%s: could not update list of slaves", dev->name);
			return -NI_ERROR_PERMISSION_DENIED;
		}
		ni_string_array_destroy(&slaves);
	}

	ni_sysfs_bonding_get_slaves(dev->name, &enslaved);
	has_slaves = enslaved.count > 0;
	if (has_slaves) {
		/*
		 * Stage 2 -- post-enslave:
		 *
		 * Some attributes as e.g. active_slave, can be set only when
		 * the bond is running with at least one enslaved slaves.
		 */
		ni_debug_ifconfig("%s: configuring bonding device (stage 2.%u.%u)",
				dev->name, is_up, has_slaves);
		if (ni_bonding_write_sysfs_attrs(dev->name, bond_cfg, bond,
						is_up, has_slaves) < 0) {
			ni_error("%s: cannot configure bonding device (stage 2.%u.%u)",
				dev->name, is_up, has_slaves);
			return -1;
		}
	} else {
		ni_error("%s: bond is in a not operable state without any slave",
				dev->name);
		return -1;
	}

	return 0;
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
	if (ni_string_array_index(&bond->slave_names, slave_dev->name) >= 0)
		return 0;

	ni_bonding_add_slave(bond, slave_dev->name);
	if (ni_sysfs_bonding_set_list_attr(dev->name, "slaves", &bond->slave_names) < 0) {
		ni_error("%s: could not update list of slaves", dev->name);
		return -NI_ERROR_PERMISSION_DENIED;
	}

	return 0;
}

/*
 * Remove a slave from a bond
 */
int
ni_system_bond_remove_slave(ni_netconfig_t *nc, ni_netdev_t *dev, unsigned int slave_idx)
{
	ni_bonding_t *bond = dev->bonding;
	ni_netdev_t *slave_dev;
	int idx;

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
	if ((idx = ni_string_array_index(&bond->slave_names, slave_dev->name)) < 0)
		return 0;

	ni_string_array_remove_index(&bond->slave_names, idx);
	if (ni_sysfs_bonding_set_list_attr(dev->name, "slaves", &bond->slave_names) < 0) {
		ni_error("%s: could not update list of slaves", dev->name);
		return -NI_ERROR_PERMISSION_DENIED;
	}

	return 0;
}

int
ni_system_tap_change(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	return __ni_rtnl_link_change(dev, cfg);
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
 * Create a ppp interface
 */
int
ni_system_ppp_create(ni_netconfig_t *nc, const char *ifname, ni_ppp_t *cfg, ni_netdev_t **dev_ret)
{
	ni_ppp_t *ppp;
	char *newname;
	int ret;

	ni_debug_ifconfig("%s: creating ppp interface", ifname);

	ppp = ni_ppp_new(NULL);
	if ((newname = __ni_ppp_create_device(ppp, ifname)) == NULL) {
		ni_error("__ni_ppp_create_device(%s) failed", ifname);
		ni_ppp_free(ppp);
		return -1;
	}

	if (cfg) {
		ppp->config = cfg->config;
		cfg->config = NULL;
	}

	ret = __ni_system_netdev_create(nc, newname, 0, NI_IFTYPE_PPP, dev_ret);
	if (ret == 0 && dev_ret && *dev_ret)
		ni_netdev_set_ppp(*dev_ret, ppp);
	return ret;
}

/*
 * Delete a ppp interface
 */
int
ni_system_ppp_delete(ni_netdev_t *dev)
{
	ni_ppp_t *ppp;

	if ((ppp = dev->ppp) == NULL)
		return 0;

	ni_ppp_close(ppp);
	return 0;
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

	if (__ni_rtnl_link_create(cfg)) {
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
	return __ni_rtnl_link_change(dev, cfg);
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
	struct nlattr *infodata;
	uint32_t *local_ip;
	uint32_t *remote_ip;
	uint8_t pmtudisc;

	if (!(infodata = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	local_ip = (uint32_t *)link->hwaddr.data;
	remote_ip = (uint32_t *)link->hwpeer.data;

	switch(type) {
	case NI_IFTYPE_IPIP:
	case NI_IFTYPE_SIT:
		NLA_PUT_U8(msg, IFLA_IPTUN_PROTO, IPPROTO_IPV6);
		NLA_PUT_U32(msg, IFLA_IPTUN_LINK, 0);
		NLA_PUT_U32(msg, IFLA_IPTUN_LOCAL, *local_ip);
		NLA_PUT_U32(msg, IFLA_IPTUN_REMOTE, *remote_ip);
		NLA_PUT_U8(msg, IFLA_IPTUN_TTL, tunnel->ttl);
		NLA_PUT_U8(msg, IFLA_IPTUN_TOS, tunnel->tos);
		pmtudisc = tunnel->pmtudisc ? 1 : 0;
		NLA_PUT_U8(msg, IFLA_IPTUN_PMTUDISC, pmtudisc);
		NLA_PUT_U16(msg, IFLA_IPTUN_FLAGS, tunnel->iflags);

		break;

	case NI_IFTYPE_GRE:
		NLA_PUT_U32(msg, IFLA_GRE_LINK, 0);
		NLA_PUT_U32(msg, IFLA_GRE_LOCAL, *local_ip);
		NLA_PUT_U32(msg, IFLA_GRE_REMOTE, *remote_ip);
		NLA_PUT_U8(msg, IFLA_GRE_TTL, tunnel->ttl);
		NLA_PUT_U8(msg, IFLA_GRE_TOS, tunnel->tos);
		pmtudisc = tunnel->pmtudisc ? 1 : 0;
		NLA_PUT_U8(msg, IFLA_GRE_PMTUDISC, pmtudisc);
		NLA_PUT_U16(msg, IFLA_GRE_FLAGS, tunnel->iflags);

		break;

	default:
		break;
	}

	nla_nest_end(msg, infodata);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_sit(struct nl_msg *msg, const ni_netdev_t *cfg)
{
	struct nlattr *linkinfo;

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;
	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "sit");

	if (cfg->sit->isatap)
		cfg->sit->tunnel.iflags |= SIT_ISATAP;

	if (__ni_rtnl_link_put_tunnel(msg, &cfg->link, &cfg->sit->tunnel, NI_IFTYPE_SIT) < 0)
		goto nla_put_failure;

	nla_nest_end(msg, linkinfo);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_ipip(struct nl_msg *msg, const ni_netdev_t *cfg)
{
	struct nlattr *linkinfo;

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;
	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "ipip");

	if (__ni_rtnl_link_put_tunnel(msg, &cfg->link, &cfg->ipip->tunnel, NI_IFTYPE_IPIP) < 0)
		goto nla_put_failure;

	nla_nest_end(msg, linkinfo);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_put_gre(struct nl_msg *msg, const ni_netdev_t *cfg)
{
	struct nlattr *linkinfo;

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;
	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "gre");

	if (__ni_rtnl_link_put_tunnel(msg, &cfg->link, &cfg->gre->tunnel, NI_IFTYPE_GRE) < 0)
		goto nla_put_failure;

	nla_nest_end(msg, linkinfo);

	return 0;

nla_put_failure:
	return -1;
}

static int
__ni_rtnl_link_create(const ni_netdev_t *cfg)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;
	int err = -1;

	if (!cfg || ni_string_empty(cfg->name))
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
__ni_rtnl_link_change(ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;

	if (!dev || !cfg)
		return -1;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = dev->link.ifindex;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST);
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (!ni_netdev_link_is_up(dev)) {
		if (cfg->name && __ni_rtnl_link_put_ifname(msg, cfg->name) < 0)
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

	default:
		break;
	}

	if (ni_nl_talk(msg, NULL))
		goto failed;

	ni_debug_ifconfig("successfully modified interface %s", cfg->name);
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

	if (ap->bcast_addr.ss_family != AF_UNSPEC
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
		/* (invalid) 0 lifetimes mean unset/not provided by the lease;
		 * kernel uses ~0 (infinity) / permanent address when omitted */
		if ((n->ipv6_cache_info.valid_lft || n->ipv6_cache_info.preferred_lft) &&
		    (o->ipv6_cache_info.valid_lft     != n->ipv6_cache_info.valid_lft ||
		     o->ipv6_cache_info.preferred_lft != n->ipv6_cache_info.preferred_lft))
			return TRUE;
		break;

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
	ni_addrconf_mode_t old_type = NI_ADDRCONF_NONE;
	unsigned int family = AF_UNSPEC;
	ni_address_t *ap, *next;
	unsigned int minprio;
	int rv;

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
			ap->owner = old_type;
		}
		minprio = ni_addrconf_lease_get_priority(ni_netdev_get_lease(dev,
							ap->family, ap->owner));

		/* If the address was managed by us (ie its owned by a lease with
		 * the same family/addrconf mode), then we want to check whether
		 * it's co-owned by any other lease. It's possible that an address
		 * is configured through several different protocols, and we don't
		 * want to delete such an address until the last of these protocols
		 * has shut down. */
		if (ap->owner == old_type) {
			ni_addrconf_lease_t *other;

			if ((other = __ni_netdev_address_to_lease(dev, ap, minprio)) != NULL)
				ap->owner = other->type;
		}

		if (ap->owner != old_type) {
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
					__ni_netdev_record_newroute(nc, dev, new_route);

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
			__ni_netdev_record_newroute(nc, dev, rp);
		}
	}

	return rv;
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
