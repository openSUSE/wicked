/*
 *	DHCP6 supplicant -- client device
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012 Marius Tomaschewski <mt@suse.de>
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
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <net/if_arp.h>
#include <netlink/netlink.h>	/* address flags, TODO: get rid of them */
#include <arpa/inet.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/util.h>
#include <wicked/vlan.h>
#include <wicked/ipv6.h>

#include "dhcp6/dhcp6.h"
#include "dhcp6/device.h"
#include "dhcp6/protocol.h"
#include "dhcp6/fsm.h"
#include "appconfig.h"
#include "util_priv.h"
#include "netinfo_priv.h"
#include "iaid.h"
#include "duid.h"
#include "dhcp.h"


/*
 * DHCP6 package name and version based on config.h
 */
#ifndef NI_DHCP6_PACKAGE_NAME
#ifndef PACKAGE_NAME
#define	NI_DHCP6_PACKAGE_NAME			"wicked-dhcp6"
#else
#define	NI_DHCP6_PACKAGE_NAME			PACKAGE_NAME "-dhcp6"
#endif
#endif
#ifndef NI_DHCP6_PACKAGE_VERSION
#ifndef PACKAGE_VERSION
#define	NI_DHCP6_PACKAGE_VERSION		"0.0.0"
#else
#define	NI_DHCP6_PACKAGE_VERSION		PACKAGE_VERSION
#endif
#endif

/*
 * Default Vendor enterprise number + data in <name>/<version> format.
 *
 * http://www.iana.org/assignments/enterprise-numbers
 */
#ifndef NI_DHCP6_VENDOR_ENTERPRISE_NUMBER
#define	NI_DHCP6_VENDOR_ENTERPRISE_NUMBER	7075	/* SUSE */
#endif
#ifndef NI_DHCP6_VENDOR_VERSION_STRING
#define NI_DHCP6_VENDOR_VERSION_STRING		NI_DHCP6_PACKAGE_NAME"/"NI_DHCP6_PACKAGE_VERSION
#endif

ni_dhcp6_device_t *		ni_dhcp6_active;

static void			ni_dhcp6_device_close(ni_dhcp6_device_t *);
static void			ni_dhcp6_device_free(ni_dhcp6_device_t *);

static void			ni_dhcp6_device_set_config(ni_dhcp6_device_t *, ni_dhcp6_config_t *);
static void			ni_dhcp6_device_start_timer_init(ni_timeout_param_t *);
static void			ni_dhcp6_device_start_timer_cancel(ni_dhcp6_device_t *);

static ni_bool_t		ni_dhcp6_device_refresh_mode(ni_dhcp6_device_t *, ni_netdev_t *);

static int			ni_dhcp6_device_transmit_arm_delay(ni_dhcp6_device_t *);
static void			ni_dhcp6_device_retransmit_arm(ni_dhcp6_device_t *);

static void			ni_dhcp6_device_config_free(ni_dhcp6_config_t *);
static void			ni_dhcp6_config_set_request_options(const char *, ni_uint_array_t *, const ni_string_array_t *);


/*
 * Create and destroy dhcp6 device handles
 */
ni_dhcp6_device_t *
ni_dhcp6_device_new(const char *ifname, const ni_linkinfo_t *link)
{
	ni_dhcp6_device_t *dev, **pos;

	for (pos = &ni_dhcp6_active; (dev = *pos) != NULL; pos = &dev->next)
		;

	dev = xcalloc(1, sizeof(*dev));
	dev->users = 1;

	ni_string_dup(&dev->ifname, ifname);
	dev->link.ifindex = link->ifindex;

	/*
	 * https://tools.ietf.org/html/rfc8415#section-18.2 (rfc3315#section-18.1)
	 * https://tools.ietf.org/html/rfc8415#section-18.2.12 (rfc3315#section-18.1.2)
	 * https://tools.ietf.org/html/rfc8415#section-18.2.10.1 (rfc3315#section-18.1.8)
	 *
	 * it's either a fresh link and we have to perform dad anyway
	 * or we just (re-)started and "may have moved to a new link",
	 * so assume a reconnect to retrigger dad in next lease commit.
	 */
	dev->link.reconnect = TRUE;

	dev->fsm.state = NI_DHCP6_STATE_INIT;

	/* append to end of list */
	*pos = dev;

	return dev;
}

ni_dhcp6_device_t *
ni_dhcp6_device_by_index(unsigned int ifindex)
{
	ni_dhcp6_device_t *dev;

	for (dev = ni_dhcp6_active; dev; dev = dev->next) {
		if (dev->link.ifindex == ifindex)
			return dev;
	}
	return NULL;
}

/*
 * Refcount handling
 */
ni_dhcp6_device_t *
ni_dhcp6_device_get(ni_dhcp6_device_t *dev)
{
	ni_assert(dev->users);
	dev->users++;
	return dev;
}

void
ni_dhcp6_device_put(ni_dhcp6_device_t *dev)
{
	ni_assert(dev->users);
	if (--(dev->users) == 0)
		ni_dhcp6_device_free(dev);
}

static ni_netdev_t *
ni_dhcp6_device_netdev(const ni_dhcp6_device_t *dev)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;

	nc = ni_global_state_handle(0);
	if (!nc || !(ifp = ni_netdev_by_index(nc, dev->link.ifindex))) {
		ni_error("%s: Unable to find network interface by index %u",
			dev->ifname, dev->link.ifindex);
		return NULL;
	}
	return ifp;
}

/*
 * Cleanup functions
 */
static void
ni_dhcp6_device_close(ni_dhcp6_device_t *dev)
{
	ni_dhcp6_mcast_socket_close(dev);

	if (dev->fsm.timer) {
		ni_warn("%s: timer active while close, disarming", dev->ifname);
		ni_timer_cancel(dev->fsm.timer);
		dev->fsm.timer = NULL;
	}
}

void
ni_dhcp6_device_stop(ni_dhcp6_device_t *dev)
{
	/*
	 * Cancel start timer if any
	 */
	ni_dhcp6_device_start_timer_cancel(dev);

	/*
	 * Reset FSM timers and go to init state
	 */
	ni_dhcp6_fsm_reset(dev);

	/*
	 * Close the sockets.
	 *
	 * Do not drop the lease -- it will be confirmed
	 * (or released on config/mode change), when the
	 * device comes up again.
	 */
	ni_dhcp6_device_close(dev);

	/*
	 * Drop existing config but not the request, that
	 * we may need to restart after confirm failure.
	 *
	 * After, the device is stopped until an acquire
	 * or restart arrives.
	 */
	ni_dhcp6_device_set_config(dev, NULL);
}

static void
ni_dhcp6_device_free(ni_dhcp6_device_t *dev)
{
	ni_dhcp6_device_t **pos;

	ni_assert(dev->users == 0);
	ni_debug_dhcp("%s: Deleting dhcp6 device with index %u",
			dev->ifname, dev->link.ifindex);

	ni_buffer_destroy(&dev->message);
	ni_dhcp6_device_drop_lease(dev);
	ni_dhcp6_device_drop_best_offer(dev);
	ni_dhcp6_device_close(dev);

	/* Drop existing config and request */
	ni_dhcp6_device_set_config(dev, NULL);
	ni_dhcp6_device_set_request(dev, NULL);

	ni_string_free(&dev->ifname);
	dev->link.ifindex = 0;

	for (pos = &ni_dhcp6_active; *pos; pos = &(*pos)->next) {
		if (*pos == dev) {
			*pos = dev->next;
			break;
		}
	}

	free(dev);
}


/*
 * Device handle request set helper
 */
void
ni_dhcp6_device_set_request(ni_dhcp6_device_t *dev, ni_dhcp6_request_t *request)
{
	if(dev->request && dev->request != request)
		ni_dhcp6_request_free(dev->request);
	dev->request = request;
}

/*
 * Device handle config set helper
 */
static void
ni_dhcp6_device_config_free(ni_dhcp6_config_t *config)
{
	if (config) {
		ni_dhcp6_ia_list_destroy(&config->ia_list);
		ni_string_array_destroy(&config->user_class);
		ni_string_array_destroy(&config->vendor_class.data);
		ni_var_array_destroy(&config->vendor_opts.data);
		ni_uint_array_destroy(&config->request_options);
		free(config);
	}
}

static void
ni_dhcp6_device_set_config(ni_dhcp6_device_t *dev, ni_dhcp6_config_t *config)
{
	if (dev->config && dev->config != config)
		ni_dhcp6_device_config_free(dev->config);
	dev->config = config;
}

void
ni_dhcp6_device_set_lease(ni_dhcp6_device_t *dev,  ni_addrconf_lease_t *lease)
{
	if (dev->lease && dev->lease != lease)
		ni_addrconf_lease_free(dev->lease);
	dev->lease = lease;
	if (dev->config && lease)
		lease->uuid = dev->config->uuid;
}

void
ni_dhcp6_device_set_best_offer(ni_dhcp6_device_t *dev, ni_addrconf_lease_t *lease,
		int pref, int weight)
{
	if (dev->best_offer.lease && dev->best_offer.lease != lease)
		ni_addrconf_lease_free(dev->best_offer.lease);
	dev->best_offer.lease = lease;
	dev->best_offer.pref = pref;
	dev->best_offer.weight = weight;
	if (dev->config && lease)
		lease->uuid = dev->config->uuid;
}

void
ni_dhcp6_device_drop_lease(ni_dhcp6_device_t *dev)
{
	ni_addrconf_lease_t *lease;

	if ((lease = dev->lease) != NULL) {
		ni_addrconf_lease_free(lease);
		dev->lease = NULL;
	}
}

void
ni_dhcp6_device_drop_best_offer(ni_dhcp6_device_t *dev)
{
	dev->best_offer.pref = -1;
	dev->best_offer.weight = -1;
	if (dev->best_offer.lease)
		ni_addrconf_lease_free(dev->best_offer.lease);
	dev->best_offer.lease = NULL;
}

unsigned int
ni_dhcp6_device_uptime(const ni_dhcp6_device_t *dev, unsigned int clamp)
{
	struct timeval now;
	struct timeval delta;
	unsigned long uptime = 0;

	ni_timer_get_time(&now);
	if (timerisset(&dev->retrans.start) && timercmp(&now, &dev->retrans.start, >)) {
		timersub(&now, &dev->retrans.start, &delta);

		/* uptime in hundredths of a second (10^-2 seconds) */
		uptime = (delta.tv_sec * 100 + delta.tv_usec / 10000);
	}
	return (uptime < clamp) ? uptime : clamp;
}

ni_bool_t
ni_dhcp6_device_iaid(const ni_dhcp6_device_t *dev, unsigned int *iaid)
{
	unsigned int migrate;
	ni_netconfig_t *nc;
	ni_netdev_t *ndev;

	if (!dev || !iaid)
		return FALSE;

	nc = ni_global_state_handle(0);
	if(!nc || !(ndev = ni_netdev_by_index(nc, dev->link.ifindex))) {
		ni_error("%s: Unable to find network interface by index %u",
			dev->ifname, dev->link.ifindex);
		return FALSE;
	}

	if (!(migrate = dev->iaid) && dev->lease) {
		if (!(migrate = ni_dhcp6_lease_ia_na_iaid(dev->lease)))
			migrate = ni_dhcp6_lease_ia_ta_iaid(dev->lease);
	}

	if (!ni_iaid_acquire(iaid, ndev, migrate))
		return FALSE;

	return TRUE;
}

void
ni_dhcp6_device_show_addrs(ni_dhcp6_device_t *dev)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;
	ni_address_t *ap;
	unsigned int nr;

	if (!ni_log_level_at(NI_LOG_DEBUG2))
		return;

	nc = ni_global_state_handle(0);
	if(!nc || !(ifp = ni_netdev_by_index(nc, dev->link.ifindex))) {
		ni_error("%s: Unable to find network interface by index %u",
			dev->ifname, dev->link.ifindex);
		return;
	}

	for (nr = 0, ap = ifp->addrs; ap; ap = ap->next) {
		if (ap->family != AF_INET6)
			continue;

		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_DHCP,
				"%s: address[%u] %s/%u%s, scope=%s, flags%s%s%s%s%s",
				dev->ifname, nr++,
				ni_sockaddr_print(&ap->local_addr), ap->prefixlen,
				(ni_address_is_linklocal(ap) ? " [link-local]" : ""),
				(ap->scope == RT_SCOPE_HOST ? "host" :
				 (ap->scope == RT_SCOPE_LINK ? "link" :
				  (ap->scope == RT_SCOPE_SITE ? "site" : "universe"))),
				(ni_address_is_temporary(ap) ? " temporary"  : ""),
				(ni_address_is_permanent(ap) ? " permanent"  : " dynamic"),
				(ni_address_is_deprecated(ap) ? " deprecated"  : ""),
				(ni_address_is_tentative(ap) ? " tentative " : ""),
				(ni_address_is_duplicate(ap) ? " duplicate " : "")
		);
	}
}

static void
ni_dhcp6_device_start_timeout_cb(void *user_data, const ni_timer_t *timer)
{
	ni_dhcp6_device_t *dev = user_data;

	if (!dev || dev->start_timer != timer)
		return;
	dev->start_timer = NULL;

	ni_timeout_recompute(&dev->start_params);
	ni_dhcp6_device_start(dev);
}

static void
ni_dhcp6_device_start_timer_cancel(ni_dhcp6_device_t *dev)
{
	if (dev && dev->start_timer) {
		ni_timer_cancel(dev->start_timer);
		dev->start_timer = NULL;
	}
}

static inline void
ni_dhcp6_device_start_timer_init(ni_timeout_param_t *tmo)
{
	memset(tmo, 0, sizeof(*tmo));
	tmo->jitter.max  = NI_DHCP6_MAX_JITTER;
	tmo->timeout     = NI_DHCP6_SOL_TIMEOUT;
	tmo->max_timeout = NI_DHCP6_SOL_MAX_RT;
	tmo->nretries    = NI_DHCP6_UNLIMITED;
	tmo->increment   = NI_DHCP6_EXP_BACKOFF;
}

static int
ni_dhcp6_device_start_timer_arm(ni_dhcp6_device_t *dev)
{
	ni_timeout_t timeout;

	timeout = ni_timeout_randomize(dev->start_params.timeout, &dev->start_params.jitter);
	if (dev->start_timer) {
		ni_timer_rearm(dev->start_timer, timeout);
	} else {
		dev->start_timer = ni_timer_register(timeout, ni_dhcp6_device_start_timeout_cb, dev);
	}
	return 1;
}

static inline int
ni_dhcp6_device_start_auto_prefix(ni_dhcp6_device_t *dev)
{
	struct timeval now;
	struct timeval end;
	unsigned int defer;
	ni_netdev_t *ifp;

	/* auto + prefix:
	 * wait a bit until ready + RA arrives, but then
	 * start to request prefix and complete it later.
	 */
	if (!(ifp = ni_dhcp6_device_netdev(dev)))
		return -1;

	ni_dhcp6_device_show_addrs(dev);
	if (!ni_dhcp6_device_is_ready(dev, ifp))
		return ni_dhcp6_device_start_timer_arm(dev);

	/* refresh in case kernel forgot to send it
	 * (we increment timeout between attempts) */
	ni_dhcp6_device_refresh_mode(dev, ifp);

	/* request prefix after 1/3 defer timeout */
	ni_timer_get_time(&now);
	end = dev->start_time;
	if (!(defer = (dev->config->defer_timeout / 3)))
		defer = dev->config->acquire_timeout / 3;
	end.tv_sec += defer;
	if (timercmp(&end, &now, >) &&
	    (dev->config->mode & NI_BIT(NI_DHCP6_MODE_AUTO)))
		return ni_dhcp6_device_start_timer_arm(dev);

	ni_dhcp6_device_start_timer_cancel(dev);
	return ni_dhcp6_fsm_start(dev);
}

static inline int
ni_dhcp6_device_start_auto(ni_dhcp6_device_t *dev)
{
	ni_netdev_t *ifp;

	/* auto:
	 * wait until ready + RA arrived
	 */
	if (dev->config->mode & NI_BIT(NI_DHCP6_MODE_PREFIX))
		return ni_dhcp6_device_start_auto_prefix(dev);

	if (!(ifp = ni_dhcp6_device_netdev(dev)))
		return -1;

	ni_dhcp6_device_show_addrs(dev);
	if (!ni_dhcp6_device_is_ready(dev, ifp))
		return ni_dhcp6_device_start_timer_arm(dev);

	/* refresh in case kernel forgot to send it
	 * (we increment timeout between attempts) */
	ni_dhcp6_device_refresh_mode(dev, ifp);

	if (dev->config->mode & NI_BIT(NI_DHCP6_MODE_AUTO))
		return ni_dhcp6_device_start_timer_arm(dev);

	ni_dhcp6_device_start_timer_cancel(dev);
	return ni_dhcp6_fsm_start(dev);
}

int
ni_dhcp6_device_start(ni_dhcp6_device_t *dev)
{
	if (!dev || !dev->config) {
		ni_error("%s: Cannot start DHCPv6 without config",
			dev->ifname);
		return -1;
	}

	if (dev->config->mode & NI_BIT(NI_DHCP6_MODE_AUTO))
		return ni_dhcp6_device_start_auto(dev);

	ni_dhcp6_device_show_addrs(dev);
	if (!ni_dhcp6_device_is_ready(dev, NULL))
		return ni_dhcp6_device_start_timer_arm(dev);

	ni_dhcp6_device_start_timer_cancel(dev);
	return ni_dhcp6_fsm_start(dev);
}

int
ni_dhcp6_device_restart(ni_dhcp6_device_t *dev)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	char *err = NULL;
	int rv = -1;

	ni_dhcp6_device_stop(dev);

	if (!dev->request)
		return -1;

	ni_debug_dhcp("%s: Restart DHCPv6 acquire request %s in mode %s",
		dev->ifname, ni_uuid_print(&dev->request->uuid),
		ni_dhcp6_mode_format(&buf, dev->request->mode, NULL));
	ni_stringbuf_destroy(&buf);

	if ((rv = ni_dhcp6_acquire(dev, dev->request, &err)) >= 0)
		return rv;

	ni_error("%s: Cannot restart DHCPv6 acquire request %s in mode %s%s%s",
		dev->ifname, ni_uuid_print(&dev->request->uuid),
		ni_dhcp6_mode_format(&buf, dev->request->mode, NULL),
		(err ? ": " : ""), (err ? err : ""));
	ni_stringbuf_destroy(&buf);
	ni_string_free(&err);

	/* Also discard the request */
	ni_dhcp6_device_set_request(dev, NULL);
	return rv;
}

void
ni_dhcp6_restart(void)
{
	ni_dhcp6_device_t *dev;

	for (dev = ni_dhcp6_active; dev; dev = dev->next) {
		ni_dhcp6_device_restart(dev);
	}
}

static int
ni_dhcp6_device_set_lladdr(ni_dhcp6_device_t *dev, const ni_address_t *addr)
{
	if (ni_address_is_duplicate(addr)) {
		ni_error("%s: Link-local IPv6 address is marked duplicate: %s",
			dev->ifname, ni_sockaddr_print(&addr->local_addr));
		return -1;
	}
	if (ni_address_is_tentative(addr)) {
		ni_debug_dhcp("%s: Link-local IPv6 address is tentative: %s",
			dev->ifname, ni_sockaddr_print(&addr->local_addr));
		return 1;
	}

	ni_debug_dhcp("%s: Found usable link-local IPv6 address: %s",
		dev->ifname, ni_sockaddr_print(&addr->local_addr));

	memcpy(&dev->link.addr, &addr->local_addr, sizeof(dev->link.addr));
	return 0;
}

static int
ni_dhcp6_device_find_lladdr(ni_dhcp6_device_t *dev)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;
	ni_address_t *addr;
	int rv = 1, cnt = 0;

	nc = ni_global_state_handle(0);
	if(!nc || !(ifp = ni_netdev_by_index(nc, dev->link.ifindex))) {
		ni_error("%s: Unable to find network interface by index %u",
			dev->ifname, dev->link.ifindex);
		return -1;
	}

	if (!ni_netdev_link_is_up(ifp)) {
		ni_debug_dhcp("%s: Link is not (yet) up", dev->ifname);
		return 1;
	}

	for(addr = ifp->addrs; addr; addr = addr->next) {
		if (addr->family != AF_INET6 || !ni_address_is_linklocal(addr))
			continue;

		cnt++;
		if ((rv = ni_dhcp6_device_set_lladdr(dev, addr)) == 0)
			return 0;
	}

	if (cnt == 0) {
		ni_debug_dhcp("%s: Link-local IPv6 address not (yet) available",
				dev->ifname);
	}
	return rv;
}

static ni_bool_t
ni_dhcp6_device_refresh_mode(ni_dhcp6_device_t *dev, ni_netdev_t *ifp)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);

	if (!nc || !dev || (!ifp && !(ifp = ni_dhcp6_device_netdev(dev))))
		return FALSE;

	/*
	 * Refresh ipv6 link info on NEWPREFIX events in auto mode
	 * when both flags are FALSE (no dhcp at all).
	 *
	 * When NEWPREFIX arrives, there definitely were an RA, but
	 * when the RA contained a RetransTimer/ReachableTime of 0
	 * (unspecified / no change to before), the kernel forgets
	 * to send a NEWLINK event, even other things in the RA, as
	 * the managed/other-config flags we wait for changed.
	 */
	__ni_device_refresh_ipv6_link_info(nc, ifp);

	return ni_dhcp6_device_update_mode(dev, ifp);
}

ni_bool_t
ni_dhcp6_device_update_mode(ni_dhcp6_device_t *dev, const ni_netdev_t *ifp)
{
	ni_stringbuf_t old = NI_STRINGBUF_INIT_DYNAMIC;
	ni_stringbuf_t new = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int omode = 0;

	if (!ifp && !(ifp = ni_dhcp6_device_netdev(dev)))
		return FALSE;

	if (ni_ipv6_devinfo_ra_received(ifp->ipv6) && dev->config) {
		omode = dev->config->mode;

		if (ifp->ipv6->radv.managed_addr) {
			dev->config->mode |= NI_BIT(NI_DHCP6_MODE_MANAGED);
			dev->config->mode = ni_dhcp6_mode_adjust(dev->config->mode);
		} else
		if (ifp->ipv6->radv.other_config) {
			dev->config->mode |= NI_BIT(NI_DHCP6_MODE_INFO);
			dev->config->mode = ni_dhcp6_mode_adjust(dev->config->mode);
		} else {
			dev->config->mode &= ~NI_BIT(NI_DHCP6_MODE_AUTO);
		}

		if (omode != dev->config->mode) {
			ni_dhcp6_mode_format(&old, omode, NULL);
			ni_dhcp6_mode_format(&new, dev->config->mode, NULL);
			ni_debug_dhcp("%s: updated dhcp6 mode from %s to %s",
					dev->ifname, old.string, new.string ?
					new.string : "disabled");
			ni_stringbuf_destroy(&old);
			ni_stringbuf_destroy(&new);
			return TRUE;
		}
	}
	return FALSE;
}

ni_bool_t
ni_dhcp6_device_is_ready(const ni_dhcp6_device_t *dev, const ni_netdev_t *ifp)
{
	if (!ifp && !(ifp = ni_dhcp6_device_netdev(dev)))
		return FALSE;

	return	ni_netdev_link_is_up(ifp) &&
		ni_sockaddr_is_ipv6_linklocal(&dev->link.addr);
}

ni_bool_t
ni_dhcp6_device_check_ready(ni_dhcp6_device_t *dev)
{
	if (ni_dhcp6_device_is_ready(dev, NULL))
		return TRUE;
	return ni_dhcp6_device_find_lladdr(dev) == 0;
}

const ni_ipv6_ra_info_t *
ni_dhcp6_device_ra_info(const ni_dhcp6_device_t *dev, const ni_netdev_t *ifp)
{
	if (!ifp) {
		ni_netconfig_t *nc = ni_global_state_handle(0);
		ifp = nc ? ni_netdev_by_index(nc, dev->link.ifindex) : NULL;
	}
	return ifp && ifp->ipv6 ? &ifp->ipv6->radv : NULL;
}

const ni_ipv6_ra_pinfo_t *
ni_dhcp6_device_ra_pinfo(const ni_dhcp6_device_t *dev, const ni_netdev_t *ifp)
{
	const ni_ipv6_ra_info_t *radv;

	radv = ni_dhcp6_device_ra_info(dev, ifp);
	return radv ? radv->pinfo : NULL;
}

int
ni_dhcp6_device_transmit_init(ni_dhcp6_device_t *dev)
{
	if (ni_dhcp6_device_transmit_arm_delay(dev))
		return 0;

	return ni_dhcp6_device_transmit_start(dev);
}

int
ni_dhcp6_device_transmit_start(ni_dhcp6_device_t *dev)
{
	ni_timer_get_time(&dev->retrans.start);
	ni_dhcp6_device_retransmit_arm(dev);

	return ni_dhcp6_device_transmit(dev);
}

static int
ni_dhcp6_device_transmit_arm_delay(ni_dhcp6_device_t *dev)
{
	ni_int_range_t jitter;
	ni_timeout_t   delay;

	/*
	 * rfc3315#section-5.5 (17.1.2, 18.1.2, 18.1.5):
	 *
	 * Initial delay is a MUST for Solicit, Confirm and InfoRequest.
	 * "[..]
	 *  MUST be delayed by a random amount of time between 0 and [..]_MAX_DELAY
	 * [..]"
	 *
	 * We could track the RA receive time that "causes the client to invoke the
	 * stateful address autoconfiguration" and subtract the delta from delay...
	 */
	if (dev->retrans.delay == 0)
		return FALSE;

	jitter.min = 0;
	jitter.max = dev->retrans.delay;
	delay = ni_timeout_randomize(0, &jitter);

	ni_debug_dhcp("%s: setting initial transmit delay of 0 .. %u.%03us",
			dev->ifname, NI_TIMEOUT_SEC(delay), NI_TIMEOUT_MSEC(delay));

	ni_dhcp6_fsm_set_timeout_msec(dev, delay);

	return TRUE;
}

static void
ni_dhcp6_device_retransmit_arm(ni_dhcp6_device_t *dev)
{
	/* when we're here, initial delay is over */
	dev->retrans.delay = 0;

	/* Leave, when retransmissions aren't enabled */
	if (dev->retrans.params.nretries == 0)
		return;

	if (dev->fsm.state == NI_DHCP6_STATE_SELECTING && dev->retrans.count == 0) {
		/*
		 * rfc3315#section-17.1.2
		 *
		 * "[...]
		 * The message exchange is not terminated by the receipt of an Advertise
		 * before the first RT has elapsed. Rather, the client collects Advertise
		 * messages until the first RT has elapsed.
		 * Also, the first RT MUST be selected to be strictly greater than IRT
		 * by choosing RAND to be strictly greater than 0.
		 * [...]"
		 */
		dev->retrans.params.jitter.min = 0; /* exception, no negative jitter */
		dev->retrans.params.jitter.max = 0 + dev->retrans.jitter;
	} else {
		/*
		 * rfc3315#section-14
		 *
		 * "[...]
		 * Each new RT include a randomization factor (RAND) [...]
		 * between -0.1 and +0.1.
		 * [...]"
		 */
		dev->retrans.params.jitter.min = 0 - dev->retrans.jitter,
		dev->retrans.params.jitter.max = 0 + dev->retrans.jitter;
	}

	/*
	 * rfc3315#section-14
	 *
	 * "[...]RT for the first message transmission is based on IRT:
	 * 		RT = IRT + RAND*IRT
	 *  [...]"
	 *
	 *  IRT is already initialized in retrans.params.timeout.
	 */
	dev->retrans.params.timeout += ni_timeout_randomize(dev->retrans.params.timeout,
							&dev->retrans.params.jitter);
	ni_timer_get_time(&dev->retrans.deadline);
	ni_timeval_add_timeout(&dev->retrans.deadline, dev->retrans.params.timeout);
	ni_debug_dhcp("%s: initialized xid 0x%06x retransmission timeout of %u.%03u [%.3f .. %.3f] sec",
			dev->ifname, dev->dhcp6.xid,
			NI_TIMEOUT_SEC(dev->retrans.params.timeout),
			NI_TIMEOUT_MSEC(dev->retrans.params.timeout),
			(double)dev->retrans.params.jitter.min/1000,
			(double)dev->retrans.params.jitter.max/1000);


	if (dev->retrans.duration) {
		/*
		 * rfc3315#section-14
		 *
		 * "[...]
		 * MRD specifies an upper bound on the length of time a client may
		 * retransmit a message. Unless MRD is zero, the message exchange
		 * fails once MRD seconds have elapsed since the client first
		 * transmitted the message.
		 * [...]"
		 */
		ni_dhcp6_fsm_set_timeout_msec(dev, dev->retrans.duration);
		ni_debug_dhcp("%s: initialized xid 0x%06x duration %u.%03u sec",
			dev->ifname, dev->dhcp6.xid,
			NI_TIMEOUT_SEC(dev->retrans.duration),
			NI_TIMEOUT_MSEC(dev->retrans.duration));
	}
}

void
ni_dhcp6_device_retransmit_disarm(ni_dhcp6_device_t *dev)
{
	struct timeval now;

	ni_timer_get_time(&now);

	if (dev->dhcp6.xid || dev->retrans.params.timeout) {
		ni_debug_dhcp("%s: disarming xid 0x%06x retransmission",
				dev->ifname, dev->dhcp6.xid);
	}

	dev->dhcp6.xid = 0;
	memset(&dev->retrans, 0, sizeof(dev->retrans));
}

static ni_bool_t
ni_dhcp6_device_retransmit_advance(ni_dhcp6_device_t *dev)
{
	ni_timeout_t previous = dev->retrans.params.timeout;

	/*
	 * rfc3315#section-14
	 *
	 * "[...]
	 * Each new RT include a randomization factor (RAND) [...]
	 * between -0.1 and +0.1.
	 * [...]
	 * RT for each subsequent message transmission is based on
	 * the previous value of RT:
	 *
	 * 	RT = 2*RTprev + RAND*RTprev
	 * [...]"
	 *
	 */
	if( ni_timeout_recompute(&dev->retrans.params)) {
		dev->retrans.params.jitter = ni_dhcp6_jitter_rebase(previous,
						0 - dev->retrans.jitter,
						0 + dev->retrans.jitter);
		dev->retrans.params.timeout += ni_timeout_randomize(previous,
						&dev->retrans.params.jitter);
		ni_timer_get_time(&dev->retrans.deadline);
		ni_timeval_add_timeout(&dev->retrans.deadline, dev->retrans.params.timeout);

		ni_debug_dhcp("%s: advanced xid 0x%06x retransmission timeout from %u.%03u to %u.%03u [%.3f .. %.3f] sec",
				dev->ifname, dev->dhcp6.xid,
				NI_TIMEOUT_SEC(previous),
				NI_TIMEOUT_MSEC(previous),
				NI_TIMEOUT_SEC(dev->retrans.params.timeout),
				NI_TIMEOUT_MSEC(dev->retrans.params.timeout),
				(double)dev->retrans.params.jitter.min/1000,
				(double)dev->retrans.params.jitter.max/1000);

		return TRUE;
	}
	ni_debug_dhcp("%s: xid 0x%06x retransmission limit reached", dev->ifname, dev->dhcp6.xid);
	return FALSE;
}

int
ni_dhcp6_device_retransmit(ni_dhcp6_device_t *dev)
{
	int rv;

	if (!ni_dhcp6_device_retransmit_advance(dev)) {
		rv = ni_dhcp6_fsm_retransmit_end(dev);
		ni_dhcp6_device_retransmit_disarm(dev);
		return rv;
	}

	if ((rv = ni_dhcp6_fsm_retransmit(dev)) < 0)
		return rv;

	ni_debug_dhcp("%s: xid 0x%06x retransmitted, next deadline in %ld.%03ld",
			dev->ifname, dev->dhcp6.xid,
			dev->retrans.deadline.tv_sec,
			dev->retrans.deadline.tv_usec/1000);
	return 0;
}

static ni_bool_t
ni_dhcp6_config_init_duid(ni_dhcp6_device_t *dev, ni_dhcp6_config_t *config, const char *preferred)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ndev;

	nc = ni_global_state_handle(0);
	if(!nc || !(ndev = ni_netdev_by_index(nc, dev->link.ifindex))) {
		ni_error("%s: Unable to find network interface by index %u",
				dev->ifname, dev->link.ifindex);
		return FALSE;
	}

	if (!ni_duid_acquire(&config->client_duid, ndev, nc, preferred))
		return FALSE;

	return TRUE;
}

static ni_addrconf_lease_t *
ni_dhcp6_recover_lease(ni_dhcp6_device_t *dev)
{
	ni_addrconf_lease_t *lease = NULL;

	if (!dev)
		return NULL;

	lease = ni_addrconf_lease_file_read(dev->ifname, NI_ADDRCONF_DHCP, AF_INET6);
	if (!ni_addrconf_lease_is_valid(lease) ||
	    lease->type != NI_ADDRCONF_DHCP || lease->family != AF_INET6) {
		ni_addrconf_lease_free(lease);
		return NULL;
	}

	return lease;
}

static inline unsigned int
__nondefault(unsigned int req, unsigned int def)
{
	return req ? req : def;
}

/*
 * Process a request to reconfigure the device (ie rebind a lease, or discover
 * a new lease).
 */
int
ni_dhcp6_acquire(ni_dhcp6_device_t *dev, const ni_dhcp6_request_t *req, char **err)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_dhcp6_config_t *config;
	const char *mode;
	size_t len;
	int rv;

	if (!dev || !req || !err) {
		return -NI_ERROR_INVALID_ARGS;
	}

	if (ni_uuid_is_null(&req->uuid)) {
		ni_string_dup(err, "Null UUID");
		return -NI_ERROR_INVALID_ARGS;
	}

	config = xcalloc(1, sizeof(*config));
	config->uuid = req->uuid;
	config->mode = ni_dhcp6_mode_adjust(req->mode);
	config->flags= req->flags;

	if ((mode = ni_dhcp6_mode_format(&buf, config->mode, NULL))) {
		ni_note("%s: Request to acquire DHCPv6 lease with UUID %s in mode %s",
			dev->ifname, ni_uuid_print(&config->uuid), mode);
		ni_stringbuf_destroy(&buf);
	} else {
		ni_string_printf(err, "invalid DHCPv6 request mode 0x%x (0x%x)",
				req->mode, config->mode);
		ni_dhcp6_device_config_free(config);
		return -NI_ERROR_INVALID_ARGS;
	}

	if (req->update == -1U) {
		config->update = ni_config_addrconf_update(dev->ifname, NI_ADDRCONF_DHCP, AF_INET6);
	} else {
		config->update = req->update;
		config->update &= ni_config_addrconf_update_mask(NI_ADDRCONF_DHCP, AF_INET6);
	}
	config->dry_run	= req->dry_run;

	if (req->address_len <= ni_af_address_prefixlen(AF_INET6))
		config->address_len = req->address_len;

	ni_timer_get_time(&dev->start_time);
	ni_dhcp6_device_start_timer_init(&dev->start_params);

	config->start_delay	= __nondefault(req->start_delay,
					NI_DHCP6_START_DELAY);

	if (config->dry_run != NI_DHCP6_RUN_NORMAL) {
		/*
		 * in dry run mode, we don't use rapid commit
		 * and do not defer but just fail.
		 */
		config->rapid_commit	= FALSE;
		config->start_delay	= __nondefault(req->start_delay,
						NI_DHCP6_START_DELAY);
		config->defer_timeout	= 0;
		config->acquire_timeout	= __nondefault(req->acquire_timeout,
						NI_DHCP6_DEFER_TIMEOUT);
	} else {
		config->rapid_commit	= req->rapid_commit;
		config->defer_timeout	= __nondefault(req->defer_timeout,
						NI_DHCP6_DEFER_TIMEOUT);
		config->acquire_timeout	= __nondefault(req->acquire_timeout,
						NI_DHCP6_ACQUIRE_TIMEOUT);

		if (config->acquire_timeout)
			config->acquire_timeout += config->defer_timeout;
	}
	config->lease_time	= __nondefault(req->lease_time,
						NI_DHCP6_LEASE_TIME);
	config->recover_lease	= req->recover_lease;
	config->refresh_lease  	= req->refresh_lease;
	config->release_lease	= req->release_lease;

	if (!dev->lease && config->dry_run != NI_DHCP6_RUN_OFFER && config->recover_lease)
		ni_dhcp6_device_set_lease(dev, ni_dhcp6_recover_lease(dev));

	if (!ni_dhcp6_device_iaid(dev, &dev->iaid)) {
		ni_string_printf(err, "Unable to generate a device IAID");
		ni_dhcp6_device_config_free(config);
		return -NI_ERROR_GENERAL_FAILURE;
	}
	if (!ni_dhcp6_config_init_duid(dev, config, req->clientid)) {
		size_t len;

		ni_dhcp6_device_config_free(config);
		if ((len = ni_string_len(req->clientid))) {
			ni_string_printf(err, "Unable to parse hex client DUID '%s'",
				ni_print_suspect(req->clientid, len));
			return -NI_ERROR_INVALID_ARGS;
		} else {
			ni_string_printf(err, "Unable to generate a client DUID");
			return -NI_ERROR_GENERAL_FAILURE;
		}
	}

	/* Copy IA-PD (only) with prefix-hint to the config for later use.
	 * Another IA's aren't using a hint and will be added according to
	 * the managed/info mode bit later to request automatically.
	 *
	 * Once we support multiple prefixes, we will need to sort requests
	 * by iaid into a unique list of IAs + per-ia prefix hints. */
	if ((config->mode & NI_BIT(NI_DHCP6_MODE_PREFIX)) && req->prefix_reqs) {
		const ni_dhcp6_prefix_req_t *pr;
		ni_dhcp6_ia_addr_t *ph, *padr;
		ni_dhcp6_ia_t *ia;

		for (pr = req->prefix_reqs; pr; pr = pr->next) {
			/* one IA using our iaid + hint for now */
			if (!(ia = ni_dhcp6_ia_pd_new(dev->iaid)))
				continue;

			for (ph = pr->hints; ph; ph = ph->next) {
				if (!ph->plen)
					continue;

				padr = ni_dhcp6_ia_addr_clone(ph);
				ni_dhcp6_ia_addr_list_append(&ia->addrs, padr);
				break; /* one pd hint per ia only */
			}
			ni_dhcp6_ia_list_append(&config->ia_list, ia);
			break; /* one ia-pd only */
		}
	}

	/* There is no hostname option, we always use FQDN option */
	config->fqdn = req->fqdn;
	if ((len = ni_string_len(req->hostname)) > 0) {
		if (ni_check_domain_name(req->hostname, len, 0)) {
			strncpy(config->hostname, req->hostname, sizeof(config->hostname) - 1);

			if (config->fqdn.enabled == NI_TRISTATE_DEFAULT)
				ni_tristate_set(&config->fqdn.enabled, TRUE);
		} else {
			ni_debug_dhcp(
				"%s: Discarded suspect hostname in DHCPv6 acquire request %s: '%s'",
				dev->ifname, ni_uuid_print(&req->uuid),
				ni_print_suspect(req->hostname, len));
		}
	}
	if (config->fqdn.enabled == NI_TRISTATE_DEFAULT)
		ni_tristate_set(&config->fqdn.enabled, FALSE);
	if (config->fqdn.enabled == NI_TRISTATE_ENABLE && ni_string_empty(config->hostname))
		config->fqdn.update = NI_DHCP_FQDN_UPDATE_NONE;

	/* TODO: get from req info */
	ni_dhcp6_config_vendor_class(&config->vendor_class.en, &config->vendor_class.data);
	ni_dhcp6_config_vendor_opts(&config->vendor_opts.en, &config->vendor_opts.data);
	ni_dhcp6_config_set_request_options(dev->ifname, &config->request_options, &req->request_options);

	/*
	 * This basically fails only if we can't find netdev (any more)
	 */
	if (!ni_dhcp6_device_is_ready(dev, NULL)) {
		ni_dhcp6_device_show_addrs(dev);
		rv = ni_dhcp6_device_find_lladdr(dev);
		if (rv < 0) {
			ni_dhcp6_device_config_free(config);
			ni_string_dup(err, "Cannot read network device settings");
			return -NI_ERROR_GENERAL_FAILURE;
		}
	}

	ni_dhcp6_device_set_config(dev, config);

	if (config->defer_timeout) {
		/*
		 * set timer to emit lease-deferred signal to wicked
		 * when there is no IPv6 RA on the network or DHCPv6
		 * is not used (managed and other-config unset).
		 */
		ni_dhcp6_fsm_set_timeout_sec(dev, config->defer_timeout);
		dev->fsm.fail_on_timeout = 0;
	} else
	if (config->acquire_timeout) {
		/*
		 * immediately set timer to fail after timeout,
		 * that is to drop config, disarm fsm and stop.
		 */
		ni_dhcp6_fsm_set_timeout_sec(dev, config->acquire_timeout);
		dev->fsm.fail_on_timeout = 1;
	}

	/*
	 * This basically fails only if we can't find netdev (any more)
	 */
	rv = ni_dhcp6_device_start(dev);
	if (rv < 0) {
		ni_dhcp6_device_stop(dev);
		ni_string_dup(err, "Cannot start DHCPv6 processing");
		return -NI_ERROR_GENERAL_FAILURE;
	}
	return rv;
}


/*
 * Process a request to unconfigure the device (ie drop the lease).
 */
void
ni_dhcp6_start_release(void *user_data, const ni_timer_t *timer)
{
	ni_dhcp6_device_t *dev = user_data;

	if (dev->fsm.timer != timer)
		return;
	dev->fsm.timer = NULL;

	ni_dhcp6_device_set_request(dev, NULL);
	if (ni_dhcp6_fsm_release(dev) > 0)
		return;

	ni_dhcp6_device_drop_lease(dev);
	ni_dhcp6_device_stop(dev);
}

int
ni_dhcp6_drop(ni_dhcp6_device_t *dev, const ni_dhcp6_drop_request_t *req)
{
	char *rel_uuid = NULL;
	const char *action = "drop";

	if (ni_tristate_is_set(req->release)) {
		if (ni_tristate_is_enabled(req->release))
			action = "release";
	} else {
		if (dev->config && dev->config->release_lease)
			action = "release";
	}

	ni_string_dup(&rel_uuid, ni_uuid_print(&req->uuid));
	if (dev->lease == NULL || dev->config == NULL) {
		ni_info("%s: Request to %s DHCPv6 lease%s%s: no lease",
			dev->ifname, action,
			rel_uuid ? " using UUID " : "", rel_uuid ? rel_uuid : "");
		ni_string_free(&rel_uuid);

		ni_dhcp6_device_set_request(dev, NULL);
		ni_dhcp6_device_drop_lease(dev);
		ni_dhcp6_device_stop(dev);
		return -NI_ERROR_ADDRCONF_NO_LEASE;
	}

	ni_note("%s: Request to %s DHCPv6 lease%s%s: starting...",
			dev->ifname, action,
			rel_uuid ? " using UUID " : "", rel_uuid ? rel_uuid : "");
	ni_string_free(&rel_uuid);

	dev->lease->uuid = req->uuid;
	dev->config->uuid = req->uuid;
	if (ni_tristate_is_enabled(req->release))
		dev->config->release_lease = TRUE;
	else
	if (ni_tristate_is_disabled(req->release))
		dev->config->release_lease = FALSE;

	ni_dhcp6_device_start_timer_cancel(dev);
	ni_dhcp6_fsm_reset(dev);
	dev->fsm.state = NI_DHCP6_STATE_RELEASING;
	dev->fsm.timer = ni_timer_register(0, ni_dhcp6_start_release, dev);
	return 1;
}

/*
 * Handle link up/down events
 */
void
ni_dhcp6_device_event(ni_dhcp6_device_t *dev, ni_netdev_t *ifp, ni_event_t event)
{
	switch (event) {
	case NI_EVENT_DEVICE_UP:
		if (!ni_string_eq(dev->ifname, ifp->name)) {
			ni_debug_dhcp("%s: Updating interface name to %s",
					dev->ifname, ifp->name);
			ni_string_dup(&dev->ifname, ifp->name);
		}
	break;
	case NI_EVENT_DEVICE_DOWN:
		ni_debug_dhcp("%s: network interface went down", dev->ifname);
		ni_dhcp6_device_stop(dev);
	break;

	case NI_EVENT_NETWORK_UP:
		ni_debug_dhcp("%s: received network up event", dev->ifname);
	break;
	case NI_EVENT_NETWORK_DOWN:
		ni_debug_dhcp("%s: received network down event", dev->ifname);
	break;

	case NI_EVENT_LINK_UP:
		/* retrigger dad on lease commit */
		dev->link.reconnect = TRUE;
		ni_debug_dhcp("received link up event");
		if (dev->config) {
			ni_dhcp6_device_start(dev);
		}
	break;
	case NI_EVENT_LINK_DOWN:
		ni_debug_dhcp("received link down event");
		if (dev->config) {
			ni_dhcp6_fsm_reset(dev);
			ni_dhcp6_device_close(dev);
		}
	break;

	case NI_EVENT_DEVICE_CHANGE:
		if (dev->config && (dev->config->mode & NI_BIT(NI_DHCP6_MODE_AUTO))) {
			ni_dhcp6_device_update_mode(dev, ifp);
			ni_dhcp6_device_start(dev);
		}
	break;

	default:
		ni_debug_dhcp("%s: received other event", dev->ifname);
	break;
	}
}

void
ni_dhcp6_address_event(ni_dhcp6_device_t *dev, ni_netdev_t *ifp, ni_event_t event,
			const ni_address_t *addr)
{
	switch (event) {
	case NI_EVENT_ADDRESS_UPDATE:
		if (dev->link.addr.ss_family == AF_UNSPEC) {
			if(addr->family == AF_INET6 && ni_address_is_linklocal(addr)) {
				ni_dhcp6_device_set_lladdr(dev, addr);
			}
		}

		ni_dhcp6_fsm_address_event(dev, ifp, event, addr);
	break;

	case NI_EVENT_ADDRESS_DELETE:
		if (addr->local_addr.ss_family == AF_INET6 &&
		    ni_sockaddr_equal(&addr->local_addr, &dev->link.addr)) {
			/*
			 * Multicast socket is bound to and unusable now; disarm
			 * until a link-local address update event arrives ...
			 */
			ni_dhcp6_fsm_reset(dev);
			ni_dhcp6_device_close(dev);
			memset(&dev->link.addr, 0, sizeof(dev->link.addr));
		}

		ni_dhcp6_fsm_address_event(dev, ifp, event, addr);
	break;

	default:
	break;
	}
}

void
ni_dhcp6_prefix_event(ni_dhcp6_device_t *dev, ni_netdev_t *ifp, ni_event_t event,
			const ni_ipv6_ra_pinfo_t *pi)
{
	switch (event) {
	case NI_EVENT_PREFIX_UPDATE:
		if (dev->config && (dev->config->mode & NI_BIT(NI_DHCP6_MODE_AUTO))) {
			/* refresh in case kernel forgot a newlink on RA */
			ni_dhcp6_device_refresh_mode(dev, ifp);
			ni_server_trace_interface_prefix_events(ifp, event, pi);
			ni_dhcp6_device_start(dev);
		} else {
			ni_server_trace_interface_prefix_events(ifp, event, pi);
		}
		break;

	case NI_EVENT_PREFIX_DELETE:
			ni_server_trace_interface_prefix_events(ifp, event, pi);
	default:
		break;
	}
}

int
ni_dhcp6_device_transmit(ni_dhcp6_device_t *dev)
{
	const ni_dhcp6_client_header_t *header;
	const char *name;
	unsigned int xid;
	ssize_t rv;
	size_t cnt;

	/* sanity check: verify the message contains at least the header */
	header = ni_buffer_peek_head(&dev->message, sizeof(*header));
	if (!header) {
		ni_error("%s: Cannot send empty DHCPv6 message packet",
				dev->ifname);

		/* Something went really wrong */
		ni_dhcp6_device_stop(dev);
		return -1;
	}

	/* get message length and header fields for logging */
	cnt  = ni_buffer_count(&dev->message);
	xid  = ni_dhcp6_message_xid(header->xid);
	name = ni_dhcp6_message_name(header->type);

	/* make sure the socket is open */
	if ((rv = ni_dhcp6_mcast_socket_open(dev)) != 0) {
		/* (transient) error already reported */
		return rv;
	}

	rv = ni_dhcp6_socket_send(dev->mcast.sock, &dev->message, &dev->mcast.dest);
	if (rv <= 0 || (size_t)rv != cnt) {
		/* Hmm... advance retrans.count here? Use stop? */

		ni_error("%s: Cannot send #%u %s message, xid 0x%x"
				" with %zu byte to %s: %m",
				dev->ifname, dev->retrans.count + 1, name, xid,
				cnt, ni_sockaddr_print(&dev->mcast.dest));

		/* Close and try reopen socket while next run */
		ni_dhcp6_mcast_socket_close(dev);
		ni_buffer_clear(&dev->message);
		return -1;
	} else {
		struct timeval now;

		dev->retrans.count++;

		ni_timer_get_time(&now);
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_DHCP,
				"%s: %s message #%u, xid 0x%x sent with %zd of %zu"
				" byte to %s",
				dev->ifname, name, dev->retrans.count, xid, rv, cnt,
				ni_sockaddr_print(&dev->mcast.dest));

		ni_buffer_clear(&dev->message);
		return 0;
	}
}

/*
 * Functions for accessing various global DHCP configuration options
 */
int
ni_dhcp6_config_user_class(ni_string_array_t *user_class_data)
{
	const struct ni_config_dhcp6 *dhconf = &ni_global.config->addrconf.dhcp6;

	ni_string_array_copy(user_class_data, &dhconf->user_class_data);
	return 0;
}

int
ni_dhcp6_config_vendor_class(unsigned int *vclass_en, ni_string_array_t *vclass_data)
{
	const struct ni_config_dhcp6 *dhconf = &ni_global.config->addrconf.dhcp6;

	if ((*vclass_en = dhconf->vendor_class_en) != 0) {
		ni_string_array_copy(vclass_data, &dhconf->vendor_class_data);
	} else {
		*vclass_en = NI_DHCP6_VENDOR_ENTERPRISE_NUMBER;
		ni_string_array_destroy(vclass_data);
		ni_string_array_append(vclass_data, NI_DHCP6_VENDOR_VERSION_STRING);
	}
	return 0;
}

int
ni_dhcp6_config_vendor_opts(unsigned int *vopts_en, ni_var_array_t *vopts_data)
{
	const struct ni_config_dhcp6 *dhconf = &ni_global.config->addrconf.dhcp6;

	ni_var_array_destroy(vopts_data);
	if ((*vopts_en = dhconf->vendor_opts_en) != 0) {
		const ni_var_array_t *nva;
		unsigned int i;

		nva = &dhconf->vendor_opts_data;
		for (i = 0; i < nva->count; ++i) {
			if (ni_string_empty(nva->data[i].name))
				continue;
			ni_var_array_set(vopts_data, nva->data[i].name, nva->data[i].value);
		}
	}
	return 0;
}

int
ni_dhcp6_config_ignore_server(struct in6_addr addr)
{
	const struct ni_config_dhcp6 *dhconf = &ni_global.config->addrconf.dhcp6;
	char        abuf[INET6_ADDRSTRLEN];
	const char *astr = inet_ntop(AF_INET, &addr, abuf, sizeof(abuf));

	// Hmm ... better another way around using IN6_ARE_ADDR_EQUAL(a,b)
	return (ni_string_array_index(&dhconf->ignore_servers, astr) >= 0);
}

ni_bool_t
ni_dhcp6_config_have_server_preference(void)
{
	const struct ni_config_dhcp6 *dhconf = &ni_global.config->addrconf.dhcp6;
	return dhconf->num_preferred_servers != 0;
}

ni_bool_t
ni_dhcp6_config_server_preference(const struct in6_addr *addr, const ni_opaque_t *duid, int *weight)
{
	const struct ni_config_dhcp6 *dhconf = &ni_global.config->addrconf.dhcp6;
	const ni_server_preference_t *pref = dhconf->preferred_server;
	unsigned int i;

	for (i = 0; i < dhconf->num_preferred_servers; ++i, ++pref) {
		ni_bool_t match = FALSE;
		if (pref->serverid.len > 0) {
			match = (duid && ni_opaque_eq(duid, &pref->serverid));
		}
		if (pref->address.ss_family == AF_INET6) {
			match = (addr && IN6_ARE_ADDR_EQUAL(addr, &pref->address.six.sin6_addr));
		}
		if (match) {
			*weight = pref->weight;
			return TRUE;
		}
	}
	return FALSE;
}

unsigned int
ni_dhcp6_config_max_lease_time(void)
{
	return ni_global.config->addrconf.dhcp6.lease_time;
}

unsigned int
ni_dhcp6_config_release_nretries(const char *ifname)
{
	const ni_config_dhcp6_t *conf = ni_config_dhcp6_find_device(ifname);
	/* >0: RFC 3315 Section 18.1.6, SHOULD retransmit one or more times */
	return conf && conf->release_nretries ? conf->release_nretries : -1U;
}

unsigned int
ni_dhcp6_config_info_refresh_time(const char *ifname, ni_uint_range_t *range)
{
	const ni_config_dhcp6_t *conf = ni_config_dhcp6_find_device(ifname);

	range->min = NI_DHCP6_IRT_MINIMUM;
	range->max = NI_LIFETIME_INFINITE;
	if (conf) {
		if (conf->info_refresh.range.min)
			range->min = conf->info_refresh.range.min;
		ni_uint_range_update_max(range, conf->info_refresh.range.max);
		if (conf->info_refresh.time &&
		    ni_uint_in_range(range, conf->info_refresh.time))
			return conf->info_refresh.time;
	}
	return NI_DHCP6_IRT_DEFAULT;
}

static void
ni_dhcp6_config_set_request_options(const char *ifname, ni_uint_array_t *cfg, const ni_string_array_t *req)
{
	const ni_config_dhcp6_t *dhconf = ni_config_dhcp6_find_device(ifname);
	const ni_dhcp_option_decl_t *custom_options = dhconf ? dhconf->custom_options : NULL;
	unsigned int i;

	for (i = 0; i < req->count; ++i) {
		const char *opt = req->data[i];
		const ni_dhcp_option_decl_t *decl;
		unsigned int code;

		if ((decl = ni_dhcp_option_decl_list_find_by_name(custom_options, opt)))
			code = decl->code;
		else if (ni_parse_uint(opt, &code, 10) < 0)
			continue;

		if (!code || code >= 65535)
			continue;

		if (!ni_uint_array_contains(cfg, code))
			ni_uint_array_append(cfg, code);
	}
}

/*
 * Create/delete a dhcp6 request object
 */
ni_dhcp6_request_t *
ni_dhcp6_request_new(void)
{
	ni_dhcp6_request_t *req;

	req = xcalloc(1, sizeof(*req));

	/* Apply defaults */
	req->enabled = TRUE; /* used by wickedd */
	req->mode = NI_BIT(NI_DHCP6_MODE_AUTO);
	req->rapid_commit = TRUE;

	/* By default, we try to obtain all sorts of config from the server */
	req->update = -1U;	/* apply wicked-config(5) defaults later */

	/* default: enable + update mode depends on hostname settings in req */
	ni_dhcp_fqdn_init(&req->fqdn);

	return req;
}

void
ni_dhcp6_request_free(ni_dhcp6_request_t *req)
{
	if(req) {
		ni_string_free(&req->hostname);
		ni_string_free(&req->clientid);
		ni_dhcp6_prefix_req_list_destroy(&req->prefix_reqs);
		ni_string_array_destroy(&req->request_options);
		/*
		 * req->vendor_class
		 * ....
		 */
		free(req);
	}
}

void
ni_dhcp6_drop_request_init(ni_dhcp6_drop_request_t *req)
{
	ni_uuid_init(&req->uuid);
	req->release = NI_TRISTATE_DEFAULT;
}

ni_dhcp6_prefix_req_t *
ni_dhcp6_prefix_req_new(void)
{
	ni_dhcp6_prefix_req_t *req;

	req = calloc(1, sizeof(*req));
	return req;
}

void
ni_dhcp6_prefix_req_free(ni_dhcp6_prefix_req_t *req)
{
	if (req) {
		ni_dhcp6_ia_addr_list_destroy(&req->hints);
#if 0
		ni_netdev_ref_destroy(&req->device);
#endif
		free(req);
	}
}

ni_bool_t
ni_dhcp6_prefix_req_list_append(ni_dhcp6_prefix_req_t **list, ni_dhcp6_prefix_req_t *req)
{
	if (list && req) {
		while (*list)
			list = &(*list)->next;
		*list = req;
		return TRUE;
	}
	return FALSE;
}

void
ni_dhcp6_prefix_req_list_destroy(ni_dhcp6_prefix_req_t **list)
{
	ni_dhcp6_prefix_req_t *req;

	if (list) {
		while ((req = *list)) {
			*list = req->next;
			ni_dhcp6_prefix_req_free(req);
		}
	}
}

ni_bool_t
ni_dhcp6_supported(const ni_netdev_t *ifp)
{
	/*
	 * currently not enslaved ether and ib types only,
	 * we've simply did not tested it on other links ...
	 */
	switch (ifp->link.hwaddr.type) {
	case ARPHRD_PPP:
		break;
	case ARPHRD_NONE:
		break;
	case ARPHRD_ETHER:
	case ARPHRD_INFINIBAND:
		if (ifp->link.masterdev.index) {
			ni_debug_dhcp("%s: DHCPv6 not supported on slaves",
					ifp->name);
			return FALSE;
		}
		break;
	default:
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: DHCPv6 not supported on %s interfaces",
				ifp->name,
				ni_linktype_type_to_name(ifp->link.type));
		return FALSE;
	}
	return TRUE;
}

