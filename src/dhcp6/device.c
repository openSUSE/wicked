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
	long           uptime = 0;

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

int
ni_dhcp6_device_start(ni_dhcp6_device_t *dev)
{
	if (!dev->config) {
		ni_error("%s: Cannot start DHCPv6 without config",
			dev->ifname);
		return -1;
	}

	if (dev->config->mode == NI_DHCP6_MODE_AUTO)
		return 1;

	ni_dhcp6_device_show_addrs(dev);
	if (!ni_dhcp6_device_is_ready(dev, NULL))
		return 1;

	dev->failed = 0;

	return ni_dhcp6_fsm_start(dev);
}

int
ni_dhcp6_device_restart(ni_dhcp6_device_t *dev)
{
	char *err = NULL;
	int rv = -1;

	ni_dhcp6_device_stop(dev);

	if (!dev->request)
		return -1;

	ni_debug_dhcp("%s: Restart DHCPv6 acquire request %s in mode %s",
		dev->ifname, ni_uuid_print(&dev->request->uuid),
		ni_dhcp6_mode_type_to_name(dev->request->mode));

	if ((rv = ni_dhcp6_acquire(dev, dev->request, &err)) >= 0)
		return rv;

	ni_error("%s: Cannot restart DHCPv6 acquire request %s in mode %s%s%s",
		dev->ifname, ni_uuid_print(&dev->request->uuid),
		ni_dhcp6_mode_type_to_name(dev->request->mode),
		(err ? ": " : ""), (err ? err : ""));
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

void
ni_dhcp6_device_refresh_mode(ni_dhcp6_device_t *dev, ni_netdev_t *ifp)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);

	if (!nc || !dev || (!ifp && !(ifp = ni_dhcp6_device_netdev(dev))))
		return;

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

	ni_dhcp6_device_update_mode(dev, ifp);
}

void
ni_dhcp6_device_update_mode(ni_dhcp6_device_t *dev, const ni_netdev_t *ifp)
{
	if (!ifp && !(ifp = ni_dhcp6_device_netdev(dev)))
		return;

	if (ifp->ipv6 && dev->config) {
		if (ifp->ipv6->radv.managed_addr)
			dev->config->mode = NI_DHCP6_MODE_MANAGED;
		else
		if (ifp->ipv6->radv.other_config)
			dev->config->mode = NI_DHCP6_MODE_INFO;
	}
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
	unsigned long  delay;

	/*
	 * rfc3315#section-5.5 (17.1.2, 18.1.2, 18.1.5):
	 *
	 * Initial delay is a MUST for Solicit, Confirm and InfoRequest.
	 */
	if (dev->retrans.delay == 0)
		return FALSE;

	ni_debug_dhcp("%s: setting initial transmit delay of %u [%d .. %d] msec",
			dev->ifname, dev->retrans.delay,
			0 - dev->retrans.jitter,
			0 + dev->retrans.jitter);

	/* we can use base jitter as is, it's 0.1 msec already */
	jitter.min = 0 - dev->retrans.jitter;
	jitter.max = 0 + dev->retrans.jitter;
	delay = ni_timeout_randomize(dev->retrans.delay, &jitter);

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
		dev->retrans.params.jitter = ni_dhcp6_jitter_rebase(
				dev->retrans.params.timeout,
				0, /* exception, no negative jitter */
				0 + dev->retrans.jitter);

		/*
		 * rfc3315#section-14
		 *
		 * "[...]
		 *  RT for the first message transmission is based on IRT:
		 * 	RT = IRT + RAND*IRT
		 *  [...]"
		 *
		 * IRT is already initialized in retrans.params.timeout.
		 */
		dev->retrans.params.timeout = ni_timeout_arm_msec(&dev->retrans.deadline,
								  &dev->retrans.params);
	} else {
		/*
		 * rfc3315#section-14
		 *
		 * "[...]
		 * Each new RT include a randomization factor (RAND) [...]
		 * between -0.1 and +0.1.
		 * [...]"
		 */
		dev->retrans.params.jitter = ni_dhcp6_jitter_rebase(
				dev->retrans.params.timeout,
				0 - dev->retrans.jitter,
				0 + dev->retrans.jitter);

		/*
		 * rfc3315#section-14
		 *
		 * "[...]RT for the first message transmission is based on IRT:
		 * 		RT = IRT + RAND*IRT
		 *  [...]"
		 *
		 *  IRT is already initialized in retrans.params.timeout.
		 */
		dev->retrans.params.timeout = ni_timeout_arm_msec(&dev->retrans.deadline,
								  &dev->retrans.params);
	}
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
		unsigned int old_timeout = dev->retrans.params.timeout;

		/*
		 * Hmm... should we set this as backoff callback?
		 */
		dev->retrans.params.jitter = ni_dhcp6_jitter_rebase(
				dev->retrans.params.timeout,
				0 - dev->retrans.jitter,
				0 + dev->retrans.jitter);

		dev->retrans.params.timeout = ni_timeout_arm_msec(
				&dev->retrans.deadline,
				&dev->retrans.params);

		ni_debug_dhcp("%s: advanced xid 0x%06x retransmission timeout from %u to %u [%d .. %d]",
				dev->ifname, dev->dhcp6.xid, old_timeout,
				dev->retrans.params.timeout,
				dev->retrans.params.jitter.min,
				dev->retrans.params.jitter.max);

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

	ni_debug_dhcp("%s: xid 0x%06x retransmitted, next deadline in %s", dev->ifname,
			dev->dhcp6.xid, ni_dhcp6_print_timeval(&dev->retrans.deadline));
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

	switch (req->mode) {
	case NI_DHCP6_MODE_AUTO:
	case NI_DHCP6_MODE_INFO:
	case NI_DHCP6_MODE_MANAGED:
		ni_note("%s: Request to acquire DHCPv6 lease with UUID %s in mode %s",
			dev->ifname, ni_uuid_print(&req->uuid),
			ni_dhcp6_mode_type_to_name(req->mode));
		break;
	default:
		if ((mode = ni_dhcp6_mode_type_to_name(req->mode)) != NULL) {
			ni_string_printf(err, "unsupported mode %s", mode);
		} else {
			ni_string_printf(err, "invalid mode %u", req->mode);
		}
		return -NI_ERROR_INVALID_ARGS;
	}

	config = xcalloc(1, sizeof(*config));
	config->uuid = req->uuid;
	config->mode = req->mode;
	config->flags= req->flags;
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
	config->release_lease	= req->release_lease;

	if (!dev->lease && config->dry_run != NI_DHCP6_RUN_OFFER && config->recover_lease)
		ni_dhcp6_device_set_lease(dev, ni_dhcp6_recover_lease(dev));

	if (!ni_dhcp6_device_iaid(dev, &dev->iaid)) {
		ni_string_printf(err, "Unable to generate a device IAID");
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

	/*
	 * Hmm... in info mode we don't need any IA's,
	 *        in auto mode, we don't know yet ...
	 */
	if (config->mode != NI_DHCP6_MODE_INFO) {
		if (req->ia_list == NULL) {
			ni_dhcp6_ia_t *ia = ni_dhcp6_ia_na_new(dev->iaid);
			ni_dhcp6_ia_set_default_lifetimes(ia, config->lease_time);
			ni_dhcp6_ia_list_append(&config->ia_list, ia);
		} else {
			/* TODO: Merge multiple ia's of same type into one?
			 *       for tests we take it as is -- at the moment */
			ni_dhcp6_ia_list_copy(&config->ia_list, req->ia_list, FALSE);
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

	if (config->mode == NI_DHCP6_MODE_AUTO) {
		/* refresh in case kernel forgot a newlink on RA */
		ni_dhcp6_device_refresh_mode(dev, NULL);
	}

	if (config->mode == NI_DHCP6_MODE_AUTO) {
		unsigned int deadline = 0;

		if (config->defer_timeout) {
			/*
			 * set timer to emit lease-deferred signal to wicked
			 * when there is no IPv6 RA on the network or DHCPv6
			 * is not used (managed and other-config unset).
			 */
			deadline = config->defer_timeout * 1000;
			ni_dhcp6_fsm_set_timeout_msec(dev, deadline);
			dev->fsm.fail_on_timeout = 0;
		} else
		if (config->acquire_timeout) {
			/*
			 * immediatelly set timer to fail after timeout,
			 * that is to drop config, disarm fsm and stop.
			 */
			deadline = config->acquire_timeout * 1000;
			ni_dhcp6_fsm_set_timeout_msec(dev, deadline);
			dev->fsm.fail_on_timeout = 1;
		}
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
ni_dhcp6_release(ni_dhcp6_device_t *dev, const ni_uuid_t *req_uuid)
{
	char *rel_uuid = NULL;

	ni_string_dup(&rel_uuid, ni_uuid_print(req_uuid));
	if (dev->lease == NULL || dev->config == NULL) {
		ni_info("%s: Request to release DHCPv6 lease%s%s: no lease", dev->ifname,
			rel_uuid ? " using UUID " : "", rel_uuid ? rel_uuid : "");
		ni_string_free(&rel_uuid);

		ni_dhcp6_device_set_request(dev, NULL);
		ni_dhcp6_device_drop_lease(dev);
		ni_dhcp6_device_stop(dev);
		return -NI_ERROR_ADDRCONF_NO_LEASE;
	}

	ni_note("%s: Request to release DHCPv6 lease%s%s: releasing...", dev->ifname,
			rel_uuid ? " using UUID " : "", rel_uuid ? rel_uuid : "");
	ni_string_free(&rel_uuid);

	dev->lease->uuid = *req_uuid;
	dev->config->uuid = *req_uuid;

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
		if (dev->config && dev->config->mode == NI_DHCP6_MODE_AUTO) {
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
		if (dev->config && dev->config->mode == NI_DHCP6_MODE_AUTO) {
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

ni_string_array_t *
ni_dhcp6_get_ia_addrs(struct ni_dhcp6_ia *ia_list, ni_var_array_t *p_lft, ni_var_array_t *v_lft)
{
	ni_string_array_t *addrs = NULL;
	const ni_dhcp6_ia_t *ia = NULL;

	addrs = xcalloc(1, sizeof(ni_string_array_t));

	for (ia = ia_list; ia; ia = ia->next) {
		const ni_dhcp6_ia_addr_t *iaddr = NULL;
		ni_sockaddr_t addr;
		const char *addr_str = NULL;
		for (iaddr = ia->addrs; iaddr; iaddr = iaddr->next) {
			ni_sockaddr_set_ipv6(&addr, iaddr->addr, 0);
			switch (ia->type) {
			case NI_DHCP6_OPTION_IA_TA:
			case NI_DHCP6_OPTION_IA_NA:
				addr_str = ni_sockaddr_print(&addr);
				ni_string_array_append(addrs, addr_str);
				break;

			case NI_DHCP6_OPTION_IA_PD:
				addr_str = ni_sockaddr_prefix_print(&addr, iaddr->plen);
				ni_string_array_append(addrs, addr_str);
				break;

			default:
				break;
			}

			if (p_lft)
				ni_var_array_set_uint(p_lft,
						addr_str,
						iaddr->preferred_lft);
			if (v_lft)
				ni_var_array_set_uint(v_lft,
						addr_str,
						iaddr->valid_lft);
		}
	}

	return addrs;
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
	req->mode = NI_DHCP6_MODE_AUTO;
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
		ni_dhcp6_ia_list_destroy(&req->ia_list);
		ni_string_array_destroy(&req->request_options);
		/*
		 * req->vendor_class
		 * ....
		 */
		free(req);
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

