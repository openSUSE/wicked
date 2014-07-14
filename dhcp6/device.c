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
#include "duid.h"


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

static ni_opaque_t		ni_dhcp6_duid;
ni_dhcp6_device_t *		ni_dhcp6_active;

static void			ni_dhcp6_device_close(ni_dhcp6_device_t *);
static void			ni_dhcp6_device_free(ni_dhcp6_device_t *);

static void			ni_dhcp6_device_set_config(ni_dhcp6_device_t *, ni_dhcp6_config_t *);

static int			ni_dhcp6_device_transmit_arm_delay(ni_dhcp6_device_t *);
static void			ni_dhcp6_device_retransmit_arm(ni_dhcp6_device_t *dev);


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

	/* FIXME: for now, we always generate one */
	ni_dhcp6_device_iaid(dev, &dev->iaid);

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
__ni_dhcp6_device_config_free(ni_dhcp6_config_t *config)
{
	if (config) {
		ni_dhcp6_ia_list_destroy(&config->ia_list);
		ni_string_array_destroy(&config->user_class);
		ni_string_array_destroy(&config->vendor_class.data);
		ni_var_array_destroy(&config->vendor_opts.data);
		free(config);
	}
}

static void
ni_dhcp6_device_set_config(ni_dhcp6_device_t *dev, ni_dhcp6_config_t *config)
{
	if (dev->config && dev->config != config)
		__ni_dhcp6_device_config_free(dev->config);
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
		int weight)
{
	if (dev->best_offer.lease && dev->best_offer.lease != lease)
		ni_addrconf_lease_free(dev->best_offer.lease);
	dev->best_offer.lease = lease;
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

int
ni_dhcp6_device_iaid(const ni_dhcp6_device_t *dev, uint32_t *iaid)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;
	size_t len, off;
	uint32_t tmp;

	nc = ni_global_state_handle(0);
	if(!nc || !(ifp = ni_netdev_by_index(nc, dev->link.ifindex))) {
		ni_error("%s: Unable to find network interface by index %u",
			dev->ifname, dev->link.ifindex);
		return -1;
	}

	/* FIXME: simple iaid with 4 last byte of the mac */

	*iaid = 0;
	if (ifp->link.hwaddr.len > 4) {
		off = ifp->link.hwaddr.len - 4;
		memcpy(iaid, ifp->link.hwaddr.data + off, sizeof(*iaid));
		return 0;
	}
	if ((len = ni_string_len(dev->ifname))) {
		memcpy(&tmp, dev->ifname, len % sizeof(tmp));
		*iaid ^= tmp;
		if (ifp->vlan && ifp->vlan->tag > 0)
			*iaid ^= ifp->vlan->tag;
		*iaid ^= dev->link.ifindex;
		return 0;
	}
	return -1;
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

static const ni_netdev_t *
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

static void
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

	/*
	 * Hmm... Remember the time of the first transmission
	 */
	ni_timer_get_time(&dev->retrans.start);

	/* Leave, when retransmissions aren't enabled */
	if (dev->retrans.params.nretries == 0)
		return;

	if (dev->fsm.state == NI_DHCP6_STATE_SELECTING && dev->retrans.count == 1) {
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

		/*
		 * Trigger fsm timeout event after first RT to process the collected
		 * Advertise messages.
		 *
		 * Note, that there is no max duration time for Solicit messages, so
		 * we can reuse the fsm duration timer ...
		 */
		ni_dhcp6_fsm_set_timeout_msec(dev, dev->retrans.params.timeout);
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
}

void
ni_dhcp6_device_retransmit_disarm(ni_dhcp6_device_t *dev)
{
	struct timeval now;

	ni_timer_get_time(&now);

	ni_debug_dhcp("%s: disarming retransmission at %s",
			dev->ifname, ni_dhcp6_print_timeval(&now));

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

		ni_debug_dhcp("%s: increased retransmission timeout from %u to %u [%d .. %d]: %s",
				dev->ifname, old_timeout,
				dev->retrans.params.timeout,
				dev->retrans.params.jitter.min,
				dev->retrans.params.jitter.max,
				ni_dhcp6_print_timeval(&dev->retrans.deadline));

		return TRUE;
	}
#if 0
	ni_trace("Retransmissions are disabled");
#endif
	return FALSE;
}

int
ni_dhcp6_device_retransmit(ni_dhcp6_device_t *dev)
{
	if (!ni_dhcp6_device_retransmit_advance(dev)) {
		ni_dhcp6_device_retransmit_disarm(dev);
		return -1;
	}

	if (ni_dhcp6_fsm_retransmit(dev) < 0)
		return -1;
#if 0
	ni_trace("Retransmitted, next deadline at %s", ni_dhcp6_format_time(&dev->retrans.deadline));
#endif
	return 0;
}

void
ni_dhcp6_generate_duid(ni_dhcp6_device_t *dev, ni_opaque_t *duid)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;
	ni_uuid_t uuid;

	nc = ni_global_state_handle(0);
	if(!nc || !(ifp = ni_netdev_by_index(nc, dev->link.ifindex))) {
		ni_error("%s: Unable to find network interface by index %u",
			dev->ifname, dev->link.ifindex);
		return;
	}

	/* try the current interface first */
	if (ifp->link.hwaddr.len) {
		if(ni_duid_init_llt(duid, ifp->link.hwaddr.type,
				ifp->link.hwaddr.data, ifp->link.hwaddr.len))
			return;
	}

	/* then another one */
	for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {
		if (ifp->link.ifindex == dev->link.ifindex)
			continue;

		switch(ifp->link.hwaddr.type) {
		case ARPHRD_ETHER:
		case ARPHRD_IEEE802:
		case ARPHRD_INFINIBAND:
			if (ifp->link.hwaddr.len) {
				if(ni_duid_init_llt(duid, ifp->link.hwaddr.type,
						ifp->link.hwaddr.data, ifp->link.hwaddr.len))
					return;
			}
		break;
		}
	}

	/*
	 * TODO:
	 * 1) MAC based uuid duid, see
	 *    http://tools.ietf.org/html/rfc4122#section-4.1.6
	 * 2) There should be some system unique uuid at least on x86_64
	 */
	memset(&uuid, 0, sizeof(uuid));
	ni_uuid_generate(&uuid);
	ni_duid_init_uuid(duid, &uuid);
}

static inline int
ni_dhcp6_duid_load(ni_opaque_t *duid)
{
	return ni_duid_load(duid, NULL, NULL);
}

static inline int
ni_dhcp6_duid_save(const ni_opaque_t *duid)
{
	return ni_duid_save(duid, NULL, NULL);
}

static ni_bool_t
ni_dhcp6_config_init_duid(ni_dhcp6_device_t *dev, ni_dhcp6_config_t *config, const char *preferred)
{
	ni_bool_t save = TRUE;

	if (preferred) {
		ni_duid_parse_hex(&config->client_duid, preferred);
	}
	if (config->client_duid.len == 0) {
		ni_dhcp6_config_default_duid(&config->client_duid);
	}
	if (config->client_duid.len == 0 && ni_dhcp6_duid.len > 0) {
		ni_duid_copy(&config->client_duid, &ni_dhcp6_duid);
	}
	if (config->client_duid.len == 0) {
		if(ni_dhcp6_duid_load(&config->client_duid) == 0)
			save = FALSE;
	}
	if (config->client_duid.len == 0) {
		ni_dhcp6_generate_duid(dev, &config->client_duid);
	}
	if (config->client_duid.len > 0 && save) {
		(void)ni_dhcp6_duid_save(&config->client_duid);
	}
	if (config->client_duid.len > 0 && !ni_dhcp6_duid.len) {
		ni_duid_copy(&ni_dhcp6_duid, &config->client_duid);
	}
	return (config->client_duid.len > 0);
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
	config->update = req->update;
	config->dry_run = req->dry_run;
	config->rapid_commit = !config->dry_run ? req->rapid_commit : FALSE;

	config->lease_time = 0;
	config->acquire_timeout = req->acquire_timeout;
	ni_timer_get_time(&dev->start_time);

	/*
         * Make sure we have a DUID for client-id
	 * Hmm... Should we fail back to req->uuid?
         */
	if(!ni_dhcp6_config_init_duid(dev, config, req->clientid)) {
		size_t len;

		__ni_dhcp6_device_config_free(config);
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

	if ((len = ni_string_len(req->hostname)) > 0) {
		if (ni_check_domain_name(req->hostname, len, 0)) {
			strncpy(config->hostname, req->hostname, sizeof(config->hostname) - 1);
		} else {
			ni_debug_dhcp(
				"%s: Discarded suspect hostname in DHCPv6 acquire request %s: '%s'",
				dev->ifname, ni_uuid_print(&req->uuid),
				ni_print_suspect(req->hostname, len));
		}
	}

	/* TODO: get from req info */
	ni_dhcp6_config_vendor_class(&config->vendor_class.en, &config->vendor_class.data);
	ni_dhcp6_config_vendor_opts(&config->vendor_opts.en, &config->vendor_opts.data);

	/*
	 * This basically fails only if we can't find netdev (any more)
	 */
	if (!ni_dhcp6_device_is_ready(dev, NULL)) {
		ni_dhcp6_device_show_addrs(dev);
		rv = ni_dhcp6_device_find_lladdr(dev);
		if (rv < 0) {
			__ni_dhcp6_device_config_free(config);
			ni_string_dup(err, "Cannot read network device settings");
			return -NI_ERROR_GENERAL_FAILURE;
		}
	}

	ni_dhcp6_device_set_config(dev, config);
	if (config->mode == NI_DHCP6_MODE_AUTO) {
		/* OK, let's look if device already has a mode */
		ni_dhcp6_device_update_mode(dev, NULL);
		if (config->mode == NI_DHCP6_MODE_AUTO) {
			unsigned int timeout = config->acquire_timeout;

			/*
			 * set timer to provide dummy lease to wicked
			 * when there is no IPv6 RA on the network or
			 * DHCPv6 is not used.
			 */
			if (timeout > 5)
				timeout = ((timeout - 1) * 1000) + 500;
			else
				timeout = 5000;
			ni_dhcp6_fsm_set_timeout_msec(dev, timeout);
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

#if 0
	config->max_lease_time = ni_dhcp6_config_max_lease_time();
	if (config->max_lease_time == 0)
		config->max_lease_time = ~0U;
	if (info->lease_time && info->lease_time < config->max_lease_time)
		config->max_lease_time = info->lease_time;

	if (info->hostname)
		strncpy(config->hostname, info->hostname, sizeof(config->hostname) - 1);

	if (info->clientid) {
		strncpy(config->client_id, info->clientid, sizeof(config->client_id)-1);
		ni_dhcp6_parse_client_id(&config->raw_client_id, dev->link.type, info->clientid);
	} else {
		/* Set client ID from interface hwaddr */
		strncpy(config->client_id, ni_link_address_print(&dev->system.hwaddr), sizeof(config->client_id)-1);
		ni_dhcp6_set_client_id(&config->raw_client_id, &dev->system.hwaddr);
	}

	if ((classid = info->vendor_class) == NULL)
		classid = ni_dhcp6_config_vendor_class();
	if (classid)
		strncpy(config->classid, classid, sizeof(config->classid) - 1);

	config->flags = DHCP6_DO_ARP | DHCP6_DO_CSR | DHCP6_DO_MSCSR;
	config->flags |= ni_dhcp6_do_bits(info->update);

	if (ni_debug & NI_TRACE_DHCP) {
		ni_trace("Received request:");
		ni_trace("  acquire-timeout %u", config->request_timeout);
		ni_trace("  lease-time      %u", config->max_lease_time);
		ni_trace("  hostname        %s", config->hostname[0]? config->hostname : "<none>");
		ni_trace("  vendor-class    %s", config->classid[0]? config->classid : "<none>");
		ni_trace("  client-id       %s", ni_print_hex(config->raw_client_id.data, config->raw_client_id.len));
		ni_trace("  uuid            %s", ni_print_hex(config->uuid.octets, 16));
		ni_trace("  flags           %s", __ni_dhcp6_print_flags(config->flags));
	}

	if (dev->config)
		free(dev->config);
	dev->config = config;

#if 0
	/* FIXME: This cores for now */
	/* If we're asked to reclaim an existing lease, try to load it. */
	if (info->reuse_unexpired && ni_dhcp6_fsm_recover_lease(dev, info) >= 0)
		return 0;
#endif

	if (dev->lease) {
		if (!ni_addrconf_lease_is_valid(dev->lease)
		 || (info->hostname && !ni_string_eq(info->hostname, dev->lease->hostname))
		 || (info->clientid && !ni_string_eq(info->clientid, dev->lease->dhcp6.client_id))) {
			ni_debug_dhcp6("%s: lease doesn't match request", dev->ifname);
			ni_dhcp6_device_drop_lease(dev);
			dev->notify = 1;
		}
	}

	/* Go back to INIT state to force a rediscovery */
	dev->fsm.state = NI_DHCP6_STATE_INIT;
	ni_dhcp6_device_start(dev);
	return 1;
#endif
}


#if 0
/*
 * Translate a bitmap of NI_ADDRCONF_UPDATE_* flags into a bitmap of
 * DHCP6_DO_* masks
 */
static unsigned int
ni_dhcp6_do_bits(unsigned int update_flags)
{
	static unsigned int	do_mask[32] = {
	[NI_ADDRCONF_UPDATE_HOSTNAME]		= DHCP6_DO_HOSTNAME,
	[NI_ADDRCONF_UPDATE_RESOLVER]		= DHCP6_DO_RESOLVER,
	[NI_ADDRCONF_UPDATE_NIS]		= DHCP6_DO_NIS,
	[NI_ADDRCONF_UPDATE_NTP]		= DHCP6_DO_NTP,
	[NI_ADDRCONF_UPDATE_DEFAULT_ROUTE]	= DHCP6_DO_GATEWAY,
	};
	unsigned int bit, result = 0;

	for (bit = 0; bit < 32; ++bit) {
		if (update_flags & (1 << bit))
			result |= do_mask[bit];
	}
	return result;
}

static const char *
__ni_dhcp6_print_flags(unsigned int flags)
{
	static ni_intmap_t flag_names[] = {
	{ "arp",		DHCP6_DO_ARP		},
	{ "csr",		DHCP6_DO_CSR		},
	{ "mscsr",		DHCP6_DO_MSCSR		},
	{ "hostname",		DHCP6_DO_HOSTNAME	},
	{ "resolver",		DHCP6_DO_RESOLVER	},
	{ "nis",		DHCP6_DO_NIS		},
	{ "ntp",		DHCP6_DO_NTP		},
	{ "gateway",		DHCP6_DO_GATEWAY		},
	{ NULL }
	};
	static char buffer[1024];
	char *pos = buffer;
	unsigned int mask;

	*pos = '\0';
	for (mask = 1; mask != 0; mask <<= 1) {
		const char *name;

		if ((flags & mask) == 0)
			continue;
		if (!(name = ni_format_int_mapped(mask, flag_names)))
			continue;
		snprintf(pos, buffer + sizeof(buffer) - pos, "%s%s",
				(pos == buffer)? "" : ", ",
				name);
		pos += strlen(pos);
	}
	if (buffer[0] == '\0')
		return "<none>";

	return buffer;
}
#endif

/*
 * Process a request to unconfigure the device (ie drop the lease).
 */
int
ni_dhcp6_release(ni_dhcp6_device_t *dev, const ni_uuid_t *lease_uuid)
{
	char *rel_uuid = NULL;
	char *our_uuid = NULL;
	int rv;

	if (dev->lease == NULL) {
		ni_error("%s: no lease set", dev->ifname);
		return -NI_ERROR_ADDRCONF_NO_LEASE;
	}

	ni_string_dup(&rel_uuid, ni_uuid_print(lease_uuid));
	ni_string_dup(&our_uuid, ni_uuid_print(&dev->lease->uuid));

	if (lease_uuid && !ni_uuid_equal(lease_uuid, &dev->lease->uuid)) {
		ni_warn("%s: lease UUID %s to release does not match current lease UUID %s",
			dev->ifname, rel_uuid, our_uuid);
		ni_string_free(&rel_uuid);
		ni_string_free(&our_uuid);
		return -NI_ERROR_ADDRCONF_NO_LEASE;
	}
	ni_string_free(&our_uuid);

	ni_note("%s: Request to release DHCPv6 lease%s%s",  dev->ifname,
		rel_uuid ? " with UUID " : "", rel_uuid ? rel_uuid : "");
	ni_string_free(&rel_uuid);

	if ((rv = ni_dhcp6_fsm_release(dev)) < 0)
		return rv;

	return 0;
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
	ni_ipv6_devinfo_t *ipv6;

	ipv6 = ni_netdev_get_ipv6(ifp);
	if (ipv6 == NULL)
		return;

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
			"%s: %s RA<%s> Prefix<%s/%u %s,%s> [%d,%d]", dev->ifname,
			(event == NI_EVENT_PREFIX_UPDATE ? "update" : "delete"),
			(ipv6->radv.managed_addr ? "managed-address" :
			(ipv6->radv.other_config ? "managed-config" : "unmanaged")),
			ni_sockaddr_print(&pi->prefix), pi->length,
			(pi->on_link ? "onlink" : "not-onlink"),
			(pi->autoconf ? "autoconf" : "no-autoconf"),
			pi->lifetime.preferred_lft, pi->lifetime.valid_lft);

	switch (event) {
	case NI_EVENT_PREFIX_UPDATE:
		if (dev->config && dev->config->mode == NI_DHCP6_MODE_AUTO) {
			ni_dhcp6_device_update_mode(dev, ifp);
			ni_dhcp6_device_start(dev);
		}
		break;

	case NI_EVENT_PREFIX_DELETE:
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
				" byte to %s at %s",
				dev->ifname, name, dev->retrans.count, xid, rv, cnt,
				ni_sockaddr_print(&dev->mcast.dest),
				ni_dhcp6_print_timeval(&now));

		ni_buffer_clear(&dev->message);
		return 0;
	}
}

/*
 * Functions for accessing various global DHCP configuration options
 */
const char *
ni_dhcp6_config_default_duid(ni_opaque_t *duid)
{
	const struct ni_config_dhcp6 *dhconf = &ni_global.config->addrconf.dhcp6;

	if (ni_string_empty(dhconf->default_duid))
		return NULL;

	if (!ni_duid_parse_hex(duid, dhconf->default_duid))
		return NULL;

	return dhconf->default_duid;
}

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
