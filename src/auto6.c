/*
 *	IPv6 autoconf related helper functions
 *
 *	Copyright (C) 2016 SUSE Linux GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <ctype.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/resolver.h>
#include <wicked/objectmodel.h>

#include "netinfo_priv.h"
#include "ipv6_priv.h"
#include "util_priv.h"
#include "leasefile.h"
#include "appconfig.h"
#include "auto6.h"

#define NI_AUTO6_UPDATER_DELAY		500	/* initial delay timeout in ms         */
#define NI_AUTO6_UPDATER_JITTER		100	/* initial delay timeout jitter in ms  */
#define NI_AUTO6_UPDATER_TIMEOUT	500	/* step timeout	in ms                  */

#define NI_AUTO6_ACQUIRE_DELAY		0	/* initial acquire start delay in sec  */
#define NI_AUTO6_ACQUIRE_TIMEOUT	1	/* acquire step timeout in sec         */
#define NI_AUTO6_ACQUIRE_DEADLINE	10	/* defer lease request deadline in sec */
#define NI_AUTO6_ACQUIRE_SEND_RS	2	/* solicits we send in ifup on UP link */

static void				ni_auto6_expire_set_timer(ni_auto6_t *, unsigned int);
static void				ni_auto6_acquire_set_timer(ni_auto6_t *, unsigned int);

struct ni_auto6 {
	ni_netdev_ref_t			device;

	ni_bool_t			enabled;
	ni_tristate_t			update;
	ni_uuid_t			uuid;

	struct {
		struct timeval		start;
		const ni_timer_t *	timer;
		unsigned int		deadline;

		unsigned int		send_rs;
	} acquire;

	struct {
		const ni_timer_t *	timer;
	} expire;
};

void
ni_auto6_request_init(ni_auto6_request_t *req)
{
	if (req) {
		memset(req, 0, sizeof(*req));
		req->enabled = FALSE;
		req->defer_timeout = NI_AUTO6_ACQUIRE_DEADLINE;
		req->update = -1U; /* apply wicked-config(5) defaults later */
	}
}

void
ni_auto6_request_destroy(ni_auto6_request_t *req)
{
	ni_auto6_request_init(req);
}

ni_auto6_t *
ni_auto6_new(const ni_netdev_t *dev)
{
	ni_auto6_t *auto6;

	if (!dev || !dev->link.ifindex)
		return NULL;

	auto6 = xcalloc(1, sizeof(*auto6));
	if (auto6) {
		auto6->enabled = TRUE;
		auto6->update = NI_TRISTATE_DEFAULT;
		ni_netdev_ref_set(&auto6->device, dev->name, dev->link.ifindex);
	}
	return auto6;
}

static void
ni_auto6_acquire_disarm(ni_auto6_t *auto6)
{
	if (auto6->acquire.timer) {
		ni_timer_cancel(auto6->acquire.timer);
		auto6->acquire.timer = NULL;
		timerclear(&auto6->acquire.start);
	}
}

static void
ni_auto6_expire_disarm(ni_auto6_t *auto6)
{
	if (auto6->expire.timer) {
		ni_timer_cancel(auto6->expire.timer);
		auto6->expire.timer = NULL;
	}
}

static void
ni_auto6_disarm(ni_auto6_t *auto6)
{
	ni_auto6_acquire_disarm(auto6);
	ni_auto6_expire_disarm(auto6);
}

static void
ni_auto6_reset(ni_auto6_t *auto6)
{
	auto6->update = NI_TRISTATE_DEFAULT;
	auto6->acquire.deadline = 0;
	auto6->acquire.send_rs  = 0;
	ni_auto6_disarm(auto6);
}

static void
ni_auto6_destroy(ni_auto6_t *auto6)
{
	ni_auto6_disarm(auto6);
	ni_netdev_ref_destroy(&auto6->device);
}

void
ni_auto6_free(ni_auto6_t *auto6)
{
	if (auto6) {
		ni_auto6_destroy(auto6);
		free(auto6);
	}
}

ni_auto6_t *
ni_netdev_get_auto6(ni_netdev_t *dev)
{
	if (!dev->auto6)
		dev->auto6 = ni_auto6_new(dev);
	else
	if (!ni_string_eq(dev->name, dev->auto6->device.name))
		ni_netdev_ref_set_ifname(&dev->auto6->device, dev->name);
	return dev->auto6;
}

void
ni_netdev_set_auto6(ni_netdev_t *dev, ni_auto6_t *auto6)
{
	if (dev->auto6)
		ni_auto6_free(dev->auto6);
	dev->auto6 = NULL;
}

static ni_bool_t
ni_netdev_auto6_supported(ni_netdev_t *dev)
{
	ni_ipv6_devinfo_t *ipv6;

	if (!dev)
		return FALSE;

	/*
	 * ipv6 is not supported (disabled via boot param)
	 */
	if (!ni_ipv6_supported())
		return FALSE;

	/*
	 * ipv6 not discovered or wiped from device
	 */
	if (!(ipv6 = dev->ipv6))
		return FALSE;

	/*
	 * ipv6 disabled on this device
	 */
	if (ni_tristate_is_disabled(dev->ipv6->conf.enabled))
		return FALSE;

	/*
	 * device may support ipv6, but not doing autoconfig
	 *
	 * accept_ra = 1 is a default set also on devices
	 * not doing/supporting autoconfig (e.g. loopback),
	 * so it is not really an reliable setting ...
	 */
	switch (dev->link.type) {
	case NI_IFTYPE_LOOPBACK:
		return FALSE;
	default:
		break;
	}
	if (!(dev->link.ifflags & NI_IFF_ARP_ENABLED))
		return FALSE;

	return TRUE;
}

static ni_bool_t
ni_netdev_auto6_enabled(ni_netdev_t *dev)
{
	ni_ipv6_devinfo_t *ipv6;

	if (!dev || !(ipv6 = dev->ipv6))
		return FALSE;

	/*
	 * when forwarding is enabled, autoconfig is disabled,
	 * except accept_ra = 2 is set as well.
	 */
	if (ni_tristate_is_enabled(ipv6->conf.forwarding)) {
		if (ipv6->conf.accept_ra <= NI_IPV6_ACCEPT_RA_HOST)
			return FALSE;
	} else {
		if (ipv6->conf.accept_ra == NI_IPV6_ACCEPT_RA_DISABLED)
			return FALSE;
	}

	return TRUE;
}

static ni_bool_t
ni_netdev_auto6_address_autoconf(ni_netdev_t *dev)
{
	ni_ipv6_devinfo_t *ipv6;

	if (!dev || !(ipv6 = dev->ipv6))
		return FALSE;

	return !ni_tristate_is_disabled(ipv6->conf.autoconf);
}

ni_bool_t
ni_auto6_send_event(ni_dbus_server_t *server, ni_netdev_t *dev, ni_event_t event, ni_uuid_t *uuid)
{
	ni_dbus_object_t *object = ni_objectmodel_get_netif_object(server, dev);

	if (object)
		return ni_objectmodel_send_netif_event(server, object, event, uuid);
	return FALSE;
}

const ni_address_t *
ni_auto6_get_linklocal(ni_netdev_t *dev)
{
	const ni_address_t *ll = NULL;
	const ni_address_t *ap;

	for (ap = dev ? dev->addrs : NULL; ap; ap = ap->next) {
		if (!ni_sockaddr_is_ipv6_linklocal(&ap->local_addr))
			continue;

		if (!ni_address_is_tentative(ap) && !ni_address_is_duplicate(ap))
			return ap;

		if (!ll || !ni_address_is_duplicate(ap))
			ll = ap;
	}
	return ll;
}

/*
 * Lease
 */
ni_bool_t
ni_auto6_is_active_lease(ni_addrconf_lease_t *lease)
{
	switch (lease->state) {
	case NI_ADDRCONF_STATE_REQUESTING:
	case NI_ADDRCONF_STATE_APPLYING:
	case NI_ADDRCONF_STATE_GRANTED:
		return TRUE;
	default:
		return FALSE;
	}
}

static ni_addrconf_lease_t *
ni_auto6_get_lease(ni_netdev_t *dev)
{
	return ni_netdev_get_lease(dev, AF_INET6, NI_ADDRCONF_AUTOCONF);
}

static ni_addrconf_lease_t *
ni_auto6_new_lease(int state, const ni_uuid_t *uuid)
{
	ni_addrconf_lease_t *lease;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_AUTOCONF, AF_INET6);
	if (lease) {
		lease->state = state;
		lease->flags = NI_BIT(NI_ADDRCONF_FLAGS_OPTIONAL);
		lease->update= ni_config_addrconf_update_mask(NI_ADDRCONF_AUTOCONF, AF_INET6);
		if (ni_uuid_is_null(uuid))
			ni_uuid_generate(&lease->uuid);
		else
			lease->uuid = *uuid;
	}
	return lease;
}

static void
ni_auto6_update_lease(ni_netdev_t *dev, ni_addrconf_lease_t *lease, unsigned int delay)
{
	ni_addrconf_updater_t *updater = lease->updater;

	lease->state = NI_ADDRCONF_STATE_APPLYING;
	if (!updater || updater->event != NI_EVENT_ADDRESS_ACQUIRED) {
		if (!(updater = ni_addrconf_updater_new_applying(lease, dev, NI_EVENT_ADDRESS_ACQUIRED)))
			return;
	}
	lease->acquired = updater->started;
	ni_addrconf_updater_background(updater, delay);
}

static int
ni_auto6_remove_lease(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_addrconf_updater_t *updater = lease->updater;

	lease->state = NI_ADDRCONF_STATE_RELEASING;
	if (!updater || updater->event != NI_EVENT_ADDRESS_RELEASED) {
		if (!(updater = ni_addrconf_updater_new_removing(lease, dev, NI_EVENT_ADDRESS_RELEASED)))
			return -1;
	}

	ni_addrconf_updater_background(updater, 0);
	return 1;
}

/*
 * Event handler hooks
 */
void
ni_auto6_on_netdev_event(ni_netdev_t *dev, ni_event_t event)
{
	if (!dev)
		return;

	/*
	 * this does not work -- the kernel sends us a NEWLINK on enable, but
	 * forgets it on disable (sysctl -w net.ipv6.conf.foo0.disable_ipv6=1)
	 */
	if (!dev->ipv6 || dev->ipv6->conf.enabled == NI_TRISTATE_DISABLE) {
		ni_auto6_release(dev, FALSE);
		return;
	}

	switch (event) {
	case NI_EVENT_LINK_UP:
		break;
	case NI_EVENT_LINK_DOWN:
		break;

	case NI_EVENT_DEVICE_UP:
		break;
	case NI_EVENT_DEVICE_DOWN:
		ni_auto6_release(dev, FALSE);
		break;

	default:
		break;
	}
}

static ni_bool_t
ni_auto6_is_autoconf_prefix(const ni_ipv6_ra_pinfo_t *pi)
{
	return pi && pi->length == 64 && pi->autoconf;
}

static ni_bool_t
ni_auto6_lease_address_update(ni_netdev_t *dev, ni_addrconf_lease_t *lease, const ni_address_t *ap)
{
	ni_bool_t changed = FALSE;
	ni_address_t *la;

	if ((la = ni_address_list_find(lease->addrs, &ap->local_addr))) {
		if (ap->owner != NI_ADDRCONF_NONE && ap->owner != NI_ADDRCONF_AUTOCONF) {
			changed = TRUE;
			__ni_address_list_remove(&lease->addrs, la);
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
					"%s: removed address %s/%u in %s:%s lease (owner %s)",
					dev->name,
					ni_sockaddr_print(&la->local_addr), la->prefixlen,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_type_to_name(ap->owner));
		} else {
			changed = TRUE;
			ni_address_copy(la, ap);
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
					"%s: updated address %s/%u in %s:%s lease (owner %s)",
					dev->name,
					ni_sockaddr_print(&la->local_addr), la->prefixlen,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_type_to_name(ap->owner));
		}
	} else
	if ((la = ni_address_new(ap->family, ap->prefixlen, &ap->local_addr, &lease->addrs))) {
		changed = TRUE;
		ni_address_copy(la, ap);
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
				"%s: added address %s/%u to %s:%s lease (owner %s)",
				dev->name,
				ni_sockaddr_print(&la->local_addr), la->prefixlen,
				ni_addrfamily_type_to_name(lease->family),
				ni_addrconf_type_to_name(lease->type),
				ni_addrconf_type_to_name(ap->owner));
	}
	return changed;
}

void
ni_auto6_on_prefix_event(ni_netdev_t *dev, ni_event_t event, const ni_ipv6_ra_pinfo_t *pi)
{
	ni_netconfig_t *nc;
	ni_addrconf_lease_t *lease;
	ni_bool_t changed = FALSE;
	ni_address_t *ap, *la, **pos;

	if (!dev || !pi)
		return;

	if (!(nc = ni_global_state_handle(0)))
		return;

	/* boo#975020, bsc#934067 workaround
	 * There are still many kernels in the wild that do not send
	 * NEWLINK on IPv6 RA changes (fixed upstream in 3.x stable),
	 * so actively refresh ipv6 link info to get current flags.
	 */
	__ni_device_refresh_ipv6_link_info(nc, dev);

	/* When autonomous autoconf prefix arrives, refresh addresses
	 * to track tentative addresses; the kernel sends the events
	 * once it finished duplicate address detection and removed
	 * the tentative flag or replaced by dadfailed.
	 */
	if (ni_auto6_is_autoconf_prefix(pi))
		__ni_system_refresh_interface_addrs(nc, dev);
	else
		return;

	if (dev->auto6 && !dev->auto6->enabled)
		return;

	switch (event) {
	case NI_EVENT_PREFIX_UPDATE:
		if (!(lease = ni_auto6_get_lease(dev))) {
			if ((lease = ni_auto6_new_lease(NI_ADDRCONF_STATE_GRANTED, NULL))) {
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
						"%s: create %s:%s lease in state %s", dev->name,
						ni_addrfamily_type_to_name(lease->family),
						ni_addrconf_type_to_name(lease->type),
						ni_addrconf_state_to_name(lease->state));
				ni_netdev_set_lease(dev, lease);
			} else {
				ni_warn("%s: failed to create a %s:%s lease: %m", dev->name,
						ni_addrfamily_type_to_name(AF_INET6),
						ni_addrconf_type_to_name(NI_ADDRCONF_AUTOCONF));
				return;
			}
		}

		for (ap = dev->addrs; ap; ap = ap->next) {
			if (ap->family != AF_INET6)
				continue;
			if (ap->prefixlen != pi->length)
				continue;
			if (!ni_address_is_mngtmpaddr(ap))
				continue;
			if (ni_sockaddr_is_ipv6_linklocal(&ap->local_addr))
				continue;

			if (ni_auto6_lease_address_update(dev, lease, ap))
				changed = TRUE;
		}
		break;

	case NI_EVENT_PREFIX_DELETE:
		if (!(lease = ni_auto6_get_lease(dev)))
			break;

		for (pos = &lease->addrs; (la = *pos); ) {
			if (ni_sockaddr_prefix_match(pi->length, &pi->prefix, &la->local_addr)) {
				changed = TRUE;
				ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
						"%s: removed address %s/%u to %s:%s lease", dev->name,
						ni_sockaddr_print(&la->local_addr), la->prefixlen,
						ni_addrfamily_type_to_name(lease->family),
						ni_addrconf_type_to_name(lease->type));
				*pos = la->next;
				ni_address_free(la);
			} else {
				pos = &la->next;
			}
		}
		break;

	default:
		break;
	}
	if (changed) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
			"%s: update %s:%s lease in state %s", dev->name,
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_type_to_name(lease->type),
			ni_addrconf_state_to_name(lease->state));

		ni_auto6_update_lease(dev, lease, NI_AUTO6_UPDATER_DELAY);
	}
}

void
ni_auto6_on_address_event(ni_netdev_t *dev, ni_event_t event, const ni_address_t *ap)
{
	ni_addrconf_lease_t *lease;
	ni_bool_t changed = FALSE;
	ni_address_t *la;

	if (!dev || !ap || ap->family != AF_INET6)
		return;

	if (ni_sockaddr_is_ipv6_linklocal(&ap->local_addr)) {
		__ni_system_refresh_interface_addrs(ni_global_state_handle(0), dev);
		if (!ni_auto6_get_linklocal(dev)) {
			ni_auto6_release(dev, FALSE);
		}
		return;
	}

	if (dev->auto6 && !dev->auto6->enabled)
		return;

	if (!ni_address_is_mngtmpaddr(ap))
		return;

	if (!(lease = ni_auto6_get_lease(dev)))
		return;

	switch (event) {
	case NI_EVENT_ADDRESS_UPDATE:
		if (ni_auto6_lease_address_update(dev, lease, ap))
			changed = TRUE;
		break;

	case NI_EVENT_ADDRESS_DELETE:
		if ((la = ni_address_list_find(lease->addrs, &ap->local_addr))) {
			changed = TRUE;
			__ni_address_list_remove(&lease->addrs, la);
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
					"%s: deleted address %s/%u in %s:%s lease (owner %s)",
					dev->name,
					ni_sockaddr_print(&la->local_addr), la->prefixlen,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_type_to_name(ap->owner));
		}
		break;

	default:
		break;
	}

	if (changed) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
			"%s: update %s:%s lease in state %s", dev->name,
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_type_to_name(lease->type),
			ni_addrconf_state_to_name(lease->state));

		ni_auto6_update_lease(dev, lease, NI_AUTO6_UPDATER_DELAY);
	}
}

static ni_bool_t
ni_auto6_lease_rdnss_update(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_string_array_t *old, cur = NI_STRING_ARRAY_INIT;
	ni_ipv6_ra_rdnss_t *rdnss;
	ni_bool_t changed = FALSE;
	ni_bool_t update = FALSE;
	ni_auto6_t *auto6;

	if (!dev || !dev->ipv6 || !lease || !(auto6 = ni_netdev_get_auto6(dev)))
		return changed;

	if (!lease->resolver && !(lease->resolver = ni_resolver_info_new()))
		return changed;

	/*
	 * rdnss servers received with lifetime of 0 are not in the list,
	 * so we put unexpired servers and report if something changed.
	 */
	old = &lease->resolver->dns_servers;
	if (auto6->update == NI_TRISTATE_DEFAULT)
		update = ni_netdev_auto6_address_autoconf(dev);
	else
	if (lease->update & NI_BIT(NI_ADDRCONF_UPDATE_DNS))
		update = TRUE;
	if (!update) {
		if (old->count) {
			changed = TRUE;
			ni_string_array_destroy(old);
		}
		return changed;
	}
	for (rdnss = dev->ipv6->radv.rdnss; rdnss; rdnss = rdnss->next) {
		const char *ptr;
		unsigned int i;

		ptr = ni_sockaddr_print(&rdnss->server);
		if (ni_string_empty(ptr))
			continue;

		if ((i = (unsigned int)ni_string_array_index(old, ptr)) != -1U)
			ni_string_array_remove_index(old, i);
		else
			changed = TRUE; /* a server to add */

		ni_string_array_append(&cur, ptr);
	}

	if (old->count)
		changed = TRUE;		/* servers to drop */

	ni_string_array_move(old, &cur);

	return changed;
}

static ni_bool_t
ni_auto6_lease_dnssl_update(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_string_array_t *old, cur = NI_STRING_ARRAY_INIT;
	ni_ipv6_ra_dnssl_t *dnssl;
	ni_bool_t changed = FALSE;
	ni_bool_t update = FALSE;
	ni_auto6_t *auto6;

	if (!dev || !dev->ipv6 || !lease || !(auto6 = ni_netdev_get_auto6(dev)))
		return changed;

	if (!lease->resolver && !(lease->resolver = ni_resolver_info_new()))
		return changed;

	/*
	 * rdnss servers received with lifetime of 0 are not in the list,
	 * so we put unexpired domains and report if something changed.
	 */
	old = &lease->resolver->dns_search;
	if (auto6->update == NI_TRISTATE_DEFAULT)
		update = ni_netdev_auto6_address_autoconf(dev);
	else
	if (lease->update & NI_BIT(NI_ADDRCONF_UPDATE_DNS))
		update = TRUE;
	if (!update) {
		if (old->count) {
			changed = TRUE;
			ni_string_array_destroy(old);
		}
		return changed;
	}
	for (dnssl = dev->ipv6->radv.dnssl; dnssl; dnssl = dnssl->next) {
		const char *ptr;
		unsigned int i;

		ptr = dnssl->domain;
		if (ni_string_empty(ptr))
			continue;

		if ((i = (unsigned int)ni_string_array_index(old, ptr)) != -1U)
			ni_string_array_remove_index(old, i);
		else
			changed = TRUE; /* a domain to add */

		ni_string_array_append(&cur, ptr);
	}

	if (old->count)
		changed = TRUE;		/* domains to drop */

	ni_string_array_move(old, &cur);

	return changed;
}

void
ni_auto6_on_nduseropt_events(ni_netdev_t *dev, ni_event_t event)
{
	ni_addrconf_lease_t *lease;
	unsigned int lifetime;
	struct timeval now;
	ni_bool_t changed = FALSE;

	if (!dev)
		return;

	if (dev->auto6 && (!dev->auto6->enabled || dev->auto6->update == NI_TRISTATE_DISABLE))
		return;

	if (!(lease = ni_auto6_get_lease(dev))) {
		if ((lease = ni_auto6_new_lease(NI_ADDRCONF_STATE_GRANTED, NULL))) {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
				"%s: create %s:%s lease in state %s", dev->name,
				ni_addrfamily_type_to_name(lease->family),
				ni_addrconf_type_to_name(lease->type),
				ni_addrconf_state_to_name(lease->state));
			ni_netdev_set_lease(dev, lease);
		} else {
			ni_warn("%s: failed to create a %s:%s lease: %m", dev->name,
					ni_addrfamily_type_to_name(AF_INET6),
					ni_addrconf_type_to_name(NI_ADDRCONF_AUTOCONF));
			return;
		}
	}

	switch (event) {
	case NI_EVENT_RDNSS_UPDATE:
	case NI_EVENT_DNSSL_UPDATE:
		ni_timer_get_time(&now);
		lifetime = ni_ipv6_ra_info_expire(&dev->ipv6->radv, &now);
		ni_auto6_expire_set_timer(ni_netdev_get_auto6(dev), lifetime);
		/* we expire both, so also update both in the lease */
		if (ni_auto6_lease_rdnss_update(dev, lease))
			changed = TRUE;
		if (ni_auto6_lease_dnssl_update(dev, lease))
			changed = TRUE;
		break;

	default:
		return;
	}

	if (changed) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
			"%s: update %s:%s lease in state %s", dev->name,
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_type_to_name(lease->type),
			ni_addrconf_state_to_name(lease->state));

		/* delay, as there may be more events to process ... */
		ni_auto6_update_lease(dev, lease, NI_AUTO6_UPDATER_DELAY);
	}
}

/*
 * Expire handling
 */
static void
ni_auto6_expire_update_lease(ni_netdev_t *dev)
{
	ni_addrconf_lease_t *lease;
	ni_bool_t changed = FALSE;

	if (!dev || !(lease = ni_auto6_get_lease(dev)))
		return;

	switch (lease->state) {
	case NI_ADDRCONF_STATE_NONE:
	case NI_ADDRCONF_STATE_RELEASING:
	case NI_ADDRCONF_STATE_RELEASED:
		return;

	default:
		break;
	}

	if (dev->ipv6 && (dev->ipv6->radv.rdnss || dev->ipv6->radv.dnssl)) {
		if (ni_auto6_lease_rdnss_update(dev, lease))
			changed = TRUE;
		if (ni_auto6_lease_dnssl_update(dev, lease))
			changed = TRUE;

		if (changed)
			ni_auto6_update_lease(dev, lease, NI_AUTO6_UPDATER_DELAY);
	} else {
		/* drop to avoid empty granted lease */
		ni_auto6_remove_lease(dev, lease);
	}
}

static void
ni_auto6_expire_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_auto6_t *auto6 = user_data;;
	unsigned int lifetime;
	ni_netconfig_t *nc;
	ni_netdev_t *dev;
	struct timeval now;

	if (!auto6 || auto6->expire.timer != timer)
		return;

	auto6->expire.timer = NULL;

	if (!(nc = ni_global_state_handle(0)))
		return;

	if (!(dev = ni_netdev_by_index(nc, auto6->device.index)))
		return;

	if (!dev->ipv6)
		return;

	ni_timer_get_time(&now);
	lifetime = ni_ipv6_ra_info_expire(&dev->ipv6->radv, &now);
	ni_auto6_expire_set_timer(ni_netdev_get_auto6(dev), lifetime);
	ni_auto6_expire_update_lease(dev);
}

static void
ni_auto6_expire_set_timer(ni_auto6_t *auto6, unsigned int lifetime)
{
	unsigned long timeout;

	if (!auto6 || lifetime == NI_LIFETIME_EXPIRED || lifetime == NI_LIFETIME_INFINITE)
		return;

	timeout = lifetime * 1000;
	if (auto6->expire.timer) {
		auto6->expire.timer = ni_timer_rearm(auto6->expire.timer, timeout);
	}
	if (!auto6->expire.timer) {
		auto6->expire.timer = ni_timer_register(timeout, ni_auto6_expire_timeout, auto6);
	}
}

/*
 * Auto6 service operations
 */
static void
ni_auto6_acquire_run(void *user_data, const ni_timer_t *timer)
{
	ni_auto6_t *auto6 = user_data;
	ni_addrconf_lease_t *lease;
	const ni_address_t *ap;
	unsigned int left;
	ni_netconfig_t *nc;
	ni_netdev_t *dev;

	if (!auto6 || auto6->acquire.timer != timer)
		return;

	auto6->acquire.timer = NULL;

	if (!(nc = ni_global_state_handle(0)))
		return;

	if (!(dev = ni_netdev_by_index(nc, auto6->device.index)))
		return;

	if (!ni_netdev_auto6_supported(dev) || !ni_netdev_auto6_enabled(dev)) {
		ni_warn("%s: ipv6:auto seems to be disabled in the kernel", dev->name);
		/* cancel waiting in the client fsm / nanny */
		ni_auto6_send_event(NULL, dev, NI_EVENT_ADDRESS_LOST, &auto6->uuid);
		/* let it also forget / remove the lease */
		ni_auto6_send_event(NULL, dev, NI_EVENT_ADDRESS_RELEASED, NULL);
		return;
	}

	if (!(lease = ni_auto6_get_lease(dev))) {
		ni_warn("%s: ipv6:auto lease request has been removed", dev->name);
		ni_auto6_send_event(NULL, dev, NI_EVENT_ADDRESS_LOST, &auto6->uuid);
		return;
	}

	if (!ni_netdev_device_is_up(dev)) {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
				"%s: link is not even set UP, fail", dev->name);
		lease->state = NI_ADDRCONF_STATE_FAILED;
		ni_auto6_send_event(NULL, dev, NI_EVENT_ADDRESS_LOST, &lease->uuid);
		return;
	}

	if (!ni_netdev_link_is_up(dev)) {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
				"%s: link is not ready yet, defer", dev->name);
		lease->state = NI_ADDRCONF_STATE_REQUESTING;
		ni_auto6_send_event(NULL, dev, NI_EVENT_ADDRESS_DEFERRED, &lease->uuid);
		return;
	}

	/*
	 * kernel sets link local on transition to link-up,
	 * so when it is not set or duplicate, just fail.
	 */
	if (!(ap = ni_auto6_get_linklocal(dev))) {
		__ni_system_refresh_interface_addrs(nc, dev);
		if (!(ap = ni_auto6_get_linklocal(dev))) {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
					"%s: no link-local address assigned, fail", dev->name);
			lease->state = NI_ADDRCONF_STATE_FAILED;
			ni_auto6_send_event(NULL, dev, NI_EVENT_ADDRESS_LOST, &lease->uuid);
			return;
		}
	}
	if (ni_address_is_duplicate(ap)) {
		ni_warn("%s: ipv6 link-local address %s is duplicate, fail", dev->name,
				ni_sockaddr_print(&ap->local_addr));
		lease->state = NI_ADDRCONF_STATE_FAILED;
		ni_auto6_send_event(NULL, dev, NI_EVENT_ADDRESS_LOST, &lease->uuid);
		return;
	}

	if (!(left = ni_lifetime_left(auto6->acquire.deadline, &auto6->acquire.start, NULL))) {
		ni_auto6_send_event(NULL, dev, NI_EVENT_ADDRESS_DEFERRED, &lease->uuid);
		return;
	}

	if (ni_address_is_tentative(ap)) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
				"%s: link-local address %s is tentative, wait up to %usec...",
				dev->name, ni_sockaddr_print(&ap->local_addr), left);
		/* the kernel sends rs itself, just let it do it's work */
		auto6->acquire.send_rs = 0;
	} else
	if (auto6->acquire.send_rs) {
		/*
		 * the link address was already ready to use
		 * (e.g. wickedd restarted or ifup ; ifup);
		 * send router solicit ourselfs to get an RA
		 * update and (re)apply the lease.
		 */
		auto6->acquire.send_rs--;
		if (ni_icmpv6_ra_solicit(&auto6->device, NULL)) {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
					"%s: ipv6 router solicit sent, waiting up to %usec for RA",
					dev->name, left);
		} else {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
					"%s: failed to send ipv6 router solicit", dev->name);
		}
	} else {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
				"%s: waiting up to %usec for ipv6 router advertisement",
				dev->name, left);
	}

	ni_auto6_acquire_set_timer(auto6, NI_AUTO6_ACQUIRE_TIMEOUT);
}

static void
ni_auto6_acquire_set_timer(ni_auto6_t *auto6, unsigned int delay)
{
	unsigned long timeout = delay * 1000;

	if (auto6->acquire.timer)
		auto6->acquire.timer = ni_timer_rearm(auto6->acquire.timer, timeout);

	if (!auto6->acquire.timer)
		auto6->acquire.timer = ni_timer_register(timeout, ni_auto6_acquire_run, auto6);
}

int
ni_auto6_acquire(ni_netdev_t *dev, const ni_auto6_request_t *req)
{
	ni_addrconf_lease_t *lease;
	ni_auto6_t *auto6;

	if (!dev || !(auto6 = ni_netdev_get_auto6(dev)) || !req || !req->enabled)
		return -1;

	ni_uuid_generate(&auto6->uuid);
	if (!(lease = ni_auto6_get_lease(dev))) {
		if ((lease = ni_auto6_new_lease(NI_ADDRCONF_STATE_REQUESTING, &auto6->uuid))) {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_AUTOIP,
					"%s: create %s:%s lease in state %s", dev->name,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_state_to_name(lease->state));
		} else {
			ni_error("%s: failed to create a %s:%s lease: %m", dev->name,
					ni_addrfamily_type_to_name(AF_INET6),
					ni_addrconf_type_to_name(NI_ADDRCONF_AUTOCONF));
			return -1;
		}
		ni_netdev_set_lease(dev, lease);
	} else {
		lease->state = NI_ADDRCONF_STATE_REQUESTING;
		lease->uuid  = auto6->uuid;
	}

	if (req->update == -1U) {
		lease->update = ni_config_addrconf_update(dev->name, NI_ADDRCONF_AUTOCONF, AF_INET6);
	} else {
		lease->update = req->update;
		lease->update &= ni_config_addrconf_update_mask(NI_ADDRCONF_AUTOCONF, AF_INET6);
	}
	ni_tristate_set(&auto6->update, !!lease->update);
	auto6->acquire.deadline = req->defer_timeout;
	auto6->acquire.send_rs  = NI_AUTO6_ACQUIRE_SEND_RS;

	ni_timer_get_time(&auto6->acquire.start);
	ni_auto6_acquire_set_timer(auto6, NI_AUTO6_ACQUIRE_DELAY);
	return 0;
}

int
ni_auto6_release(ni_netdev_t *dev, ni_bool_t background)
{
	ni_addrconf_lease_t *lease;
	ni_auto6_t *auto6;

	if (!dev || !(auto6 = ni_netdev_get_auto6(dev)))
		return -1;

	ni_auto6_reset(auto6);
	auto6->enabled = FALSE;
	auto6->update  = NI_TRISTATE_DISABLE;

	if ((lease = ni_auto6_get_lease(dev)))
		return ni_auto6_remove_lease(dev, lease);

	/* do we have to background, even there is no lease? */
	if (!background)
		return 0;

	ni_uuid_generate(&auto6->uuid);
	if (!(lease = ni_auto6_new_lease(NI_ADDRCONF_STATE_RELEASING, &auto6->uuid)))
		return -1;

	lease->update = 0;
	ni_netdev_set_lease(dev, lease);

	return ni_auto6_remove_lease(dev, lease);
}

