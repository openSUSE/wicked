/*
 * DHCP4 client for wicked.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/time.h>
#include <wicked/xml.h>
#include "netinfo_priv.h"
#include "appconfig.h"

#include "dhcp4/dhcp4.h"
#include "dhcp4/protocol.h"
#include "dhcp.h"
#include "iaid.h"
#include "duid.h"


static unsigned int	ni_dhcp4_do_bits(const ni_dhcp4_device_t *, unsigned int);
static const char *	ni_dhcp4_print_doflags(unsigned int);
static void		ni_dhcp4_config_set_request_options(const char *, ni_uint_array_t *, const ni_string_array_t *);

ni_dhcp4_device_t *	ni_dhcp4_active;

/*
 * Create and destroy dhcp4 device handles
 */
ni_dhcp4_device_t *
ni_dhcp4_device_new(const char *ifname, const ni_linkinfo_t *link)
{
	ni_dhcp4_device_t *dev, **pos;

	for (pos = &ni_dhcp4_active; (dev = *pos) != NULL; pos = &dev->next)
		;

	dev = calloc(1, sizeof(*dev));
	ni_string_dup(&dev->ifname, ifname);
	dev->users = 1;
	dev->listen_fd = -1;
	dev->link.ifindex = link->ifindex;
	/*
	 * it's either a fresh link and we have to perform dad anyway
	 * or we just (re-)started and "may have moved to a new link",
	 * so assume a reconnect to retrigger dad in next lease commit.
	 */
	dev->link.reconnect = TRUE;

	if (ni_capture_devinfo_init(&dev->system, dev->ifname, link) < 0) {
		ni_error("%s: cannot set up %s for DHCP4", __func__, ifname);
		ni_dhcp4_device_put(dev);
		return NULL;
	}

	ni_timer_get_time(&dev->start_time);
	dev->fsm.state = NI_DHCP4_STATE_INIT;

	/* append to end of list */
	*pos = dev;

	return dev;
}

static void
ni_dhcp4_device_free(ni_dhcp4_device_t *dev)
{
	ni_dhcp4_device_t **pos;

	ni_assert(dev->users == 0);
	ni_debug_dhcp("%s: Deleting dhcp4 device with index %u",
			dev->ifname, dev->link.ifindex);

	ni_dhcp4_device_drop_buffer(dev);
	ni_dhcp4_device_drop_lease(dev);
	ni_dhcp4_device_drop_best_offer(dev);
	ni_dhcp4_device_stop(dev);

	ni_capture_devinfo_destroy(&dev->system);

	ni_string_free(&dev->ifname);

	for (pos = &ni_dhcp4_active; *pos; pos = &(*pos)->next) {
		if (*pos == dev) {
			*pos = dev->next;
			break;
		}
	}
	free(dev);
}

/*
 * Refcount handling
 */
ni_dhcp4_device_t *
ni_dhcp4_device_get(ni_dhcp4_device_t *dev)
{
	ni_assert(dev->users);
	dev->users++;
	return dev;
}

void
ni_dhcp4_device_put(ni_dhcp4_device_t *dev)
{
	ni_assert(dev->users);
	if (--(dev->users) == 0)
		ni_dhcp4_device_free(dev);
}

/*
 * Lookup dhcp4 client device, netdev, linkinfo
 */
ni_dhcp4_device_t *
ni_dhcp4_device_by_index(unsigned int ifindex)
{
	ni_dhcp4_device_t *dev;

	for (dev = ni_dhcp4_active; dev; dev = dev->next) {
		if (dev->system.ifindex == ifindex)
			return dev;
	}

	return NULL;
}

static ni_netdev_t *
ni_dhcp4_device_netdev(const ni_dhcp4_device_t *dev)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;

	if (!dev || !(nc = ni_global_state_handle(0)))
		return NULL;
	if (!(ifp = ni_netdev_by_index(nc, dev->link.ifindex)))
		return NULL;
	return ifp;
}

static ni_bool_t
ni_dhcp4_device_link_is_up(const ni_dhcp4_device_t *dev)
{
	const ni_netdev_t *ifp;

	if (!(ifp = ni_dhcp4_device_netdev(dev)))
		return FALSE;
	return ni_netdev_link_is_up(ifp);
}

ni_bool_t
ni_dhcp4_timer_arm(const ni_timer_t **timer, ni_timeout_t timeout,
		ni_timeout_callback_t *callback, ni_dhcp4_device_t *dev)
{
	ni_assert(timer && callback && dev);

	ni_dhcp4_timer_disarm(timer);
	if ((*timer = ni_timer_register(timeout, callback, dev)))
		return TRUE;

	return FALSE;
}

void
ni_dhcp4_timer_disarm(const ni_timer_t **timer)
{
	ni_assert(timer);

	if (*timer) {
		ni_timer_cancel(*timer);
		*timer = NULL;
	}
}

void
ni_dhcp4_device_timer_disarm(ni_dhcp4_device_t *dev)
{
	ni_dhcp4_timer_disarm(&dev->fsm.timer);
	ni_dhcp4_timer_disarm(&dev->timer.delay);
	ni_dhcp4_timer_disarm(&dev->timer.defer);
	ni_dhcp4_timer_disarm(&dev->timer.acquire);
}

static void
ni_dhcp4_device_close(ni_dhcp4_device_t *dev)
{
	ni_dhcp4_device_disarm_retransmit(dev);
	ni_dhcp4_device_timer_disarm(dev);

	ni_dhcp4_device_arp_close(dev);
	ni_dhcp4_socket_close(dev);
}

void
ni_dhcp4_device_stop(ni_dhcp4_device_t *dev)
{
	ni_dhcp4_device_close(dev);

	/* Drop existing config and request */
	ni_dhcp4_device_set_config(dev, NULL);
	ni_dhcp4_device_set_request(dev, NULL);
}

void
ni_dhcp4_device_set_config(ni_dhcp4_device_t *dev, ni_dhcp4_config_t *config)
{
	if (dev->config) {
		ni_string_array_destroy(&dev->config->user_class.class_id);
		ni_uint_array_destroy(&dev->config->request_options);
		free(dev->config);
	}
	dev->config = config;
}

void
ni_dhcp4_device_set_request(ni_dhcp4_device_t *dev, ni_dhcp4_request_t *request)
{
	if (dev->request)
		ni_dhcp4_request_free(dev->request);
	dev->request = request;
}

unsigned int
ni_dhcp4_device_uptime(const ni_dhcp4_device_t *dev, unsigned int clamp)
{
	struct timeval now, uptime;

	ni_timer_get_time(&now);
	if (timercmp(&now, &dev->start_time, >))
		timersub(&now, &dev->start_time, &uptime);
	else
		timerclear(&uptime);

	if ((unsigned long)uptime.tv_sec < (unsigned long)clamp)
		return (unsigned int)uptime.tv_sec;
	else
		return clamp;
}

void
ni_dhcp4_device_set_lease(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	ni_addrconf_lease_hold(&dev->lease, lease);
	if (dev->config && lease)
		lease->uuid = dev->config->uuid;
}

void
ni_dhcp4_device_drop_lease(ni_dhcp4_device_t *dev)
{
	ni_addrconf_lease_drop(&dev->lease);
}

void
ni_dhcp4_device_set_best_offer(ni_dhcp4_device_t *dev, ni_addrconf_lease_t **lease,
							int weight)
{
	ni_addrconf_lease_move(&dev->best_offer.lease, lease);
	dev->best_offer.weight = weight;
	if (dev->config && dev->best_offer.lease)
		dev->best_offer.lease->uuid = dev->config->uuid;
}

void
ni_dhcp4_device_drop_best_offer(ni_dhcp4_device_t *dev)
{
	dev->best_offer.weight = -1;
	ni_addrconf_lease_drop(&dev->best_offer.lease);
}

/*
 * Refresh the device mtu and MAC address info prior to taking any actions
 */
int
ni_dhcp4_device_refresh(ni_dhcp4_device_t *dev)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *ifp;
	int rv = -1;

	ifp = nc ? ni_netdev_by_index(nc, dev->link.ifindex) : NULL;
	if (!ifp || (rv = __ni_device_refresh_link_info(nc, &ifp->link)) < 0) {
		ni_error("%s: cannot refresh interface link info", dev->ifname);
		return rv;
	}

	return ni_capture_devinfo_refresh(&dev->system, dev->ifname, &ifp->link);
}

/*
 * Process a request to reconfigure the device (ie rebind a lease, or discover
 * a new lease).
 */
int
ni_dhcp4_acquire(ni_dhcp4_device_t *dev, const ni_dhcp4_request_t *info)
{
	ni_dhcp4_config_t *config;
	const char *classid;
	size_t len;
	int rv;

	if ((rv = ni_dhcp4_device_refresh(dev)) < 0)
		return rv;

	config = xcalloc(1, sizeof(*config));

	config->dry_run = info->dry_run;
	config->start_delay = info->start_delay;
	config->defer_timeout = info->defer_timeout;
	config->acquire_timeout = info->acquire_timeout;
	config->uuid = info->uuid;
	config->flags = info->flags;
	if (info->update == -1U) {
		config->update = ni_config_addrconf_update(dev->ifname, NI_ADDRCONF_DHCP, AF_INET);
	} else {
		config->update = info->update;
		config->update &= ni_config_addrconf_update_mask(NI_ADDRCONF_DHCP, AF_INET);
	}
	config->doflags = ni_dhcp4_do_bits(dev, config->update);

	config->route_priority = info->route_priority;
	config->route_set_src = info->route_set_src;
	config->recover_lease = info->recover_lease;
	config->release_lease = info->release_lease;
	config->broadcast = info->broadcast;

	config->max_lease_time = max_t(unsigned int,
				ni_dhcp4_config_max_lease_time(dev->ifname),
				NI_DHCP4_LEASE_TIME_MIN);
	if (info->lease_time && info->lease_time < config->max_lease_time) {
		config->max_lease_time = max_t(unsigned int,
				info->lease_time, NI_DHCP4_LEASE_TIME_MIN);
	}

	/*
	 * RFC 4702 section 3.1 defines, that a client sending the fqdn
	 * option (81), MUST NOT send the Host Name option (12) and
	 * prefer the fqdn option in server responses.
	 * We're using the request/config hostname field for both options.
	 */
	config->fqdn = info->fqdn;
	if ((len = ni_string_len(info->hostname)) > 0) {
		if (ni_check_domain_name(info->hostname, len, 0)) {
			strncpy(config->hostname, info->hostname, sizeof(config->hostname) - 1);

			if (config->fqdn.enabled == NI_TRISTATE_DEFAULT)
				ni_tristate_set(&config->fqdn.enabled, !!strchr(config->hostname, '.'));
		} else {
			ni_debug_dhcp("Discarded request to use suspect hostname: '%s'",
				ni_print_suspect(info->hostname, len));
		}
	}
	if (config->fqdn.enabled == NI_TRISTATE_DEFAULT)
		ni_tristate_set(&config->fqdn.enabled, FALSE);
	if (config->fqdn.enabled == NI_TRISTATE_ENABLE && ni_string_empty(config->hostname))
		config->fqdn.update = NI_DHCP_FQDN_UPDATE_NONE;

	if (!ni_dhcp4_parse_client_id(&config->client_id, dev->system.hwaddr.type, info->clientid))
		ni_dhcp4_set_config_client_id(&config->client_id, dev, info->create_cid);

	if ((classid = info->vendor_class) == NULL)
		classid = ni_dhcp4_config_vendor_class();
	if (classid)
		strncpy(config->classid, classid, sizeof(config->classid) - 1);

	if (info->user_class.class_id.count) {
		config->user_class.format = info->user_class.format;
		ni_string_array_copy(&config->user_class.class_id, &info->user_class.class_id);
	}

	if (ni_log_facility(NI_TRACE_DHCP)) {
		ni_trace("Received request:");
		ni_trace("  start-delay     %s", ni_sprint_timeout(config->start_delay));
		ni_trace("  defer-timeout   %s", ni_sprint_timeout(config->defer_timeout));
		ni_trace("  acquire-timeout %s", ni_sprint_timeout(config->acquire_timeout));
		ni_trace("  max lease-time  %s", ni_sprint_timeout(config->max_lease_time));
		ni_trace("  hostname        %s", config->hostname[0]? config->hostname : "<none>");
		if (config->fqdn.enabled == NI_TRISTATE_ENABLE) {
			ni_trace("  fqdn            update %s, encode %s, qualify %s",
					ni_dhcp_fqdn_update_mode_to_name(config->fqdn.update),
					ni_format_boolean(config->fqdn.encode),
					ni_format_boolean(config->fqdn.qualify));
		}
		ni_trace("  vendor-class    %s", config->classid[0]? config->classid : "<none>");
		if (config->user_class.class_id.count) {
			char *userclass = NULL;
			const char *fmt = ni_dhcp4_user_class_format_type_to_name(config->user_class.format);
			ni_string_join(&userclass, &config->user_class.class_id, ", ");
			ni_trace("  user-class      %s: %s", fmt, userclass);
			ni_string_free(&userclass);
		}
		ni_trace("  client-id       %s", ni_print_hex(config->client_id.data, config->client_id.len));
		ni_trace("  uuid            %s", ni_uuid_print(&config->uuid));
		ni_trace("  update-flags    %s", ni_dhcp4_print_doflags(config->doflags));
		ni_trace("  recover_lease   %s", config->recover_lease ? "true" : "false");
		ni_trace("  release_lease   %s", config->release_lease ? "true" : "false");
	}
	ni_dhcp4_config_set_request_options(dev->ifname, &config->request_options, &info->request_options);

	ni_dhcp4_device_set_config(dev, config);

	ni_note("%s: Request to acquire DHCPv4 lease with UUID %s",
		dev->ifname, ni_uuid_print(&config->uuid));

	if (config->dry_run != NI_DHCP4_RUN_OFFER &&
	    config->recover_lease && ni_dhcp4_recover_lease(dev) == 0)
		dev->fsm.state = NI_DHCP4_STATE_REBOOT;
	else
		dev->fsm.state = NI_DHCP4_STATE_INIT;

	if (ni_dhcp4_device_start(dev) < 0)
		return -1;
	return 1;
}

/*
 * When the supplicant restarts, we reload the state from file, and check
 * for which devices we have existing requests.
 *
 * For now, we go through a full discover/request cycle. If this proves
 * a too coarse approach, we should probably store the current leases
 * in the state file as well, and just do a renew/rebind.
 */
void
ni_dhcp4_restart_leases(void)
{
	ni_dhcp4_device_t *dev;

	for (dev = ni_dhcp4_active; dev; dev = dev->next) {
		if (dev->request)
			ni_dhcp4_acquire(dev, dev->request);
	}
}

/*
 * Translate a bitmap of NI_ADDRCONF_UPDATE_* flags into a bitmap of
 * DHCP4_DO_* masks
 */
static unsigned int
ni_dhcp4_do_bits(const ni_dhcp4_device_t *dev, unsigned int update_flags)
{
	static unsigned int	do_mask[32] = {
	[NI_ADDRCONF_UPDATE_DEFAULT_ROUTE]	= DHCP4_DO_GATEWAY,
	[NI_ADDRCONF_UPDATE_HOSTNAME]		= DHCP4_DO_HOSTNAME,
	[NI_ADDRCONF_UPDATE_DNS]		= DHCP4_DO_DNS,
	[NI_ADDRCONF_UPDATE_NIS]		= DHCP4_DO_NIS,
	[NI_ADDRCONF_UPDATE_NTP]		= DHCP4_DO_NTP,
	[NI_ADDRCONF_UPDATE_NDS]		= DHCP4_DO_NDS,
	[NI_ADDRCONF_UPDATE_SMB]		= DHCP4_DO_SMB,
	[NI_ADDRCONF_UPDATE_SIP]		= DHCP4_DO_SIP,
	[NI_ADDRCONF_UPDATE_LPR]		= DHCP4_DO_LPR,
	[NI_ADDRCONF_UPDATE_LOG]		= DHCP4_DO_LOG,
	[NI_ADDRCONF_UPDATE_MTU]		= DHCP4_DO_MTU,
	[NI_ADDRCONF_UPDATE_BOOT]		= DHCP4_DO_ROOT,
	[NI_ADDRCONF_UPDATE_TZ]			= DHCP4_DO_POSIX_TZ,
	};
	unsigned int bit, result = DHCP4_DO_CSR | DHCP4_DO_STATIC_ROUTES;
	const ni_config_dhcp4_t *conf = NULL;
	const ni_netdev_t *ifp;

	conf = ni_config_dhcp4_find_device(dev ? dev->ifname : NULL);
	if ((ifp = ni_dhcp4_device_netdev(dev))) {
		if (ifp->link.ifflags & NI_IFF_ARP_ENABLED)
			result |= DHCP4_DO_ARP;
	}

	for (bit = 0; bit < 32; ++bit) {
		if (update_flags & NI_BIT(bit))
			result |= do_mask[bit];
		else
			result &= ~do_mask[bit];
	}

	if (conf && conf->routes_opts != -1U) {
		result &= ~(DHCP4_DO_CSR|DHCP4_DO_STATIC_ROUTES);

		if (conf->routes_opts & NI_BIT(NI_CONFIG_DHCP4_ROUTES_CSR))
			result |= DHCP4_DO_CSR;
		if (conf->routes_opts & NI_BIT(NI_CONFIG_DHCP4_ROUTES_MSCSR))
			result |= DHCP4_DO_MSCSR;
		if (conf->routes_opts & NI_BIT(NI_CONFIG_DHCP4_ROUTES_CLASS))
			result |= DHCP4_DO_STATIC_ROUTES;
	}

	return result;
}

static const char *
ni_dhcp4_print_doflags(unsigned int flags)
{
	static ni_intmap_t flag_names[] = {
	{ "arp",		DHCP4_DO_ARP		},
	{ "csr",		DHCP4_DO_CSR		},
	{ "mscsr",		DHCP4_DO_MSCSR		},
	{ "static-routes",	DHCP4_DO_STATIC_ROUTES	},
	{ "gateway",		DHCP4_DO_GATEWAY	},
	{ "hostname",		DHCP4_DO_HOSTNAME	},
	{ "dns",		DHCP4_DO_DNS		},
	{ "nis",		DHCP4_DO_NIS		},
	{ "ntp",		DHCP4_DO_NTP		},
	{ "nds",		DHCP4_DO_NDS		},
	{ "smb",		DHCP4_DO_SMB		},
	{ "sip",		DHCP4_DO_SIP		},
	{ "lpr",		DHCP4_DO_LPR		},
	{ "log",		DHCP4_DO_LOG		},
	{ "tz",			DHCP4_DO_POSIX_TZ	},
	{ "mtu",		DHCP4_DO_MTU		},
	{ "root",		DHCP4_DO_ROOT		},
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
		if (!(name = ni_format_uint_mapped(mask, flag_names)))
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

/*
 * Process a request to unconfigure the device (ie drop the lease).
 */
static void
ni_dhcp4_start_release(void *user_data, const ni_timer_t *timer)
{
	ni_dhcp4_device_t *dev = user_data;

	if (dev->timer.delay != timer) {
		ni_warn("%s: bad timer handle", __func__);
		return;
	}
	dev->timer.delay = NULL;

	/* We just send out a single RELEASE without waiting for the
	 * server's reply. We just keep our fingers crossed that it's
	 * getting out. If it doesn't, it's rather likely the network
	 * is hosed anyway, so there's little point in delaying. */
	ni_dhcp4_fsm_release_init(dev);

	ni_dhcp4_device_stop(dev);
}

int
ni_dhcp4_drop(ni_dhcp4_device_t *dev, const ni_dhcp4_drop_request_t *req)
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
		ni_info("%s: Request to %s DHCPv4 lease%s%s: no lease",
			dev->ifname, action,
			rel_uuid ? " with UUID " : "", rel_uuid ? rel_uuid : "");

		ni_string_free(&rel_uuid);
		ni_dhcp4_device_drop_lease(dev);
		ni_dhcp4_device_stop(dev);
		return -NI_ERROR_ADDRCONF_NO_LEASE;
	}

	ni_note("%s: Request to %s DHCPv4 lease%s%s: starting...",
		dev->ifname, action,
		rel_uuid ? " with UUID " : "", rel_uuid ? rel_uuid : "");
	ni_string_free(&rel_uuid);

	dev->lease->uuid = req->uuid;
	dev->config->uuid = req->uuid;
	if (ni_tristate_is_enabled(req->release))
		dev->config->release_lease = TRUE;
	else
	if (ni_tristate_is_disabled(req->release))
		dev->config->release_lease = FALSE;

	dev->fsm.state = NI_DHCP4_STATE_INIT;
	ni_dhcp4_device_disarm_retransmit(dev);
	ni_dhcp4_timer_disarm(&dev->fsm.timer);

	ni_dhcp4_device_drop_best_offer(dev);
	ni_dhcp4_device_arp_close(dev);

	ni_dhcp4_timer_arm(&dev->timer.delay, 0, ni_dhcp4_start_release, dev);
	return 1;
}

/*
 * Handle link up/down events
 */
void
ni_dhcp4_device_event(ni_dhcp4_device_t *dev, ni_netdev_t *ifp, ni_event_t event)
{
	switch (event) {
	case NI_EVENT_DEVICE_CHANGE:
	case NI_EVENT_DEVICE_RENAME:
	case NI_EVENT_DEVICE_UP:
		if (!ni_string_eq(dev->ifname, ifp->name)) {
			ni_debug_dhcp("%s: Updating interface name to %s",
					dev->ifname, ifp->name);
			ni_string_dup(&dev->ifname, ifp->name);
		}
		/* Does return -1 on failure. */
		ni_dhcp4_device_refresh(dev);
		break;

	case NI_EVENT_LINK_DOWN:
		ni_debug_dhcp("%s: link went down in state %s", dev->ifname,
				ni_dhcp4_fsm_state_name(dev->fsm.state));
		ni_dhcp4_fsm_link_down(dev);
		break;

	case NI_EVENT_LINK_UP:
		/* retrigger dad on lease commit */
		dev->link.reconnect = TRUE;
		ni_debug_dhcp("%s: link came up in state %s", dev->ifname,
				ni_dhcp4_fsm_state_name(dev->fsm.state));
		ni_dhcp4_fsm_link_up(dev);
		break;

	default: ;
	}
}

static void
ni_dhcp4_device_start_delayed(void *user_data, const ni_timer_t *timer)
{
	ni_dhcp4_device_t *dev = user_data;

	if (dev->timer.delay != timer) {
		ni_warn("%s: bad timer handle", __func__);
		return;
	}
	dev->timer.delay = NULL;

	if (ni_dhcp4_device_link_is_up(dev)) {
		ni_dhcp4_fsm_link_up(dev);
	} else {
		ni_debug_dhcp("%s: deferred start until link is up", dev->ifname);
	}
}

int
ni_dhcp4_device_start(ni_dhcp4_device_t *dev)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;
	unsigned int sec;

	ni_dhcp4_device_drop_buffer(dev);

	nc = ni_global_state_handle(0);
	if(!nc || !(ifp = ni_netdev_by_index(nc, dev->link.ifindex))) {
		ni_error("%s: unable to start device", dev->ifname);
		ni_dhcp4_device_stop(dev);
		return -1;
	}

	sec = ni_dhcp4_fsm_start_delay(dev->config->start_delay);
	ni_dhcp4_timer_arm(&dev->timer.delay, NI_TIMEOUT_FROM_SEC(sec),
			ni_dhcp4_device_start_delayed, dev);

	ni_dhcp4_defer_timer_arm(dev);
	ni_dhcp4_acquire_timer_arm(dev);
	return 1;
}

void
ni_dhcp4_device_alloc_buffer(ni_dhcp4_device_t *dev)
{
	unsigned int mtu = 0;

	mtu = dev->system.mtu;
	if (mtu == 0)
		mtu = MTU_MAX;

	if (dev->message.size == mtu) {
		ni_buffer_clear(&dev->message);
	} else {
		ni_dhcp4_device_drop_buffer(dev);
		ni_buffer_init_dynamic(&dev->message, mtu);
	}
}

void
ni_dhcp4_device_drop_buffer(ni_dhcp4_device_t *dev)
{
	ni_buffer_destroy(&dev->message);
}

static int
ni_dhcp4_device_prepare_message(void *data)
{
	ni_dhcp4_device_t *dev = data;

	/* Allocate an empty buffer */
	ni_dhcp4_device_alloc_buffer(dev);

	/* Build the DHCP4 message */
	if (ni_dhcp4_build_message(dev, dev->transmit.msg_code, dev->transmit.lease, &dev->message) < 0) {
		/* This is really terminal */
		ni_error("%s: unable to build %s message with xid 0x%x in state %s",
			dev->ifname, ni_dhcp4_message_name(dev->transmit.msg_code),
			dev->dhcp4.xid, ni_dhcp4_fsm_state_name(dev->fsm.state));
		return -1;
	}

	ni_debug_dhcp("%s: sending %s with xid 0x%x in state %s",
			dev->ifname, ni_dhcp4_message_name(dev->transmit.msg_code),
			dev->dhcp4.xid, ni_dhcp4_fsm_state_name(dev->fsm.state));
	return 0;
}

int
ni_dhcp4_device_send_message_broadcast(ni_dhcp4_device_t *dev, unsigned int msg_code, ni_addrconf_lease_t *lease)
{
	int rv;

	dev->transmit.msg_code = msg_code;
	ni_addrconf_lease_hold(&dev->transmit.lease, lease);

	if (ni_dhcp4_socket_open(dev) < 0) {
		ni_error("%s: unable to open capture socket", dev->ifname);
		goto transient_failure;
	}

	if ((rv = ni_dhcp4_device_prepare_message(dev)) < 0)
		return -1;

	switch (msg_code) {
	case DHCP4_DECLINE:
	case DHCP4_RELEASE:
		rv = ni_capture_send(dev->capture, &dev->message, NULL);
		break;

	case DHCP4_DISCOVER:
	case DHCP4_REQUEST:
	case DHCP4_INFORM:
		dev->transmit.params.timeout_callback = ni_dhcp4_device_prepare_message;
		dev->transmit.params.timeout_data = dev;
		rv = ni_capture_send(dev->capture, &dev->message, &dev->transmit.params);
		break;

	default:
		ni_warn("not sure whether I should retransmit %s message",
				ni_dhcp4_message_name(msg_code));
	}
	if (rv < 0)
		ni_debug_dhcp("unable to broadcast message");

	return 0;

transient_failure:
	/* We ran into a transient problem, such as being unable to open
	 * a raw socket. We should schedule a "short" timeout after which
	 * we should re-try the operation. */
	/* FIXME: Not done yet. */
	return 0;
}

int
ni_dhcp4_device_send_message_unicast(ni_dhcp4_device_t *dev, unsigned int msg_code, ni_addrconf_lease_t *lease)
{
	ni_sockaddr_t addr;

	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.server_id, DHCP4_SERVER_PORT);
	dev->transmit.msg_code = msg_code;
	ni_addrconf_lease_hold(&dev->transmit.lease, lease);

	if (ni_dhcp4_socket_open(dev) < 0) {
		ni_error("%s: unable to open capture socket", dev->ifname);
		return -1;
	}

	if (ni_dhcp4_device_prepare_message(dev) < 0)
		return -1;

	if (sendto(dev->listen_fd, ni_buffer_head(&dev->message),
				ni_buffer_count(&dev->message), 0,
				&addr.sa, sizeof(addr.sin)) < 0)
		ni_error("%s: sendto failed: %m", dev->ifname);
	return 0;
}

void
ni_dhcp4_device_disarm_retransmit(ni_dhcp4_device_t *dev)
{
	/* Clear transmit struct except of transmit.start */
	dev->transmit.msg_code = 0;
	memset(&dev->transmit.params, 0, sizeof(dev->transmit.params));
	ni_addrconf_lease_drop(&dev->transmit.lease);

	/* Clear capture retransmit timer params */
	if (dev->capture)
		ni_capture_disarm_retransmit(dev->capture);

	/* Drop the (raw) message buffer content */
	ni_dhcp4_device_drop_buffer(dev);
}

void
ni_dhcp4_device_force_retransmit(ni_dhcp4_device_t *dev, unsigned int delay)
{
	if (dev->capture)
		ni_capture_force_retransmit(dev->capture, delay);
}

void
ni_dhcp4_device_arp_close(ni_dhcp4_device_t *dev)
{
	if (dev->arp.handle) {
		ni_arp_socket_close(dev->arp.handle);
		dev->arp.handle = NULL;
	}
}

/*
 * Set the client ID from a link layer type and address, according to RFC 2132#section-9.14
 */
ni_bool_t
ni_dhcp4_set_hwaddr_client_id(ni_opaque_t *raw, const ni_hwaddr_t *hwa)
{
	if (!raw || !hwa || !hwa->len)
		return FALSE;

	if ((size_t)hwa->len + 1 > sizeof(raw->data))
		return FALSE;

	raw->data[0] = hwa->type;
	memcpy(raw->data + 1, hwa->data, hwa->len);
	raw->len = hwa->len + 1;
	return TRUE;
}

/*
 * Set the client ID from DHCPv6 IAID and DUID, according to RFC 4361
 */
ni_bool_t
ni_dhcp4_set_dhcpv6_client_id(ni_opaque_t *raw, unsigned int iaid, const ni_opaque_t *duid)
{
	if (!raw || !duid)
		return FALSE;

	if (sizeof(iaid) + duid->len + 1 > sizeof(raw->data))
		return FALSE;

	raw->data[0] = 0xff;
	iaid = htonl(iaid);
	memcpy(raw->data + 1, &iaid, sizeof(iaid));
	memcpy(raw->data + 1 + sizeof(iaid), duid->data, duid->len);
	raw->len = sizeof(iaid) + duid->len + 1;
	return TRUE;

}

/*
 * Set the client ID as defined in the wicked-config(5)
 */
ni_bool_t
ni_dhcp4_set_config_client_id(ni_opaque_t *raw, const ni_dhcp4_device_t *dev,
				unsigned int create_cid)
{
	const ni_config_dhcp4_t *dhcp4;
	ni_netconfig_t *nc;
	ni_netdev_t *ndev;
	unsigned int iaid;
	ni_opaque_t  duid;

	if (!raw || !dev || !(nc = ni_global_state_handle(0)))
		return FALSE;

	if (!(ndev = ni_netdev_by_index(nc, dev->link.ifindex)))
		return FALSE;

	if (create_cid == NI_CONFIG_DHCP4_CID_TYPE_AUTO) {
		/* use wicked-config(5) setting if any */
		if ((dhcp4 = ni_config_dhcp4_find_device(dev->ifname)))
			create_cid = dhcp4->create_cid;
	}

	if (create_cid == NI_CONFIG_DHCP4_CID_TYPE_AUTO) {
		/*
		 * We should always use dhcp6 based client-id as
		 * specified in RFC 4361, also on ethernet...
		 *
		 * This is also required to update DDNS records for
		 * DHCPv6 and DHCPv4 IP addresses in same zone (the
		 * server maintains a dhcid DNS record using it).
		 *
		 * Unfortunately, it would be a default behavior
		 * change and may cause non-matching lease as well
		 * as (ipv4 only) ddns update issues:
		 *
		 * There are many existing dhcp servers in the wild
		 * relying on or using (static) leases with the
		 * the "old" dhcp4 link address (mac) client-id,
		 * incl. updated ddns records using it already...
		 *
		 * DHCPv4 over infiniband RFC mandates DHCPv6 based
		 * client-id, on ethernet it currently requires to
		 * enable it.
		 */
		switch (dev->system.hwaddr.type) {
		case ARPHRD_ETHER:
#ifndef NI_DHCP4_RFC4361_CID
			create_cid = NI_CONFIG_DHCP4_CID_TYPE_HWADDR;
			break;
#endif
		case ARPHRD_INFINIBAND:
		default:
			create_cid = NI_CONFIG_DHCP4_CID_TYPE_DHCPv6;
			break;
		}
	}

	switch (create_cid) {
	case NI_CONFIG_DHCP4_CID_TYPE_DHCPv6:
		if (!ni_iaid_acquire(&iaid, ndev, 0))
			return FALSE;

		if (!ni_duid_acquire(&duid, ndev, nc, NULL))
			return FALSE;

		return ni_dhcp4_set_dhcpv6_client_id(raw, iaid, &duid);

	case NI_CONFIG_DHCP4_CID_TYPE_HWADDR:
		return ni_dhcp4_set_hwaddr_client_id(raw, &dev->system.hwaddr);

	case NI_CONFIG_DHCP4_CID_TYPE_DISABLE:
		return TRUE;

	case NI_CONFIG_DHCP4_CID_TYPE_AUTO:
	default:
		return FALSE;
	}
}

/*
 * Parse requested client id
 */
ni_bool_t
ni_dhcp4_parse_client_id(ni_opaque_t *raw, unsigned short arp_type, const char *cooked)
{
	ni_hwaddr_t hwaddr;
	size_t len;

	if (!raw || ni_string_empty(cooked))
		return FALSE;

	/* Check if it's a hardware address */
	if (ni_link_address_parse(&hwaddr, arp_type, cooked) == 0)
		return ni_dhcp4_set_hwaddr_client_id(raw, &hwaddr);

	/* Try to parse as a client-id hex string */
	raw->len = ni_parse_hex(cooked, raw->data, sizeof(raw->data));
	if ((int)(raw->len) > 1)
		return TRUE;

	/* nope, fallback to use as-is (attic legacy) */
	len = ni_string_len(cooked);
	if (len > sizeof(raw->data) - 1)
		len = sizeof(raw->data) - 1;

	raw->data[0] = 0x00; /* RFC 2132#section-9.14, other */
	memcpy(raw->data + 1, cooked, len);
	raw->len = len + 1;
	return TRUE;
}

/*
 * Functions for accessing various global DHCP4 configuration options
 */
const char *
ni_dhcp4_config_vendor_class(void)
{
	const struct ni_config_dhcp4 *dhconf = &ni_global.config->addrconf.dhcp4;

	return dhconf->vendor_class;
}

int
ni_dhcp4_config_ignore_server(const char *name)
{
	const struct ni_config_dhcp4 *dhconf = &ni_global.config->addrconf.dhcp4;

	return (ni_string_array_index(&dhconf->ignore_servers, name) >= 0);
}

int
ni_dhcp4_config_have_server_preference(void)
{
	const struct ni_config_dhcp4 *dhconf = &ni_global.config->addrconf.dhcp4;
	return dhconf->num_preferred_servers != 0;
}

int
ni_dhcp4_config_server_preference_ipaddr(struct in_addr addr)
{
	const struct ni_config_dhcp4 *dhconf = &ni_global.config->addrconf.dhcp4;
	const ni_server_preference_t *pref = dhconf->preferred_server;
	unsigned int i;

	for (i = 0; i < dhconf->num_preferred_servers; ++i, ++pref) {
		if (pref->address.ss_family != AF_INET)
			continue;
		if (pref->address.sin.sin_addr.s_addr == addr.s_addr)
			return pref->weight;
	}
	return 0;
}

int
ni_dhcp4_config_server_preference_hwaddr(const ni_hwaddr_t *hwaddr)
{
	const struct ni_config_dhcp4 *dhconf = &ni_global.config->addrconf.dhcp4;
	const ni_server_preference_t *pref = dhconf->preferred_server;
	unsigned int i;

	if (!hwaddr || !hwaddr->len)
		return 0;

	for (i = 0; i < dhconf->num_preferred_servers; ++i, ++pref) {
		if (pref->serverid.len != (size_t)hwaddr->len + 1)
			continue;
		if ((unsigned short)pref->serverid.data[0] != hwaddr->type)
			continue;
		if (memcmp(&pref->serverid.data[1], hwaddr->data, hwaddr->len))
			continue;
		return pref->weight;
	}
	return 0;
}

unsigned int
ni_dhcp4_config_max_lease_time(const char *ifname)
{
	const ni_config_dhcp4_t *dhconf = ni_config_dhcp4_find_device(ifname);

	return dhconf && dhconf->lease_time ? dhconf->lease_time : NI_SECONDS_INFINITE;
}

static void
ni_dhcp4_config_set_request_options(const char *ifname, ni_uint_array_t *cfg, const ni_string_array_t *req)
{
	const ni_config_dhcp4_t *dhconf = ni_config_dhcp4_find_device(ifname);
	const ni_dhcp_option_decl_t *custom_options = dhconf ? dhconf->custom_options : NULL;
	unsigned int i, n;

	for (n = i = 0; i < req->count; ++i) {
		const char *opt = req->data[i];
		const ni_dhcp_option_decl_t *decl;
		unsigned int code;

		if ((decl = ni_dhcp_option_decl_list_find_by_name(custom_options, opt)))
			code = decl->code;
		else if (ni_parse_uint(opt, &code, 10) < 0)
			continue;

		if (!code || code >= 255)
			continue;

		if (!ni_uint_array_contains(cfg, code)) {
			ni_debug_dhcp("  request-option[%u]: %u %s", n++, code,
							decl ? decl->name : "");
			ni_uint_array_append(cfg, code);
		}
	}
}

/*
 * Create or delete a dhcp4 request object
 */
ni_dhcp4_request_t *
ni_dhcp4_request_new(void)
{
	ni_dhcp4_request_t *req;

	req = xcalloc(1, sizeof(*req));
	req->enabled = TRUE; /* used by wickedd */

	req->broadcast = NI_TRISTATE_DEFAULT;

	/* By default, we try to obtain all sorts of settings from the server */
	req->update = -1U; /* apply wicked-config(5) defaults later */

	/* default: enable + update mode depends on request hostname + dots */
	ni_dhcp_fqdn_init(&req->fqdn);

	return req;
}

void
ni_dhcp4_request_free(ni_dhcp4_request_t *req)
{
	ni_string_free(&req->hostname);
	ni_string_free(&req->clientid);
	ni_string_free(&req->vendor_class);
	ni_string_array_destroy(&req->user_class.class_id);
	ni_string_array_destroy(&req->request_options);
	free(req);
}

void
ni_dhcp4_drop_request_init(ni_dhcp4_drop_request_t *req)
{
	ni_uuid_init(&req->uuid);
	req->release = NI_TRISTATE_DEFAULT;
}

ni_bool_t
ni_dhcp4_supported(const ni_netdev_t *ifp)
{
	/*
	 * currently broadcast and arp capable ether and ib types only,
	 * we've simply did not tested it on other links ...
	 */
	switch (ifp->link.hwaddr.type) {
	case ARPHRD_NONE:
		break;
	case ARPHRD_ETHER:
	case ARPHRD_INFINIBAND:
		if (ifp->link.masterdev.index) {
			ni_debug_dhcp("%s: DHCPv4 not supported on slaves",
					ifp->name);
			return FALSE;
		}

		if (!(ifp->link.ifflags & NI_IFF_ARP_ENABLED)) {
			ni_debug_dhcp("%s: DHCPv4 not supported without "
					"ARP support", ifp->name);
			return FALSE;
		}
		/* Hmm... can this happen? */
		if (!(ifp->link.ifflags & NI_IFF_BROADCAST_ENABLED)) {
			ni_debug_dhcp("%s: DHCPv4 not supported without "
					" broadcast support", ifp->name);
			return FALSE;
		}
		if ((ifp->link.ifflags & NI_IFF_POINT_TO_POINT)) {
			ni_debug_dhcp("%s: DHCPv4 not supported on point-"
					"to-point interfaces", ifp->name);
			return FALSE;
		}
		break;
	default:
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: DHCPv4 not supported on %s interfaces",
				ifp->name,
				ni_linktype_type_to_name(ifp->link.type));
		return FALSE;
	}
	return TRUE;
}

void
ni_dhcp4_new_xid(ni_dhcp4_device_t *cur)
{
	ni_dhcp4_device_t *dev;
	unsigned int xid;

	if (!cur)
		return;

	do {
		do {
			xid = random();
		} while (!xid);

		for (dev = ni_dhcp4_active; dev; dev = dev->next) {
			if (xid == dev->dhcp4.xid) {
				xid = 0;
				break;
			}
		}
	} while (!xid);

	cur->dhcp4.xid = xid;
}
