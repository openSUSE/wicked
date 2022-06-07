/*
 *	Address configuration aka lease for wicked
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2022 SUSE LLC
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
 *		Olaf Kirch
 *		Marius Tomaschewski
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include <wicked/util.h>
#include <wicked/address.h>
#include <wicked/addrconf.h>
#include <wicked/nis.h>
#include <wicked/route.h>
#include <wicked/resolver.h>
#include <wicked/objectmodel.h>

#include "appconfig.h"
#include "addrconf.h"
#include "netinfo_priv.h"
#include "dhcp6/options.h"
#include "dhcp.h"


extern void		ni_addrconf_updater_free(ni_addrconf_updater_t **);

static inline ni_bool_t
ni_addrconf_lease_init(ni_addrconf_lease_t *lease, int type, int family)
{
	if (lease) {
		memset(lease, 0, sizeof(*lease));
		lease->seqno = __ni_global_seqno++;
		lease->type = type;
		lease->family = family;
		ni_config_addrconf_update_mask(lease->type, lease->family);
		return TRUE;
	}
	return FALSE;
}

extern ni_refcounted_define_new(ni_addrconf_lease, int, int);
extern ni_refcounted_define_ref(ni_addrconf_lease);
extern ni_refcounted_define_hold(ni_addrconf_lease);
extern ni_refcounted_define_free(ni_addrconf_lease);
extern ni_refcounted_define_drop(ni_addrconf_lease);
extern ni_refcounted_define_move(ni_addrconf_lease);

static inline void
ni_addrconf_lease_clone_dhcp4(struct ni_addrconf_lease_dhcp4 *clone, const struct ni_addrconf_lease_dhcp4 *orig)
{
	ni_opaque_set(&clone->client_id, orig->client_id.data, orig->client_id.len);
	clone->server_id    = orig->server_id;
	clone->relay_addr   = orig->relay_addr;
	ni_string_dup(&clone->sender_hwa, orig->sender_hwa);

	clone->address      = orig->address;
	clone->netmask      = orig->netmask;
	clone->broadcast    = orig->broadcast;
	clone->mtu          = orig->mtu;

	clone->lease_time   = orig->lease_time;
	clone->renewal_time = orig->renewal_time;
	clone->rebind_time  = orig->rebind_time;

	clone->boot_saddr   = orig->boot_saddr;
	ni_string_dup(&clone->boot_sname, orig->boot_sname);
	ni_string_dup(&clone->boot_file,  orig->boot_file);
	ni_string_dup(&clone->root_path,  orig->root_path);
	ni_string_dup(&clone->message,    orig->message);

	ni_dhcp_option_list_copy(&clone->options, orig->options);
}

static inline void
ni_addrconf_lease_clone_dhcp6(struct ni_addrconf_lease_dhcp6 *clone, const struct ni_addrconf_lease_dhcp6 *orig)
{
	ni_opaque_set(&clone->client_id, orig->client_id.data, orig->client_id.len);
	ni_opaque_set(&clone->server_id, orig->server_id.data, orig->server_id.len);
	clone->server_pref = orig->server_pref;
	clone->server_addr = orig->server_addr;

	clone->rapid_commit = orig->rapid_commit;
	clone->info_refresh = orig->info_refresh;

	if (orig->status && (clone->status = ni_dhcp6_status_new())) {
		clone->status->code = orig->status->code;
		ni_string_dup(&clone->status->message, orig->status->message);
	}

	ni_dhcp6_ia_list_copy(&clone->ia_list, orig->ia_list, FALSE);

	ni_string_dup(&clone->boot_url, orig->boot_url);
	ni_string_array_copy(&clone->boot_params, &orig->boot_params);

	ni_dhcp_option_list_copy(&clone->options, orig->options);
}

ni_addrconf_lease_t *
ni_addrconf_lease_clone(const ni_addrconf_lease_t *orig)
{
	ni_addrconf_lease_t *clone;

	if (!orig || !(clone = ni_addrconf_lease_new(orig->type, orig->family)))
		return NULL;

	clone->flags    = orig->flags;
	ni_string_dup(&clone->owner, orig->owner);

	clone->uuid     = orig->uuid;
	clone->state    = orig->state;
	clone->acquired = orig->acquired;

	clone->update   = orig->update;

	clone->fqdn     = orig->fqdn;
	ni_string_dup(&clone->hostname, orig->hostname);

	ni_address_list_copy(&clone->addrs, orig->addrs);
	ni_route_tables_copy(&clone->routes, orig->routes);
	clone->rules    = ni_rule_array_clone(orig->rules);

	clone->nis      = ni_nis_info_clone(orig->nis);
	clone->resolver = ni_resolver_info_clone(orig->resolver);

	ni_string_array_copy(&clone->ntp_servers, &orig->ntp_servers);
	ni_string_array_copy(&clone->nds_servers, &orig->nds_servers);
	ni_string_array_copy(&clone->nds_context, &orig->nds_context);
	ni_string_dup(&clone->nds_tree, orig->nds_tree);

	ni_string_array_copy(&clone->netbios_name_servers, &orig->netbios_name_servers);
	ni_string_array_copy(&clone->netbios_dd_servers, &orig->netbios_dd_servers);
	ni_string_dup(&clone->netbios_scope, orig->netbios_scope);
	clone->netbios_type = orig->netbios_type;

	ni_string_array_copy(&clone->slp_servers, &orig->slp_servers);
	ni_string_array_copy(&clone->slp_scopes,  &orig->slp_scopes);

	ni_string_array_copy(&clone->sip_servers, &orig->sip_servers);
	ni_string_array_copy(&clone->lpr_servers, &orig->lpr_servers);
	ni_string_array_copy(&clone->log_servers, &orig->log_servers);

	ni_string_dup(&clone->posix_tz_string, orig->posix_tz_string);
	ni_string_dup(&clone->posix_tz_dbname, orig->posix_tz_dbname);

	if (orig->type == NI_ADDRCONF_DHCP) {
		if (orig->family == AF_INET)
			ni_addrconf_lease_clone_dhcp4(&clone->dhcp4, &orig->dhcp4);
		else
		if (orig->family == AF_INET6)
			ni_addrconf_lease_clone_dhcp6(&clone->dhcp6, &orig->dhcp6);
	}
	return clone;
}

static void
ni_addrconf_lease_dhcp4_destroy(struct ni_addrconf_lease_dhcp4 *dhcp4)
{
	if (dhcp4) {
		ni_string_free(&dhcp4->boot_sname);
		ni_string_free(&dhcp4->boot_file);
		ni_string_free(&dhcp4->root_path);
		ni_string_free(&dhcp4->message);

		ni_dhcp_option_list_destroy(&dhcp4->options);
	}
}

static void
ni_addrconf_lease_dhcp6_destroy(struct ni_addrconf_lease_dhcp6 *dhcp6)
{
	if (dhcp6) {
		ni_dhcp6_status_destroy(&dhcp6->status);
		ni_dhcp6_ia_list_destroy(&dhcp6->ia_list);

		ni_string_free(&dhcp6->boot_url);
		ni_string_array_destroy(&dhcp6->boot_params);

		ni_dhcp_option_list_destroy(&dhcp6->options);
	}
}

void
ni_addrconf_lease_destroy(ni_addrconf_lease_t *lease)
{
	ni_addrconf_updater_free(&lease->updater);
	if (lease->old) {
		ni_addrconf_lease_free(lease->old);
		lease->old = NULL;
	}

	ni_string_free(&lease->owner);
	ni_string_free(&lease->hostname);

	ni_address_list_destroy(&lease->addrs);
	ni_route_tables_destroy(&lease->routes);

	if (lease->rules) {
		ni_rule_array_free(lease->rules);
		lease->rules = NULL;
	}

	if (lease->nis) {
		ni_nis_info_free(lease->nis);
		lease->nis = NULL;
	}
	if (lease->resolver) {
		ni_resolver_info_free(lease->resolver);
		lease->resolver = NULL;
	}

	ni_string_array_destroy(&lease->ntp_servers);
	ni_string_array_destroy(&lease->nds_servers);
	ni_string_array_destroy(&lease->nds_context);
	ni_string_free(&lease->nds_tree);
	ni_string_array_destroy(&lease->netbios_name_servers);
	ni_string_array_destroy(&lease->netbios_dd_servers);
	ni_string_free(&lease->netbios_scope);
	ni_string_array_destroy(&lease->slp_servers);
	ni_string_array_destroy(&lease->slp_scopes);
	ni_string_array_destroy(&lease->sip_servers);
	ni_string_array_destroy(&lease->lpr_servers);
	ni_string_array_destroy(&lease->log_servers);

	ni_string_free(&lease->posix_tz_string);
	ni_string_free(&lease->posix_tz_dbname);

	switch (lease->type) {
	case NI_ADDRCONF_DHCP:

		switch (lease->family) {
		case AF_INET:
			ni_addrconf_lease_dhcp4_destroy(&lease->dhcp4);
			break;

		case AF_INET6:
			ni_addrconf_lease_dhcp6_destroy(&lease->dhcp6);
			break;

		default: ;
		}

		break;

	default: ;
	}
}

void
ni_addrconf_lease_list_destroy(ni_addrconf_lease_t **list)
{
	ni_addrconf_lease_t *lease;

	while ((lease = *list) != NULL) {
		*list = lease->next;
		ni_addrconf_lease_free(lease);
	}
}

unsigned int
ni_addrconf_lease_get_priority(const ni_addrconf_lease_t *lease)
{
	if (!lease)
		return 0;

	switch (lease->type) {
	case NI_ADDRCONF_STATIC:
		return 2;

	case NI_ADDRCONF_DHCP:
	case NI_ADDRCONF_INTRINSIC:
		return 1;

	case NI_ADDRCONF_AUTOCONF:
	default:
		return 0;
	}
}

unsigned int
ni_addrconf_lease_addrs_set_tentative(ni_addrconf_lease_t *lease, ni_bool_t tentative)
{
	unsigned int count = 0;
	ni_address_t * ap;

	for (ap = lease ? lease->addrs : NULL; ap; ap = ap->next) {
		ni_address_set_tentative(ap, tentative);
		count++;
	}
	return count;
}


/*
 * addrconf updater and it's actions
 */
typedef struct ni_addrconf_action_static {
	ni_addrconf_action_exec_t *	exec;
	const char *			info;
} ni_addrconf_action_static_t;

static const ni_addrconf_action_static_t	updater_applying_common[] = {
	{ ni_addrconf_action_mtu_apply,		"adjusting mtu",	},
	{ ni_addrconf_action_addrs_apply,	"applying addresses"	},
	{ ni_addrconf_action_addrs_verify,	"verifying adressses"	},
	{ ni_addrconf_action_routes_apply,	"applying routes"	},
	{ ni_addrconf_action_system_update,	"applying system config"},
	{ ni_addrconf_action_verify_apply,	"verifying apply state" },
	{ NULL }
};

static const ni_addrconf_action_static_t	updater_removing_common[] = {
	{ ni_addrconf_action_addrs_remove,	"removing addresses"	},
	{ ni_addrconf_action_routes_remove,	"removing routes"	},
	{ ni_addrconf_action_system_update,	"removing system config"},
	{ ni_addrconf_action_mtu_restore,	"reverting mtu change"	},
	{ NULL }
};

static const ni_addrconf_action_static_t	updater_applying_auto6[] = {
	{ ni_addrconf_action_addrs_verify,	"verifying adressses"	},
	{ ni_addrconf_action_write_lease,	"writing lease file"   },
	{ ni_addrconf_action_system_update,	"applying system config"},
	{ NULL }
};

static const ni_addrconf_action_static_t	updater_removing_auto6[] = {
	{ ni_addrconf_action_system_update,	"applying system config"},
	{ ni_addrconf_action_remove_lease,	"removing lease file"   },
	{ NULL }
};

ni_addrconf_action_t *
ni_addrconf_action_new(const char *info, ni_addrconf_action_exec_t *exec)
{
	ni_addrconf_action_t *action;

	if (!info || !exec)
		return NULL;

	if (!(action = calloc(1, sizeof(*action))))
		return NULL;

	action->info = info;
	action->exec = exec;
	return action;
}

void
ni_addrconf_action_free(ni_addrconf_action_t *action)
{
	if (action) {
		if (action->free) {
			action->free(action);
		} else {
			free(action);
		}
	}
}

ni_addrconf_action_t *
ni_addrconf_action_list_find_exec(ni_addrconf_action_t *list, ni_addrconf_action_exec_t *exec)
{
	ni_addrconf_action_t *item;

	for (item = list; item; item = item->next) {
		if (exec == item->exec)
			return item;
	}
	return NULL;
}

ni_bool_t
ni_addrconf_action_list_insert(ni_addrconf_action_t **pos, ni_addrconf_action_t *item)
{
	if (!pos || !item)
		return FALSE;

	item->next = *pos;
	*pos = item;
	return TRUE;
}

ni_bool_t
ni_addrconf_action_list_append(ni_addrconf_action_t **list, ni_addrconf_action_t *item)
{
	if (list && item) {
		while (*list)
			list = &(*list)->next;
		*list = item;
		return TRUE;
	}
	return FALSE;
}

void
ni_addrconf_action_list_destroy(ni_addrconf_action_t **list)
{
	ni_addrconf_action_t *item;

	if (list) {
		while ((item = *list)) {
			*list = item->next;
			item->next = NULL;
			ni_addrconf_action_free(item);
		}
	}
}

static inline ni_bool_t
ni_addrconf_action_list_create(ni_addrconf_action_t **list, const ni_addrconf_action_static_t *table)
{
	const ni_addrconf_action_static_t *entry;
	ni_addrconf_action_t *action;

	if (!list || !table)
		return FALSE;

	for (entry = table; entry->exec; ++entry) {
		if (!(action = ni_addrconf_action_new(entry->info, entry->exec)))
			return FALSE;

		ni_addrconf_action_list_append(list, action);
	}
	return TRUE;
}

static inline ni_addrconf_action_t *
ni_addrconf_updater_action_advance(ni_addrconf_action_t **list)
{
	ni_addrconf_action_t *item;

	if (list) {
		if ((item = *list)) {
			*list = item->next;
			item->next = NULL;
			ni_addrconf_action_free(item);
		}
		return *list;
	}
	return NULL;
}

static ni_addrconf_updater_t *
ni_addrconf_updater_new(const ni_addrconf_action_static_t *table, const ni_netdev_t *dev, ni_event_t event)
{
	ni_addrconf_updater_t *updater;

	updater = calloc(1, sizeof(*updater));
	if (updater) {
		if (!ni_addrconf_action_list_create(&updater->action, table)) {
			ni_addrconf_updater_free(&updater);
			return NULL;
		}
		updater->event  = event;
		ni_timer_get_time(&updater->started);
		if (dev)
			ni_netdev_ref_set(&updater->device, dev->name, dev->link.ifindex);
	}
	return updater;
}

ni_addrconf_updater_t *
ni_addrconf_updater_new_applying(ni_addrconf_lease_t *lease, const ni_netdev_t *dev, ni_event_t event)
{
	if (!lease)
		return NULL;

	ni_addrconf_updater_free(&lease->updater);
	if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_AUTOCONF) {
		lease->updater = ni_addrconf_updater_new(updater_applying_auto6, dev, event);
	} else {
		lease->updater = ni_addrconf_updater_new(updater_applying_common, dev, event);
	}
	return lease->updater;
}

ni_addrconf_updater_t *
ni_addrconf_updater_new_removing(ni_addrconf_lease_t *lease, const ni_netdev_t *dev, ni_event_t event)
{
	if (!lease)
		return NULL;

	ni_addrconf_updater_free(&lease->updater);
	if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_AUTOCONF) {
		lease->updater = ni_addrconf_updater_new(updater_removing_auto6, dev, event);
	} else {
		lease->updater = ni_addrconf_updater_new(updater_removing_common, dev, event);
	}
	return lease->updater;
}

static int
ni_addrconf_updater_action_call(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_addrconf_updater_t *updater;
	struct timeval now, delta;
	int res = 0;

	if (!dev || !lease)
		return 0;

	while ((updater = lease->updater) != NULL) {
		if (!updater->action || !updater->action->exec) {
			ni_addrconf_updater_free(&lease->updater);
			break;
		}

		if (!timerisset(&updater->astart))
			ni_timer_get_time(&updater->astart);

		res = updater->action->exec(dev, lease);

		ni_timer_get_time(&now);
		if (timercmp(&now, &updater->astart, >))
			timersub(&now, &updater->astart, &delta);
		else
			timerclear(&delta);

		if (updater->action->info) {
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
					"%s: %s for %s:%s lease in state %s: %s [%s %ldm%ld.%03lds]",
					dev->name, updater->action->info,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_state_to_name(lease->state),
					(res < 0  ? "failure"  :
					 res > 0  ? "deferred" : "success"),
					(res == 1 ? "since"    : "after"),
					delta.tv_sec / 60, delta.tv_sec % 60,
					delta.tv_usec / 1000);
		}
		if (res != 1)
			timerclear(&updater->astart);
		if (res != 0)
			break;
		ni_addrconf_updater_action_advance(&updater->action);
	}
	return res;
}

int
ni_addrconf_updater_execute(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_addrconf_updater_t *updater;
	struct timeval pre, now, delta;
	ni_event_t event;
	int ret = 0;

	if (!dev || !lease || !(updater = lease->updater))
		return -1;

	if (updater->timer)
		ni_timer_cancel(updater->timer);
	updater->timer = NULL;

	event = updater->event;
	pre = updater->started;
	ret = ni_addrconf_updater_action_call(dev, lease);

	if (ret > 0) {
		struct timeval now;

		ni_timer_get_time(&now);
		if (updater->deadline &&
		    !ni_lifetime_left(updater->deadline, &updater->started, &now)) {
			lease->state = NI_ADDRCONF_STATE_FAILED;
			ni_debug_ifconfig("%s: %s:%s lease update deadline reached (state %s)",
					dev->name,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_state_to_name(lease->state));
			ret = -1;
		} else
		if (!ni_addrconf_updater_background(updater, updater->timeout)) {
			ni_debug_ifconfig("%s: unable to background %s:%s lease update (state %s)",
					dev->name,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_state_to_name(lease->state));
			ret = -1;
		} else {
			return ret;
		}
	} else {
		ni_timer_get_time(&now);
		if (timercmp(&now, &pre, >)) {
			timersub(&now, &pre, &delta);
		} else {
			timerclear(&delta);
		}
		ni_debug_ifconfig("%s: updater for lease %s:%s in state %s finished: %s [%ldm%ld.%03lds]",
				dev->name,
				ni_addrfamily_type_to_name(lease->family),
				ni_addrconf_type_to_name(lease->type),
				ni_addrconf_state_to_name(lease->state),
				ret < 0 ? "failure" : "success",
				delta.tv_sec / 60, delta.tv_sec % 60,
				delta.tv_usec / 1000);
	}

	if (ret == 0) {
		if (lease->old) {
			ni_addrconf_lease_free(lease->old);
			lease->old = NULL;
		}
		ni_addrconf_updater_free(&lease->updater);

		switch (lease->state) {
		case NI_ADDRCONF_STATE_GRANTED:
		case NI_ADDRCONF_STATE_APPLYING:
			lease->state = NI_ADDRCONF_STATE_GRANTED;
			if (event != NI_EVENT_ADDRESS_ACQUIRED)
				ret = -1;
			else
			if (ni_addrconf_flag_bit_is_set(lease->flags, NI_ADDRCONF_FLAGS_PRIMARY))
				ni_objectmodel_addrconf_fallback_action(dev, event, lease->family, NULL);
			break;

		case NI_ADDRCONF_STATE_RELEASED:
		case NI_ADDRCONF_STATE_RELEASING:
			lease->state = NI_ADDRCONF_STATE_RELEASED;
			if (event != NI_EVENT_ADDRESS_RELEASED)
				ret = -1;
			break;

		case NI_ADDRCONF_STATE_FAILED:
			if (event != NI_EVENT_ADDRESS_RELEASED &&
			    event != NI_EVENT_ADDRESS_LOST)
				ret = -1;
			break;

		case NI_ADDRCONF_STATE_REQUESTING:
			/* reenter requesting on partial success */
			if (event == NI_EVENT_ADDRESS_ACQUIRED)
				event = NI_EVENT_ADDRESS_DEFERRED;
			else
				ret = -1;
			break;

		default:
			lease->state = NI_ADDRCONF_STATE_FAILED;
			event = __NI_EVENT_MAX;
			break;
		}

		if (ret == 0 && event < __NI_EVENT_MAX) {
			ni_debug_ifconfig("%s: %s:%s lease updated (state %s), sending %s event",
					dev->name,
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_state_to_name(lease->state),
					ni_objectmodel_event_to_signal(event));

			ni_objectmodel_addrconf_send_event(dev, event, &lease->uuid);
			if (event == NI_EVENT_ADDRESS_RELEASED) {
				if (ni_addrconf_flag_bit_is_set(lease->flags, NI_ADDRCONF_FLAGS_FALLBACK))
					ni_objectmodel_addrconf_fallback_action(dev, event, lease->family, lease);
				else
					ni_netdev_unset_lease(dev, lease->family, lease->type);
			}
		}
		if (ret == 0)
			return ret;
	}

	if (ret < 0) {
		if (lease->old) {
			ni_addrconf_lease_free(lease->old);
			lease->old = NULL;
		}
		ni_addrconf_updater_free(&lease->updater);

		/* aborted by dad, dhcp6 supplicant will decline */
		if (lease->family == AF_INET6 && lease->state == NI_ADDRCONF_STATE_REQUESTING)
			return 0;

		lease->state = NI_ADDRCONF_STATE_FAILED;
		ni_objectmodel_addrconf_send_event(dev, NI_EVENT_ADDRESS_LOST, &lease->uuid);
	}
	return ret;
}

static void
ni_addrconf_updater_timer_call(void *user_data, const ni_timer_t *timer)
{
	ni_addrconf_updater_t *updater = user_data;
	ni_addrconf_lease_t *lease;
	ni_netconfig_t *nc;
	ni_netdev_t *dev;

	if (!updater || updater->timer != timer)
		return;

	updater->timer = NULL;

	if (!(nc = ni_global_state_handle(0)))
		return;

	if (!(dev = ni_netdev_by_index(nc, updater->device.index)))
		return;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (lease->updater == updater) {
			ni_addrconf_updater_execute(dev, lease);
			return;
		}
	}
}

ni_bool_t
ni_addrconf_updater_background(ni_addrconf_updater_t *updater, unsigned int delay)
{
	unsigned long timeout = 0;

	if (!updater)
		return FALSE;

	if (!updater->timeout)
		updater->timeout = 1000;

	updater->jitter.max = 100;
	if (delay > 1000)
		updater->jitter.min = 0 - updater->jitter.max;
	else
		updater->jitter.min = 0;
	timeout = ni_timeout_randomize(delay, &updater->jitter);

	if (updater->timer != NULL)
		updater->timer = ni_timer_rearm(updater->timer, timeout);

	if (updater->timer == NULL)
		updater->timer = ni_timer_register(timeout,
				ni_addrconf_updater_timer_call, updater);

	return updater->timer != NULL;
}

void
ni_addrconf_updater_set_data(ni_addrconf_updater_t *updater, void *user_data,
				ni_addrconf_updater_cleanup_t *cleanup)
{
	if (updater) {
		if (updater->user_data && updater->cleanup) {
			void *data = updater->user_data;
			updater->user_data = NULL;
			updater->cleanup(data);
		}
		updater->user_data = user_data;
		updater->cleanup = cleanup;
	}
}

void *
ni_addrconf_updater_get_data(ni_addrconf_updater_t *updater,
				ni_addrconf_updater_cleanup_t *cleanup)
{
	if (updater && updater->cleanup == cleanup)
		return updater->user_data;
	return NULL;
}

static inline void
ni_addrconf_updater_destroy(ni_addrconf_updater_t *updater)
{
	if (updater->timer)
		ni_timer_cancel(updater->timer);
	updater->timer = NULL;
	ni_addrconf_updater_set_data(updater, NULL, NULL);
	ni_netdev_ref_destroy(&updater->device);
}

void
ni_addrconf_updater_free(ni_addrconf_updater_t **updater)
{
	if (updater && *updater) {
		ni_addrconf_updater_destroy(*updater);
		free(*updater);
		*updater = NULL;
	}
}

