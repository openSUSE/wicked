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

#include <wicked/util.h>
#include <wicked/address.h>
#include <wicked/addrconf.h>
#include <wicked/nis.h>
#include <wicked/route.h>
#include <wicked/resolver.h>

#include "appconfig.h"
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
