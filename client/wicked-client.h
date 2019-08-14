/*
 *	wicked client (compat) interface config
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
#ifndef WICKED_CLIENT_H
#define WICKED_CLIENT_H

#include <wicked/client.h>
#include <wicked/objectmodel.h>
#include <wicked/addrconf.h>
#include <wicked/route.h>
#include <wicked/fsm.h>
#include <wicked/ovs.h>

extern int			opt_global_dryrun;
extern char *			opt_global_rootdir;
extern ni_bool_t		opt_systemd;

/* We may want to move this into the library. */
extern int			ni_resolve_hostname_timed(const char *, int, ni_sockaddr_t *, unsigned int);
extern int			ni_host_is_reachable(const char *, const ni_sockaddr_t *);

typedef struct ni_compat_netdev {
	ni_netdev_t *		dev;
	ni_ifworker_control_t * control;
	ni_var_array_t		scripts;
	struct {
		ni_bool_t	enabled;
		char *		zone;
	} firewall;

	struct {
		ni_hwaddr_t	hwaddr;
	} identify;

	struct {
		ni_ovs_bridge_port_config_t ovsbr;
	} link_port;

	ni_rule_array_t		rules;

	struct {
		ni_bool_t	enabled;
		unsigned int	flags;

		ni_dhcp_fqdn_t  fqdn;
		char *		hostname;
		char *		client_id;
		char *		vendor_class;
		ni_dhcp4_user_class_t user_class;

		unsigned int	start_delay;
		unsigned int	defer_timeout;
		unsigned int	acquire_timeout;

		unsigned int	lease_time;
		ni_bool_t	recover_lease;
		ni_bool_t	release_lease;
		ni_tristate_t	broadcast;

		unsigned int	route_priority;
		unsigned int	update;

		ni_string_array_t request_options;
	} dhcp4;
	struct {
		ni_bool_t	enabled;
		unsigned int	flags;
	} auto4;
	struct {
		ni_bool_t	enabled;
		unsigned int	flags;

		unsigned int	mode;
		ni_bool_t	rapid_commit;
		unsigned int	address_len;

		ni_dhcp_fqdn_t  fqdn;
		char *		hostname;
		char *		client_id;

		unsigned int	start_delay;
		unsigned int	defer_timeout;
		unsigned int	acquire_timeout;

		unsigned int	lease_time;
		ni_bool_t	recover_lease;
		ni_bool_t	release_lease;

		unsigned int	update;

		ni_string_array_t request_options;
	} dhcp6;
	struct {
		ni_bool_t	enabled;
		unsigned int    defer_timeout;
		unsigned int	update;
	} auto6;
} ni_compat_netdev_t;

typedef struct ni_compat_netdev_array {
	unsigned int		count;
	ni_compat_netdev_t **	data;
} ni_compat_netdev_array_t;

typedef struct ni_compat_ifconfig {
	char *			schema;
	unsigned int		timeout;

	ni_compat_netdev_array_t netdevs;
} ni_compat_ifconfig_t;

extern ni_compat_netdev_t *	ni_compat_netdev_new(const char *);
extern void			ni_compat_netdev_free(ni_compat_netdev_t *);
extern ni_compat_netdev_t *	ni_compat_netdev_by_name(ni_compat_netdev_array_t *, const char *);
extern ni_compat_netdev_t *	ni_compat_netdev_by_hwaddr(ni_compat_netdev_array_t *, const ni_hwaddr_t *);

extern void			ni_compat_netdev_array_init(ni_compat_netdev_array_t *);
extern void			ni_compat_netdev_array_append(ni_compat_netdev_array_t *, ni_compat_netdev_t *);
extern void			ni_compat_netdev_array_destroy(ni_compat_netdev_array_t *);

extern void			ni_compat_ifconfig_init(ni_compat_ifconfig_t *, const char *);
extern void			ni_compat_ifconfig_destroy(ni_compat_ifconfig_t *);
extern unsigned int		ni_compat_generate_interfaces(xml_document_array_t *, ni_compat_ifconfig_t *, ni_bool_t, ni_bool_t);
extern void			ni_compat_netdev_set_origin(ni_compat_netdev_t *, const char *, const char *);

extern ni_bool_t		ni_ifconfig_read(xml_document_array_t *, const char *, const char *, ni_bool_t, ni_bool_t);
extern ni_bool_t		ni_ifconfig_load(ni_fsm_t *, const char *, ni_string_array_t *, ni_bool_t, ni_bool_t);

extern const ni_string_array_t *ni_config_sources(const char *);

extern ni_bool_t		ni_ifconfig_validate_adding_doc(xml_document_t *, ni_bool_t);
extern void			ni_ifconfig_metadata_add_to_node(xml_node_t *, ni_client_state_config_t *);
extern ni_bool_t		ni_ifconfig_metadata_get_from_node(ni_client_state_config_t *, xml_node_t *);
extern void			ni_ifconfig_metadata_clear(xml_node_t *);
extern const char *		ni_ifconfig_format_origin(char **, const char *, const char *);

typedef struct ni_nanny_fsm_monitor	ni_nanny_fsm_monitor_t;

extern ni_nanny_fsm_monitor_t *	ni_nanny_fsm_monitor_new(ni_fsm_t *);
extern ni_bool_t		ni_nanny_fsm_monitor_arm(ni_nanny_fsm_monitor_t *,
							unsigned long);
extern void			ni_nanny_fsm_monitor_run(ni_nanny_fsm_monitor_t *,
							ni_ifworker_array_t *, int);
extern void			ni_nanny_fsm_monitor_reset(ni_nanny_fsm_monitor_t *);
extern void			ni_nanny_fsm_monitor_free(ni_nanny_fsm_monitor_t *);

static inline void
ni_client_get_state_strings(ni_stringbuf_t *sb, const ni_uint_range_t *range)
{
	if (sb) {
		ni_fsm_state_t state;

		for (state = (range ? range->min : NI_FSM_STATE_NONE);
		     state <= (range ? range->max : __NI_FSM_STATE_MAX - 1);
		     state++) {
			ni_stringbuf_printf(sb, "%s ", ni_ifworker_state_name(state));
		}
	}
}

#endif /* WICKED_CLIENT_H */
