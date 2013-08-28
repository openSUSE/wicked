/*
 * Update system settings with information received from an addrconf service.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/system.h>
#include <wicked/resolver.h>
#include <wicked/util.h>

#include "netinfo_priv.h"
#include "process.h"
#include "appconfig.h"
#include "debug.h"

typedef struct ni_updater_source	ni_updater_source_t;
struct ni_updater_source {
	ni_updater_source_t *		next;
	unsigned int			seqno;		/* sequence number of lease */
	unsigned int			weight;
	const ni_addrconf_lease_t *	lease;
};

typedef struct ni_updater {
	ni_updater_source_t *		sources;

	unsigned int			type;
	unsigned int			seqno;
	unsigned int			have_backup;
	unsigned int			max_source_weight;

	ni_bool_t			enabled;
	ni_shellcmd_t *			proc_backup;
	ni_shellcmd_t *			proc_restore;
	ni_shellcmd_t *			proc_install;
	ni_shellcmd_t *			proc_remove;
} ni_updater_t;

static ni_updater_t			updaters[__NI_ADDRCONF_UPDATE_MAX];

static const char *			ni_updater_name(unsigned int);
static ni_string_array_t *		ni_system_updater_populate_args(ni_string_array_t *, int, ...);

/*
 * Initialize the system updaters based on the data found in the config
 * file.
 */
void
ni_system_updaters_init(void)
{
	static int initialized = 0;
	unsigned int kind;

	if (initialized)
		return;
	initialized = 1;

	for (kind = 0; kind < __NI_ADDRCONF_UPDATE_MAX; ++kind) {
		ni_updater_t *updater = &updaters[kind];
		const char *name = ni_updater_name(kind);
		ni_extension_t *ex;

		updater->type = kind;
		updater->max_source_weight = 0;
		if (name == NULL)
			continue;

		if (!(ex = ni_config_find_system_updater(ni_global.config, name)))
			continue;

		updater->enabled = 1;
		updater->proc_backup = ni_extension_script_find(ex, "backup");
		updater->proc_restore = ni_extension_script_find(ex, "restore");
		updater->proc_install = ni_extension_script_find(ex, "install");
		updater->proc_remove = ni_extension_script_find(ex, "remove");

		if (updater->proc_install == NULL) {
			ni_warn("system-updater %s configured, but no install script defined", name);
			updater->enabled = 0;
		} else
		if (updater->proc_backup == NULL || updater->proc_restore == NULL) {
			ni_warn("system-updater %s configured, but no backup/restore script defined", name);
			updater->proc_backup = updater->proc_restore = NULL;
		}
	}
}

/*
 * Get the name used for identifying a sysconfig/netconfig wicked service.
 */
static char *
ni_netconfig_service_name(ni_addrconf_mode_t lease_type, unsigned int lease_family)
{
	char *service_name = NULL;
	const char *wicked_name = "wicked"; /* TODO: check if this is already available. */
	const char *addrconf_name = ni_addrconf_type_to_name(lease_type);
	const char *addrfamily_name = ni_addrfamily_type_to_name(lease_family);

	if (addrconf_name == NULL || addrfamily_name == NULL) {
		ni_error("failed to generate netconfig service name.");
	} else {
		/* service_name: "wicked_name-addrconf_name-addrfamily_name\0" */
		if (!ni_string_printf(&service_name, "%s-%s-%s", wicked_name,
					addrconf_name, addrfamily_name)) {
			ni_error("derived invalid netconfig service_name: %s",
				service_name);
		} else {
			ni_debug_ifconfig("derived valid netconfig service_name: %s",
					service_name);
		}
	}
	return service_name; /* NULL if ni_string_printf() failed. */
}

/*
 * Get the name of an updater
 */
static const char *
ni_updater_name(unsigned int kind)
{
	static ni_intmap_t names[] = {
	{ "hostname",		NI_ADDRCONF_UPDATE_HOSTNAME	},
	{ "resolver",		NI_ADDRCONF_UPDATE_RESOLVER	},

	{ NULL }
	};

	return ni_format_uint_mapped(kind, names);
}

static inline ni_bool_t
can_update_hostname(const ni_addrconf_lease_t *lease)
{
	return __ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_HOSTNAME) && lease->hostname;
}

static inline ni_bool_t
can_update_resolver(const ni_addrconf_lease_t *lease)
{
	return __ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_RESOLVER) && lease->resolver;
}

/*
 * Add this lease to the given updater, to record that we can use the
 * information from this lease.
 */
static void
ni_objectmodel_updater_add_source(unsigned int kind, const ni_addrconf_lease_t *lease)
{
	static unsigned int addrconf_weight[__NI_ADDRCONF_MAX] = {
	[NI_ADDRCONF_DHCP]	= 5,
	/* [NI_ADDRCONF_IBFT]	= 10, */
	};
	ni_updater_source_t **pos, *up;

	for (pos = &updaters[kind].sources; (up = *pos) != NULL; pos = &up->next) {
		if (up->seqno == lease->seqno) {
			/* This lease is still there */
			up->lease = lease;
			return;
		}
	}

	up = calloc(1, sizeof(*up));
	up->seqno = lease->seqno;
	up->lease = lease;

	if (lease->type < __NI_ADDRCONF_MAX)
		up->weight = 10 * addrconf_weight[lease->type];

	if (up->weight > updaters[kind].max_source_weight) {
		updaters[kind].max_source_weight = up->weight;
	}

	*pos = up;
}

/*
 * Select the best sources for updating the system settings
 */
static int
ni_objectmodel_updater_select_sources(ni_updater_t *updater, ni_updater_source_t ***sources)
{
	ni_updater_source_t *src;
	int num_max_weighted;
	int num_sources = 0;
	for (num_max_weighted = 0, src = updater->sources; src; src = src->next) {
		if (src->weight == updater->max_source_weight) {
			num_max_weighted += 1;
		}
	}
	// allocate array of pointers and assign only if we have valid sources
	if (num_max_weighted) {
		*sources = calloc(0, num_max_weighted * sizeof(ni_updater_source_t *));
		if (!(*sources)) {
			ni_error("Failed to allocate %d*%d sources", num_max_weighted,
				sizeof(ni_updater_source_t *));
			/* num_sources == 0 */
		} else {
			for (num_sources = 0, src = updater->sources;
			     src, num_sources < num_max_weighted;
			     src = src->next) {
				if (src->weight == updater->max_source_weight) {
					(*sources)[num_sources++] = src;
				}
			}
		}
	}
	return num_sources;
}

/*
 * Select the best source for updating the system settings
 */
static ni_updater_source_t *
ni_objectmodel_updater_select_source(ni_updater_t *updater)
{
	ni_updater_source_t *src, *best = NULL;

	for (src = updater->sources; src; src = src->next) {
		if (best == NULL || src->weight > best->weight)
			best = src;
	}

#if 0
	if (best == NULL)
		ni_trace("%s: no source", ni_updater_name(updater->type));
	else {
		const ni_addrconf_lease_t *lease = best->lease;

		ni_trace("%s: select source %s/%s", ni_updater_name(updater->type),
					ni_addrconf_type_to_name(lease->type),
					ni_addrfamily_type_to_name(lease->family));
	}
#endif
	return best;
}

/*
 * Run an extension script to update resolver, hostname etc.
 */
static ni_bool_t
ni_system_updater_run(ni_shellcmd_t *shellcmd, ni_string_array_t *args)
{
	ni_process_t *pi;
	int rv;

	pi = ni_process_new(shellcmd);
	if (args) {
		unsigned int i;
		for (i = 0; i < args->count; i++) {
			ni_string_array_append(&pi->argv, args->data[i]);
		}
	}

	rv = ni_process_run_and_wait(pi);
	ni_process_free(pi);

	return rv >= 0;
}

/*
 * Back up current configuration
 */
static ni_bool_t
ni_system_updater_backup(ni_updater_t *updater)
{
	if (updater->have_backup)
		return TRUE;

	if (!updater->proc_backup)
		return TRUE;
#if 0	/* Can re-enable when actual backup procedure is better defined. */
	if (!ni_system_updater_run(updater->proc_backup, ni_updater_name(updater->type))) {
		ni_error("failed to back up current %s settings",
				ni_updater_name(updater->type));
		return FALSE;
	}
#endif
	updater->have_backup = 1;
	return TRUE;
}

/*
 * Restore existing configuration
 */
static ni_bool_t
ni_system_updater_restore(ni_updater_t *updater)
{
	if (!updater->have_backup)
		return TRUE;

	if (!updater->proc_restore)
		return TRUE;
#if 0	/* Can re-enable when actual restore procedure is better defined. */
	if (!ni_system_updater_run(updater->proc_restore, ni_updater_name(updater->type))) {
		ni_error("failed to restore current %s settings",
				ni_updater_name(updater->type));
		return FALSE;
	}
#endif
	updater->have_backup = 0;
	return TRUE;
}

/*
 * Remove information from a lease which has been released and already detached
 * from a device.
 */
static ni_bool_t
ni_system_updater_remove(ni_updater_t *updater, ni_addrconf_lease_t *lease, char *devname)
{
	ni_string_array_t arguments = NI_STRING_ARRAY_INIT;
	ni_bool_t result = FALSE;
	char *service_name = NULL;

	ni_debug_ifconfig("Removing system %s settings from %s/%s lease",
			ni_updater_name(updater->type),
			ni_addrconf_type_to_name(lease->type),
			ni_addrfamily_type_to_name(lease->family));

	switch (updater->type) {
	case NI_ADDRCONF_UPDATE_RESOLVER:
		if(!(service_name = ni_netconfig_service_name(lease->type, lease->family))) {
			goto done;
		}
		if (ni_string_array_append(&arguments, ni_updater_name(updater->type)) != 0 ||
			ni_string_array_append(&arguments, service_name) != 0 ||
			ni_string_array_append(&arguments, devname) != 0) {
			ni_error("failed to populate arguments for %s",
				ni_updater_name(updater->type));
			goto done;
		}
		break;

	case NI_ADDRCONF_UPDATE_HOSTNAME:
		//argument = lease->hostname;
		break;

	default:
		ni_error("cannot remove old %s settings - file format not understood",
				ni_updater_name(updater->type));
		updater->enabled = 0;
		goto done;
	}

	if (!ni_system_updater_run(updater->proc_remove, &arguments)) {
		ni_error("failed to remove %s settings", ni_updater_name(updater->type));
		goto done;
	}

	lease->applied = FALSE;
	result = TRUE;

	if (ni_global.other_event)
		ni_global.other_event(NI_EVENT_RESOLVER_UPDATED);

done:
	ni_string_free(&service_name);
	ni_string_array_destroy(&arguments);
	return result;
}

/*
 * Install information from a lease, and remember that we did
 */
static ni_bool_t
ni_system_updater_install(ni_updater_t *updater, ni_addrconf_lease_t *lease, char *devname)
{
	const char *tempname = NULL;
	ni_string_array_t arguments = NI_STRING_ARRAY_INIT;
	char *service_name = NULL;
	ni_bool_t result = FALSE;
	int rv = 0;

	ni_debug_ifconfig("Updating system %s settings from %s/%s lease",
					ni_updater_name(updater->type),
					ni_addrconf_type_to_name(lease->type),
					ni_addrfamily_type_to_name(lease->family));

	if (!updater->have_backup && !ni_system_updater_backup(updater))
		return FALSE;
	/* FIXME: build a file containing the new configuration, and run the
	 * indicated script with it */
	switch (updater->type) {
	case NI_ADDRCONF_UPDATE_RESOLVER:
		if(!(service_name = ni_netconfig_service_name(lease->type, lease->family))) {
			goto done;
		}
		tempname = _PATH_RESOLV_CONF ".new";
		if (ni_string_array_append(&arguments, ni_updater_name(updater->type)) != 0 ||
			ni_string_array_append(&arguments, tempname) != 0 ||
			ni_string_array_append(&arguments, service_name) != 0 ||
			ni_string_array_append(&arguments, devname) != 0) {
			ni_error("failed to populate arguments for %s",
				ni_updater_name(updater->type));
			goto done;
		}
		if ((rv = ni_resolver_write_resolv_conf(tempname, lease->resolver, NULL)) < 0) {
			ni_error("failed to write resolver info to temp file: %s",
					ni_strerror(rv));
			goto done;
		}
		break;

	case NI_ADDRCONF_UPDATE_HOSTNAME:
		//argument = lease->hostname;
		break;

	default:
		ni_error("cannot install new %s settings - file format not understood",
				ni_updater_name(updater->type));
		updater->enabled = 0;
		goto done;
	}

	if (!ni_system_updater_run(updater->proc_install, &arguments)) {
		ni_error("failed to install %s settings", ni_updater_name(updater->type));
		goto done;
	}

	lease->applied = TRUE;
	result = TRUE;

	if (ni_global.other_event)
		ni_global.other_event(NI_EVENT_RESOLVER_UPDATED);

done:
	if (tempname)
		unlink(tempname);
	ni_string_free(&service_name);
	ni_string_array_destroy(&arguments);
	return result;
}

ni_bool_t
ni_system_update_all(const ni_addrconf_lease_t *lease_to_remove, char *devname)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_updater_source_t *up;
	ni_netdev_t *dev;
	unsigned int kind;
	ni_bool_t result = TRUE;

	ni_debug_ifconfig("%s()", __func__);
	ni_system_updaters_init();

	/* If lease_to_remove is present, remove it's information directly. */
	if (lease_to_remove) {
		if (can_update_hostname(lease_to_remove) &&
			updaters[NI_ADDRCONF_UPDATE_HOSTNAME].enabled) {
			if(!ni_system_updater_remove(&updaters[NI_ADDRCONF_UPDATE_HOSTNAME],
							lease_to_remove, devname)) {
				result = FALSE;
			}
		}
		if (can_update_resolver(lease_to_remove) &&
			updaters[NI_ADDRCONF_UPDATE_RESOLVER].enabled) {
			if(!ni_system_updater_remove(&updaters[NI_ADDRCONF_UPDATE_RESOLVER],
							lease_to_remove, devname)) {
				result = FALSE;
			}
		}
		/* After removal, let remainder of update happen. */
	}

	for (kind = 0; kind < __NI_ADDRCONF_UPDATE_MAX; ++kind) {
		for (up = updaters[kind].sources; up; up = up->next)
			up->lease = NULL;
	}

	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next) {
		ni_addrconf_lease_t *lease;

		for (lease = dev->leases; lease; lease = lease->next) {
#if 0
			ni_trace(" %s: %s/%s hostname %s resolver %s",
					dev->name,
					ni_addrconf_type_to_name(lease->type),
					ni_addrfamily_type_to_name(lease->family),
					can_update_hostname(lease)? "YES" : "NO",
					can_update_resolver(lease)? "YES" : "NO");
#endif
			if (can_update_hostname(lease))
				ni_objectmodel_updater_add_source(NI_ADDRCONF_UPDATE_HOSTNAME, lease);
			if (can_update_resolver(lease))
				ni_objectmodel_updater_add_source(NI_ADDRCONF_UPDATE_RESOLVER, lease);
		}
	}


	for (kind = 0; kind < __NI_ADDRCONF_UPDATE_MAX; ++kind) {
		ni_updater_t *updater = &updaters[kind];
		ni_updater_source_t **pos = &updater->sources;

		if (!updater->enabled)
			continue;

		/* Purge all updater sources for which the lease went away. */
		while ((up = *pos)) {
			if (up->lease == NULL) {
				*pos = up->next;
				free(up);
			} else {
				pos = &up->next;
			}
		}

		/* If we no longer have any lease data for this resource, restore
		 * the system default.
		 * If we do have, update the system only if the lease was updated.
		 */
		if ((up = ni_objectmodel_updater_select_source(updater)) == NULL) {
			ni_system_updater_restore(updater);
		} else
		if (updater->seqno != up->seqno) {
			if (up->lease && up->lease->state == NI_ADDRCONF_STATE_RELEASED) {
				ni_system_updater_remove(updater, up->lease, devname);
			} else {
				ni_system_updater_install(updater, up->lease, devname);
			}
		}
	}

	return result;
}

/*
 * A lease has changed, and we are asked to update the system configuration.
 * When we get here, the old lease has already been removed from the interface,
 * and the new one has been added.
 */
int
ni_system_update_from_lease(const ni_addrconf_lease_t *lease, char *devname)
{
	int res;
	if (lease && lease->state == NI_ADDRCONF_STATE_RELEASED) {
		res = ni_system_update_all(lease, devname);
	} else {
		res = ni_system_update_all(NULL, devname);
	}
	if (!res) {
		return -1;
	} else {
		return 0;
	}
}
