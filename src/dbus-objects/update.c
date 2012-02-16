/*
 * Generic dbus client functions for updating system settings with
 * information received from an addrconf service.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/system.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "config.h"
#include "model.h"
#include "debug.h"

enum {
	NI_UPDATER_HOSTNAME,
	NI_UPDATER_RESOLVER,

	__NI_UPDATER_MAX
};

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

	dbus_bool_t			enabled;
	ni_process_t *			proc_backup;
	ni_process_t *			proc_restore;
	ni_process_t *			proc_install;
} ni_updater_t;

static ni_updater_t			updaters[__NI_UPDATER_MAX];

static const char *		ni_objectmodel_updater_name(unsigned int);

dbus_bool_t
ni_objectmodel_update_from_lease(const ni_addrconf_lease_t *lease)
{
	if (!lease) {
		/* FIXME: restore previous state and/or install alternative lease. */
		return TRUE;
	}

	ni_debug_dbus("%s(update=0x%x)", __func__, lease->update);
	if (__ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_HOSTNAME) && lease->hostname) {
		ni_debug_dbus("update hostname=%s", lease->hostname);
	}
	if (__ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_RESOLVER) && lease->resolver) {
		ni_debug_dbus("update resolver");
	}
	return TRUE;
}

void
ni_objectmodel_updaters_init(void)
{
	static int initialized = 0;
	unsigned int kind;

	if (initialized)
		return;
	initialized = 1;

	for (kind = 0; kind < __NI_UPDATER_MAX; ++kind) {
		ni_updater_t *updater = &updaters[kind];
		const char *name = ni_objectmodel_updater_name(kind);
		ni_extension_t *ex;
		char exname[128];

		updater->type = kind;
		if (name == NULL)
			continue;
		snprintf(exname, sizeof(exname), "%s-updater", name);
		if (!(ex = ni_config_find_extension(ni_global.config, exname)))
			continue;

		updater->enabled = TRUE;
		updater->proc_backup = ni_extension_script_find(ex, "backup");
		updater->proc_restore = ni_extension_script_find(ex, "restore");
		updater->proc_install = ni_extension_script_find(ex, "install");

		if (updater->proc_install == NULL) {
			ni_warn("extension %s configured, but no install script defined", exname);
			updater->enabled = FALSE;
		} else
		if (updater->proc_backup == NULL || updater->proc_restore == NULL) {
			ni_warn("extension %s configured, but no backup/restore script defined", exname);
			updater->proc_backup = updater->proc_restore = NULL;
		}
	}
}

/*
 * Get the name of an updater
 */
static const char *
ni_objectmodel_updater_name(unsigned int kind)
{
	static ni_intmap_t names[] = {
	{ "hostname",		NI_UPDATER_HOSTNAME	},
	{ "resolver",		NI_UPDATER_RESOLVER	},

	{ NULL }
	};

	return ni_format_int_mapped(kind, names);
}

static inline dbus_bool_t
can_update_hostname(const ni_addrconf_lease_t *lease)
{
	return __ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_HOSTNAME) && lease->hostname;
}

static inline dbus_bool_t
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
	[NI_ADDRCONF_IBFT]	= 10,
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
	/* Prefer IPv4 over IPv6 for now. IPv6 dhcp servers
	 * may not be terribly good for a couple of years to
	 * come... */
	up->weight += (lease->family == AF_INET)? 1 : 0;

	*pos = up;
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

	return best;
}

/*
 * Run an extension script to update resolver, hostname etc.
 */
static dbus_bool_t
ni_objectmodel_updater_run(ni_process_t *proc, const char *filename)
{
	return FALSE;
}

/*
 * Back up current configuration
 */
static dbus_bool_t
ni_objectmodel_updater_backup(ni_updater_t *updater)
{
	if (updater->have_backup)
		return TRUE;

	if (!updater->proc_backup)
		return TRUE;

	if (!ni_objectmodel_updater_run(updater->proc_backup, NULL)) {
		ni_error("failed to back up current %s settings",
				ni_objectmodel_updater_name(updater->type));
		return FALSE;
	}

	updater->have_backup = TRUE;
	return TRUE;
}

/*
 * Restore existing configuration
 */
static dbus_bool_t
ni_objectmodel_updater_restore(ni_updater_t *updater)
{
	if (!updater->have_backup)
		return TRUE;

	if (!updater->proc_restore)
		return TRUE;

	if (!ni_objectmodel_updater_run(updater->proc_restore, NULL)) {
		ni_error("failed to restore current %s settings",
				ni_objectmodel_updater_name(updater->type));
		return FALSE;
	}

	updater->have_backup = FALSE;
	return TRUE;
}

/*
 * Install information from a lease, and remember that we did
 */
static dbus_bool_t
ni_objectmodel_updater_install(ni_updater_t *updater, const ni_addrconf_lease_t *lease)
{
	if (!updater->have_backup && !ni_objectmodel_updater_backup(updater))
		return FALSE;

	/* FIXME: build a file containing the new configuration, and run the
	 * indicated script with it */
	switch (updater->type) {
	case NI_UPDATER_HOSTNAME:
	case NI_UPDATER_RESOLVER:
	default:
		ni_error("cannot install new %s settings - file format not understood",
				ni_objectmodel_updater_name(updater->type));
		updater->enabled = FALSE;
		return FALSE;
	}

	updater->seqno = lease->seqno;
	return TRUE;
}

dbus_bool_t
ni_objectmodel_update_all(void)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_updater_source_t *up;
	ni_interface_t *dev;
	unsigned int kind;

	ni_objectmodel_updaters_init();

	for (kind = 0; kind < __NI_UPDATER_MAX; ++kind) {
		for (up = updaters[kind].sources; up; up = up->next)
			up->lease = NULL;
	}

	for (dev = ni_interfaces(nc); dev; dev = dev->next) {
		ni_addrconf_lease_t *lease;

		for (lease = dev->leases; lease; lease = lease->next) {
			if (can_update_hostname(lease))
				ni_objectmodel_updater_add_source(NI_UPDATER_HOSTNAME, lease);
			if (can_update_resolver(lease))
				ni_objectmodel_updater_add_source(NI_UPDATER_RESOLVER, lease);
		}
	}

	for (kind = 0; kind < __NI_UPDATER_MAX; ++kind) {
		ni_updater_t *updater = &updaters[kind];
		ni_updater_source_t **pos;

		if (!updater->enabled)
			continue;

		/* Purge all updater sources for which the lease went away. */
		for (pos = &updater->sources; (up = *pos) != NULL; pos = &up->next) {
			if (up->lease == NULL) {
				*pos = up->next;
				free(up);
			}
		}

		/* If we no longer have any lease data for this resource, restore
		 * the system default.
		 * If we do have, update the system only if the lease was updated.
		 */
		if ((up = ni_objectmodel_updater_select_source(updater)) == NULL) {
			ni_objectmodel_updater_restore(updater);
		} else
		if (updater->seqno != up->seqno) {
			ni_objectmodel_updater_install(updater, up->lease);
		}
	}

	return TRUE;
}
