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
#include <wicked/leaseinfo.h>

#include "netinfo_priv.h"
#include "socket_priv.h"
#include "util_priv.h"
#include "process.h"
#include "appconfig.h"
#include "buffer.h"
#include "debug.h"

/* secs we try to reverse resolve hostnames */
#ifndef NI_UPDATER_REVERSE_TIMEOUT
#define NI_UPDATER_REVERSE_TIMEOUT	2
#endif
/* how many lease addresses we try out */
#ifndef NI_UPDATER_REVERSE_MAX_CNT
#define NI_UPDATER_REVERSE_MAX_CNT	1
#endif

#define	NI_UPDATER_SOURCE_ARRAY_CHUNK	4
#define	NI_UPDATER_SOURCE_ARRAY_INIT	{ 0, NULL }

typedef struct ni_updater_source	ni_updater_source_t;
struct ni_updater_source {
	unsigned int			refcount;

	ni_netdev_ref_t			device;
	struct {
		unsigned int		family;
		unsigned int		type;
	} lease;
};

typedef struct ni_updater_source_array	ni_updater_source_array_t;
struct ni_updater_source_array {
	unsigned int			count;
	ni_updater_source_t **		data;
};

typedef struct ni_updater		ni_updater_t;
typedef struct ni_updater_job		ni_updater_job_t;
typedef struct ni_updater_action	ni_updater_action_t;

typedef enum {
	NI_UPDATER_FLOW_INSTALL,
	NI_UPDATER_FLOW_REMOVAL,
} ni_updater_job_flow_t;

typedef enum {
	NI_UPDATER_JOB_PENDING = 0,
	NI_UPDATER_JOB_RUNNING,
	NI_UPDATER_JOB_FINISHED,
} ni_updater_job_state_t;

struct ni_updater_action {
	int				(*func)(ni_updater_t *updater, ni_updater_job_t *job);
};

struct ni_updater_job {
	unsigned int			refcount;
	ni_updater_job_t **		pprev;
	ni_updater_job_t *		next;
	unsigned long			nr;

	ni_netdev_ref_t			device;
	const ni_addrconf_lease_t *	lease;

	ni_updater_job_state_t		state;

	ni_updater_job_flow_t		flow;
	unsigned int			kind;
	ni_uint_array_t			updater;

	const ni_updater_action_t *	actions;
	ni_process_t *			process;
	int				result;

	char *				hostname;
};

struct ni_updater {
	ni_updater_source_array_t	sources;

	unsigned int			kind;
	int				format;
	ni_bool_t			enabled;
	unsigned int			have_backup;

	ni_shellcmd_t *			proc_backup;
	ni_shellcmd_t *			proc_restore;
	ni_shellcmd_t *			proc_install;
	ni_shellcmd_t *			proc_remove;
	ni_shellcmd_t *			proc_batch;
};

static ni_updater_t			updaters[__NI_ADDRCONF_UPDATER_MAX];
static ni_updater_job_t *		job_list = NULL;
static unsigned long			job_nr = 0;

static const ni_intmap_t		ni_updater_format_names[] = {
	{ "info",			NI_ADDRCONF_UPDATER_FORMAT_INFO	},
	{ NULL,				NI_ADDRCONF_UPDATER_FORMAT_NONE }
};

static const ni_intmap_t		ni_updater_kind_names[] = {
	{ "hostname",			NI_ADDRCONF_UPDATER_HOSTNAME	},
	{ "resolver",			NI_ADDRCONF_UPDATER_RESOLVER	},
	{ "generic",			NI_ADDRCONF_UPDATER_GENERIC	},
	{ NULL,				__NI_ADDRCONF_UPDATER_MAX	}
};

static ni_bool_t			ni_system_updater_generic_batch_test(ni_updater_t *);

/*
 * Get the name of an updater
 */
static const char *
ni_updater_name(unsigned int kind)
{
	return ni_format_uint_mapped(kind, ni_updater_kind_names);
}
static unsigned int
ni_updater_format_type(const char *format)
{
	unsigned int type;

	if (ni_parse_uint_mapped(format, ni_updater_format_names, &type))
		return NI_ADDRCONF_UPDATER_FORMAT_NONE;
	return type;
}

static const char *
ni_updater_format_name(unsigned int format)
{
	return ni_format_uint_mapped(format, ni_updater_format_names);
}

static ni_updater_source_t *
ni_updater_source_new(void)
{
	ni_updater_source_t *src;

	src = xcalloc(1, sizeof(*src));
	if (src) {
		src->refcount = 1;
	}
	return src;
}

ni_updater_source_t *
ni_updater_source_ref(ni_updater_source_t *src)
{
	if (src) {
		ni_assert(src->refcount);
		src->refcount++;

		return src;
	}
	return NULL;
}

static void
ni_updater_source_free(ni_updater_source_t *src)
{
	if (src) {
		ni_assert(src->refcount);
		src->refcount--;

		if (src->refcount == 0) {
			ni_netdev_ref_destroy(&src->device);
			free(src);
		}
	}
}

static inline void
ni_updater_source_array_init(ni_updater_source_array_t *usa)
{
	memset(usa, 0, sizeof(*usa));
}

void
ni_updater_source_array_destroy(ni_updater_source_array_t *usa)
{
	if (usa) {
		while (usa->count) {
			usa->count--;
			ni_updater_source_free(usa->data[usa->count]);
		}
		ni_updater_source_array_init(usa);
	}
}

static void
__ni_updater_source_array_realloc(ni_updater_source_array_t *usa, unsigned int newsize)
{
	unsigned int i;

	newsize = (newsize + NI_UPDATER_SOURCE_ARRAY_CHUNK);
	usa->data = xrealloc(usa->data, newsize * sizeof(ni_updater_source_t *));

	for (i = usa->count; i < newsize; ++i)
		usa->data[i] = NULL;
}

static ni_bool_t
ni_updater_source_array_append(ni_updater_source_array_t *usa, ni_updater_source_t *src)
{
	if (!usa || !src)
		return FALSE;

	if ((usa-> count % NI_UPDATER_SOURCE_ARRAY_CHUNK) == 0)
		__ni_updater_source_array_realloc(usa, usa->count);

	usa->data[usa->count++] = src;
	return TRUE;
}

static ni_updater_source_t *
ni_updater_source_array_remove(ni_updater_source_array_t *usa, unsigned int index)
{
	ni_updater_source_t *ptr;

	if (!usa || index >= usa->count)
		return NULL;

	ptr = usa->data[index];
	usa->count--;
	if (index < usa->count) {
		memmove(&usa->data[index], &usa->data[index + 1],
			(usa->count - index) * sizeof(ni_updater_source_t *));
	}
	usa->data[usa->count] = NULL;

	/* Don't bother with shrinking the array. It's not worth the trouble */
	return ptr;
}

static ni_updater_source_t *
ni_updater_sources_remove_match(ni_updater_source_array_t *usa,
					const ni_netdev_ref_t *device,
					const ni_addrconf_lease_t *lease)
{
	ni_updater_source_t *ptr;
	unsigned int i;

	if (!usa || !device || !lease)
		return NULL;

	for (i = 0; i < usa->count; ++i) {
		ptr = usa->data[i];
		if (ptr &&
		    ptr->device.index == device->index &&
		    ptr->lease.family == lease->family &&
		    ptr->lease.type   == lease->type)
			return ni_updater_source_array_remove(usa, i);
	}
	return NULL;
}

/*
 * Add this lease to the given updater, to record that we can use the
 * information from this lease.
 */
static void
ni_updater_sources_update_match(ni_updater_source_array_t *usa,
				const ni_netdev_ref_t *device,
				const ni_addrconf_lease_t *lease)
{
	ni_updater_source_t *src;

	if (!usa || !device || !lease)
		return;

	if ((src = ni_updater_sources_remove_match(usa, device, lease)))
		ni_updater_source_free(src);

	src = ni_updater_source_new();
	if (src) {
		src->lease.type = lease->type;
		src->lease.family = lease->family;
		if (!ni_netdev_ref_set(&src->device, device->name, device->index))
			ni_updater_source_free(src);
		else
			ni_updater_source_array_append(usa, src);
	}
}

static inline void
do_updater_job_list_insert(ni_updater_job_t **list, ni_updater_job_t *job)
{
	job->pprev = list;
	job->next = *list;
	if (job->next)
		job->next->pprev = &job->next;
	*list = job;
}

static inline void
do_updater_job_list_append(ni_updater_job_t **list, ni_updater_job_t *job)
{
	ni_updater_job_t **tail, *cur;

	for (tail = list; (cur = *tail); tail = &cur->next)
		;
	do_updater_job_list_insert(tail, job);
}

static ni_bool_t
ni_updater_job_list_unlink(ni_updater_job_t *job)
{
	ni_updater_job_t **pprev, *next;

	pprev = job->pprev;
	next = job->next;
	if (pprev)
		*pprev = next;
	if (next)
		next->pprev = pprev;
	job->pprev = NULL;
	job->next = NULL;
	return pprev != NULL;
}

static const char *
ni_updater_job_info(ni_stringbuf_t *out, const ni_updater_job_t *job)
{
	const char *kind;

	if (!out || !job)
		return NULL;

	kind = ni_updater_name(job->kind);
	ni_stringbuf_clear(out);

	ni_stringbuf_printf(out,
			"%s %s job[%lu](%u) on device %s[%u] for lease %s:%s state %s%s%s%s%s",
			job->state == NI_UPDATER_JOB_PENDING  ? "pending"  :
			job->state == NI_UPDATER_JOB_RUNNING  ? "running"  :
			job->state == NI_UPDATER_JOB_FINISHED ? "finished" : "broken",
			job->flow  == NI_UPDATER_FLOW_INSTALL ? "install"  :
			job->flow  == NI_UPDATER_FLOW_REMOVAL ? "remove"   : "invalid",
			job->nr,  job->refcount,
			job->device.name, job->device.index,
			ni_addrfamily_type_to_name(job->lease->family),
			ni_addrconf_type_to_name(job->lease->type),
			ni_addrconf_state_to_name(job->lease->state),
			ni_process_running(job->process) ?
				" subprocess " : "", job->process ?
				ni_sprint_uint(job->process->pid) : "",
			kind ? " kind " : "", kind ? kind : "");
	return out->string;
}

static ni_updater_job_t *
ni_updater_job_new(ni_updater_job_t **list, const ni_addrconf_lease_t *lease,
			unsigned int ifindex, const char *ifname)
{
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;
	ni_updater_job_t *job;
	int kind;

	if (!list || !lease || !ifindex || ni_string_empty(ifname))
		return NULL;

	job = calloc(1, sizeof(*job));
	if (!job)
		return NULL;

	job->nr = job_nr++; /* for debugging purposes only */
	job->refcount = 1;
	if (!ni_netdev_ref_set(&job->device, ifname, ifindex)) {
		free(job);
		return NULL;
	}

	job->lease = lease;
	switch (lease->state) {
	case NI_ADDRCONF_STATE_APPLYING:
	case NI_ADDRCONF_STATE_GRANTED:
		job->flow = NI_UPDATER_FLOW_INSTALL;
		break;
	case NI_ADDRCONF_STATE_RELEASING:
	case NI_ADDRCONF_STATE_RELEASED:
	default:
		job->flow = NI_UPDATER_FLOW_REMOVAL;
		break;
	}
	for (kind = 0; kind < __NI_ADDRCONF_UPDATER_MAX; ++kind) {
		ni_updater_t *updater = &updaters[kind];
		if (updater->enabled)
			ni_uint_array_append(&job->updater, kind);
	}
	ni_uint_array_get(&job->updater, 0, &job->kind);

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EXTENSION,
			"created %s", ni_updater_job_info(&out, job));
	ni_stringbuf_destroy(&out);

	do_updater_job_list_append(list, job);

	return job;
}

static ni_updater_job_t *
ni_updater_job_ref(ni_updater_job_t *job)
{
	if (job) {
		ni_assert(job->refcount);

		job->refcount++;
	}
	return job;
}

static void
ni_updater_job_destroy(ni_updater_job_t *job)
{
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EXTENSION,
			"destroy %s", ni_updater_job_info(&out, job));
	ni_stringbuf_destroy(&out);

	ni_netdev_ref_destroy(&job->device);
	ni_uint_array_destroy(&job->updater);
	job->kind = __NI_ADDRCONF_UPDATER_MAX;
	job->lease = NULL;
	job->actions = NULL;
	if (job->process) {
		job->process->user_data = NULL;
		ni_process_free(job->process);
		job->process = NULL;
	}
	ni_string_free(&job->hostname);
}

static void
ni_updater_job_free(ni_updater_job_t *job)
{
	if (job) {
		ni_assert(job->refcount);

		job->refcount--;
		if (job->refcount == 0) {
			ni_updater_job_list_unlink(job);
			ni_updater_job_destroy(job);
			free(job);
		}
	}
}

static void
ni_updater_job_cancel(ni_updater_job_t *job)
{
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;
	if (job) {
		if (job->state != NI_UPDATER_JOB_FINISHED || job->process)
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EXTENSION,
					"cancel %s", ni_updater_job_info(&out, job));
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EXTENSION,
					"cleanup %s", ni_updater_job_info(&out, job));
		ni_stringbuf_destroy(&out);

		job->kind    = __NI_ADDRCONF_UPDATER_MAX;
		job->state   = NI_UPDATER_JOB_FINISHED;
		job->result  = -1;
		job->actions = NULL;
		if (job->process) {
			ni_updater_job_t *ref;

			ref = job->process->user_data;
			job->process->user_data = NULL;
			ni_updater_job_free(ref);

			ni_process_free(job->process);
			job->process = NULL;
		}
	}
}

static ni_bool_t
ni_updater_job_call_updater(ni_updater_job_t *job)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_addrconf_lease_t *lease;
	ni_netdev_t *dev;

	if (!job || !(nc = ni_global_state_handle(0)))
		return FALSE;

	if (!(dev = ni_netdev_by_index(nc, job->device.index)))
		return FALSE;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (job->lease == lease) {
			ni_addrconf_updater_background(lease->updater, 0);
			return TRUE;
		}
	}
	return FALSE;
}

static inline ni_bool_t
ni_updater_job_pending(ni_updater_job_t *job)
{
	return job->state == NI_UPDATER_JOB_PENDING;
}

static inline ni_bool_t
ni_updater_job_running(ni_updater_job_t *job)
{
	return job->state == NI_UPDATER_JOB_RUNNING;
}

static inline ni_bool_t
ni_updater_job_finished(ni_updater_job_t *job)
{
	return job->state == NI_UPDATER_JOB_FINISHED;
}

static ni_updater_job_t *
ni_updater_job_list_find_running(ni_updater_job_t **list)
{
	ni_updater_job_t *job;

	for (job = list ? *list : NULL; job; job = job->next) {
		if (job->state == NI_UPDATER_JOB_RUNNING)
			return job;
	}
	return NULL;
}

static ni_updater_job_t *
ni_updater_job_list_find_pending(ni_updater_job_t **list)
{
	ni_updater_job_t *job;

	for (job = list ? *list : NULL; job; job = job->next) {
		if (job->state == NI_UPDATER_JOB_PENDING)
			return job;
	}
	return NULL;
}

/*
 * Initialize the system updaters based on the data found in the config
 * file.
 */
static void
ni_system_updaters_init(void)
{
	static int initialized = 0;
	unsigned int kind;

	if (initialized)
		return;
	initialized = 1;

	for (kind = 0; kind < __NI_ADDRCONF_UPDATER_MAX; ++kind) {
		ni_updater_t *updater = &updaters[kind];
		const char *name = ni_updater_name(kind);
		ni_extension_t *ex;

		updater->enabled = FALSE;
		updater->kind = kind;
		if (name == NULL)
			continue;

		if (!(ex = ni_config_find_system_updater(ni_global.config, name)))
			continue;

		updater->enabled = TRUE;
		updater->format = ni_updater_format_type(ex->format);
		updater->proc_backup = ni_extension_script_find(ex, "backup");
		updater->proc_restore = ni_extension_script_find(ex, "restore");
		updater->proc_install = ni_extension_script_find(ex, "install");
		updater->proc_remove = ni_extension_script_find(ex, "remove");
		if (kind == NI_ADDRCONF_UPDATER_GENERIC) {
			if ((updater->proc_batch = ni_extension_script_find(ex, "batch"))) {
				if (!ni_system_updater_generic_batch_test(updater))
					updater->proc_batch = NULL;
			}
		}

		/* Create runtime directories for resolver and hostname extensions. */
		if (!(ni_extension_statedir(name))) {
			updater->enabled = FALSE;
		} else
		if (updater->proc_install == NULL && updater->proc_batch == NULL) {
			ni_warn("system-updater %s configured, but no install script defined", name);
			updater->enabled = FALSE;
		} else
		if (updater->proc_remove == NULL && updater->proc_batch == NULL) {
			ni_warn("system-updater %s configured, but no remove script defined", name);
			updater->enabled = FALSE;
		}
		if (updater->enabled && (updater->proc_backup == NULL || updater->proc_restore == NULL)) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EXTENSION,
				"system-updater %s configured, but no backup/restore script defined", name);
			updater->proc_backup = updater->proc_restore = NULL;
		}
	}
}

static inline ni_bool_t
can_try_reverse_lookup(const ni_addrconf_lease_t *lease)
{
	/* bnc#861476 workaround */
	if (lease->state != NI_ADDRCONF_STATE_APPLYING &&
	    lease->state != NI_ADDRCONF_STATE_GRANTED)
		return FALSE;

	/* Limit to dhcp leases (for now) */
	if (lease->type != NI_ADDRCONF_DHCP)
		return FALSE;

	return lease->addrs != NULL;
}

static inline ni_bool_t
can_update_type(const ni_addrconf_lease_t *lease, unsigned int kind)
{
	ni_bool_t can = FALSE;

	switch (kind) {
	case NI_ADDRCONF_UPDATER_HOSTNAME:
		if (__ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_HOSTNAME))
			can = lease->hostname ? TRUE : can_try_reverse_lookup(lease);
		break;

	case NI_ADDRCONF_UPDATER_RESOLVER:
		if (__ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_DNS))
			can = lease->resolver ? TRUE : FALSE;
		break;

	case NI_ADDRCONF_UPDATER_GENERIC:
		/* Always attempt generic update. */
		can = TRUE;
		break;

	default:
		break;
	}
	return can;
}

/*
 * Run an extension script to update resolver, hostname etc.
 */
static void
ni_system_updater_notify(ni_process_t *pi)
{
	ni_updater_job_t *job = pi->user_data;
	const char *ptr;
	size_t len;

	if (!job || job->process != pi)
		return;

	pi->user_data = NULL;
	job->process = NULL;
	job->result = ni_process_exit_status(pi);
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EXTENSION,
		"%s: job[%lu](%u) notify for lease %s:%s in state %s %s updater (%s) pid %d finished, status %d",
			job->device.name, job->nr, job->refcount,
			ni_addrfamily_type_to_name(job->lease->family),
			ni_addrconf_type_to_name(job->lease->type),
			ni_addrconf_state_to_name(job->lease->state),
			ni_updater_name(job->kind),
			ni_basename(pi->process->command), pi->pid, job->result);
	switch (job->kind) {
	case NI_ADDRCONF_UPDATER_HOSTNAME:
		if (pi->socket && (len = ni_buffer_count(&pi->socket->rbuf))) {
			ptr = ni_buffer_head(&pi->socket->rbuf);
			if (ni_check_domain_name(ptr, len, 0))
				ni_string_set(&job->hostname, ptr, len);
		}
	default:
		break;
	}
	ni_updater_job_call_updater(job);
	ni_updater_job_free(job);
}

static int
ni_system_updater_run(ni_updater_job_t *job, ni_shellcmd_t *shellcmd, ni_string_array_t *args)
{
	ni_process_t *pi;
	int rv;

	if (!job || job->process || !shellcmd)
		return NI_PROCESS_FAILURE;

	if (!(pi = ni_process_new(shellcmd)))
		return NI_PROCESS_FAILURE;

	if (args) {
		unsigned int i;

		for (i = 0; i < args->count; ++i) {
			const char *arg = args->data[i];

			if (arg == NULL)
				arg = "";
			ni_string_array_append(&pi->argv, arg);
		}
	}

	rv = ni_process_run(pi);
	if (rv == NI_PROCESS_SUCCESS) {
		job->process = pi;
		pi->user_data = ni_updater_job_ref(job);
		pi->notify_callback = ni_system_updater_notify;
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EXTENSION,
			"%s: started lease %s:%s in state %s %s updater (%s) with pid %d",
				job->device.name,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state),
				ni_updater_name(job->kind),
				ni_basename(shellcmd->command), pi->pid);
	} else {
		ni_process_free(pi);
	}
	return rv;
}

/*
 * Retrieve result of a running call
 */
static int
ni_system_updater_process_wait(ni_updater_t *updater, ni_updater_job_t *job, const char *action)
{
	ni_process_t *pi = job->process;

	if (pi && ni_process_running(pi)) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EXTENSION,
			"%s: waiting for %s job to %s lease %s:%s in state %s executing subprocess %d",
			job->device.name,
			job->state == NI_UPDATER_JOB_PENDING  ? "pending"  :
			job->state == NI_UPDATER_JOB_RUNNING  ? "running"  :
			job->state == NI_UPDATER_JOB_FINISHED ? "finished" : "broken state",
			job->flow  == NI_UPDATER_FLOW_INSTALL ? "install"  :
			job->flow  == NI_UPDATER_FLOW_REMOVAL ? "remove"   : "broken flow",
			ni_addrfamily_type_to_name(job->lease->family),
			ni_addrconf_type_to_name(job->lease->type),
			ni_addrconf_state_to_name(job->lease->state),
			pi->pid);
		return 1;
	}

	job->process = NULL;
	if (job->result == 0)
		return 0;

	job->result = 0;
	return -1;
}


/*
 * Common back up current configuration call
 */
static int
ni_system_updater_backup_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	job->result = 0;

	if (updater->have_backup)
		return 0;

	if (!updater->proc_backup)
		return 0;

	if (ni_system_updater_run(job, updater->proc_backup, NULL) != NI_PROCESS_SUCCESS) {
		ni_warn("%s: unable to execute %s updater (%s) for lease %s:%s in state %s",
				job->device.name, ni_updater_name(updater->kind),
				updater->proc_backup->command,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		return -1;
	}
	return 0;
}
static int
ni_system_updater_backup_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	int ret;

	if ((ret = ni_system_updater_process_wait(updater, job, __func__)))
		return ret;

	updater->have_backup = 1;

	return ret;
}

/*
 * Common restore existing configuration call
 */
static int
ni_system_updater_restore_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	job->result = 0;

	if (updater->sources.count)
		return 0;

	if (!updater->have_backup)
		return 0;

	if (!updater->proc_restore)
		return 0;

	if (ni_system_updater_run(job, updater->proc_restore, NULL) != NI_PROCESS_SUCCESS) {
		ni_warn("%s: unable to execute %s updater (%s) for lease %s:%s in state %s",
				job->device.name, ni_updater_name(updater->kind),
				updater->proc_restore->command,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		return -1;
	}
	return 0;
}
static int
ni_system_updater_restore_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	int ret;

	if ((ret = ni_system_updater_process_wait(updater, job, __func__)))
		return ret;

	updater->have_backup = 0;

	return ret;
}


static ni_bool_t
ni_system_updater_common_args(ni_string_array_t *args, const char *ifname, unsigned int type, unsigned int family)
{
	ni_string_array_append(args, "-i");
	ni_string_array_append(args, ifname);

	ni_string_array_append(args, "-t");
	ni_string_array_append(args, ni_addrconf_type_to_name(type));

	ni_string_array_append(args, "-f");
	ni_string_array_append(args, ni_addrfamily_type_to_name(family));
	return TRUE;
}

/*
 * Generic aka netconfig updater specific calls
 */
static int
ni_system_updater_generic_cleanup_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	ni_string_array_t args = NI_STRING_ARRAY_INIT;
	ni_updater_source_t *src;
	int ret = -1;

	/* Call remove action only, when the name changed */
	src = ni_updater_sources_remove_match(&updater->sources, &job->device, job->lease);
	if (!src || ni_string_eq(job->device.name, src->device.name)) {
		ret = 0;
		goto cleanup;
	}

	if (!ni_system_updater_common_args(&args, src->device.name,
				src->lease.type, src->lease.family))
		goto cleanup;

	if (updater->kind == NI_ADDRCONF_UPDATER_GENERIC &&
	    updater->format == NI_ADDRCONF_UPDATER_FORMAT_INFO)
		ni_leaseinfo_remove(src->device.name, src->lease.type, src->lease.family);

	job->result = 0;
	if (ni_system_updater_run(job, updater->proc_remove, &args) != NI_PROCESS_SUCCESS) {
		ni_warn("%s: unable to cleanup %s updater (%s) for lease %s:%s in state %s",
				src->device.name, ni_updater_name(updater->kind),
				updater->proc_remove->command,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		goto cleanup;
	}

	ret = 0; /* started, advance to wait for finish */

cleanup:
	ni_updater_source_free(src);
	ni_string_array_destroy(&args);
	return ret;
}
static int
ni_system_updater_generic_cleanup_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	if (ni_system_updater_process_wait(updater, job, __func__) > 0)
		return 1;
	return 0;
}

static ni_bool_t
ni_system_updater_generic_leaseinfo_create(ni_updater_t *updater, ni_updater_job_t *job,
						ni_string_array_t *args)
{
	char *filename = NULL;
	ni_bool_t ret = FALSE;

	switch (updater->format) {
	case NI_ADDRCONF_UPDATER_FORMAT_INFO:
		filename = ni_leaseinfo_path(job->device.name, job->lease->type, job->lease->family);
		if (ni_string_empty(filename)) {
			ni_warn("%s: unable to construct %s updater %s:%s lease info file name",
					job->device.name, ni_updater_name(updater->kind),
					ni_addrfamily_type_to_name(job->lease->family),
					ni_addrconf_type_to_name(job->lease->type));
			goto cleanup;
		}
		ni_string_array_append(args, filename);
		ni_string_array_append(args, ni_updater_format_name(updater->format));

		ni_leaseinfo_dump(NULL, job->lease, job->device.name, NULL);
		break;

	case NI_ADDRCONF_UPDATER_FORMAT_NONE:
	default:
		ni_error("unsupported %s system updater data format",
				ni_updater_name(updater->kind));
		goto cleanup;
	}

	ret = TRUE;

cleanup:
	ni_string_free(&filename);
	return ret;
}

static int
ni_system_updater_generic_batch_add(FILE *out, const ni_updater_job_t *job, const char *ident)
{
	char *filename = NULL;
	char *command = NULL;
	int ret = -1;

	switch (job->flow) {
	case NI_UPDATER_FLOW_INSTALL:
		filename = ni_leaseinfo_path(job->device.name,	job->lease->type,
								job->lease->family);
		if (!filename)
			goto cleanup;

		if (!ni_string_printf(&command, "modify -i %s -s wicked-%s-%s -I %s",
					job->device.name,
					ni_addrconf_type_to_name(job->lease->type),
					ni_addrfamily_type_to_name(job->lease->family),
					filename))
			goto cleanup;

		if (fprintf(out, "%s\n", command) <= 0)
			goto cleanup;

		ni_leaseinfo_dump(NULL, job->lease, job->device.name, NULL);
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_EXTENSION,
				"%s add: %s", ident, command);
		ret = 0;
		break;

	case NI_UPDATER_FLOW_REMOVAL:
		if (!ni_string_printf(&command, "remove -i %s -s wicked-%s-%s",
					job->device.name,
					ni_addrconf_type_to_name(job->lease->type),
					ni_addrfamily_type_to_name(job->lease->family)))
			goto cleanup;

		if (fprintf(out, "%s\n", command) <= 0)
			goto cleanup;

		ni_leaseinfo_remove(job->device.name, job->lease->type, job->lease->family);
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_EXTENSION,
				"%s add: %s", ident, command);

		ret = 0;
		break;
	default:
		break;
	}

cleanup:
	ni_string_free(&command);
	ni_string_free(&filename);
	return ret;
}

static ni_process_t *
ni_system_updater_generic_batch_create(ni_updater_t *updater, char **filename, FILE **out)
{
	ni_process_t *pi = NULL;
	const char *statedir;
	FILE *fp = NULL;
	int fd;

	statedir = ni_extension_statedir(ni_updater_name(updater->kind));
	if (!statedir)
		goto cleanup;

	if (!statedir || !ni_string_printf(filename, "%s/batch.XXXXXX", statedir))
		goto cleanup;

	if (!(pi = ni_process_new(updater->proc_batch)))
		goto cleanup;

	if (!pi->argv.count || !ni_file_executable(pi->argv.data[0]))
		goto cleanup;

	if (!(pi->temp_state = ni_tempstate_new("batch")))
		goto cleanup;

	if ((fd = mkstemp(*filename)) < 0)
		goto cleanup;

	ni_string_array_append(&pi->argv, *filename);
	ni_string_array_append(&pi->argv, "info");
	ni_tempstate_add_file(pi->temp_state, *filename);

	if (!(fp = fdopen(fd, "w"))) {
		close(fd);
		goto cleanup;
	}

	*out = fp;
	return pi;

cleanup:
	ni_string_free(filename);
	if (pi)
		ni_process_free(pi);
	return NULL;
}

static ni_bool_t
ni_system_updater_generic_batch_test(ni_updater_t *updater)
{
	ni_process_t *pi = NULL;
	char *filename = NULL;
	ni_bool_t ret = FALSE;
	const char *ident;
	FILE *out = NULL;

	if (!updater->proc_batch || ni_string_empty(updater->proc_batch->command))
		return ret;

	ident = ni_basename(updater->proc_batch->command);
	if (!ni_string_eq(ident, "netconfig batch")) {
		ni_note("disabling %s batch updater action '%s': only netconfig supported",
				ni_updater_name(updater->kind), ident);
		return ret;
	}

	if (!(pi = ni_system_updater_generic_batch_create(updater, &filename, &out)))
		goto cleanup;

	fflush(out);
	fclose(out);
	out = NULL;
	ret = ni_process_run_and_wait(pi) == NI_PROCESS_SUCCESS;

cleanup:
	if (out)
		fclose(out);
	if (pi)
		ni_process_free(pi);
	ni_string_free(&filename);
	if (!ret) {
		ni_note("disabling %s batch updater action '%s': test failure, "
				"update to sysconfig-netconfig >= 0.84",
				ni_updater_name(updater->kind), ident);
	}
	return ret;
}

static int
ni_system_updater_generic_batch_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	ni_process_t *pi = NULL;
	char *filename = NULL;
	ni_updater_job_t *j;
	const char *ident;
	FILE *out = NULL;
	int ret = -1;

	if (!updater->proc_batch || !updater->proc_batch->command)
		return -1;

	ident = ni_basename(updater->proc_batch->command);
	pi = ni_system_updater_generic_batch_create(updater, &filename, &out);
	if (!pi) {
		ni_error("%s: unable to create %s file to update lease %s:%s in state %s",
				job->device.name, ident,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		goto cleanup;
	} else {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_EXTENSION,
				"%s: created %s file to update lease %s:%s in state %s",
				job->device.name, ident,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
	}

	if (ni_system_updater_generic_batch_add(out, job, ident) < 0)
		goto cleanup;

	/* pickup pending job actions to the batch */
	for (j = job->next; (j = ni_updater_job_list_find_pending(&j)); j = j->next) {
		unsigned int pos;

		if ((pos = ni_uint_array_index(&j->updater, j->kind)) == -1U)
			continue;

		if (ni_system_updater_generic_batch_add(out, j, ident) < 0)
			break;

		ni_uint_array_remove_at(&j->updater, pos);
	}

	if (fprintf(out, "update\n") <= 0)
		goto cleanup;
	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_EXTENSION, "%s add: update", ident);

	fflush(out);
	fclose(out);
	out = NULL;

	ret = ni_process_run(pi);
	if (ret == NI_PROCESS_SUCCESS) {
		job->process = pi;
		pi->user_data = ni_updater_job_ref(job);
		pi->notify_callback = ni_system_updater_notify;
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EXTENSION,
			"%s: started lease %s:%s in state %s %s updater (%s) with pid %d",
			job->device.name,
			ni_addrfamily_type_to_name(job->lease->family),
			ni_addrconf_type_to_name(job->lease->type),
			ni_addrconf_state_to_name(job->lease->state),
			ni_updater_name(job->kind),
			ni_basename(pi->process->command), pi->pid);
		pi = NULL;
	}

cleanup:
	if (out)
		fclose(out);
	if (pi)
		ni_process_free(pi);
	ni_string_free(&filename);
	return ret;
}
static int
ni_system_updater_generic_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	int ret;

	if ((ret = ni_system_updater_process_wait(updater, job, __func__)))
		return ret;

	if (ni_global.other_event)
		ni_global.other_event(NI_EVENT_GENERIC_UPDATED);

	return ret;
}

static int
ni_system_updater_generic_install_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	ni_string_array_t args = NI_STRING_ARRAY_INIT;
	int ret = -1;

	if (updater->proc_batch)
		return ni_system_updater_generic_batch_call(updater, job);

	if (!ni_system_updater_common_args(&args, job->device.name,
				job->lease->type, job->lease->family))
		goto cleanup;

	if (!ni_system_updater_generic_leaseinfo_create(updater, job, &args))
		goto cleanup;

	job->result = 0;
	if (ni_system_updater_run(job, updater->proc_install, &args) != NI_PROCESS_SUCCESS) {
		ni_warn("%s: unable to execute %s updater (%s) for lease %s:%s in state %s",
				job->device.name, ni_updater_name(updater->kind),
				updater->proc_install->command,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		goto cleanup;
	}

	ni_updater_sources_update_match(&updater->sources, &job->device, job->lease);

	ret = 0; /* started, advance to wait for finish */

cleanup:
	ni_string_array_destroy(&args);
	return ret;
}
static int
ni_system_updater_generic_install_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	return ni_system_updater_generic_wait(updater, job);
}

static int
ni_system_updater_generic_remove_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	ni_string_array_t args = NI_STRING_ARRAY_INIT;
	ni_updater_source_t *src;
	int ret = -1;

	if (updater->proc_batch)
		return ni_system_updater_generic_batch_call(updater, job);

	/* Call remove action only, when we applied it */
	src = ni_updater_sources_remove_match(&updater->sources, &job->device, job->lease);
	if (!src)
		return 0;
	ni_updater_source_free(src);

	if (!ni_system_updater_common_args(&args, job->device.name,
				job->lease->type, job->lease->family))
		goto cleanup;

	switch (updater->format) {
	case NI_ADDRCONF_UPDATER_FORMAT_INFO:
		ni_leaseinfo_remove(job->device.name, job->lease->type, job->lease->family);
	default:
		break;
	}

	job->result = 0;
	if (ni_system_updater_run(job, updater->proc_remove, &args) != NI_PROCESS_SUCCESS) {
		ni_warn("%s: unable to execute %s updater (%s) for lease %s:%s in state %s",
				job->device.name, ni_updater_name(updater->kind),
				updater->proc_remove->command,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		goto cleanup;
	}

	ret = 0; /* started, advance to wait for finish */

cleanup:
	ni_string_array_destroy(&args);
	return ret;
}
static int
ni_system_updater_generic_remove_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	return ni_system_updater_generic_wait(updater, job);
}

/*
 * Resolver updater specific calls
 */
static int
ni_system_updater_resolver_cleanup_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	return ni_system_updater_generic_cleanup_call(updater, job);
}
static int
ni_system_updater_resolver_cleanup_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	if (ni_system_updater_process_wait(updater, job, __func__) > 0)
		return 1;
	return 0;
}

static int
ni_system_updater_resolver_install_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	ni_string_array_t args = NI_STRING_ARRAY_INIT;
	const char *statedir;
	char *filename = NULL;
	int ret = -1;

	if (!ni_system_updater_common_args(&args, job->device.name,
				job->lease->type, job->lease->family))
		goto cleanup;

	statedir = ni_extension_statedir(ni_updater_name(updater->kind));
	if (ni_string_empty(statedir)) {
		ni_warn("%s: unable to construct %s updater state-dir",
				job->device.name, ni_updater_name(updater->kind));
		goto cleanup;
	}
	ni_string_printf(&filename, "%s/resolv.conf.%s.%s.%s",
			statedir, job->device.name,
			ni_addrconf_type_to_name(job->lease->type),
			ni_addrfamily_type_to_name(job->lease->family));
	if (ni_string_empty(filename)) {
		ni_warn("%s: unable to construct %s updater resolv.conf file for lease %s:%s",
				job->device.name, ni_updater_name(updater->kind),
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type));
		goto cleanup;
	}
	ni_string_array_append(&args, filename);

	if (ni_resolver_write_resolv_conf(filename, job->lease->resolver, NULL) < 0) {
		ni_error("%s: unable to write %s updater resolv.conf file %s: %m",
				job->device.name, ni_updater_name(updater->kind),
				filename);
		goto cleanup;
	}

	job->result = 0;
	if (ni_system_updater_run(job, updater->proc_install, &args) != NI_PROCESS_SUCCESS) {
		ni_warn("%s: unable to execute %s updater (%s) for lease %s:%s in state %s",
				job->device.name, ni_updater_name(updater->kind),
				updater->proc_install->command,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		goto cleanup;
	}

	ni_updater_sources_update_match(&updater->sources, &job->device, job->lease);

	ret = 0; /* started, advance to wait for finish */

cleanup:
	ni_string_free(&filename);
	ni_string_array_destroy(&args);
	return ret;
}
static int
ni_system_updater_resolver_install_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	int ret;

	if ((ret = ni_system_updater_process_wait(updater, job, __func__)))
		return ret;

	if (ni_global.other_event)
		ni_global.other_event(NI_EVENT_RESOLVER_UPDATED);

	return ret;
}

static int
ni_system_updater_resolver_remove_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	ni_string_array_t args = NI_STRING_ARRAY_INIT;
	ni_updater_source_t *src;
	int ret = -1;

	/* Call remove action only, when we applied it */
	src = ni_updater_sources_remove_match(&updater->sources, &job->device, job->lease);
	if (!src)
		return 0;
	ni_updater_source_free(src);

	if (!ni_system_updater_common_args(&args, job->device.name,
				job->lease->type, job->lease->family))
		goto cleanup;

	job->result = 0;
	if (ni_system_updater_run(job, updater->proc_remove, &args) != NI_PROCESS_SUCCESS) {
		ni_warn("%s: unable to execute %s updater (%s) for lease %s:%s in state %s",
				job->device.name, ni_updater_name(updater->kind),
				updater->proc_remove->command,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		goto cleanup;
	}

	ret = 0; /* started, advance to wait for finish */

cleanup:
	ni_string_array_destroy(&args);
	return ret;
}
static int
ni_system_updater_resolver_remove_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	int ret;

	if ((ret = ni_system_updater_process_wait(updater, job, __func__)))
		return ret;

	if (ni_global.other_event)
		ni_global.other_event(NI_EVENT_RESOLVER_UPDATED);

	return ret;
}

/*
 * Resolver updater specific calls
 */
static int
ni_system_updater_hostname_cleanup_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	return ni_system_updater_generic_cleanup_call(updater, job);
}
static int
ni_system_updater_hostname_cleanup_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	if (ni_system_updater_process_wait(updater, job, __func__) > 0)
		return 1;
	return 0;
}

static int
do_reverse_resolve_ip_address(int argc, char *const argv[], char *const envp[])
{
	unsigned int count = 0;
	char *name = NULL;
	int n;

	if (argc < 1 || !argv)
		return EXIT_FAILURE;

	if (!freopen("/dev/null", "w", stderr))
		{}

	for (n = 1; n < argc && argv[n]; ++n) {
		ni_sockaddr_t addr;

		if (ni_sockaddr_parse(&addr, argv[n], AF_UNSPEC) ||
		    !ni_sockaddr_is_specified(&addr))
			continue;

		if (!ni_resolve_reverse_timed(&addr, &name,
					NI_UPDATER_REVERSE_TIMEOUT)) {
			fprintf(stdout, "%s", name);
			fflush(stdout);
			ni_string_free(&name);
			return EXIT_SUCCESS;
		}

		if (++count >= NI_UPDATER_REVERSE_MAX_CNT)
			break;
	}
	return EXIT_FAILURE;
}

static int
ni_system_updater_hostname_lookup_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	const ni_address_t *ap;
	ni_shellcmd_t *shellcmd;
	ni_process_t *pi;
	int rv;

	job->result = 0;

	if (!ni_string_empty(job->lease->hostname)) {
		ni_string_dup(&job->hostname, job->lease->hostname);
		return 0;
	}

	/* bnc#861476 workaround */
	if (!can_try_reverse_lookup(job->lease))
		return -1;

	shellcmd = ni_shellcmd_parse("wickedd-resolver");
	if (!shellcmd)
		return -1;

	pi = ni_process_new(shellcmd);
	ni_shellcmd_free(shellcmd);
	if (!pi)
		return -1;

	for (ap = job->lease->addrs; ap; ap = ap->next) {
		const char *addr;

		if (ni_address_is_tentative(ap) || ni_address_is_duplicate(ap))
			continue;

		if (!ni_sockaddr_is_specified(&ap->local_addr))
			continue;

		if ((addr = ni_sockaddr_print(&ap->local_addr)))
			ni_string_array_append(&pi->argv, addr);
	}
	if (pi->argv.count <= 1) {
		ni_process_free(pi);
		return -1;
	}

	pi->exec = do_reverse_resolve_ip_address;
	rv = ni_process_run(pi);
	if (rv == NI_PROCESS_SUCCESS) {
		job->process = pi;
		pi->user_data = ni_updater_job_ref(job);
		pi->notify_callback = ni_system_updater_notify;
		ni_debug_extension("%s: started lease %s:%s state %s %s updater (%s) with pid %d",
				job->device.name,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state),
				ni_updater_name(job->kind),
				ni_basename(pi->process->command), pi->pid);
	} else {
		ni_process_free(pi);
	}
	return rv;
}
static int
ni_system_updater_hostname_lookup_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	return ni_system_updater_process_wait(updater, job, __func__);
}

static int
ni_system_updater_hostname_install_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	ni_string_array_t args = NI_STRING_ARRAY_INIT;
	int ret = -1;

	if (ni_string_empty(job->hostname))
		return -1;

	if (!ni_system_updater_common_args(&args, job->device.name,
				job->lease->type, job->lease->family))
		goto cleanup;

	ni_string_array_append(&args, job->hostname);

	job->result = 0;
	if (ni_system_updater_run(job, updater->proc_install, &args) != NI_PROCESS_SUCCESS) {
		ni_warn("%s: unable to execute %s updater (%s) for lease %s:%s in state %s",
				job->device.name, ni_updater_name(updater->kind),
				updater->proc_install->command,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		goto cleanup;
	}

	ret = 0; /* started, advance to wait for finish */

cleanup:
	ni_string_array_destroy(&args);
	return ret;
}
static int
ni_system_updater_hostname_install_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	int ret;

	if ((ret = ni_system_updater_process_wait(updater, job, __func__)))
		return ret;

	if (ni_global.other_event)
		ni_global.other_event(NI_EVENT_HOSTNAME_UPDATED);

	return ret;
}

static int
ni_system_updater_hostname_remove_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	ni_string_array_t args = NI_STRING_ARRAY_INIT;
	ni_updater_source_t *src;
	int ret = -1;

	/* Call remove action only, when we applied it */
	src = ni_updater_sources_remove_match(&updater->sources, &job->device, job->lease);
	if (!src)
		return 0;
	ni_updater_source_free(src);

	if (!ni_system_updater_common_args(&args, job->device.name,
				job->lease->type, job->lease->family))
		goto cleanup;

	job->result = 0;
	if (ni_system_updater_run(job, updater->proc_remove, &args) != NI_PROCESS_SUCCESS) {
		ni_warn("%s: unable to execute %s updater (%s) for lease %s:%s in state %s",
				job->device.name, ni_updater_name(updater->kind),
				updater->proc_remove->command,
				ni_addrfamily_type_to_name(job->lease->family),
				ni_addrconf_type_to_name(job->lease->type),
				ni_addrconf_state_to_name(job->lease->state));
		goto cleanup;
	}

	ret = 0; /* started, advance to wait for finish */

cleanup:
	ni_string_array_destroy(&args);
	return ret;
}
static int
ni_system_updater_hostname_remove_wait(ni_updater_t *updater, ni_updater_job_t *job)
{
	int ret;

	if ((ret = ni_system_updater_process_wait(updater, job, __func__)))
		return ret;

	if (ni_global.other_event)
		ni_global.other_event(NI_EVENT_HOSTNAME_UPDATED);

	return ret;
}

static const ni_updater_action_t	system_updater_generic_install[] = {
	{ ni_system_updater_generic_cleanup_call	},
	{ ni_system_updater_generic_cleanup_wait	},
	{ ni_system_updater_backup_call			},
	{ ni_system_updater_backup_wait			},
	{ ni_system_updater_generic_install_call	},
	{ ni_system_updater_generic_install_wait	},
	{ NULL }
};
static const ni_updater_action_t	system_updater_generic_removal[] = {
	{ ni_system_updater_generic_remove_call		},
	{ ni_system_updater_generic_remove_wait		},
	{ ni_system_updater_restore_call		},
	{ ni_system_updater_restore_wait		},
	{ NULL }
};

static const ni_updater_action_t	system_updater_resolver_install[] = {
	{ ni_system_updater_resolver_cleanup_call	},
	{ ni_system_updater_resolver_cleanup_wait	},
	{ ni_system_updater_backup_call			},
	{ ni_system_updater_backup_wait			},
	{ ni_system_updater_resolver_install_call	},
	{ ni_system_updater_resolver_install_wait	},
	{ NULL }
};
static const ni_updater_action_t	system_updater_resolver_removal[] = {
	{ ni_system_updater_resolver_remove_call	},
	{ ni_system_updater_resolver_remove_wait	},
	{ ni_system_updater_restore_call		},
	{ ni_system_updater_restore_wait		},
	{ NULL }
};

static const ni_updater_action_t	system_updater_hostname_install[] = {
	{ ni_system_updater_hostname_cleanup_call	},
	{ ni_system_updater_hostname_cleanup_wait	},
	{ ni_system_updater_backup_call			},
	{ ni_system_updater_backup_wait			},
	{ ni_system_updater_hostname_lookup_call	},
	{ ni_system_updater_hostname_lookup_wait	},
	{ ni_system_updater_hostname_install_call	},
	{ ni_system_updater_hostname_install_wait	},
	{ NULL }
};
static const ni_updater_action_t	system_updater_hostname_removal[] = {
	{ ni_system_updater_hostname_remove_call	},
	{ ni_system_updater_hostname_remove_wait	},
	{ ni_system_updater_restore_call		},
	{ ni_system_updater_restore_wait		},
	{ NULL }
};

static const ni_updater_action_t *
system_updater_action_table(unsigned int kind, ni_updater_job_flow_t flow)
{
	switch (kind) {
	case NI_ADDRCONF_UPDATER_GENERIC:
		switch (flow) {
		case NI_UPDATER_FLOW_INSTALL:
			return system_updater_generic_install;
		case NI_UPDATER_FLOW_REMOVAL:
			return system_updater_generic_removal;
		default:
			break;
		}
		break;

	case NI_ADDRCONF_UPDATER_RESOLVER:
		switch (flow) {
		case NI_UPDATER_FLOW_INSTALL:
			return system_updater_resolver_install;
		case NI_UPDATER_FLOW_REMOVAL:
			return system_updater_resolver_removal;
		default:
			break;
		}
		break;

	case NI_ADDRCONF_UPDATER_HOSTNAME:
		switch (flow) {
		case NI_UPDATER_FLOW_INSTALL:
			return system_updater_hostname_install;
		case NI_UPDATER_FLOW_REMOVAL:
			return system_updater_hostname_removal;
		default:
			break;
		}
		break;

	default:
		break;
	}
	return NULL;
}


static void
do_addrconf_updater_job_cleanup(void *user_data)
{
	ni_updater_job_t *job = user_data;
	ni_updater_job_cancel(job);
	ni_updater_job_free(job);
}

static ni_updater_job_t *
ni_addrconf_updater_get_job(ni_addrconf_updater_t *updater)
{
	return ni_addrconf_updater_get_data(updater, do_addrconf_updater_job_cleanup);
}

static ni_bool_t
ni_addrconf_updater_set_job(ni_addrconf_updater_t *updater, ni_updater_job_t *job)
{
	if (updater && job) {
		if (job != ni_addrconf_updater_get_job(updater)) {
			ni_updater_job_t *ref = ni_updater_job_ref(job);

			ni_addrconf_updater_set_data(updater, ref,
					do_addrconf_updater_job_cleanup);
		}
		return TRUE;
	}
	return FALSE;
}

static void
ni_updater_job_set_timeout(ni_updater_job_t *job, unsigned int timeout)
{
	ni_addrconf_updater_t *updater;
	if (job && (updater = job->lease->updater))
		updater->timeout = timeout;
}

static int
ni_updater_job_action_call(ni_updater_t *updater, ni_updater_job_t *job)
{
	int res = 0;

	if (!updater && !job)
		return -1;

	while (job->actions && job->actions->func) {
		res = job->actions->func(updater, job);
		if (res)
			break;
		job->actions++;
	}
	return res;
}

static int
ni_updater_job_execute(ni_updater_job_t *job)
{
	ni_updater_t *updater = NULL;
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;

	if (!job)
		return -1;

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EXTENSION,
			"executing %s", ni_updater_job_info(&out, job));
	ni_stringbuf_destroy(&out);

	switch (job->state) {
	case NI_UPDATER_JOB_FINISHED:
		goto skip;
	case NI_UPDATER_JOB_PENDING:
		job->state = NI_UPDATER_JOB_RUNNING;
	case NI_UPDATER_JOB_RUNNING:
	default:
		break;
	}

	while (ni_uint_array_get(&job->updater, 0, &job->kind)) {
		updater = &updaters[job->kind];

		if (updater && updater->enabled && can_update_type(job->lease, job->kind)) {
			if (!job->actions)
				job->actions = system_updater_action_table(job->kind, job->flow);

			ni_updater_job_set_timeout(job, 5 * 1000);
			if (ni_updater_job_action_call(updater, job) > 0)
				return 1;
			job->actions = NULL;
		}

		ni_uint_array_remove(&job->updater, job->kind);
	}

skip:
	job->state = NI_UPDATER_JOB_FINISHED;
	job->kind  = __NI_ADDRCONF_UPDATER_MAX;
	ni_uint_array_destroy(&job->updater);

	ni_trace("finished %s", ni_updater_job_info(&out, job));
	ni_stringbuf_destroy(&out);

	/* call updater to trigger it to fetch the status of it's job    */
	ni_updater_job_call_updater(job);

	/* remove job from the processing list and release the reference */
	ni_updater_job_list_unlink(job);
	ni_updater_job_free(job);
	return 0;
}

int
ni_system_update_from_lease(const ni_addrconf_lease_t *lease, const unsigned int ifindex, const char *ifname)
{
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;
	ni_updater_job_t *job, *found;

	if (!lease || !ifindex || ni_string_empty(ifname))
		return -1;

	ni_system_updaters_init();

	job = ni_addrconf_updater_get_job(lease->updater);
	if (!job) {
		job = ni_updater_job_new(&job_list, lease, ifindex, ifname);
		if (!ni_addrconf_updater_set_job(lease->updater, job)) {
			ni_updater_job_free(job);
			return -1;
		}
	}

	do {
		if ((found = ni_updater_job_list_find_running(&job_list))) {
			if (ni_updater_job_execute(found) == 1) {
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EXTENSION,
						"deferred by %s",
						ni_updater_job_info(&out, found));
				ni_stringbuf_destroy(&out);
				return 1;
			}
		}
		if ((found = ni_updater_job_list_find_pending(&job_list))) {
			if (ni_updater_job_execute(found) == 1) {
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EXTENSION,
						"deferred by %s",
						ni_updater_job_info(&out, found));
				ni_stringbuf_destroy(&out);
				return 1;
			}
		}
	} while (found && job != found);

	if (ni_updater_job_finished(job)) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EXTENSION, "%s",
				ni_updater_job_info(&out, job));
		ni_stringbuf_destroy(&out);
		return 0;
	}

	return ni_updater_job_execute(job);
}
