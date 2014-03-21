/*
 * Routines for runtime-persistent interface fsm ifup state used
 * while ifdown to stop managed interfaces.
 *
 * Copyright (C) 2011 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Authors: Marius Tomaschewski <mt@suse.de>
 *          Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/time.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

#include <wicked/fsm.h>
#include <wicked/xml.h>
#include <wicked/util.h>
#include <wicked/socket.h>	/* for ni_timer_get_time()  */
#include <wicked/netinfo.h>	/* for ni_config_statedir() */
#include <wicked/logging.h>

#include "client/client_state.h"
#include "util_priv.h"

/*
 * Internal utilities
 */
static void
ni_client_state_filename(unsigned int ifindex, char *path, size_t size)
{
	snprintf(path, size, "%s/state-%u.xml",
			ni_config_statedir(),
			ifindex);
}

ni_bool_t
ni_client_state_parse_timeval(const char *str, struct timeval *tv)
{
	char *usec, *sec = NULL;
	unsigned long s, u;

	if (!str || !tv)
		return FALSE;

	ni_string_dup(&sec, str);
	if (!sec || !(usec = strchr(sec, '.'))) {
		ni_string_free(&sec);
		return FALSE;
	}
	*usec++ = '\0';

	if (ni_parse_ulong(sec, &s, 10) < 0) {
		ni_string_free(&sec);
		return FALSE;
	}

	if (ni_parse_ulong(usec, &u, 10) < 0) {
		ni_string_free(&sec);
		return FALSE;
	}

	tv->tv_sec = s;
	tv->tv_usec = u;

	ni_string_free(&sec);
	return TRUE;
}

static ni_bool_t
ni_client_state_state_print_xml(const unsigned int state, xml_node_t *node)
{
	const char *ptr;

	if (!node)
		return FALSE;

	if (!(ptr = ni_ifworker_state_name(state)) ||
	    !xml_node_new_element(NI_CLIENT_STATE_XML_STATE_NODE, node, ptr))
		return FALSE;

	return TRUE;
}

static ni_bool_t
ni_client_state_control_print_xml(const ni_client_state_control_t *ctrl, xml_node_t *node)
{
	xml_node_t *parent;

	if (!ctrl || !node)
		return FALSE;

	if (!(parent = xml_node_new(NI_CLIENT_STATE_XML_CONTROL_NODE, node)))
		return FALSE;

	if (!xml_node_new_element(NI_CLIENT_STATE_XML_PERSISTENT_NODE, parent,
			ni_format_boolean(ctrl->persistent)) ||
	    !xml_node_new_element(NI_CLIENT_STATE_XML_USERCONTROL_NODE, parent,
			ni_format_boolean(ctrl->usercontrol))) {
			return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_client_state_config_print_xml(const ni_client_state_config_t *conf, xml_node_t *node)
{
	xml_node_t *parent;
	const char *ptr;
	char *tmp = NULL;

	if (!conf || !node)
		return FALSE;

	if (!(parent = xml_node_new(NI_CLIENT_STATE_XML_CONFIG_NODE, node)))
		return FALSE;

	if (!(ptr = ni_uuid_print(&conf->uuid)) ||
	    !xml_node_new_element(NI_CLIENT_STATE_XML_CONFIG_UUID_NODE, parent, ptr)) {
		return FALSE;
	}

	if (!(ptr = conf->origin) ||
	    !xml_node_new_element(NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE, parent, ptr)) {
		return FALSE;
	}

	ni_string_printf(&tmp, "%u", conf->owner);
	if (!xml_node_new_element(NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE, parent, tmp)) {
		ni_string_free(&tmp);
		return FALSE;
	}
	ni_string_free(&tmp);

	return TRUE;
}

#ifdef CLIENT_STATE_STATS
static ni_bool_t
ni_client_state_stats_print_xml(const ni_client_state_stats_t *stats, xml_node_t *node)
{
	xml_node_t *parent;
	const char *ptr;
	char *tmp = NULL;

	if (!stats || !node)
		return FALSE;

	if (!(parent = xml_node_new(NI_CLIENT_STATE_XML_STATS_NODE, node)))
		return FALSE;

	if (!(ptr = ni_ifworker_state_name(stats->init_state)) ||
	    !xml_node_new_element(NI_CLIENT_STATE_XML_INIT_STATE_NODE, parent, ptr)) {
		return FALSE;
	}

	if (!ni_client_state_print_timeval(&stats->init_time, &tmp) ||
	    !xml_node_new_element(NI_CLIENT_STATE_XML_INIT_TIME_NODE, parent, tmp)) {
		ni_string_free(&tmp);
		return FALSE;
	}
	ni_string_free(&tmp);

	if (!ni_client_state_print_timeval(&stats->last_time, &tmp) ||
	    !xml_node_new_element(NI_CLIENT_STATE_XML_LAST_TIME_NODE, parent, tmp)) {
		ni_string_free(&tmp);
		return FALSE;
	}
	ni_string_free(&tmp);

	return TRUE;
}
#endif

ni_bool_t
ni_client_state_print_xml(const ni_client_state_t *client_state, xml_node_t *node)
{
	if (!client_state || !node)
		return FALSE;

	if (!ni_client_state_state_print_xml(client_state->state, node) ||
	    !ni_client_state_control_print_xml(&client_state->control, node) ||
	    !ni_client_state_config_print_xml(&client_state->config, node)) {
		return FALSE;
	}
#ifdef CLIENT_STATE_STATS
	ni_client_state_stats_print_xml(&client_state->stats, node);
#endif

	return TRUE;
}

static ni_bool_t
ni_client_state_state_parse_xml(const xml_node_t *node, unsigned int *state)
{
	const xml_node_t *child;

	if (!node || !state)
		return FALSE;

	/* <state> node is optional */
	if ((child = xml_node_get_child(node, NI_CLIENT_STATE_XML_STATE_NODE))) {
		if (!child->cdata || !ni_ifworker_state_from_name(child->cdata, state)) {
			return FALSE;
		}
	}

	return TRUE;
}

static ni_bool_t
ni_client_state_control_parse_xml(const xml_node_t *node, ni_client_state_control_t *ctrl)
{
	const xml_node_t *parent, *child;

	if (!node || !ctrl)
		return FALSE;

	/* <control> node is mandatory */
	if (!(parent = xml_node_get_child(node, NI_CLIENT_STATE_XML_CONTROL_NODE)))
		return FALSE;

	/* <persistent> node is mandatory */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_PERSISTENT_NODE);
	if (!child || !child->cdata ||
	    ni_parse_boolean(child->cdata, &ctrl->persistent)) {
		return FALSE;
	}

	/* <usercontrol> node is mandatory */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_USERCONTROL_NODE);
	if (!child || !child->cdata ||
	    ni_parse_boolean(child->cdata, &ctrl->usercontrol)) {
		return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_client_state_config_parse_xml(const xml_node_t *node, ni_client_state_config_t *conf)
{
	const xml_node_t *parent, *child;

	if (!node || !conf)
		return FALSE;

	/* <config> node is mandatory */
	if (!(parent = xml_node_get_child(node, NI_CLIENT_STATE_XML_CONFIG_NODE)))
		return FALSE;

	/* within <config> node <uuid> is mandatory */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_CONFIG_UUID_NODE);
	if (!child || !child->cdata || ni_uuid_parse(&conf->uuid, child->cdata))
		return FALSE;

	/* within <config> node <origin> is mandatory */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE);
	if (!child || !child->cdata)
		return FALSE;
	ni_string_dup(&conf->origin, child->cdata);

	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE);
	if (!child || !child->cdata || ni_parse_uint(child->cdata, &conf->owner, 10))
		return FALSE;

	return TRUE;
}

#ifdef CLIENT_STATE_STATS
static ni_bool_t
ni_client_state_stats_parse_xml(const xml_node_t *node, ni_client_state_stats_t *stats)
{
	const xml_node_t *parent, *child;

	if (!node || !stats)
		return FALSE;

	/* <stats> is not mandatory */
	if (!(parent = xml_node_get_child(node, NI_CLIENT_STATE_XML_STATS_NODE)))
		return TRUE;

	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_INIT_STATE_NODE);
	if (!child || !child->cdata ||
	    !ni_ifworker_state_from_name(child->cdata, &stats->init_state)) {
		return FALSE;
	}

	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_INIT_TIME_NODE);
	if (!child || !child->cdata ||
	    !ni_client_state_parse_timeval(child->cdata, &stats->init_time)) {
		return FALSE;
	}

	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_LAST_TIME_NODE);
	if (!child || !child->cdata ||
		!ni_client_state_parse_timeval(child->cdata, &stats->last_time)) {
		return FALSE;
	}

	return TRUE;
}
#endif

ni_bool_t
ni_client_state_parse_xml(const xml_node_t *node, ni_client_state_t *client_state)
{
	if (!node || !client_state)
		return FALSE;

	if (!ni_client_state_state_parse_xml(node, &client_state->state) ||
	    !ni_client_state_control_parse_xml(node, &client_state->control) ||
	    !ni_client_state_config_parse_xml(node, &client_state->config)) {
		return FALSE;
	}
#ifdef CLIENT_STATE_STATS
	ni_client_state_stats_parse_xml(node, &client_state->stats);
#endif

	return TRUE;
}

static inline ni_bool_t
__ni_client_state_is_valid_time(const struct timeval *tv)
{
	if (!tv || tv->tv_sec < 0 || tv->tv_usec < 0)
		return FALSE;

	return (tv->tv_sec || tv->tv_usec);
}

ni_bool_t
ni_client_state_control_is_valid(const ni_client_state_control_t *ctrl)
{
	/* FIXME: Add some sanity checks */
	return ctrl && TRUE;
}

ni_bool_t
ni_client_state_config_is_valid(const ni_client_state_config_t *conf)
{
	return conf && !ni_string_empty(conf->origin) &&
		!ni_uuid_is_null(&conf->uuid);
}

#ifdef CLIENT_STATE_STATS
ni_bool_t
ni_client_state_stats_is_valid(const ni_client_state_stats_t *stats)
{
	return stats && ni_ifworker_is_valid_state(stats->init_state) &&
		   __ni_client_state_is_valid_time(&stats->init_time) &&
		   __ni_client_state_is_valid_time(&stats->last_time);
}
#endif

ni_bool_t
ni_client_state_is_valid(const ni_client_state_t *client_state)
{
	return client_state && ni_ifworker_is_valid_state(client_state->state) &&
		   ni_client_state_control_is_valid(&client_state->control) &&
		   ni_client_state_config_is_valid(&client_state->config) &&
#ifdef CLIENT_STATE_STATS
		   ni_client_state_stats_is_valid(&client_state->stats);
#else
		   TRUE;
#endif
}

#ifdef CLIENT_STATE_STATS
void
ni_client_state_update_stats(ni_client_state_stats_t *stats, unsigned int new_state)
{
	ni_timer_get_time(&stats->last_time);
	if (!ni_ifworker_is_valid_state(stats->init_state)) {
		stats->init_state = new_state;
		stats->init_time = stats->last_time;
	}
}
#endif

/*
 * Exported functions
 */
ni_client_state_t *
ni_client_state_new(unsigned int state)
{
	ni_client_state_t *client_state;

	client_state = xcalloc(1, sizeof(*client_state));
	ni_client_state_set_state(client_state, state);
	ni_client_state_config_init(&client_state->config);

	return client_state;
}

void
ni_client_state_init(ni_client_state_t *client_state)
{
	if (client_state) {
		memset(client_state, 0, sizeof(*client_state));
		ni_client_state_config_init(&client_state->config);
	}
}

ni_client_state_t *
ni_client_state_clone(ni_client_state_t *client_state)
{
	ni_client_state_t *copy = NULL;

	if (client_state) {
		copy = xcalloc(1, sizeof(*copy));
		*copy = *client_state;
	}

	return copy;
}

void
ni_client_state_destroy(ni_client_state_t *cs)
{
	if (cs)
		ni_string_free(&cs->config.origin);
}

void
ni_client_state_free(ni_client_state_t *cs)
{
	ni_client_state_destroy(cs);
	free(cs);
}

static inline void
__ni_set_config_owner(ni_client_state_config_t *conf)
{
	conf->owner = geteuid();
}

void
ni_client_state_config_init(ni_client_state_config_t *conf)
{
	if (conf) {
		ni_string_free(&conf->origin);
		memset(conf, 0, sizeof(*conf));
		__ni_set_config_owner(conf);
	}
}

void
ni_client_state_set_state(ni_client_state_t *client_state, unsigned int state)
{
	if (!client_state || !ni_ifworker_is_valid_state(state))
		return;

	client_state->state = state;

#ifdef CLIENT_STATE_STATS
	ni_client_state_update_stats(&client_state->stats, state);
#endif
}

ni_bool_t
ni_client_state_save(const ni_client_state_t *client_state, unsigned int ifindex)
{
	char path[PATH_MAX] = {'\0'};
	char temp[PATH_MAX] = {'\0'};
	xml_node_t *node;
	FILE *fp = NULL;
	int fd;

	if (!ni_client_state_is_valid(client_state))
		return FALSE;

	ni_client_state_filename(ifindex, path, sizeof(path));
	snprintf(temp, sizeof(temp), "%s.XXXXXX", path);

	if ((fd = mkstemp(temp)) < 0) {
		ni_error("Cannot create %s state temp file", path);
		return FALSE;
	}
	if (!(fp = fdopen(fd, "we"))) {
		close(fd);
		ni_error("Cannot create %s state temp file", path);
		goto failure;
	}

	if (!(node = xml_node_new(NI_CLIENT_STATE_XML_NODE, NULL))) {
		ni_error("Cannot create %s node for %s", NI_CLIENT_STATE_XML_NODE, path);
		goto failure;
	}

	if (!ni_client_state_print_xml(client_state, node)) {
		ni_error("Cannot format state into xml for %s", path);
		xml_node_free(node);
		goto failure;
	}

	if (xml_node_print(node, fp) < 0) {
		ni_error("Cannot write into %s state temp file", path);
		xml_node_free(node);
		goto failure;
	}

	if (rename(temp, path) < 0) {
		ni_error("Cannot move temp file to state file %s", path);
		goto failure;
	}

	fclose(fp);

	return TRUE;

failure:
	if (fp) {
		fclose(fp);
	}
	unlink(temp);
	return FALSE;
}

ni_bool_t
ni_client_state_load(ni_client_state_t *client_state, unsigned int ifindex)
{
	char path[PATH_MAX] = {'\0'};
	xml_node_t *xml;
	xml_node_t *node;
	FILE *fp;

	if (!client_state)
		return FALSE;

	ni_client_state_filename(ifindex, path, sizeof(path));
	if (!(fp = fopen(path, "re"))) {
		if (errno != ENOENT)
			ni_error("Cannot open state file '%s': %m", path);
		return FALSE;
	}

	if (!(xml = xml_node_scan(fp, path))) {
		fclose(fp);
		ni_error("Cannot parse xml from state file '%s", path);
		return FALSE;
	}
	fclose(fp);

	node = xml->name ? xml : xml->children;
	if (!node || !ni_string_eq(node->name, NI_CLIENT_STATE_XML_NODE)) {
		ni_error("State file '%s' does not contain %s node",
			path, NI_CLIENT_STATE_XML_NODE);
		xml_node_free(xml);
		return FALSE;
	}

	ni_client_state_init(client_state);
	if (!ni_client_state_parse_xml(node, client_state) ||
	    !ni_client_state_is_valid(client_state)) {
		ni_error("Cannot parse state from file '%s'", path);
		xml_node_free(xml);
		return FALSE;
	}

	xml_node_free(xml);
	return TRUE;
}


ni_bool_t
ni_client_state_move(unsigned int ifindex_old, unsigned int ifindex_new)
{
	char path_old[PATH_MAX] = {'\0'};
	char path_new[PATH_MAX] = {'\0'};

	if (ifindex_old == ifindex_new)
		return TRUE;

	ni_client_state_filename(ifindex_old, path_old, sizeof(path_old));
	ni_client_state_filename(ifindex_new, path_new, sizeof(path_new));

	if (rename(path_old, path_new) < 0) {
		if (errno == ENOENT && !ni_file_exists(path_old)) {
			ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
				"%s does not exists, not renamed to %s", path_old, path_new);
			return TRUE;
		}
		ni_error("Cannot rename state %s to %s", path_old, path_new);
		return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_client_state_drop(unsigned int ifindex)
{
	char path[PATH_MAX] = {'\0'};

	ni_client_state_filename(ifindex, path, sizeof(path));

	if (unlink(path) < 0) {
		if (errno == ENOENT)
			return TRUE;

		ni_error("Cannot remove state file '%s': %m", path);
		return FALSE;
	}
	return TRUE;
}

void
ni_client_state_state_debug(const char *name, unsigned int state, const char *action)
{
	ni_assert(action);
	ni_debug_application("%s: %s <%s> %s: %s", name ? name : "unknown",
		action, NI_CLIENT_STATE_XML_NODE, NI_CLIENT_STATE_XML_STATE_NODE,
		ni_ifworker_state_name(state)
	);
}

void
ni_client_state_control_debug(const char *name, const ni_client_state_control_t *ctrl, const char *action)
{
	ni_assert(ctrl && action);
	ni_debug_application("%s: %s <%s> %s: %s=%s, %s=%s", name ? name : "unknown",
		action, NI_CLIENT_STATE_XML_NODE, NI_CLIENT_STATE_XML_CONTROL_NODE,
		NI_CLIENT_STATE_XML_PERSISTENT_NODE, ni_format_boolean(ctrl->persistent),
		NI_CLIENT_STATE_XML_USERCONTROL_NODE, ni_format_boolean(ctrl->usercontrol)
	);
}

void
ni_client_state_config_debug(const char *name, const ni_client_state_config_t *conf, const char *action)
{
	ni_assert(conf && action);
	ni_debug_application("%s: %s <%s> %s: %s=%s, %s=%s, %s=%u", name ? name : "unknown",
		action, NI_CLIENT_STATE_XML_NODE, NI_CLIENT_STATE_XML_CONFIG_NODE,
		NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE, conf->origin,
		NI_CLIENT_STATE_XML_CONFIG_UUID_NODE, ni_uuid_print(&conf->uuid),
		NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE, conf->owner
	);
}

#ifdef CLIENT_STATE_STATS
void
ni_client_state_stats_debug(const char *name, const ni_client_state_stats_t *stats, const char *action)
{
	ni_assert(stats && action);
	ni_debug_application(
		"%s: %s <%s> %s: %s=%s, %s=%lu.%02lu, %s=%lu.%02lu", name ? name : "unknown",
		action, NI_CLIENT_STATE_XML_NODE, NI_CLIENT_STATE_XML_STATS_NODE,
		NI_CLIENT_STATE_XML_INIT_STATE_NODE,
		ni_ifworker_state_name(stats->init_state),
		NI_CLIENT_STATE_XML_INIT_TIME_NODE,
		stats->init_time.tv_sec, stats->init_time.tv_usec,
		NI_CLIENT_STATE_XML_LAST_TIME_NODE,
		stats->last_time.tv_sec, stats->last_time.tv_usec
	);
}
#endif

void
ni_client_state_debug(const char *name, const ni_client_state_t *cs, const char *action)
{
	ni_assert(cs && action);
	ni_client_state_state_debug(name, cs->state, action);
	ni_client_state_control_debug(name, &cs->control, action);
	ni_client_state_config_debug(name, &cs->config, action);
#ifdef CLIENT_STATE_STATS
	ni_client_state_stats_debug(name, &cs->stats, action);
#endif
}
