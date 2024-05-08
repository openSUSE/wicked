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
			ni_format_boolean(ctrl->usercontrol)))
		return FALSE;

	if (ni_tristate_is_set(ctrl->require_link)) {
		if (!xml_node_new_element(NI_CLIENT_STATE_XML_REQUIRE_LINK_NODE, parent,
			ni_format_boolean(ni_tristate_is_enabled(ctrl->require_link))))
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

	ptr = ni_uuid_print(&conf->uuid);
	if (!xml_node_new_element(NI_CLIENT_STATE_XML_CONFIG_UUID_NODE, parent, ptr))
		return FALSE;

	ptr = conf->origin;
	if (!xml_node_new_element(NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE, parent, ptr))
		return FALSE;

	ni_string_printf(&tmp, "%u", conf->owner);
	if (!xml_node_new_element(NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE, parent, tmp)) {
		ni_string_free(&tmp);
		return FALSE;
	}
	ni_string_free(&tmp);

	return TRUE;
}

static ni_bool_t
ni_client_state_scripts_print_xml(const ni_client_state_scripts_t *scripts, xml_node_t *node)
{
	if (!scripts)
		return FALSE;

	if (!scripts->node)
		return TRUE;

	return xml_node_clone(scripts->node, node) != NULL;
}

ni_bool_t
ni_client_state_print_xml(const ni_client_state_t *client_state, xml_node_t *node)
{
	if (!client_state || !node)
		return FALSE;

	if (!ni_client_state_control_print_xml(&client_state->control, node) ||
	    !ni_client_state_config_print_xml(&client_state->config, node)   ||
	    !ni_client_state_scripts_print_xml(&client_state->scripts, node)) {
		return FALSE;
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

	/* <persistent> node */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_PERSISTENT_NODE);
	if (child && ni_parse_boolean(child->cdata, &ctrl->persistent) != 0)
		return FALSE;

	/* <usercontrol> node */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_USERCONTROL_NODE);
	if (child && ni_parse_boolean(child->cdata, &ctrl->usercontrol) != 0)
		return FALSE;

	/* <require-link> node */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_REQUIRE_LINK_NODE);
	if (child) {
		ni_bool_t require_link;
		if (ni_parse_boolean(child->cdata, &require_link) != 0)
			return FALSE;
		ni_tristate_set(&ctrl->require_link, require_link);
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

	/* within <config> node <uuid> is mandatory, yet may be empty */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_CONFIG_UUID_NODE);
	if (!child || (child->cdata && ni_uuid_parse(&conf->uuid, child->cdata)))
		return FALSE;

	/* within <config> node <origin> is mandatory, yet may be empty */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE);
	if (!child)
		return FALSE;
	ni_string_dup(&conf->origin, child->cdata);

	/* within <config> node <owner-uid> is optional */
	child = xml_node_get_child(parent, NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE);
	if (child && !ni_string_empty(child->cdata)) {
		if (ni_parse_uint(child->cdata, &conf->owner, 10))
			return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_client_state_scripts_parse_xml(const xml_node_t *node, ni_client_state_scripts_t *scripts)
{
	const xml_node_t *child;

	if (!node || !scripts)
		return FALSE;

	/* kick away old set if any */
	ni_client_state_scripts_reset(scripts);

	/* <scripts> node is optional */
	if (!(child = xml_node_get_child(node, NI_CLIENT_STATE_XML_SCRIPTS_NODE)))
		return TRUE;

	/* deep clone the scripts */
	scripts->node = xml_node_clone(child, NULL);
	return scripts->node != NULL;
}

ni_bool_t
ni_client_state_parse_xml(const xml_node_t *node, ni_client_state_t *client_state)
{
	if (!node || !client_state)
		return FALSE;

	if (!ni_client_state_control_parse_xml(node, &client_state->control) ||
	    !ni_client_state_config_parse_xml(node, &client_state->config)   ||
	    !ni_client_state_scripts_parse_xml(node, &client_state->scripts)) {
		return FALSE;
	}

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
	return ctrl != NULL;
}

ni_bool_t
ni_client_state_config_is_valid(const ni_client_state_config_t *conf)
{
	return conf && !ni_string_empty(conf->origin) &&
		!ni_uuid_is_null(&conf->uuid);
}

ni_bool_t
ni_client_state_is_valid(const ni_client_state_t *client_state)
{
	return client_state &&
		ni_client_state_control_is_valid(&client_state->control) &&
		ni_client_state_config_is_valid(&client_state->config);
}

/*
 * Exported functions
 */
ni_client_state_t *
ni_client_state_new(void)
{
	ni_client_state_t *client_state;

	client_state = xcalloc(1, sizeof(*client_state));
	ni_client_state_control_init(&client_state->control);
	ni_client_state_config_init(&client_state->config);
	ni_client_state_scripts_init(&client_state->scripts);

	return client_state;
}

void
ni_client_state_init(ni_client_state_t *client_state)
{
	if (client_state) {
		ni_client_state_control_init(&client_state->control);
		ni_client_state_config_init(&client_state->config);
		ni_client_state_scripts_init(&client_state->scripts);
	}
}

void
ni_client_state_reset(ni_client_state_t *client_state)
{
	if (client_state) {
		ni_client_state_control_reset(&client_state->control);
		ni_client_state_config_reset(&client_state->config);
		ni_client_state_scripts_reset(&client_state->scripts);
	}
}

ni_client_state_t *
ni_client_state_clone(ni_client_state_t *client_state)
{
	ni_client_state_t *copy = NULL;

	if (client_state) {
		copy = xcalloc(1, sizeof(*copy));
		ni_client_state_control_copy(&copy->control, &client_state->control);
		ni_client_state_config_copy(&copy->config, &client_state->config);
		ni_client_state_scripts_copy(&copy->scripts, &client_state->scripts);
	}
	return copy;
}

void
ni_client_state_free(ni_client_state_t *cs)
{
	if (cs) {
		ni_string_free(&cs->config.origin);
		xml_node_free(cs->scripts.node);
		free(cs);
	}
}

void
ni_client_state_config_init(ni_client_state_config_t *conf)
{
	if (conf) {
		memset(conf, 0, sizeof(*conf));
		conf->owner = -1U;
	}
}

void
ni_client_state_config_reset(ni_client_state_config_t *conf)
{
	if (conf) {
		ni_string_free(&conf->origin);
		ni_client_state_config_init(conf);
	}
}

void
ni_client_state_config_copy(ni_client_state_config_t *conf,
			const ni_client_state_config_t *src)
{
	if (conf) {
		if (src) {
			conf->uuid = src->uuid;
			conf->owner = src->owner;
			ni_string_dup(&conf->origin, src->origin);
		} else {
			ni_client_state_config_reset(conf);
		}
	}
}

void
ni_client_state_control_init(ni_client_state_control_t *ctrl)
{
	if (ctrl) {
		memset(ctrl, 0, sizeof(*ctrl));
		ctrl->require_link = NI_TRISTATE_DEFAULT;
	}
}

void
ni_client_state_control_reset(ni_client_state_control_t *ctrl)
{
	ni_client_state_control_init(ctrl);
}

void
ni_client_state_control_copy(ni_client_state_control_t *dst,
			const ni_client_state_control_t *src)
{
	if (src && dst)
		*dst = *src;
}

void
ni_client_state_scripts_init(ni_client_state_scripts_t *scripts)
{
	if (scripts)
		scripts->node = NULL;
}

void
ni_client_state_scripts_reset(ni_client_state_scripts_t *scripts)
{
	if (scripts && scripts->node) {
		xml_node_free(scripts->node);
		scripts->node = NULL;
	}
}

void
ni_client_state_scripts_copy(ni_client_state_scripts_t *dst,
			const ni_client_state_scripts_t *src)
{
	ni_client_state_scripts_reset(dst);
	if (dst && src && src->node)
		dst->node = xml_node_clone(src->node, NULL);
}

ni_bool_t
ni_client_state_save(const ni_client_state_t *client_state, unsigned int ifindex)
{
	char path[PATH_MAX - sizeof(".XXXXXX")] = {'\0'};
	char temp[PATH_MAX] = {'\0'};
	xml_node_t *node;
	FILE *fp = NULL;
	int fd;

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
	xml_node_free(node);

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

	ni_client_state_reset(client_state);
	if (!ni_client_state_parse_xml(node, client_state)) {
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

ni_bool_t
ni_client_state_set_persistent(xml_node_t *config)
{
	xml_node_t *cnode, *pernode;
	ni_bool_t persistent;

	if (xml_node_is_empty(config))
		return FALSE;

	cnode = xml_node_get_child(config, NI_CLIENT_STATE_XML_CONTROL_NODE);
	if (!cnode) {
		if (!(cnode = xml_node_new(NI_CLIENT_STATE_XML_CONTROL_NODE, config)))
			return FALSE;
	}

	pernode = xml_node_get_child(cnode, NI_CLIENT_STATE_XML_PERSISTENT_NODE);
	if (!pernode) {
		pernode = xml_node_new_element(NI_CLIENT_STATE_XML_PERSISTENT_NODE, cnode,
			ni_format_boolean(TRUE));

		return pernode ? TRUE : FALSE;
	}

	if (ni_parse_boolean(pernode->cdata, &persistent))
		return FALSE;

	if (!persistent)
		ni_string_dup(&pernode->cdata, ni_format_boolean(TRUE));

	return TRUE;
}

void
ni_client_state_control_debug(const char *name, const ni_client_state_control_t *ctrl, const char *action)
{
	if (!ctrl)
		return;

	ni_debug_application("%s: %s <%s> %s: %s=%s, %s=%s, %s=%s",
		name ? name : "unknown", action ? action : "unknown",
		NI_CLIENT_STATE_XML_NODE, NI_CLIENT_STATE_XML_CONTROL_NODE,
		NI_CLIENT_STATE_XML_PERSISTENT_NODE,
		ni_format_boolean(ctrl->persistent),
		NI_CLIENT_STATE_XML_USERCONTROL_NODE,
		ni_format_boolean(ctrl->usercontrol),
		NI_CLIENT_STATE_XML_REQUIRE_LINK_NODE,
		!ni_tristate_is_set(ctrl->require_link) ? "auto" :
		ni_format_boolean(ni_tristate_is_enabled(ctrl->require_link))
	);
}

void
ni_client_state_config_debug(const char *name, const ni_client_state_config_t *conf, const char *action)
{
	if (!conf)
		return;

	ni_debug_application("%s: %s <%s> %s: %s=%s, %s=%s, %s=%u",
		name ? name : "unknown", action ? action : "unknown",
		NI_CLIENT_STATE_XML_NODE, NI_CLIENT_STATE_XML_CONFIG_NODE,
		NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE, conf->origin,
		NI_CLIENT_STATE_XML_CONFIG_UUID_NODE, ni_uuid_print(&conf->uuid),
		NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE, conf->owner
	);
}

void
ni_client_state_debug(const char *name, const ni_client_state_t *cs, const char *action)
{
	if (!cs)
		return;

	ni_client_state_control_debug(name, &cs->control, action);
	ni_client_state_config_debug(name, &cs->config, action);
}
