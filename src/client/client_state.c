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

ni_bool_t
ni_client_state_print_xml(const ni_client_state_t *client_state, xml_node_t *node)
{
	const char *ptr;
	char *tmp = NULL;

	if (!client_state || !node)
		return FALSE;

	if (!xml_node_new_element(NI_CLIENT_STATE_XML_PERSISTENT_NODE, node,
		ni_format_boolean(client_state->persistent)))
		return FALSE;

	if (!(ptr = ni_ifworker_state_name(client_state->init_state)) ||
	    !xml_node_new_element(NI_CLIENT_STATE_XML_INIT_STATE_NODE, node, ptr))
		return FALSE;

	if (!ni_client_state_print_timeval(&client_state->init_time, &tmp))
		return FALSE;
	if (!xml_node_new_element(NI_CLIENT_STATE_XML_INIT_TIME_NODE, node, tmp)) {
		ni_string_free(&tmp);
		return FALSE;
	}
	ni_string_free(&tmp);

	if (!ni_client_state_print_timeval(&client_state->last_time, &tmp))
		return FALSE;
	if (!xml_node_new_element(NI_CLIENT_STATE_XML_LAST_TIME_NODE, node, tmp)) {
		ni_string_free(&tmp);
		return FALSE;
	}
	ni_string_free(&tmp);

	return TRUE;
}

ni_bool_t
ni_client_state_parse_xml(const xml_node_t *node, ni_client_state_t *client_state)
{
	const xml_node_t *child;

	if (!node || !client_state)
		return FALSE;

	/* <persistent> node is mandatory */
	child = xml_node_get_child(node, NI_CLIENT_STATE_XML_PERSISTENT_NODE);
	if (!child || !child->cdata ||
	    ni_parse_boolean(child->cdata, &client_state->persistent)) {
		return FALSE;
	}

	/* following nodes may be missing - to be checked within a caller when needed */
	if ((child = xml_node_get_child(node, NI_CLIENT_STATE_XML_INIT_STATE_NODE))) {
		if (!child->cdata ||
		    !ni_ifworker_state_from_name(child->cdata, &client_state->init_state)) {
			return FALSE;
		}
	}

	if ((child = xml_node_get_child(node, NI_CLIENT_STATE_XML_INIT_TIME_NODE))) {
		if (!child->cdata ||
		    !ni_client_state_parse_timeval(child->cdata, &client_state->init_time)) {
			return FALSE;
		}
	}

	if ((child = xml_node_get_child(node, NI_CLIENT_STATE_XML_LAST_TIME_NODE))) {
		if (!child->cdata ||
		    !ni_client_state_parse_timeval(child->cdata, &client_state->last_time)) {
			return FALSE;
		}
	}

	return TRUE;
}

static inline void
__ni_client_state_update_state(ni_client_state_t *client_state, unsigned int state)
{
	ni_timer_get_time(&client_state->last_time);
	if (!ni_client_state_is_valid_state(client_state->init_state)) {
		client_state->init_state = state;
		client_state->init_time = client_state->last_time;
	}
}

/*
 * Exported functions
 */
ni_client_state_t *
ni_client_state_new(unsigned int state)
{
	ni_client_state_t *client_state;

	client_state = xcalloc(1, sizeof(*client_state));
	if (ni_client_state_is_valid_state(state)) {
		__ni_client_state_update_state(client_state, state);
	}
	return client_state;
}

void
ni_client_state_init(ni_client_state_t *client_state)
{
	if (client_state) {
		memset(client_state, 0, sizeof(*client_state));
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
ni_client_state_free(ni_client_state_t *client_state)
{
	free(client_state);
}

ni_bool_t
ni_client_state_set_state(ni_client_state_t *client_state, unsigned int state)
{
	if (client_state) {
		if (ni_client_state_is_valid_state(state)) {
			__ni_client_state_update_state(client_state, state);
			return TRUE;
		}
	}
	return FALSE;
}

ni_bool_t
ni_client_state_is_valid_state(unsigned int state)
{
	return	state > NI_FSM_STATE_NONE &&
		state < __NI_FSM_STATE_MAX;
}

const char *
ni_client_state_print(ni_client_state_t *client_state, char **str)
{
	return ni_string_printf(str, "client_state structure: "
		"persistent: %s, "
		"init_state: %s, "
		"init_time: %lu.%02lu, "
		"last_time: %lu.%02lu",
		ni_format_boolean(client_state->persistent),
		ni_ifworker_state_name(client_state->init_state),
		client_state->init_time.tv_sec, client_state->init_time.tv_usec,
		client_state->last_time.tv_sec, client_state->last_time.tv_usec);
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

	if (!(node = xml_node_new(NI_CLIENT_STATE_XML_STATE_NODE, NULL))) {
		ni_error("Cannot create %s xml state node", path);
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
	if (!node || !ni_string_eq(node->name, NI_CLIENT_STATE_XML_STATE_NODE)) {
		ni_error("State file '%s' does not contain %s xml node",
			path, NI_CLIENT_STATE_XML_STATE_NODE);
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
