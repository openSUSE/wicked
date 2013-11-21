/*
 * Routines for runtime-persistent interface fsm ifup state used
 * while ifdown to stop managed interfaces.
 *
 * Copyright (C) 2011 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Authors: Marius Tomaschewski <mt@suse.de>
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
#include <wicked/ifstate.h>

#include "util_priv.h"

/*
 * Internal utilities
 */
static void
ni_ifstate_filename(const char *ifname, char *path, size_t size)
{
	snprintf(path, size, "%s/state-%s.xml",
			ni_config_statedir(),
			ifname);
}

static inline ni_bool_t
ni_ifstate_is_valid_state(unsigned int state)
{
	return	state > NI_FSM_STATE_NONE &&
		state < __NI_FSM_STATE_MAX;
}

static inline ni_bool_t
ni_ifstate_is_valid_time(const struct timeval *tv)
{
	if (tv->tv_sec < 0 || tv->tv_usec < 0)
		return FALSE;
	return (tv->tv_sec || tv->tv_usec);
}

inline ni_bool_t
ni_ifstate_is_valid(const ni_ifstate_t *ifstate)
{
	return ifstate &&
		   ni_ifstate_is_valid_state(ifstate->init_state) &&
		   ni_ifstate_is_valid_time(&ifstate->init_time) &&
		   ni_ifstate_is_valid_time(&ifstate->last_time);
}

inline const char *
ni_ifstate_print(ni_ifstate_t *ifstate, char **str)
{
	return ni_string_printf(str, "ifstate structure: "
		"persistent: %s, "
		"init_state: %s, "
		"init_time: %lu.%02lu, "
		"last_time: %lu.%02lu",
		ni_format_boolean(ifstate->persistent),
		ni_ifworker_state_name(ifstate->init_state),
		ifstate->init_time.tv_sec, ifstate->init_time.tv_usec,
		ifstate->last_time.tv_sec, ifstate->last_time.tv_usec);
}

const char *
ni_ifstate_print_timeval(const struct timeval *tv, char **str)
{
	return ni_string_printf(str, "%lu.%02lu",
			(unsigned long)tv->tv_sec,
			(unsigned long)tv->tv_usec);
}

ni_bool_t
ni_ifstate_parse_timeval(const char *str, struct timeval *tv)
{
	char *usec, *sec = NULL;
	unsigned long val;

	if (!str || !tv)
		return FALSE;

	ni_string_dup(&sec, str);
	if (!sec || !(usec = strchr(sec, '.'))) {
		ni_string_free(&sec);
		return FALSE;
	}
	*usec++ = '\0';

	if (ni_parse_ulong(sec, &val, 10) < 0) {
		ni_string_free(&sec);
		return FALSE;
	}
	tv->tv_sec = val;

	if (ni_parse_ulong(usec, &val, 10) < 0) {
		ni_string_free(&sec);
		return FALSE;
	}
	tv->tv_usec = val;

	ni_string_free(&sec);
	return TRUE;
}

ni_bool_t
ni_ifstate_print_xml(const ni_ifstate_t *ifstate, xml_node_t *node)
{
	const char *ptr;
	char *tmp = NULL;

	if (!ifstate || !node)
		return FALSE;

	if (!xml_node_new_element(NI_IFSTATE_XML_PERSISTENT_NODE, node,
		ni_format_boolean(ifstate->persistent)))
		return FALSE;

	if (!(ptr = ni_ifworker_state_name(ifstate->init_state)) ||
	    !xml_node_new_element(NI_IFSTATE_XML_INIT_STATE_NODE, node, ptr))
		return FALSE;

	if (!ni_ifstate_print_timeval(&ifstate->init_time, &tmp))
		return FALSE;
	if (!xml_node_new_element(NI_IFSTATE_XML_INIT_TIME_NODE, node, tmp)) {
		ni_string_free(&tmp);
		return FALSE;
	}
	ni_string_free(&tmp);

	if (!ni_ifstate_print_timeval(&ifstate->last_time, &tmp))
		return FALSE;
	if (!xml_node_new_element(NI_IFSTATE_XML_LAST_TIME_NODE, node, tmp)) {
		ni_string_free(&tmp);
		return FALSE;
	}
	ni_string_free(&tmp);

	return TRUE;
}

ni_bool_t
ni_ifstate_parse_xml(const xml_node_t *node, ni_ifstate_t *ifstate)
{
	const xml_node_t *child;

	if (!node || !ifstate)
		return FALSE;

	/* <persistent> node is mandatory */
	child = xml_node_get_child(node, NI_IFSTATE_XML_PERSISTENT_NODE);
	if (!child || !child->cdata ||
	    ni_parse_boolean(child->cdata, &ifstate->persistent)) {
		return FALSE;
	}

	/* following nodes may be missing - to be checked within a caller when needed */
	if ((child = xml_node_get_child(node, NI_IFSTATE_XML_INIT_STATE_NODE))) {
		if (!child->cdata ||
		    !ni_ifworker_state_from_name(child->cdata, &ifstate->init_state)) {
			return FALSE;
		}
	}

	if ((child = xml_node_get_child(node, NI_IFSTATE_XML_INIT_TIME_NODE))) {
		if (!child->cdata ||
		    !ni_ifstate_parse_timeval(child->cdata, &ifstate->init_time)) {
			return FALSE;
		}
	}

	if ((child = xml_node_get_child(node, NI_IFSTATE_XML_LAST_TIME_NODE))) {
		if (!child->cdata ||
		    !ni_ifstate_parse_timeval(child->cdata, &ifstate->last_time)) {
			return FALSE;
		}
	}

	return TRUE;
}

static inline void
__ni_ifstate_update_state(ni_ifstate_t *ifstate, unsigned int state)
{
	ni_timer_get_time(&ifstate->last_time);
	if (!ni_ifstate_is_valid_state(ifstate->init_state)) {
		ifstate->init_state = state;
		ifstate->init_time = ifstate->last_time;
	}
}

/*
 * Exported functions
 */
ni_ifstate_t *
ni_ifstate_new(unsigned int state)
{
	ni_ifstate_t *ifstate;

	ifstate = xcalloc(1, sizeof(*ifstate));
	if (ni_ifstate_is_valid_state(state)) {
		__ni_ifstate_update_state(ifstate, state);
	}
	return ifstate;
}

ni_bool_t
ni_ifstate_set_state(ni_ifstate_t *ifstate, unsigned int state)
{
	if (ifstate) {
		if (ni_ifstate_is_valid_state(state)) {
			__ni_ifstate_update_state(ifstate, state);
			return TRUE;
		}
	}
	return FALSE;
}

void
ni_ifstate_free(ni_ifstate_t *ifstate)
{
	if (ifstate) {
		free(ifstate);
	}
}

ni_bool_t
ni_ifstate_save(const ni_ifstate_t *ifstate, const char *ifname)
{
	char path[PATH_MAX] = {'\0'};
	char temp[PATH_MAX] = {'\0'};
	xml_node_t *node;
	FILE *fp = NULL;
	int fd;

	if (ni_string_empty(ifname) || !ni_ifstate_is_valid(ifstate))
		return FALSE;

	ni_ifstate_filename(ifname, path, sizeof(path));
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

	if (!(node = xml_node_new(NI_IFSTATE_XML_STATE_NODE, NULL))) {
		ni_error("Cannot create %s xml state node", path);
		goto failure;
	}

	if (!ni_ifstate_print_xml(ifstate, node)) {
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
ni_ifstate_load(ni_ifstate_t *ifstate, const char *ifname)
{
	char path[PATH_MAX] = {'\0'};
	xml_node_t *xml;
	xml_node_t *node;
	FILE *fp;

	if (ni_string_empty(ifname) || !ifstate)
		return FALSE;

	ni_ifstate_filename(ifname, path, sizeof(path));
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
	if (!node || !ni_string_eq(node->name, NI_IFSTATE_XML_STATE_NODE)) {
		ni_error("State file '%s' does not contain %s xml node",
			path, NI_IFSTATE_XML_STATE_NODE);
		xml_node_free(xml);
		return FALSE;
	}

	if (!ni_ifstate_parse_xml(node, ifstate) ||
	    !ni_ifstate_is_valid(ifstate)) {
		ni_error("Cannot parse state from file '%s'", path);
		xml_node_free(xml);
		return FALSE;
	}
	xml_node_free(xml);
	return TRUE;
}


ni_bool_t
ni_ifstate_move(const char *ifname_old, const char *ifname_new)
{
	char path_old[PATH_MAX] = {'\0'};
	char path_new[PATH_MAX] = {'\0'};

	if (ni_string_empty(ifname_old) || ni_string_empty(ifname_new))
		return FALSE;

	ni_ifstate_filename(ifname_old, path_old, sizeof(path_old));
	ni_ifstate_filename(ifname_new, path_new, sizeof(path_new));

	if (rename(path_old, path_new) < 0) {
		if (errno == ENOENT && !ni_file_exists(ifname_old)) {
			ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
				"State %s does not exists, not renamed to %s",
				ifname_old, ifname_new);
			return TRUE;
		}
		ni_error("Cannot rename state %s to %s", path_old, path_new);
		return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_ifstate_drop(const char *ifname)
{
	char path[PATH_MAX] = {'\0'};

	if (ni_string_empty(ifname))
		return FALSE;

	ni_ifstate_filename(ifname, path, sizeof(path));

	if (unlink(path) < 0) {
		if (errno == ENOENT)
			return TRUE;

		ni_error("Cannot remove state file '%s': %m", path);
		return FALSE;
	}
	return TRUE;
}
