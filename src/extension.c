/*
 * Handle extensions (aka external commands to configure aspects of
 * the network).
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include <wicked/xpath.h>
#include "netinfo_priv.h"
#include "config.h"

/*
 * Constructor and destructor for extension config
 */
ni_extension_t *
ni_extension_new(ni_extension_t **list, const char *name, unsigned int type)
{
	ni_extension_t *ex;

	ex = calloc(1, sizeof(*ex));
	ex->type = type;
	ni_string_dup(&ex->name, name);

	while (*list)
		list = &(*list)->next;
	*list = ex;

	return ex;
}

void
ni_extension_free(ni_extension_t *ex)
{
	ni_script_action_t *act;

	ni_string_free(&ex->name);
	if (ex->pid_file_path)
		xpath_format_free(ex->pid_file_path);

	while ((act = ex->actions) != NULL) {
		ex->actions = act->next;
		ni_script_action_free(act);
	}

	xpath_format_array_destroy(&ex->environment);
}

/*
 * Destroy extension list
 */
void
ni_extension_list_destroy(ni_extension_t **list)
{
	ni_extension_t *ex;

	while ((ex = *list) != NULL) {
		*list = ex->next;
		ni_extension_free(ex);
	}
}

/*
 * Find extension given a type (dhcp, ibft, ..) and address family.
 */
ni_extension_t *
ni_extension_list_find(ni_extension_t *head, int type, int af)
{
	unsigned int mask = 0;
	ni_extension_t *ex;

	switch (af) {
	case AF_UNSPEC:
		mask = ~0;
		break;
	case AF_INET:
		mask = NI_AF_MASK_IPV4;
		break;
	case AF_INET6:
		mask = NI_AF_MASK_IPV6;
		break;
	default:
		return NULL;
	}

	for (ex = head; ex; ex = ex->next) {
		if ((ex->supported_af & mask) && ex->type == type)
			return ex;
	}

	return NULL;
}

/*
 * Check if a given extension is running for a given interface.
 */
int
ni_extension_active(const ni_extension_t *ex, const char *ifname, xml_node_t *xml)
{
	ni_string_array_t result;
	int rv = 0;

	ni_string_array_init(&result);
	if (ex->pid_file_path == NULL)
		return 0;

	if (!xpath_format_eval(ex->pid_file_path, xml, &result) || result.count != 1) {
		error("unable to check extension %s for %s: error evaluating xpath expression",
				ex->name, ifname);
	} else {
		/* FIXME: actually read the pid file and check whether process still exists. */
		if (access(result.data[0], F_OK) == 0)
			rv = 1;
	}

	ni_string_array_destroy(&result);
	return rv;
}

/*
 * Run an extension command
 */
static int
__ni_extension_run(const ni_extension_t *ex, const char *ifname, xml_node_t *xml, const char *command_name)
{
	ni_script_action_t *script;
	const char *command_string;
	ni_string_array_t result;
	ni_string_array_t env;
	unsigned int i;
	pid_t pid;
	int rv = -1;

	if (!(script = ni_script_action_find(ex->actions, command_name))) {
		ni_error("extension %s: no %s script defined",
				ex->name, command_name);
		return -1;
	}

	ni_string_array_init(&result);
	ni_string_array_init(&env);

	debug_extension("%s extension %s for interface %s", command_name, ex->name, ifname);

	/* First, expand any environment variables. */
	for (i = 0; i < ex->environment.count; ++i) {
		if (!xpath_format_eval(ex->environment.data[i], xml, &result) || result.count > 1) {
			error("unable to %s extension %s for %s: error evaluating xpath expression",
					command_name, ex->name, ifname);
			goto done;
		}

		if (result.count != 0) {
			debug_extension("  putenv %s", result.data[0]);
			ni_string_array_append(&env, result.data[0]);
		}
		ni_string_array_destroy(&result);
	}

	if (!xpath_format_eval(script->command, xml, &result) || result.count != 1) {
		error("unable to %s extension %s for %s: error evaluating xpath expression",
				command_name, ex->name, ifname);
		goto done;
	}
	command_string = result.data[0];

	debug_extension("  run %s", command_string);

	/* Make sure we see the child's exit status, even if we
	 * set SIGCHLD to SIG_IGN somewhere. */
	signal(SIGCHLD, SIG_DFL);

	pid = fork();
	if (pid < 0) {
		ni_error("extension %s: unable to fork", ex->name);
		goto done;
	}

	if (pid == 0) {
		/* child process */

		for (i = 0; i < env.count; ++i)
			putenv(env.data[i]);

		execl("/bin/sh", "sh", "-c", command_string, NULL);
		ni_fatal("Unable to execute /bin/sh");
	} else {
		int status;

		while (1) {
			pid_t reaped;

			reaped = waitpid(pid, &status, 0);
			if (reaped < 0) {
				if (errno == EINTR)
					continue;
				ni_error("error waiting for extension process to finish: %m");
				goto done;
			}
			if (reaped != pid)
				continue;
			if (WIFSTOPPED(status))
				continue;
			break;
		}

		if (!WIFEXITED(status)) {
			error("extension %s: %s command terminated abnormally",
					ex->name, command_name);
		} else if (WEXITSTATUS(status) != 0) {
			error("extension %s: %s command exited with error status %d",
					ex->name, command_name, WEXITSTATUS(status));
		} else if (ex->pid_file_path) {
			int is_active = ni_extension_active(ex, ifname, xml);

			if (!strcmp(command_name, "start") && !is_active) {
				error("extension %s: %s command succeeded, but service not running",
						ex->name, command_name);
			} else if (!strcmp(command_name, "stop") && is_active) {
				error("extension %s: %s command succeeded, but service still running",
						ex->name, command_name);
			} else {
				rv = 0;
			}
		} else {
			rv = 0;
		}
	}

done:
	ni_string_array_destroy(&result);
	ni_string_array_destroy(&env);
	return rv;
}


/*
 * Start extension for a given interface.
 */
int
ni_extension_start(const ni_extension_t *ex, const char *ifname, xml_node_t *xml)
{
	return __ni_extension_run(ex, ifname, xml, "start");
}

/*
 * Stop extension for a given interface.
 */
int
ni_extension_stop(const ni_extension_t *ex, const char *ifname, xml_node_t *xml)
{
	return __ni_extension_run(ex, ifname, xml, "stop");
}

/*
 * Create/destroy script actions
 */
ni_script_action_t *
ni_script_action_new(const char *name, ni_script_action_t **list)
{
	ni_script_action_t *script;

	while ((script = *list) != NULL)
		list = &script->next;

	script = calloc(1, sizeof(*script));
	ni_string_dup(&script->name, name);
	*list = script;

	return script;
}

void
ni_script_action_free(ni_script_action_t *script)
{
	if (script->command)
		xpath_format_free(script->command);
	ni_string_free(&script->name);
	free(script);
}

ni_script_action_t *
ni_script_action_find(ni_script_action_t *list, const char *name)
{
	ni_script_action_t *script;

	for (script = list; script; script = script->next) {
		if (!strcmp(script->name, name))
			return script;
	}
	return NULL;
}

/*
 * Register addrconf extensions
 */
static int
ni_addrconf_extension_request(const ni_addrconf_t *ace, ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	const ni_extension_t *ex = ace->private;

	if (ni_extension_start(ex, ifp->name, (xml_node_t *) cfg_xml) < 0)
		return -1;

	return 0;
}

static int
ni_addrconf_extension_release(const ni_addrconf_t *ace, ni_interface_t *ifp, ni_addrconf_state_t *lease)
{
	const ni_extension_t *ex = ace->private;
	ni_handle_t *nih = ni_dummy_open();
	xml_node_t *cfg_xml;
	int rv;

	cfg_xml = ni_syntax_xml_from_interface(ni_default_xml_syntax(), nih, ifp);
	rv = ni_extension_stop(ex, ifp->name, cfg_xml);
	xml_node_free(cfg_xml);
	ni_close(nih);

	if (lease)
		lease->state = NI_ADDRCONF_STATE_RELEASED;

	return rv;
}

static int
ni_addrconf_extension_test(const ni_addrconf_t *ace, const ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	const ni_extension_t *ex = ace->private;

	return ni_extension_active(ex, ifp->name, (xml_node_t *) cfg_xml);
}

void
ni_addrconf_extension_register(ni_extension_t *ex)
{
	ni_addrconf_t *ace = calloc(1, sizeof(*ace));

	ace->type = ex->type;
	ace->supported_af = ex->supported_af;
	ace->private = ex;

	ace->request = ni_addrconf_extension_request;
	ace->release = ni_addrconf_extension_release;
	if (ex->pid_file_path)
		ace->test = ni_addrconf_extension_test;
	ni_addrconf_register(ace);
}

