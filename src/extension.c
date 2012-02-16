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

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/xpath.h>
#include "netinfo_priv.h"
#include "config.h"
#include "process.h"

static void		__ni_script_action_free(ni_script_action_t *);

/*
 * Constructor and destructor for extension config
 */
ni_extension_t *
ni_extension_new(ni_extension_t **list, const char *interface)
{
	ni_extension_t *ex;

	ex = calloc(1, sizeof(*ex));
	ni_string_dup(&ex->name, interface);
	ni_string_dup(&ex->interface, interface);

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
	ni_string_free(&ex->interface);
	while ((act = ex->actions) != NULL) {
		ex->actions = act->next;
		__ni_script_action_free(act);
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
ni_extension_list_find(ni_extension_t *head, const char *name)
{
	ni_extension_t *ex;

	for (ex = head; ex; ex = ex->next) {
		if (!strcmp(ex->interface, name))
			return ex;
	}

	return NULL;
}

ni_extension_t *
ni_extension_by_name(ni_extension_t *head, const char *name)
{
	ni_extension_t *ex;

	for (ex = head; ex; ex = ex->next) {
		if (!strcmp(ex->name, name))
			return ex;
	}

	return NULL;
}

/*
 * Check if a given extension is running for a given interface.
 */
int
xni_extension_active(const ni_extension_t *ex, const char *ifname, xml_node_t *xml)
{
	return 0;
}

#if 0
/*
 * Run an extension command
 */
static int
__ni_extension_run(const ni_extension_t *ex, ni_script_action_t *script, xml_node_t *xml)
{
	ni_string_array_t result;
	ni_string_array_t env;
	unsigned int i;
	pid_t pid;
	int rv = -1;

	ni_string_array_init(&result);
	ni_string_array_init(&env);

	ni_debug_extension("running extension %s %s", ex->name, script->name);

	/* First, expand any environment variables. */
#if 0
	for (i = 0; i < ex->environment.count; ++i) {
		if (!xpath_format_eval(ex->environment.data[i], xml, &result) || result.count > 1) {
			ni_error("unable to %s extension %s: error evaluating xpath expression",
					script->name, ex->name);
			goto done;
		}

		if (result.count != 0) {
			ni_debug_extension("  putenv %s", result.data[0]);
			ni_string_array_append(&env, result.data[0]);
		}
		ni_string_array_destroy(&result);
	}
#endif

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

		execl("/bin/sh", "sh", "-c", script->command, NULL);
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
			ni_error("extension %s: %s command terminated abnormally",
					ex->name, script->name);
		} else if (WEXITSTATUS(status) != 0) {
			ni_error("extension %s: %s command exited with error status %d",
					ex->name, script->name, WEXITSTATUS(status));
		} else {
			rv = 0;
		}
	}

done:
	ni_string_array_destroy(&result);
	ni_string_array_destroy(&env);
	return rv;
}
#endif

int
ni_extension_run(const ni_extension_t *ex, ni_script_action_t *script)
{
	return -1;
}

ni_script_action_t *
ni_extension_get_action(const ni_extension_t *ex, const char *name)
{
	ni_script_action_t *script;

	for (script = ex->actions; script; script = script->next) {
		if (!strcmp(script->name, name))
			return script;
	}
	return NULL;
}

/*
 * Create/destroy script actions
 */
static ni_script_action_t *
__ni_script_action_new(const char *name, ni_script_action_t **list)
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
__ni_script_action_free(ni_script_action_t *script)
{
	ni_string_free(&script->name);
	if (script->process)
		ni_process_release(script->process);
	free(script);
}

ni_process_t *
ni_extension_script_new(ni_extension_t *extension, const char *name, const char *command)
{
	ni_script_action_t *script;

	script = __ni_script_action_new(name, &extension->actions);
	script->process = ni_process_new(command);

	return script->process;
}

ni_process_t *
ni_extension_script_find(ni_extension_t *extension, const char *name)
{
	ni_script_action_t *script;

	for (script = extension->actions; script; script = script->next) {
		if (!strcmp(script->name, name))
			return script->process;
	}
	return NULL;
}
